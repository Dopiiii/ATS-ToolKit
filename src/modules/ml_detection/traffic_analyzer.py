"""Network traffic analysis module for threat detection.

Analyze connection records to detect port scans, beacon patterns,
data exfiltration, and DNS tunneling using statistical methods.
"""

import asyncio
import re
import json
import math
from typing import Any
from collections import Counter, defaultdict
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class TrafficAnalyzerModule(AtsModule):
    """Analyze network traffic patterns for security threats."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="traffic_analyzer",
            category=ModuleCategory.ML_DETECTION,
            description="Analyze network traffic patterns to detect port scans, beacons, exfiltration, and DNS tunneling",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="traffic_data",
                    type=ParameterType.STRING,
                    description="JSON array of connection records with fields: src, dst, port, bytes, timestamp, and optional protocol/domain",
                    required=True,
                ),
                Parameter(
                    name="analysis_type",
                    type=ParameterType.CHOICE,
                    description="Type of analysis to perform",
                    required=False,
                    default="full",
                    choices=["full", "beacon", "exfil", "scan"],
                ),
                Parameter(
                    name="beacon_tolerance",
                    type=ParameterType.FLOAT,
                    description="Coefficient of variation threshold for beacon detection (lower = stricter)",
                    required=False,
                    default=0.2,
                    min_value=0.01,
                    max_value=1.0,
                ),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Detected threats with severity and details"),
                OutputField(name="finding_count", type="integer", description="Total number of findings"),
                OutputField(name="risk_summary", type="dict", description="Summary of risk by category"),
                OutputField(name="traffic_stats", type="dict", description="General traffic statistics"),
            ],
            tags=["ml", "detection", "traffic", "network", "beacon", "exfiltration"],
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("traffic_data", "").strip()
        if not raw:
            return False, "traffic_data is required"
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, list):
                return False, "traffic_data must be a JSON array"
            if len(parsed) == 0:
                return False, "traffic_data array must not be empty"
        except json.JSONDecodeError as exc:
            return False, f"traffic_data is not valid JSON: {exc}"
        analysis = config.get("analysis_type", "full")
        if analysis not in ("full", "beacon", "exfil", "scan"):
            return False, "analysis_type must be one of: full, beacon, exfil, scan"
        return True, ""

    def _parse_timestamp(self, raw: str) -> datetime | None:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(str(raw), fmt)
            except (ValueError, TypeError):
                continue
        try:
            return datetime.fromtimestamp(float(raw))
        except (ValueError, TypeError, OSError):
            return None

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _detect_port_scans(self, records: list[dict]) -> list[dict[str, Any]]:
        """Detect hosts scanning many ports on single destinations."""
        findings = []
        # Group by (src -> dst): set of ports
        pair_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        for r in records:
            src, dst = r.get("src", ""), r.get("dst", "")
            port = r.get("port")
            if src and dst and port is not None:
                try:
                    pair_ports[(src, dst)].add(int(port))
                except (ValueError, TypeError):
                    continue

        for (src, dst), ports in pair_ports.items():
            if len(ports) >= 10:
                severity = "critical" if len(ports) >= 100 else "high" if len(ports) >= 50 else "medium"
                findings.append({
                    "type": "port_scan",
                    "severity": severity,
                    "source": src,
                    "destination": dst,
                    "unique_ports": len(ports),
                    "port_sample": sorted(list(ports))[:20],
                    "description": f"{src} scanned {len(ports)} ports on {dst}",
                })
        return findings

    def _detect_beacons(self, records: list[dict], tolerance: float) -> list[dict[str, Any]]:
        """Detect periodic communication (C2 beacons) via interval regularity."""
        findings = []
        # Group by (src, dst, port): list of timestamps
        streams: dict[tuple[str, str, str], list[datetime]] = defaultdict(list)
        for r in records:
            src, dst = r.get("src", ""), r.get("dst", "")
            port = str(r.get("port", ""))
            ts = self._parse_timestamp(str(r.get("timestamp", "")))
            if src and dst and ts:
                streams[(src, dst, port)].append(ts)

        for (src, dst, port), timestamps in streams.items():
            if len(timestamps) < 5:
                continue
            sorted_ts = sorted(timestamps)
            intervals = [(sorted_ts[i + 1] - sorted_ts[i]).total_seconds() for i in range(len(sorted_ts) - 1)]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue
            variance = sum((iv - mean_interval) ** 2 for iv in intervals) / len(intervals)
            stddev = math.sqrt(variance)
            cv = stddev / mean_interval  # coefficient of variation

            if cv <= tolerance:
                severity = "critical" if cv < tolerance * 0.5 else "high"
                findings.append({
                    "type": "beacon_pattern",
                    "severity": severity,
                    "source": src,
                    "destination": dst,
                    "port": port,
                    "connection_count": len(timestamps),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "description": f"Regular {mean_interval:.0f}s interval from {src} to {dst}:{port} (CV={cv:.3f})",
                })
        return findings

    def _detect_exfiltration(self, records: list[dict]) -> list[dict[str, Any]]:
        """Detect potential data exfiltration via large outbound transfers."""
        findings = []
        outbound_by_dest: dict[str, int] = defaultdict(int)
        for r in records:
            dst = r.get("dst", "")
            byte_count = r.get("bytes", 0)
            try:
                byte_count = int(byte_count)
            except (ValueError, TypeError):
                byte_count = 0
            if dst and byte_count > 0:
                outbound_by_dest[dst] += byte_count

        if not outbound_by_dest:
            return findings

        values = list(outbound_by_dest.values())
        mean_bytes = sum(values) / len(values)
        variance = sum((v - mean_bytes) ** 2 for v in values) / len(values) if len(values) > 1 else 0
        stddev = math.sqrt(variance)

        for dst, total_bytes in outbound_by_dest.items():
            zscore = ((total_bytes - mean_bytes) / stddev) if stddev > 0 else 0
            if total_bytes > 10_000_000 or (zscore > 2.5 and total_bytes > 1_000_000):
                severity = "critical" if total_bytes > 100_000_000 else "high" if total_bytes > 10_000_000 else "medium"
                findings.append({
                    "type": "data_exfiltration",
                    "severity": severity,
                    "destination": dst,
                    "total_bytes": total_bytes,
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                    "z_score": round(zscore, 4),
                    "description": f"{total_bytes / (1024*1024):.1f} MB transferred to {dst} (z={zscore:.2f})",
                })
        return findings

    def _detect_dns_tunneling(self, records: list[dict]) -> list[dict[str, Any]]:
        """Detect DNS tunneling via high-entropy domain queries."""
        findings = []
        domains = [r.get("domain", "") for r in records if r.get("domain")]
        if not domains:
            return findings

        for domain in set(domains):
            # Analyze the subdomain portion (everything before the last two labels)
            parts = domain.split(".")
            if len(parts) <= 2:
                continue
            subdomain = ".".join(parts[:-2])
            entropy = self._shannon_entropy(subdomain)
            length = len(subdomain)
            if entropy > 4.0 and length > 20:
                severity = "critical" if entropy > 5.0 else "high" if entropy > 4.5 else "medium"
                count = domains.count(domain)
                findings.append({
                    "type": "dns_tunneling",
                    "severity": severity,
                    "domain": domain,
                    "subdomain_entropy": round(entropy, 4),
                    "subdomain_length": length,
                    "query_count": count,
                    "description": f"High-entropy subdomain in {domain} (entropy={entropy:.2f}, len={length})",
                })
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        records = json.loads(config["traffic_data"].strip())
        analysis_type = config.get("analysis_type", "full")
        beacon_tolerance = config.get("beacon_tolerance", 0.2)

        self.logger.info("starting_traffic_analysis", type=analysis_type, records=len(records))

        findings: list[dict[str, Any]] = []

        # Run requested analyses
        if analysis_type in ("full", "scan"):
            findings.extend(self._detect_port_scans(records))
        if analysis_type in ("full", "beacon"):
            findings.extend(self._detect_beacons(records, beacon_tolerance))
        if analysis_type in ("full", "exfil"):
            findings.extend(self._detect_exfiltration(records))
        if analysis_type in ("full",):
            findings.extend(self._detect_dns_tunneling(records))

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 3))

        # Build risk summary
        risk_summary: dict[str, int] = Counter()
        for f in findings:
            risk_summary[f.get("severity", "low")] += 1

        # Compute traffic statistics
        total_bytes = 0
        unique_sources: set[str] = set()
        unique_dests: set[str] = set()
        unique_ports: set[int] = set()
        for r in records:
            try:
                total_bytes += int(r.get("bytes", 0))
            except (ValueError, TypeError):
                pass
            if r.get("src"):
                unique_sources.add(r["src"])
            if r.get("dst"):
                unique_dests.add(r["dst"])
            if r.get("port") is not None:
                try:
                    unique_ports.add(int(r["port"]))
                except (ValueError, TypeError):
                    pass

        traffic_stats = {
            "total_records": len(records),
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2) if total_bytes > 0 else 0,
            "unique_sources": len(unique_sources),
            "unique_destinations": len(unique_dests),
            "unique_ports": len(unique_ports),
        }

        self.logger.info(
            "traffic_analysis_complete",
            finding_count=len(findings),
            risk_summary=dict(risk_summary),
        )

        return {
            "findings": findings,
            "finding_count": len(findings),
            "risk_summary": dict(risk_summary),
            "traffic_stats": traffic_stats,
            "analysis_type": analysis_type,
        }
