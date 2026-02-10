"""Network forensics analysis module.

Analyze network capture logs for forensic indicators including
DNS tunneling patterns, large data transfers, beacon behavior, and unusual ports.
"""

import asyncio
import os
import re
import math
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Common well-known ports
WELL_KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465,
    514, 587, 636, 993, 995, 1433, 1434, 3306, 3389, 5432,
    5900, 8080, 8443, 8888,
}

# Suspicious ports often used by malware
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
    1234, 31337, 12345, 54321,  # Classic trojan ports
    4443, 8443, 8880,  # Alt HTTPS/HTTP
    6667, 6668, 6669,  # IRC (C2)
    1080, 3128, 8118,  # Proxy ports
}

# Regex patterns for network log parsing
CONN_LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:.*?\s+)?(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(?P<src_port>\d+)\s+"
    r"(?:->|-->|\s+)"
    r"\s*(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(?P<dst_port>\d+)"
    r"(?:\s+(?P<proto>\w+))?"
    r"(?:\s+(?P<bytes>\d+))?"
)

DNS_QUERY_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r".*?(?:query|DNS).*?"
    r"(?P<domain>[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?)"
    r"(?:\s+(?P<type>A|AAAA|MX|NS|TXT|CNAME|PTR|SRV|SOA))?"
)

# Simpler fallback patterns
SIMPLE_CONN_PATTERN = re.compile(
    r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<dst_port>\d+)"
)


class NetworkForensicsModule(AtsModule):
    """Analyze network captures and logs for forensic indicators."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="network_forensics",
            category=ModuleCategory.FORENSICS,
            description="Analyze network captures/logs for forensic indicators including DNS tunneling, data exfiltration, beacon behavior, and unusual ports",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="log_path",
                    type=ParameterType.FILE,
                    description="Path to network log or connection log file",
                    required=True,
                ),
                Parameter(
                    name="log_format",
                    type=ParameterType.CHOICE,
                    description="Format of the network log",
                    required=False,
                    default="auto",
                    choices=["auto", "conn_log", "dns_log", "csv", "zeek"],
                ),
                Parameter(
                    name="beacon_threshold",
                    type=ParameterType.FLOAT,
                    description="Beacon regularity threshold (0.0-1.0, lower = more regular = more suspicious)",
                    required=False,
                    default=0.15,
                    min_value=0.01,
                    max_value=1.0,
                ),
                Parameter(
                    name="data_threshold_mb",
                    type=ParameterType.FLOAT,
                    description="Threshold in MB for flagging large data transfers",
                    required=False,
                    default=50.0,
                    min_value=1.0,
                    max_value=10000.0,
                ),
                Parameter(
                    name="max_lines",
                    type=ParameterType.INTEGER,
                    description="Maximum number of lines to analyze (0 = unlimited)",
                    required=False,
                    default=500000,
                    min_value=0,
                    max_value=10000000,
                ),
            ],
            outputs=[
                OutputField(name="total_connections", type="integer", description="Total connections analyzed"),
                OutputField(name="unusual_ports", type="list", description="Connections to unusual or suspicious ports"),
                OutputField(name="dns_tunneling_suspects", type="list", description="Domains suspected of DNS tunneling"),
                OutputField(name="large_transfers", type="list", description="Large data transfer events"),
                OutputField(name="beacon_candidates", type="list", description="Connections showing beacon-like regularity"),
                OutputField(name="top_talkers", type="dict", description="Top source and destination IPs by connection count"),
                OutputField(name="risk_score", type="float", description="Overall network risk score 0-100"),
            ],
            tags=["forensics", "network", "pcap", "dns", "beacon", "exfiltration"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        log_path = config.get("log_path", "").strip()
        if not log_path:
            return False, "log_path is required"
        if not os.path.isfile(log_path):
            return False, f"Log file not found: {log_path}"
        return True, ""

    def _parse_connections(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse connection entries from log lines."""
        connections = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = CONN_LOG_PATTERN.search(line)
            if match:
                d = match.groupdict()
                conn = {
                    "timestamp": d.get("timestamp", ""),
                    "src_ip": d.get("src_ip", ""),
                    "src_port": int(d["src_port"]) if d.get("src_port") else 0,
                    "dst_ip": d.get("dst_ip", ""),
                    "dst_port": int(d["dst_port"]) if d.get("dst_port") else 0,
                    "protocol": d.get("proto", "tcp"),
                    "bytes": int(d["bytes"]) if d.get("bytes") else 0,
                }
                connections.append(conn)
                continue

            # Fallback simple pattern
            match = SIMPLE_CONN_PATTERN.search(line)
            if match:
                d = match.groupdict()
                connections.append({
                    "timestamp": "",
                    "src_ip": d.get("src_ip", ""),
                    "src_port": 0,
                    "dst_ip": d.get("dst_ip", ""),
                    "dst_port": int(d["dst_port"]) if d.get("dst_port") else 0,
                    "protocol": "unknown",
                    "bytes": 0,
                })

        return connections

    def _parse_dns_queries(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse DNS query entries from log lines."""
        queries = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = DNS_QUERY_PATTERN.search(line)
            if match:
                d = match.groupdict()
                queries.append({
                    "timestamp": d.get("timestamp", ""),
                    "domain": d.get("domain", ""),
                    "query_type": d.get("type", "A"),
                })
        return queries

    def _detect_dns_tunneling(self, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling by analyzing query patterns."""
        suspects = []
        domain_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "count": 0,
            "subdomains": set(),
            "total_label_length": 0,
            "txt_queries": 0,
        })

        for q in queries:
            domain = q.get("domain", "")
            if not domain or "." not in domain:
                continue

            parts = domain.split(".")
            if len(parts) < 2:
                continue

            # Use base domain (last 2 parts)
            base = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])

            stats = domain_stats[base]
            stats["count"] += 1
            if subdomain:
                stats["subdomains"].add(subdomain)
                stats["total_label_length"] += len(subdomain)
            if q.get("query_type") == "TXT":
                stats["txt_queries"] += 1

        for base_domain, stats in domain_stats.items():
            score = 0
            reasons = []

            # High number of unique subdomains
            unique_subs = len(stats["subdomains"])
            if unique_subs > 50:
                score += 40
                reasons.append(f"High unique subdomain count: {unique_subs}")
            elif unique_subs > 20:
                score += 20
                reasons.append(f"Elevated unique subdomain count: {unique_subs}")

            # Long subdomain labels (encoded data)
            if stats["count"] > 0:
                avg_label_len = stats["total_label_length"] / max(stats["count"], 1)
                if avg_label_len > 30:
                    score += 30
                    reasons.append(f"Long average subdomain length: {avg_label_len:.1f}")
                elif avg_label_len > 15:
                    score += 15
                    reasons.append(f"Elevated subdomain length: {avg_label_len:.1f}")

            # High TXT query ratio
            if stats["count"] > 10:
                txt_ratio = stats["txt_queries"] / stats["count"]
                if txt_ratio > 0.5:
                    score += 20
                    reasons.append(f"High TXT query ratio: {txt_ratio:.2f}")

            # High query volume
            if stats["count"] > 500:
                score += 10
                reasons.append(f"High query volume: {stats['count']}")

            if score >= 30:
                suspects.append({
                    "domain": base_domain,
                    "score": score,
                    "query_count": stats["count"],
                    "unique_subdomains": unique_subs,
                    "reasons": reasons,
                })

        suspects.sort(key=lambda x: x["score"], reverse=True)
        return suspects[:50]

    def _detect_beacons(self, connections: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
        """Detect beacon-like behavior (regular intervals between connections)."""
        candidates = []
        # Group by src_ip -> dst_ip:dst_port
        groups: Dict[str, List[str]] = defaultdict(list)
        for conn in connections:
            if conn["timestamp"]:
                key = f"{conn['src_ip']}->{conn['dst_ip']}:{conn['dst_port']}"
                groups[key].append(conn["timestamp"])

        for key, timestamps in groups.items():
            if len(timestamps) < 10:
                continue

            # Parse timestamps and compute intervals
            parsed_ts = []
            for ts_str in timestamps:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace("+00:00", ""))
                    parsed_ts.append(ts)
                except ValueError:
                    continue

            if len(parsed_ts) < 10:
                continue

            parsed_ts.sort()
            intervals = []
            for i in range(1, len(parsed_ts)):
                delta = (parsed_ts[i] - parsed_ts[i - 1]).total_seconds()
                if delta > 0:
                    intervals.append(delta)

            if len(intervals) < 5:
                continue

            # Calculate coefficient of variation (lower = more regular)
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval

            if cv <= threshold:
                parts = key.split("->")
                candidates.append({
                    "source": parts[0] if len(parts) > 0 else "",
                    "destination": parts[1] if len(parts) > 1 else "",
                    "connection_count": len(parsed_ts),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "first_seen": parsed_ts[0].isoformat(),
                    "last_seen": parsed_ts[-1].isoformat(),
                })

        candidates.sort(key=lambda x: x["coefficient_of_variation"])
        return candidates[:50]

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        log_path = config["log_path"].strip()
        beacon_threshold = config.get("beacon_threshold", 0.15)
        data_threshold_mb = config.get("data_threshold_mb", 50.0)
        max_lines = config.get("max_lines", 500000)

        self.logger.info("starting_network_forensics", path=log_path)

        loop = asyncio.get_event_loop()

        def _read_lines():
            lines = []
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if max_lines and i >= max_lines:
                        break
                    lines.append(line)
            return lines

        lines = await loop.run_in_executor(None, _read_lines)

        # Parse connections and DNS queries
        connections = self._parse_connections(lines)
        dns_queries = self._parse_dns_queries(lines)

        # Detect unusual ports
        unusual_ports = []
        for conn in connections:
            port = conn["dst_port"]
            if port and port not in WELL_KNOWN_PORTS:
                entry = {
                    "src_ip": conn["src_ip"],
                    "dst_ip": conn["dst_ip"],
                    "dst_port": port,
                    "timestamp": conn.get("timestamp", ""),
                    "suspicious": port in SUSPICIOUS_PORTS,
                }
                unusual_ports.append(entry)

        # Detect large data transfers
        data_threshold_bytes = data_threshold_mb * 1024 * 1024
        transfer_totals: Dict[str, int] = defaultdict(int)
        for conn in connections:
            if conn["bytes"] > 0:
                key = f"{conn['src_ip']}->{conn['dst_ip']}"
                transfer_totals[key] += conn["bytes"]

        large_transfers = []
        for key, total_bytes in sorted(transfer_totals.items(), key=lambda x: x[1], reverse=True):
            if total_bytes >= data_threshold_bytes:
                parts = key.split("->")
                large_transfers.append({
                    "source": parts[0],
                    "destination": parts[1],
                    "total_bytes": total_bytes,
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                })

        # Detect DNS tunneling
        dns_tunneling = self._detect_dns_tunneling(dns_queries)

        # Detect beacons
        beacons = self._detect_beacons(connections, beacon_threshold)

        # Top talkers
        src_counter = Counter(c["src_ip"] for c in connections if c["src_ip"])
        dst_counter = Counter(c["dst_ip"] for c in connections if c["dst_ip"])
        top_talkers = {
            "top_sources": dict(src_counter.most_common(20)),
            "top_destinations": dict(dst_counter.most_common(20)),
        }

        # Risk score
        risk = 0.0
        if dns_tunneling:
            risk += min(len(dns_tunneling) * 10, 30)
        if beacons:
            risk += min(len(beacons) * 8, 25)
        if large_transfers:
            risk += min(len(large_transfers) * 5, 15)
        suspicious_port_count = sum(1 for p in unusual_ports if p.get("suspicious"))
        if suspicious_port_count:
            risk += min(suspicious_port_count * 3, 20)
        if len(unusual_ports) > 100:
            risk += 10
        risk = min(risk, 100.0)

        self.logger.info(
            "network_forensics_complete",
            connections=len(connections),
            dns_queries=len(dns_queries),
            risk_score=risk,
        )

        return {
            "log_path": log_path,
            "total_connections": len(connections),
            "total_dns_queries": len(dns_queries),
            "unusual_ports": unusual_ports[:200],
            "dns_tunneling_suspects": dns_tunneling,
            "large_transfers": large_transfers[:50],
            "beacon_candidates": beacons,
            "top_talkers": top_talkers,
            "risk_score": risk,
        }
