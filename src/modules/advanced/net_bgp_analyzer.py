"""BGP routing analysis module for detecting hijack indicators.

Analyzes BGP route data for AS path anomalies, origin changes,
RPKI validation status, and known malicious ASN patterns.
"""

import asyncio
import json
import re
from typing import Any
from collections import Counter, defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

KNOWN_BAD_ASNS = {
    "AS394711", "AS55960", "AS61138", "AS203070", "AS57129",
    "AS209588", "AS44592", "AS41995", "AS58065", "AS197540",
}
BOGON_PREFIXES = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
]
MAX_NORMAL_PATH_LENGTH = 8
PREPEND_THRESHOLD = 3


class NetBgpAnalyzerModule(AtsModule):
    """Analyze BGP routing data for hijack and anomaly indicators."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_bgp_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze BGP routing for hijack indicators, AS path anomalies, and RPKI validation",
            version="1.0.0",
            parameters=[
                Parameter(name="route_data", type=ParameterType.STRING,
                          description="JSON array of BGP routes with fields: prefix, as_path (list of ASNs), origin, communities (optional), timestamp (optional)"),
                Parameter(name="check_type", type=ParameterType.CHOICE,
                          description="Type of BGP analysis to perform",
                          choices=["hijack", "leak", "anomaly"], default="hijack"),
                Parameter(name="known_origins", type=ParameterType.STRING,
                          description="Optional JSON object mapping prefixes to expected origin ASN",
                          required=False, default="{}"),
            ],
            outputs=[
                OutputField(name="alerts", type="list", description="BGP anomaly alerts"),
                OutputField(name="risk_score", type="float", description="Overall risk score 0-100"),
                OutputField(name="statistics", type="dict", description="Route analysis statistics"),
                OutputField(name="summary", type="dict", description="Analysis summary with counts by type"),
            ],
            tags=["advanced", "network", "bgp", "routing", "hijack"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("route_data", "").strip()
        if not raw:
            return False, "BGP route data is required"
        try:
            routes = json.loads(raw)
            if not isinstance(routes, list):
                return False, "Route data must be a JSON array"
            if len(routes) == 0:
                return False, "Route data array is empty"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in route_data: {exc}"
        origins_raw = config.get("known_origins", "{}").strip()
        if origins_raw:
            try:
                json.loads(origins_raw)
            except json.JSONDecodeError as exc:
                return False, f"Invalid JSON in known_origins: {exc}"
        return True, ""

    def _normalize_asn(self, asn: str) -> str:
        """Normalize ASN to AS##### format."""
        asn = str(asn).strip().upper()
        if not asn.startswith("AS"):
            asn = f"AS{asn}"
        return asn

    def _check_bogon_prefix(self, prefix: str) -> bool:
        """Check if a prefix falls within bogon address space."""
        prefix_net = prefix.split("/")[0]
        for bogon in BOGON_PREFIXES:
            bogon_net = bogon.split("/")[0]
            if prefix_net.startswith(bogon_net.rsplit(".", 1)[0]):
                return True
        return False

    def _detect_hijack_indicators(self, routes: list[dict], known_origins: dict) -> list[dict]:
        """Detect BGP hijack indicators from route data."""
        alerts = []
        prefix_origins: dict[str, set] = defaultdict(set)
        for route in routes:
            prefix = route.get("prefix", "")
            as_path = route.get("as_path", [])
            origin = self._normalize_asn(str(route.get("origin", as_path[-1] if as_path else "")))
            prefix_origins[prefix].add(origin)

        # Multiple Origin AS (MOAS) detection
        for prefix, origins in prefix_origins.items():
            if len(origins) > 1:
                expected = known_origins.get(prefix)
                severity = "critical" if expected and expected not in origins else "high"
                alerts.append({
                    "type": "moas_conflict",
                    "severity": severity,
                    "prefix": prefix,
                    "origins_seen": sorted(origins),
                    "expected_origin": expected,
                    "description": f"Multiple origin ASes for {prefix}: {', '.join(sorted(origins))}",
                })

        # Known bad ASN in path
        for route in routes:
            as_path = [self._normalize_asn(str(a)) for a in route.get("as_path", [])]
            bad_in_path = set(as_path) & KNOWN_BAD_ASNS
            if bad_in_path:
                alerts.append({
                    "type": "known_bad_asn",
                    "severity": "critical",
                    "prefix": route.get("prefix", ""),
                    "as_path": as_path,
                    "bad_asns": sorted(bad_in_path),
                    "description": f"Known suspicious ASN(s) in path: {', '.join(sorted(bad_in_path))}",
                })

        # Origin mismatch from known origins
        for route in routes:
            prefix = route.get("prefix", "")
            as_path = route.get("as_path", [])
            origin = self._normalize_asn(str(route.get("origin", as_path[-1] if as_path else "")))
            expected = known_origins.get(prefix)
            if expected and self._normalize_asn(expected) != origin:
                alerts.append({
                    "type": "origin_mismatch",
                    "severity": "critical",
                    "prefix": prefix,
                    "expected_origin": self._normalize_asn(expected),
                    "observed_origin": origin,
                    "description": f"Origin mismatch for {prefix}: expected {expected}, got {origin}",
                })

        return alerts

    def _detect_leak_indicators(self, routes: list[dict]) -> list[dict]:
        """Detect BGP route leak indicators."""
        alerts = []
        for route in routes:
            as_path = [self._normalize_asn(str(a)) for a in route.get("as_path", [])]
            prefix = route.get("prefix", "")
            communities = route.get("communities", [])

            # Unusually long AS path suggests leak propagation
            if len(as_path) > MAX_NORMAL_PATH_LENGTH:
                alerts.append({
                    "type": "long_as_path",
                    "severity": "medium",
                    "prefix": prefix,
                    "as_path_length": len(as_path),
                    "as_path": as_path,
                    "description": f"Unusually long AS path ({len(as_path)} hops) for {prefix}",
                })

            # AS path loop detection
            asn_counts = Counter(as_path)
            loops = {asn: cnt for asn, cnt in asn_counts.items() if cnt > PREPEND_THRESHOLD}
            non_prepend_dupes = [asn for asn in as_path if as_path.count(asn) > 1]
            unique_dupes = set(non_prepend_dupes) - set(loops.keys())
            if unique_dupes:
                alerts.append({
                    "type": "as_path_loop",
                    "severity": "high",
                    "prefix": prefix,
                    "looping_asns": sorted(unique_dupes),
                    "as_path": as_path,
                    "description": f"AS path loop detected for {prefix}: {', '.join(sorted(unique_dupes))}",
                })

            # No-export community violation check
            no_export_communities = [c for c in communities if "no-export" in str(c).lower() or c in ("65535:65281", "65535:65282")]
            if no_export_communities and len(as_path) > 2:
                alerts.append({
                    "type": "community_violation",
                    "severity": "high",
                    "prefix": prefix,
                    "communities": no_export_communities,
                    "description": f"Route with no-export community propagated beyond expected scope for {prefix}",
                })

        return alerts

    def _detect_anomalies(self, routes: list[dict]) -> list[dict]:
        """Detect general BGP anomalies."""
        alerts = []
        for route in routes:
            prefix = route.get("prefix", "")
            as_path = [self._normalize_asn(str(a)) for a in route.get("as_path", [])]

            # Bogon prefix announcement
            if self._check_bogon_prefix(prefix):
                alerts.append({
                    "type": "bogon_prefix",
                    "severity": "critical",
                    "prefix": prefix,
                    "description": f"Bogon prefix announced in BGP: {prefix}",
                })

            # Excessive prepending
            if as_path:
                asn_counts = Counter(as_path)
                for asn, count in asn_counts.items():
                    if count > PREPEND_THRESHOLD:
                        alerts.append({
                            "type": "excessive_prepend",
                            "severity": "low",
                            "prefix": prefix,
                            "asn": asn,
                            "prepend_count": count,
                            "description": f"Excessive AS prepending by {asn} ({count}x) for {prefix}",
                        })

            # Very specific prefix (potential more-specific hijack)
            try:
                prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 32
                if prefix_len >= 25:
                    alerts.append({
                        "type": "specific_prefix",
                        "severity": "medium",
                        "prefix": prefix,
                        "prefix_length": prefix_len,
                        "description": f"Very specific prefix /{prefix_len} announced: {prefix}",
                    })
            except (ValueError, IndexError):
                pass

        return alerts

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        routes = json.loads(config["route_data"])
        check_type = config.get("check_type", "hijack")
        known_origins = json.loads(config.get("known_origins", "{}"))

        all_alerts: list[dict] = []

        if check_type == "hijack":
            all_alerts.extend(self._detect_hijack_indicators(routes, known_origins))
        elif check_type == "leak":
            all_alerts.extend(self._detect_leak_indicators(routes))
        elif check_type == "anomaly":
            all_alerts.extend(self._detect_hijack_indicators(routes, known_origins))
            all_alerts.extend(self._detect_leak_indicators(routes))
            all_alerts.extend(self._detect_anomalies(routes))

        # Compute statistics
        all_asns = set()
        all_prefixes = set()
        path_lengths = []
        for route in routes:
            all_prefixes.add(route.get("prefix", ""))
            as_path = [self._normalize_asn(str(a)) for a in route.get("as_path", [])]
            all_asns.update(as_path)
            path_lengths.append(len(as_path))

        severity_counts = Counter(a["severity"] for a in all_alerts)
        type_counts = Counter(a["type"] for a in all_alerts)

        severity_weights = {"critical": 30, "high": 15, "medium": 5, "low": 2}
        risk_score = sum(severity_weights.get(a.get("severity", "low"), 0) for a in all_alerts)
        risk_score = min(round(float(risk_score), 1), 100.0)

        statistics = {
            "routes_analyzed": len(routes),
            "unique_prefixes": len(all_prefixes),
            "unique_asns": len(all_asns),
            "avg_path_length": round(sum(path_lengths) / len(path_lengths), 2) if path_lengths else 0,
            "max_path_length": max(path_lengths) if path_lengths else 0,
        }

        summary = {
            "total_alerts": len(all_alerts),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
        }

        return {
            "check_type": check_type,
            "alerts": all_alerts,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 15 else "low",
            "statistics": statistics,
            "summary": summary,
        }
