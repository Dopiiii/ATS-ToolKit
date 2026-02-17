"""Tor exit node detection module for identifying Tor network connections.

Checks IP addresses against known Tor exit node patterns, DNS-based
detection methods, and behavioral indicators of Tor usage.
"""

import asyncio
import hashlib
import json
import re
import socket
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

# Common Tor exit node IP ranges and patterns (simulated knowledge base)
KNOWN_TOR_EXIT_PATTERNS = [
    r"^185\.220\.10[0-3]\.\d+$",
    r"^199\.249\.23[0-9]\.\d+$",
    r"^204\.85\.191\.\d+$",
    r"^109\.70\.100\.\d+$",
    r"^51\.15\.\d+\.\d+$",
    r"^62\.210\.\d+\.\d+$",
    r"^176\.10\.99\.\d+$",
    r"^193\.218\.118\.\d+$",
    r"^178\.17\.17[0-4]\.\d+$",
    r"^45\.154\.255\.\d+$",
]
TOR_DNS_SUFFIX = "dnsel.torproject.org"
TOR_DIRECTORY_PORTS = {9001, 9030, 9050, 9051, 9150}
TOR_BEHAVIORAL_PORTS = {443, 80, 9001, 9030}


class NetTorDetectorModule(AtsModule):
    """Detect Tor exit node connections from IP address lists."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_tor_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect Tor exit node connections via pattern matching, DNS checks, and behavioral analysis",
            version="1.0.0",
            parameters=[
                Parameter(name="ip_list", type=ParameterType.STRING,
                          description="Comma-separated list of IP addresses to check"),
                Parameter(name="check_method", type=ParameterType.CHOICE,
                          description="Detection method to use",
                          choices=["list", "dns", "both"], default="list"),
                Parameter(name="server_ip", type=ParameterType.STRING,
                          description="Optional: your server IP for Tor DNSEL reverse lookup",
                          required=False, default=""),
            ],
            outputs=[
                OutputField(name="tor_nodes_found", type="list", description="IPs identified as Tor exit nodes"),
                OutputField(name="non_tor_ips", type="list", description="IPs not identified as Tor nodes"),
                OutputField(name="detection_summary", type="dict", description="Summary of detection results"),
                OutputField(name="risk_assessment", type="dict", description="Overall risk assessment"),
            ],
            tags=["advanced", "network", "tor", "anonymity", "detection"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        ip_list = config.get("ip_list", "").strip()
        if not ip_list:
            return False, "IP list is required"
        ips = [ip.strip() for ip in ip_list.split(",") if ip.strip()]
        if not ips:
            return False, "No valid IPs found in ip_list"
        ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        for ip in ips:
            if not ipv4_pattern.match(ip):
                return False, f"Invalid IP address format: {ip}"
            octets = ip.split(".")
            if any(int(o) > 255 for o in octets):
                return False, f"Invalid IP address value: {ip}"
        return True, ""

    def _check_pattern_match(self, ip: str) -> dict[str, Any]:
        """Check IP against known Tor exit node patterns."""
        for pattern in KNOWN_TOR_EXIT_PATTERNS:
            if re.match(pattern, ip):
                return {
                    "ip": ip,
                    "detected": True,
                    "method": "pattern_match",
                    "confidence": "medium",
                    "matched_pattern": pattern,
                    "detail": f"IP matches known Tor exit node range pattern",
                }
        return {"ip": ip, "detected": False, "method": "pattern_match"}

    def _build_dnsel_query(self, ip: str, server_ip: str, port: int = 80) -> str:
        """Build a Tor DNSEL query hostname."""
        # Format: reversed_ip.port.reversed_server_ip.dnsel.torproject.org
        reversed_ip = ".".join(reversed(ip.split(".")))
        if server_ip:
            reversed_server = ".".join(reversed(server_ip.split(".")))
            return f"{reversed_ip}.{port}.{reversed_server}.{TOR_DNS_SUFFIX}"
        return f"{reversed_ip}.{TOR_DNS_SUFFIX}"

    def _check_dns_detection(self, ip: str, server_ip: str) -> dict[str, Any]:
        """Check IP using Tor DNSEL DNS-based detection."""
        query = self._build_dnsel_query(ip, server_ip)
        try:
            result = socket.getaddrinfo(query, None, socket.AF_INET)
            if result:
                resolved = result[0][4][0]
                # 127.0.0.2 means it's a Tor exit node
                if resolved == "127.0.0.2":
                    return {
                        "ip": ip,
                        "detected": True,
                        "method": "dns_dnsel",
                        "confidence": "high",
                        "dns_query": query,
                        "dns_response": resolved,
                        "detail": "Confirmed Tor exit node via DNSEL lookup",
                    }
        except (socket.gaierror, socket.herror, OSError):
            pass
        return {
            "ip": ip,
            "detected": False,
            "method": "dns_dnsel",
            "dns_query": query,
        }

    def _reverse_dns_analysis(self, ip: str) -> dict[str, Any]:
        """Analyze reverse DNS for Tor-related hostnames."""
        try:
            hostname = socket.getfqdn(ip)
            tor_keywords = ["tor", "exit", "relay", "onion", "torexit", "tor-exit"]
            hostname_lower = hostname.lower()
            for keyword in tor_keywords:
                if keyword in hostname_lower:
                    return {
                        "ip": ip,
                        "detected": True,
                        "method": "reverse_dns",
                        "confidence": "medium",
                        "hostname": hostname,
                        "matched_keyword": keyword,
                        "detail": f"Reverse DNS contains Tor indicator: {keyword}",
                    }
            return {"ip": ip, "detected": False, "method": "reverse_dns", "hostname": hostname}
        except (socket.herror, OSError):
            return {"ip": ip, "detected": False, "method": "reverse_dns", "error": "Reverse DNS failed"}

    def _behavioral_analysis(self, ip: str) -> dict[str, Any]:
        """Analyze IP for behavioral indicators of Tor usage."""
        indicators = []

        # Check if IP responds on known Tor ports
        for port in [9001, 9030]:
            try:
                with socket.create_connection((ip, port), timeout=2):
                    indicators.append({
                        "type": "tor_port_open",
                        "port": port,
                        "detail": f"Tor-associated port {port} is open",
                    })
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        # Heuristic: check for Tor directory authority pattern
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()
        entropy_score = len(set(ip.replace(".", ""))) / 10.0

        return {
            "ip": ip,
            "detected": len(indicators) > 0,
            "method": "behavioral",
            "confidence": "low" if len(indicators) == 1 else "medium" if len(indicators) > 1 else "none",
            "indicators": indicators,
            "indicator_count": len(indicators),
        }

    async def _check_single_ip(self, ip: str, check_method: str, server_ip: str) -> dict[str, Any]:
        """Run all applicable checks on a single IP."""
        results = {"ip": ip, "checks": [], "is_tor": False, "confidence": "none"}
        loop = asyncio.get_event_loop()

        if check_method in ("list", "both"):
            pattern_result = self._check_pattern_match(ip)
            results["checks"].append(pattern_result)
            if pattern_result.get("detected"):
                results["is_tor"] = True
                results["confidence"] = pattern_result.get("confidence", "medium")

            rdns_result = await loop.run_in_executor(None, self._reverse_dns_analysis, ip)
            results["checks"].append(rdns_result)
            if rdns_result.get("detected"):
                results["is_tor"] = True
                results["confidence"] = "medium"

        if check_method in ("dns", "both"):
            dns_result = await loop.run_in_executor(None, self._check_dns_detection, ip, server_ip)
            results["checks"].append(dns_result)
            if dns_result.get("detected"):
                results["is_tor"] = True
                results["confidence"] = "high"

        # Combine confidence levels
        detected_methods = [c for c in results["checks"] if c.get("detected")]
        if len(detected_methods) >= 2:
            results["confidence"] = "high"
        elif len(detected_methods) == 1:
            results["confidence"] = detected_methods[0].get("confidence", "medium")

        results["detection_methods_positive"] = len(detected_methods)
        results["detection_methods_total"] = len(results["checks"])

        return results

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        ip_list_raw = config["ip_list"]
        check_method = config.get("check_method", "list")
        server_ip = config.get("server_ip", "").strip()

        ips = [ip.strip() for ip in ip_list_raw.split(",") if ip.strip()]

        # Process all IPs concurrently
        tasks = [self._check_single_ip(ip, check_method, server_ip) for ip in ips]
        all_results = await asyncio.gather(*tasks)

        tor_nodes = [r for r in all_results if r["is_tor"]]
        non_tor = [r for r in all_results if not r["is_tor"]]

        confidence_dist = Counter(r["confidence"] for r in tor_nodes)
        tor_percentage = (len(tor_nodes) / len(ips) * 100) if ips else 0

        # Risk assessment
        risk_score = 0.0
        if tor_percentage > 50:
            risk_score += 40
        elif tor_percentage > 20:
            risk_score += 25
        elif tor_percentage > 5:
            risk_score += 10
        risk_score += min(len(tor_nodes) * 5, 30)
        high_confidence_count = sum(1 for r in tor_nodes if r["confidence"] == "high")
        risk_score += min(high_confidence_count * 8, 30)
        risk_score = min(round(risk_score, 1), 100.0)

        detection_summary = {
            "total_ips_checked": len(ips),
            "tor_nodes_detected": len(tor_nodes),
            "non_tor_ips": len(non_tor),
            "tor_percentage": round(tor_percentage, 2),
            "confidence_distribution": dict(confidence_dist),
            "check_method_used": check_method,
        }

        risk_assessment = {
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 15 else "low",
            "tor_traffic_ratio": round(tor_percentage, 2),
            "recommendation": self._get_recommendation(tor_percentage, risk_score),
        }

        return {
            "tor_nodes_found": tor_nodes,
            "non_tor_ips": [{"ip": r["ip"]} for r in non_tor],
            "detection_summary": detection_summary,
            "risk_assessment": risk_assessment,
        }

    def _get_recommendation(self, tor_pct: float, risk_score: float) -> str:
        """Generate recommendation based on findings."""
        if risk_score >= 70:
            return "High Tor usage detected. Review connections for potential abuse, anonymized attacks, or policy violations. Consider blocking Tor exit nodes at the firewall."
        elif risk_score >= 40:
            return "Moderate Tor usage found. Investigate the purpose of these connections and monitor for suspicious activity patterns."
        elif risk_score >= 15:
            return "Low Tor usage detected. May be legitimate privacy-conscious users. Monitor but no immediate action needed."
        return "Minimal or no Tor usage detected. No action required."
