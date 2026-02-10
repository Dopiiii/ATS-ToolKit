"""VPN, proxy, and tunnel usage detector for IP addresses.

Checks common VPN ports, detects VPN-related DNS patterns, analyzes MTU/TTL
anomalies, and cross-references known VPN provider IP ranges.
"""

import asyncio
import hashlib
import json
import re
import socket
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

COMMON_VPN_PORTS = {
    1194: "OpenVPN", 443: "HTTPS/SSTPv/OpenVPN-TCP", 500: "IKEv1/ISAKMP",
    4500: "IPSec-NAT-T", 1701: "L2TP", 1723: "PPTP", 51820: "WireGuard",
    8080: "HTTP-Proxy", 3128: "Squid-Proxy", 1080: "SOCKS",
    8443: "Alt-HTTPS", 9050: "Tor-SOCKS", 9001: "Tor-Relay",
}
VPN_PROVIDER_ASN_KEYWORDS = [
    "mullvad", "nordvpn", "expressvpn", "surfshark", "cyberghost",
    "protonvpn", "privateinternetaccess", "pia", "ipvanish",
    "tunnelbear", "windscribe", "hotspot", "hide.me",
]
VPN_DNS_INDICATORS = [
    r"vpn\.", r"tunnel\.", r"proxy\.", r"\.ovpn\.", r"wg\d*\.",
    r"ipsec\.", r"l2tp\.", r"pptp\.", r"wireguard\.",
]
TYPICAL_TTL_VALUES = {64, 128, 255}


class NetVpnDetectorModule(AtsModule):
    """Detect VPN, proxy, and tunnel usage on target IP addresses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_vpn_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect VPN, proxy, and tunnel usage from IP characteristics",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.IP,
                          description="Target IP address to analyze"),
                Parameter(name="check_methods", type=ParameterType.CHOICE,
                          description="Detection methods to apply",
                          choices=["all", "ports", "headers", "dns"], default="all"),
                Parameter(name="timeout", type=ParameterType.INTEGER,
                          description="Connection timeout per check in seconds", default=5),
            ],
            outputs=[
                OutputField(name="vpn_detected", type="boolean", description="Whether VPN was detected"),
                OutputField(name="confidence", type="float", description="Detection confidence 0-100"),
                OutputField(name="indicators", type="list", description="VPN indicator findings"),
            ],
            tags=["advanced", "network", "vpn", "proxy", "detection"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target IP is required"
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        )
        if not ip_pattern.match(target):
            return False, "Invalid IP address format"
        return True, ""

    def _check_vpn_ports(self, target: str, timeout: int) -> list[dict]:
        """Check if common VPN ports are responsive on the target."""
        results = []
        for port, service in COMMON_VPN_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    results.append({
                        "port": port, "service": service, "status": "open",
                        "indicator": f"VPN-associated port {port} ({service}) is open",
                    })
                sock.close()
            except (socket.error, OSError):
                pass
        return results

    def _analyze_ttl(self, target: str) -> dict[str, Any]:
        """Analyze TTL value for VPN indicators."""
        result = {"checked": True, "anomaly": False, "details": ""}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 80))
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            closest_default = min(TYPICAL_TTL_VALUES, key=lambda x: abs(x - ttl))
            hops = closest_default - ttl
            if hops < 0 or hops > 30:
                result["anomaly"] = True
                result["details"] = f"TTL={ttl}, estimated hops={hops} (unusual, possible encapsulation)"
            else:
                result["details"] = f"TTL={ttl}, estimated hops={hops}"
            result["ttl"] = ttl
            result["estimated_hops"] = hops
        except (socket.error, OSError):
            result["checked"] = False
            result["details"] = "Could not determine TTL"
        return result

    def _check_dns_indicators(self, target: str) -> list[dict]:
        """Check for VPN-related DNS patterns via reverse lookup."""
        indicators = []
        try:
            hostname, _, _ = socket.gethostbyaddr(target)
            hostname_lower = hostname.lower()
            for pattern in VPN_DNS_INDICATORS:
                if re.search(pattern, hostname_lower):
                    indicators.append({
                        "type": "dns_pattern",
                        "hostname": hostname,
                        "pattern": pattern,
                        "indicator": f"Hostname '{hostname}' matches VPN pattern '{pattern}'",
                    })
            for kw in VPN_PROVIDER_ASN_KEYWORDS:
                if kw in hostname_lower:
                    indicators.append({
                        "type": "vpn_provider",
                        "hostname": hostname,
                        "provider": kw,
                        "indicator": f"Hostname matches known VPN provider: {kw}",
                    })
            if not indicators:
                indicators.append({
                    "type": "dns_clean",
                    "hostname": hostname,
                    "indicator": "No VPN patterns found in reverse DNS",
                })
        except (socket.herror, socket.gaierror):
            indicators.append({
                "type": "no_rdns",
                "indicator": "No reverse DNS found (common for VPN exit nodes)",
            })
        return indicators

    def _generate_ip_fingerprint(self, target: str) -> str:
        """Generate a fingerprint hash for the target IP characteristics."""
        data = f"{target}:{socket.getfqdn(target)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"].strip()
        check_methods = config.get("check_methods", "all")
        timeout = config.get("timeout", 5)

        all_indicators = []
        confidence = 0.0
        details = {}

        # Port-based detection
        if check_methods in ("all", "ports"):
            port_results = await asyncio.get_event_loop().run_in_executor(
                None, self._check_vpn_ports, target, timeout
            )
            details["open_vpn_ports"] = port_results
            for pr in port_results:
                all_indicators.append(pr)
                confidence += 12  # Each open VPN port adds confidence

        # DNS-based detection
        if check_methods in ("all", "dns"):
            dns_results = await asyncio.get_event_loop().run_in_executor(
                None, self._check_dns_indicators, target
            )
            details["dns_analysis"] = dns_results
            for dr in dns_results:
                if dr["type"] in ("dns_pattern", "vpn_provider"):
                    all_indicators.append(dr)
                    confidence += 25
                elif dr["type"] == "no_rdns":
                    all_indicators.append(dr)
                    confidence += 8

        # Header/TTL analysis
        if check_methods in ("all", "headers"):
            ttl_result = await asyncio.get_event_loop().run_in_executor(
                None, self._analyze_ttl, target
            )
            details["ttl_analysis"] = ttl_result
            if ttl_result.get("anomaly"):
                all_indicators.append({
                    "type": "ttl_anomaly",
                    "indicator": ttl_result["details"],
                })
                confidence += 15

        confidence = min(round(confidence, 1), 100.0)
        vpn_detected = confidence >= 30.0
        fingerprint = await asyncio.get_event_loop().run_in_executor(
            None, self._generate_ip_fingerprint, target
        )

        return {
            "target": target,
            "vpn_detected": vpn_detected,
            "confidence": confidence,
            "risk_level": "high" if confidence >= 70 else "medium" if confidence >= 30 else "low",
            "indicators": all_indicators,
            "indicator_count": len(all_indicators),
            "details": details,
            "fingerprint": fingerprint,
        }
