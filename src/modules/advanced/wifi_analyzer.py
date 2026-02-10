"""WiFi network configuration analyzer for security auditing.

Analyzes WiFi network configurations for encryption weaknesses, channel overlap,
SSID patterns, and hidden network detection indicators.
"""

import asyncio
import re
import json
import math
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

ENCRYPTION_RATINGS = {
    "open": {"score": 0, "severity": "critical", "note": "No encryption - all traffic visible"},
    "wep": {"score": 1, "severity": "critical", "note": "WEP is trivially crackable in minutes"},
    "wpa": {"score": 3, "severity": "high", "note": "WPA-TKIP has known vulnerabilities"},
    "wpa2": {"score": 7, "severity": "low", "note": "WPA2-AES is acceptable for most uses"},
    "wpa2-enterprise": {"score": 8, "severity": "info", "note": "Enterprise with RADIUS is strong"},
    "wpa3": {"score": 9, "severity": "info", "note": "WPA3-SAE provides strong forward secrecy"},
}

OVERLAPPING_CHANNELS_24GHZ = {
    1: [2, 3, 4, 5], 2: [1, 3, 4, 5, 6], 3: [1, 2, 4, 5, 6, 7],
    4: [1, 2, 3, 5, 6, 7, 8], 5: [1, 2, 3, 4, 6, 7, 8, 9],
    6: [2, 3, 4, 5, 7, 8, 9, 10], 7: [3, 4, 5, 6, 8, 9, 10, 11],
    8: [4, 5, 6, 7, 9, 10, 11], 9: [5, 6, 7, 8, 10, 11],
    10: [6, 7, 8, 9, 11], 11: [7, 8, 9, 10],
}

SUSPICIOUS_SSID_PATTERNS = [
    (r"(?i)^free[_\-\s]?wi?fi", "Possible rogue AP - 'Free WiFi' pattern"),
    (r"(?i)(airport|hotel|cafe|starbucks)", "Common public venue impersonation"),
    (r"(?i)(linksys|netgear|dlink|tplink|default)", "Default manufacturer SSID - unconfigured"),
    (r"(?i)^$", "Empty SSID - hidden network broadcasting"),
    (r"(.)\1{5,}", "Repeating character pattern - possible fuzzing"),
]


class WifiAnalyzerModule(AtsModule):
    """Analyze WiFi network configurations for security weaknesses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="wifi_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze WiFi network configurations for encryption, channel, and SSID security issues",
            version="1.0.0",
            parameters=[
                Parameter(name="network_config", type=ParameterType.STRING,
                          description="JSON with ssid, encryption, channel fields (or array of networks)"),
                Parameter(name="audit_level", type=ParameterType.CHOICE,
                          description="Depth of audit analysis",
                          choices=["basic", "security", "full"], default="security"),
                Parameter(name="check_hidden", type=ParameterType.BOOLEAN,
                          description="Check for hidden network indicators", default=True),
            ],
            outputs=[
                OutputField(name="networks_analyzed", type="integer", description="Number of networks analyzed"),
                OutputField(name="findings", type="list", description="Security findings per network"),
                OutputField(name="risk_score", type="float", description="Overall risk score 0-10"),
            ],
            tags=["advanced", "wireless", "wifi", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("network_config", "").strip()
        if not raw:
            return False, "Network configuration JSON is required"
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list) or len(data) == 0:
                return False, "JSON must be an object or non-empty array of network objects"
            for net in data:
                if "ssid" not in net and "encryption" not in net:
                    return False, "Each network must have at least 'ssid' or 'encryption'"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _analyze_encryption(self, encryption: str) -> dict[str, Any]:
        enc_lower = encryption.lower().replace(" ", "").replace("-", "").replace("_", "")
        for key, rating in ENCRYPTION_RATINGS.items():
            if key.replace("-", "") in enc_lower:
                return {"encryption": encryption, "rating": key, **rating}
        return {"encryption": encryption, "score": 5, "severity": "medium",
                "note": f"Unknown encryption type: {encryption}"}

    def _check_channel_overlap(self, networks: list[dict]) -> list[dict[str, Any]]:
        channel_map: dict[int, list[str]] = {}
        for net in networks:
            ch = net.get("channel")
            if ch and isinstance(ch, int):
                channel_map.setdefault(ch, []).append(net.get("ssid", "unknown"))
        issues = []
        checked = set()
        for ch, ssids in channel_map.items():
            if len(ssids) > 1:
                issues.append({"channel": ch, "type": "co-channel",
                               "networks": ssids, "impact": "Significant interference"})
            overlaps = OVERLAPPING_CHANNELS_24GHZ.get(ch, [])
            for ov_ch in overlaps:
                pair = tuple(sorted([ch, ov_ch]))
                if pair not in checked and ov_ch in channel_map:
                    checked.add(pair)
                    issues.append({"channels": list(pair), "type": "adjacent-overlap",
                                   "networks": ssids + channel_map[ov_ch],
                                   "impact": "Partial interference"})
        return issues

    def _check_ssid_patterns(self, ssid: str) -> list[dict[str, Any]]:
        alerts = []
        for pattern, description in SUSPICIOUS_SSID_PATTERNS:
            if re.search(pattern, ssid):
                alerts.append({"pattern": pattern, "description": description, "ssid": ssid})
        if len(ssid) > 32:
            alerts.append({"description": "SSID exceeds 32-char limit - malformed", "ssid": ssid})
        non_ascii = [c for c in ssid if ord(c) > 127]
        if non_ascii:
            alerts.append({"description": "Non-ASCII characters in SSID - possible homoglyph attack",
                           "characters": [hex(ord(c)) for c in non_ascii]})
        return alerts

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        raw = json.loads(config["network_config"].strip())
        networks = [raw] if isinstance(raw, dict) else raw
        audit_level = config.get("audit_level", "security")
        check_hidden = config.get("check_hidden", True)

        all_findings = []
        total_score = 0.0

        for net in networks:
            ssid = net.get("ssid", "")
            encryption = net.get("encryption", "open")
            finding: dict[str, Any] = {"ssid": ssid, "issues": []}

            enc_result = self._analyze_encryption(encryption)
            finding["encryption_analysis"] = enc_result
            total_score += (10 - enc_result["score"])

            if audit_level in ("security", "full"):
                ssid_alerts = self._check_ssid_patterns(ssid)
                if ssid_alerts:
                    finding["ssid_alerts"] = ssid_alerts
                    total_score += len(ssid_alerts) * 1.5

            if check_hidden and (not ssid or ssid.strip() == ""):
                finding["hidden_network"] = True
                finding["issues"].append("Hidden SSID detected - may indicate rogue AP or misconfiguration")
                total_score += 2.0

            if audit_level == "full" and net.get("bssid"):
                bssid = net["bssid"].upper()
                oui = bssid[:8]
                finding["bssid_oui"] = oui

            all_findings.append(finding)

        channel_issues = []
        if audit_level in ("security", "full"):
            channel_issues = self._check_channel_overlap(networks)

        avg_risk = min(10.0, total_score / max(len(networks), 1))

        return {
            "networks_analyzed": len(networks),
            "audit_level": audit_level,
            "findings": all_findings,
            "channel_overlap_issues": channel_issues,
            "risk_score": round(avg_risk, 2),
            "risk_level": "critical" if avg_risk >= 8 else "high" if avg_risk >= 6 else
                          "medium" if avg_risk >= 4 else "low",
        }
