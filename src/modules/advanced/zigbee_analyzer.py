"""Zigbee network security analyzer.

Analyzes Zigbee network configurations for encryption weaknesses, default keys,
topology issues, and coordinator identification.
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

KNOWN_DEFAULT_KEYS = {
    "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39": {
        "name": "ZigBee HA Trust Center Link Key",
        "risk": "critical",
        "note": "Default Home Automation key - publicly known",
    },
    "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00": {
        "name": "Null Key",
        "risk": "critical",
        "note": "Null key provides no security",
    },
    "ab:cd:ef:01:23:45:67:89:00:00:00:00:00:00:00:00": {
        "name": "Common Test Key",
        "risk": "high",
        "note": "Commonly used test/development key",
    },
}

ZIGBEE_PROFILES = {
    "0x0104": "Home Automation (HA)",
    "0x0109": "Smart Energy (SE)",
    "0x0105": "Commercial Building Automation (CBA)",
    "0x0107": "Telecom Applications (TA)",
    "0x0108": "Health Care (HC)",
    "0xc05e": "ZigBee Light Link (ZLL)",
    "0xa1e0": "Green Power",
}


class ZigbeeAnalyzerModule(AtsModule):
    """Analyze Zigbee network security configurations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="zigbee_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze Zigbee network security including encryption, keys, and topology",
            version="1.0.0",
            parameters=[
                Parameter(name="network_data", type=ParameterType.STRING,
                          description="JSON with pan_id, channel, encryption, network_key, devices array, profile fields"),
                Parameter(name="check_type", type=ParameterType.CHOICE,
                          description="Type of security check to perform",
                          choices=["encryption", "keys", "topology"], default="encryption"),
                Parameter(name="deep_scan", type=ParameterType.BOOLEAN,
                          description="Perform deep analysis of all device relationships", default=False),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Security findings"),
                OutputField(name="risk_level", type="string", description="Overall risk assessment"),
                OutputField(name="topology", type="dict", description="Network topology info"),
            ],
            tags=["advanced", "wireless", "zigbee", "iot", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("network_data", "").strip()
        if not raw:
            return False, "Network data JSON is required"
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False, "Network data must be a JSON object"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _normalize_key(self, key: str) -> str:
        cleaned = re.sub(r'[^a-fA-F0-9]', '', key)
        if len(cleaned) == 32:
            return ':'.join(cleaned[i:i+2] for i in range(0, 32, 2)).lower()
        return key.lower().strip()

    def _check_encryption(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        encryption = data.get("encryption", "none").lower()

        if encryption == "none" or encryption == "disabled":
            findings.append({"type": "no_encryption", "severity": "critical",
                             "detail": "Network has no encryption enabled - all traffic in cleartext"})
        elif "aes" not in encryption and "ccm" not in encryption:
            findings.append({"type": "weak_encryption", "severity": "high",
                             "detail": f"Encryption mode '{encryption}' may not provide adequate protection"})
        else:
            findings.append({"type": "encryption_ok", "severity": "info",
                             "detail": f"AES-CCM encryption detected: {encryption}"})

        security_level = data.get("security_level", 0)
        if isinstance(security_level, int):
            if security_level == 0:
                findings.append({"type": "no_security_level", "severity": "critical",
                                 "detail": "Security level 0 - no security processing"})
            elif security_level < 5:
                findings.append({"type": "low_security_level", "severity": "high",
                                 "detail": f"Security level {security_level} provides encryption but weak integrity"})
            elif security_level >= 5:
                findings.append({"type": "adequate_security", "severity": "info",
                                 "detail": f"Security level {security_level} provides both encryption and integrity"})

        channel = data.get("channel")
        if channel and isinstance(channel, int):
            if channel < 11 or channel > 26:
                findings.append({"type": "invalid_channel", "severity": "medium",
                                 "detail": f"Channel {channel} outside valid Zigbee range (11-26)"})
            elif channel in (15, 20, 25):
                findings.append({"type": "optimal_channel", "severity": "info",
                                 "detail": f"Channel {channel} has minimal WiFi overlap"})
            else:
                wifi_overlap = channel in range(11, 23)
                if wifi_overlap:
                    findings.append({"type": "wifi_overlap", "severity": "low",
                                     "detail": f"Channel {channel} may overlap with WiFi channels"})

        return findings

    def _check_keys(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        network_key = data.get("network_key", "")

        if network_key:
            norm_key = self._normalize_key(network_key)
            for known_key, info in KNOWN_DEFAULT_KEYS.items():
                if norm_key == known_key.lower():
                    findings.append({
                        "type": "default_key_detected",
                        "severity": info["risk"],
                        "key_name": info["name"],
                        "detail": info["note"],
                    })
                    break
            else:
                key_bytes = bytes.fromhex(re.sub(r'[^a-fA-F0-9]', '', norm_key))
                unique_bytes = len(set(key_bytes))
                entropy = 0.0
                for b in set(key_bytes):
                    p = key_bytes.count(b) / len(key_bytes)
                    entropy -= p * math.log2(p)
                if unique_bytes <= 4:
                    findings.append({"type": "low_entropy_key", "severity": "high",
                                     "detail": f"Key has only {unique_bytes} unique bytes - very low entropy"})
                elif entropy < 3.0:
                    findings.append({"type": "weak_key_entropy", "severity": "medium",
                                     "detail": f"Key entropy {entropy:.2f} bits/byte is below recommended threshold"})
                else:
                    findings.append({"type": "key_entropy_ok", "severity": "info",
                                     "detail": f"Key entropy {entropy:.2f} bits/byte appears adequate"})

        trust_center_key = data.get("trust_center_key", "")
        if trust_center_key:
            tc_norm = self._normalize_key(trust_center_key)
            for known_key, info in KNOWN_DEFAULT_KEYS.items():
                if tc_norm == known_key.lower():
                    findings.append({
                        "type": "default_tc_key",
                        "severity": "critical",
                        "detail": f"Trust Center using default key: {info['name']}",
                    })
                    break

        key_transport = data.get("key_transport", "")
        if key_transport.lower() in ("plaintext", "unencrypted", "clear"):
            findings.append({"type": "plaintext_key_transport", "severity": "critical",
                             "detail": "Network key transported in plaintext - can be sniffed during join"})

        return findings

    def _analyze_topology(self, data: dict[str, Any], deep_scan: bool) -> dict[str, Any]:
        devices = data.get("devices", [])
        topology: dict[str, Any] = {
            "device_count": len(devices),
            "coordinators": [],
            "routers": [],
            "end_devices": [],
            "issues": [],
        }

        for dev in devices:
            role = dev.get("role", "end_device").lower()
            addr = dev.get("address", dev.get("short_addr", "unknown"))
            entry = {"address": addr, "role": role}
            if dev.get("name"):
                entry["name"] = dev["name"]

            if role == "coordinator":
                topology["coordinators"].append(entry)
            elif role == "router":
                topology["routers"].append(entry)
            else:
                topology["end_devices"].append(entry)

        if len(topology["coordinators"]) == 0:
            topology["issues"].append({"severity": "medium",
                                        "detail": "No coordinator identified in network data"})
        elif len(topology["coordinators"]) > 1:
            topology["issues"].append({"severity": "high",
                                        "detail": "Multiple coordinators detected - possible rogue coordinator"})

        if len(topology["routers"]) == 0 and len(topology["end_devices"]) > 5:
            topology["issues"].append({"severity": "medium",
                                        "detail": "No routers with many end devices - potential reliability issue"})

        if deep_scan:
            parent_map: dict[str, list] = {}
            for dev in devices:
                parent = dev.get("parent", "")
                if parent:
                    parent_map.setdefault(parent, []).append(dev.get("address", "unknown"))
            topology["parent_map"] = parent_map
            for parent, children in parent_map.items():
                if len(children) > 20:
                    topology["issues"].append({
                        "severity": "medium",
                        "detail": f"Device {parent} has {len(children)} children - potential bottleneck",
                    })

        profile = data.get("profile", "")
        if profile:
            profile_name = ZIGBEE_PROFILES.get(profile, f"Unknown ({profile})")
            topology["profile"] = profile_name

        return topology

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(config["network_data"].strip())
        check_type = config.get("check_type", "encryption")
        deep_scan = config.get("deep_scan", False)

        findings = []
        risk_scores = []

        if check_type in ("encryption", "keys"):
            enc_findings = self._check_encryption(data)
            findings.extend(enc_findings)

        if check_type in ("keys", "encryption"):
            key_findings = self._check_keys(data)
            findings.extend(key_findings)

        topology = self._analyze_topology(data, deep_scan)
        if check_type == "topology":
            findings.extend(topology.get("issues", []))

        severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
        for f in findings:
            risk_scores.append(severity_scores.get(f.get("severity", "info"), 0))

        avg_risk = sum(risk_scores) / max(len(risk_scores), 1)
        max_risk = max(risk_scores, default=0)

        risk_level = ("critical" if max_risk >= 10 else "high" if max_risk >= 7
                      else "medium" if avg_risk >= 3 else "low")

        return {
            "pan_id": data.get("pan_id", "unknown"),
            "channel": data.get("channel", "unknown"),
            "check_type": check_type,
            "findings": findings,
            "risk_level": risk_level,
            "topology": topology,
        }
