"""Bluetooth device security analyzer.

Analyzes Bluetooth device data for information disclosure, pairing mode weaknesses,
BLE advertising patterns, and device type identification.
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

DEVICE_TYPE_PATTERNS = {
    r"(?i)(airpod|earbud|headphone|speaker|bose|jbl|sony\s*wh)": "audio",
    r"(?i)(watch|fitbit|garmin|mi\s*band|galaxy\s*watch)": "wearable",
    r"(?i)(keyboard|mouse|logitech|mx\s*keys)": "input_device",
    r"(?i)(phone|iphone|galaxy|pixel|oneplus)": "smartphone",
    r"(?i)(printer|hp\s*|epson|canon)": "printer",
    r"(?i)(tile|airtag|smarttag|chipolo)": "tracker",
    r"(?i)(lock|august|yale|kwikset)": "smart_lock",
    r"(?i)(thermostat|nest|ecobee)": "iot_thermostat",
    r"(?i)(tv|roku|firestick|chromecast|apple\s*tv)": "media_device",
}

INFO_DISCLOSURE_PATTERNS = [
    (r"(?i)[a-zA-Z]+['']?s\s+(iphone|phone|mac|ipad)", "Owner name in device name"),
    (r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", "Possible personal name in device"),
    (r"(?i)(office|home|bedroom|kitchen|garage)", "Location disclosed in name"),
    (r"(?i)(admin|root|test|debug)", "Privileged context disclosed"),
    (r"\b\d{4,}\b", "Numeric identifier (serial/model) exposed"),
]

BLE_AD_TYPE_NAMES = {
    0x01: "Flags", 0x02: "Incomplete 16-bit UUIDs", 0x03: "Complete 16-bit UUIDs",
    0x07: "Complete 128-bit UUIDs", 0x08: "Shortened Local Name",
    0x09: "Complete Local Name", 0x0A: "TX Power Level",
    0xFF: "Manufacturer Specific Data", 0x16: "Service Data",
}


class BluetoothScannerModule(AtsModule):
    """Analyze Bluetooth device data for security issues."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="bluetooth_scanner",
            category=ModuleCategory.ADVANCED,
            description="Analyze Bluetooth device security including name disclosure, pairing modes, and BLE advertising",
            version="1.0.0",
            parameters=[
                Parameter(name="device_data", type=ParameterType.STRING,
                          description="JSON array of device objects with name, address, rssi, type, pairing_mode, ad_data fields"),
                Parameter(name="scan_type", type=ParameterType.CHOICE,
                          description="Bluetooth scan type to analyze",
                          choices=["classic", "ble", "all"], default="all"),
                Parameter(name="check_disclosure", type=ParameterType.BOOLEAN,
                          description="Check device names for information disclosure", default=True),
            ],
            outputs=[
                OutputField(name="devices_analyzed", type="integer", description="Number of devices processed"),
                OutputField(name="findings", type="list", description="Security findings per device"),
                OutputField(name="device_types", type="dict", description="Breakdown of detected device types"),
            ],
            tags=["advanced", "wireless", "bluetooth", "ble", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("device_data", "").strip()
        if not raw:
            return False, "Device data JSON array is required"
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list) or len(data) == 0:
                return False, "JSON must be a non-empty array of device objects"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _identify_device_type(self, name: str) -> str:
        for pattern, dev_type in DEVICE_TYPE_PATTERNS.items():
            if re.search(pattern, name):
                return dev_type
        return "unknown"

    def _check_info_disclosure(self, name: str) -> list[dict[str, str]]:
        issues = []
        for pattern, description in INFO_DISCLOSURE_PATTERNS:
            match = re.search(pattern, name)
            if match:
                issues.append({"pattern": description, "matched": match.group(0)})
        return issues

    def _analyze_pairing_mode(self, mode: str) -> dict[str, Any]:
        mode_lower = mode.lower().strip()
        ratings = {
            "just_works": {"score": 2, "severity": "high",
                           "note": "Just Works has no MITM protection"},
            "pin": {"score": 4, "severity": "medium",
                    "note": "Static PIN is brute-forceable (4 digit = 10000 combos)"},
            "passkey": {"score": 7, "severity": "low",
                        "note": "Passkey entry provides reasonable MITM protection"},
            "numeric_comparison": {"score": 8, "severity": "info",
                                   "note": "Numeric comparison is strong against MITM"},
            "oob": {"score": 9, "severity": "info",
                    "note": "Out-of-band pairing is strongest method"},
        }
        for key, rating in ratings.items():
            if key in mode_lower.replace(" ", "_"):
                return {"mode": mode, **rating}
        return {"mode": mode, "score": 5, "severity": "medium", "note": "Unknown pairing mode"}

    def _analyze_ble_advertising(self, ad_data: list[dict]) -> list[dict[str, Any]]:
        findings = []
        for ad in ad_data:
            ad_type = ad.get("type", 0)
            ad_value = ad.get("value", "")
            type_name = BLE_AD_TYPE_NAMES.get(ad_type, f"Unknown(0x{ad_type:02X})")
            entry = {"ad_type": type_name, "raw_type": ad_type}
            if ad_type == 0xFF and len(ad_value) >= 4:
                company_id = ad_value[:4]
                entry["company_id"] = company_id
                entry["note"] = "Manufacturer data can fingerprint device vendor"
            if ad_type == 0x0A:
                try:
                    tx_power = int(ad_value)
                    entry["tx_power_dbm"] = tx_power
                    if tx_power > 10:
                        entry["note"] = "High TX power - device visible at extended range"
                except (ValueError, TypeError):
                    pass
            if ad_type in (0x08, 0x09):
                entry["local_name"] = ad_value
                entry["note"] = "Device name broadcast in advertisements"
            findings.append(entry)
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        raw = json.loads(config["device_data"].strip())
        devices = [raw] if isinstance(raw, dict) else raw
        scan_type = config.get("scan_type", "all")
        check_disclosure = config.get("check_disclosure", True)

        findings = []
        type_counts: dict[str, int] = {}

        for dev in devices:
            name = dev.get("name", "")
            address = dev.get("address", "00:00:00:00:00:00")
            dev_bt_type = dev.get("type", "classic")

            if scan_type != "all" and dev_bt_type != scan_type:
                continue

            result: dict[str, Any] = {"name": name, "address": address, "issues": []}
            device_type = self._identify_device_type(name)
            result["device_type"] = device_type
            type_counts[device_type] = type_counts.get(device_type, 0) + 1

            if check_disclosure and name:
                disclosure = self._check_info_disclosure(name)
                if disclosure:
                    result["info_disclosure"] = disclosure
                    result["issues"].append(f"Information disclosure: {len(disclosure)} pattern(s) found")

            pairing = dev.get("pairing_mode", "")
            if pairing:
                result["pairing_analysis"] = self._analyze_pairing_mode(pairing)

            ad_data = dev.get("ad_data", [])
            if ad_data and isinstance(ad_data, list) and dev_bt_type in ("ble", "all"):
                result["advertising_analysis"] = self._analyze_ble_advertising(ad_data)

            rssi = dev.get("rssi")
            if rssi is not None:
                result["rssi_dbm"] = rssi
                result["proximity"] = ("very_close" if rssi > -40 else "close" if rssi > -60
                                       else "medium" if rssi > -80 else "far")

            findings.append(result)

        return {
            "devices_analyzed": len(findings),
            "scan_type": scan_type,
            "findings": findings,
            "device_types": type_counts,
            "total_issues": sum(len(f.get("issues", [])) for f in findings),
        }
