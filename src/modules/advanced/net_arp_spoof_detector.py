"""ARP spoofing detection module for analyzing ARP table data.

Detects duplicate IPs with different MACs, MAC address changes over time,
gratuitous ARP floods, and gateway impersonation attempts.
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

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
COMMON_GATEWAY_SUFFIXES = [".1", ".254"]
VENDOR_OUI_PREFIXES = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Hyper-V", "00:16:3e": "Xen",
    "02:42:ac": "Docker", "00:1a:4a": "Cisco", "00:1b:44": "Cisco",
}


class NetArpSpoofDetectorModule(AtsModule):
    """Detect ARP spoofing attacks from ARP table analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_arp_spoof_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect ARP spoofing attacks by analyzing ARP table entries and history",
            version="1.0.0",
            parameters=[
                Parameter(name="arp_table", type=ParameterType.STRING,
                          description="JSON array of current ARP entries with ip and mac fields"),
                Parameter(name="history", type=ParameterType.STRING,
                          description="JSON array of previous ARP entries for change detection",
                          required=False, default=""),
                Parameter(name="gateway_ip", type=ParameterType.STRING,
                          description="Known gateway IP for impersonation checks",
                          required=False, default=""),
            ],
            outputs=[
                OutputField(name="spoofing_detected", type="boolean", description="Whether ARP spoofing was detected"),
                OutputField(name="alerts", type="list", description="Spoofing alert details"),
                OutputField(name="risk_score", type="float", description="Risk score 0-100"),
            ],
            tags=["advanced", "network", "arp", "spoofing", "mitm"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("arp_table", "").strip()
        if not raw:
            return False, "ARP table data is required"
        try:
            entries = json.loads(raw)
            if not isinstance(entries, list):
                return False, "ARP table must be a JSON array"
            if len(entries) == 0:
                return False, "ARP table is empty"
            for entry in entries:
                if "ip" not in entry or "mac" not in entry:
                    return False, "Each ARP entry must have 'ip' and 'mac' fields"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in arp_table: {e}"
        history = config.get("history", "").strip()
        if history:
            try:
                json.loads(history)
            except json.JSONDecodeError as e:
                return False, f"Invalid JSON in history: {e}"
        return True, ""

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to lowercase colon-separated format."""
        mac = mac.lower().strip()
        mac = re.sub(r'[^0-9a-f]', '', mac)
        if len(mac) == 12:
            return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def _get_vendor(self, mac: str) -> str:
        """Get vendor from OUI prefix."""
        prefix = mac[:8]
        return VENDOR_OUI_PREFIXES.get(prefix, "Unknown")

    def _detect_duplicate_mappings(self, entries: list[dict]) -> list[dict]:
        """Detect IPs that map to multiple different MAC addresses."""
        ip_to_macs: dict[str, set] = defaultdict(set)
        for entry in entries:
            ip = entry["ip"]
            mac = self._normalize_mac(entry["mac"])
            ip_to_macs[ip].add(mac)

        alerts = []
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                alerts.append({
                    "type": "duplicate_mapping",
                    "severity": "critical",
                    "ip": ip,
                    "mac_addresses": list(macs),
                    "vendors": [self._get_vendor(m) for m in macs],
                    "description": f"IP {ip} maps to {len(macs)} different MAC addresses",
                })
        return alerts

    def _detect_mac_changes(self, current: list[dict], previous: list[dict]) -> list[dict]:
        """Detect MAC address changes between current and previous ARP tables."""
        prev_map = {}
        for entry in previous:
            prev_map[entry["ip"]] = self._normalize_mac(entry["mac"])

        alerts = []
        for entry in current:
            ip = entry["ip"]
            current_mac = self._normalize_mac(entry["mac"])
            if ip in prev_map and prev_map[ip] != current_mac:
                alerts.append({
                    "type": "mac_change",
                    "severity": "high",
                    "ip": ip,
                    "previous_mac": prev_map[ip],
                    "current_mac": current_mac,
                    "previous_vendor": self._get_vendor(prev_map[ip]),
                    "current_vendor": self._get_vendor(current_mac),
                    "description": f"MAC for {ip} changed: {prev_map[ip]} -> {current_mac}",
                })
        return alerts

    def _detect_gratuitous_arp(self, entries: list[dict]) -> list[dict]:
        """Detect gratuitous ARP patterns (same IP appearing many times)."""
        ip_counts = Counter(entry["ip"] for entry in entries)
        alerts = []
        for ip, count in ip_counts.items():
            if count > 3:
                alerts.append({
                    "type": "gratuitous_arp_flood",
                    "severity": "high",
                    "ip": ip,
                    "occurrence_count": count,
                    "description": f"IP {ip} appears {count} times - possible gratuitous ARP flood",
                })
        return alerts

    def _detect_gateway_impersonation(self, entries: list[dict], gateway_ip: str) -> list[dict]:
        """Check if gateway IP is being spoofed."""
        alerts = []
        gateways = [gateway_ip] if gateway_ip else []
        if not gateways:
            # Auto-detect possible gateways from common suffixes
            seen_subnets = set()
            for entry in entries:
                parts = entry["ip"].rsplit(".", 1)
                if len(parts) == 2:
                    seen_subnets.add(parts[0])
            for subnet in seen_subnets:
                for suffix in COMMON_GATEWAY_SUFFIXES:
                    gateways.append(f"{subnet}{suffix}")

        for gw in gateways:
            gw_macs = set()
            for entry in entries:
                if entry["ip"] == gw:
                    gw_macs.add(self._normalize_mac(entry["mac"]))
            if len(gw_macs) > 1:
                alerts.append({
                    "type": "gateway_impersonation",
                    "severity": "critical",
                    "gateway_ip": gw,
                    "mac_addresses": list(gw_macs),
                    "vendors": [self._get_vendor(m) for m in gw_macs],
                    "description": f"Gateway {gw} has multiple MACs - likely ARP spoofing",
                })
        return alerts

    def _detect_vm_mac_anomalies(self, entries: list[dict]) -> list[dict]:
        """Detect virtual machine MAC addresses that might indicate rogue VMs."""
        alerts = []
        vm_entries = []
        for entry in entries:
            mac = self._normalize_mac(entry["mac"])
            vendor = self._get_vendor(mac)
            if vendor != "Unknown":
                vm_entries.append({"ip": entry["ip"], "mac": mac, "vendor": vendor})
        if len(vm_entries) > len(entries) * 0.5 and len(entries) > 5:
            alerts.append({
                "type": "vm_mac_prevalence",
                "severity": "medium",
                "vm_count": len(vm_entries),
                "total_count": len(entries),
                "description": f"High proportion of virtual MAC addresses ({len(vm_entries)}/{len(entries)})",
                "vm_entries": vm_entries[:10],
            })
        return alerts

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        entries = json.loads(config["arp_table"])
        history_raw = config.get("history", "").strip()
        gateway_ip = config.get("gateway_ip", "").strip()

        previous = json.loads(history_raw) if history_raw else []

        all_alerts = []

        # Duplicate IP-to-MAC mappings
        all_alerts.extend(self._detect_duplicate_mappings(entries))

        # MAC changes over time
        if previous:
            all_alerts.extend(self._detect_mac_changes(entries, previous))

        # Gratuitous ARP floods
        all_alerts.extend(self._detect_gratuitous_arp(entries))

        # Gateway impersonation
        all_alerts.extend(self._detect_gateway_impersonation(entries, gateway_ip))

        # VM MAC anomalies
        all_alerts.extend(self._detect_vm_mac_anomalies(entries))

        # Risk score
        severity_weights = {"critical": 30, "high": 15, "medium": 5, "low": 2}
        risk_score = 0.0
        for alert in all_alerts:
            risk_score += severity_weights.get(alert.get("severity", "low"), 0)
        risk_score = min(round(risk_score, 1), 100.0)

        severity_counts = Counter(a.get("severity", "low") for a in all_alerts)

        return {
            "spoofing_detected": risk_score >= 25.0,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 15 else "low",
            "alerts": all_alerts,
            "alert_count": len(all_alerts),
            "severity_counts": dict(severity_counts),
            "entries_analyzed": len(entries),
            "history_entries": len(previous),
            "unique_ips": len(set(e["ip"] for e in entries)),
            "unique_macs": len(set(self._normalize_mac(e["mac"]) for e in entries)),
        }
