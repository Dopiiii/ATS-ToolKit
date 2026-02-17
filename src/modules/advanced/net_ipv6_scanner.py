"""IPv6 network scanning module for host discovery and enumeration.

Performs IPv6 host discovery using common address patterns, EUI-64 detection,
multicast group enumeration, and link-local address analysis.
"""

import asyncio
import hashlib
import json
import re
import socket
import struct
from typing import Any
from collections import defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

WELL_KNOWN_MULTICAST = {
    "ff02::1": "All Nodes (link-local)",
    "ff02::2": "All Routers (link-local)",
    "ff02::5": "OSPF Routers",
    "ff02::6": "OSPF Designated Routers",
    "ff02::9": "RIPng Routers",
    "ff02::a": "EIGRP Routers",
    "ff02::d": "PIM Routers",
    "ff02::16": "MLDv2 Reports",
    "ff02::fb": "mDNS",
    "ff02::1:2": "DHCPv6 Agents",
    "ff02::1:3": "LLMNR",
    "ff05::1:3": "DHCP Servers (site-local)",
    "ff02::101": "NTP",
}
COMMON_HOST_SUFFIXES = [
    "::1", "::2", "::3", "::a", "::b", "::c", "::d", "::e", "::f",
    "::10", "::11", "::100", "::dead:beef", "::cafe", "::face",
    "::1:1", "::53", "::80", "::443",
]
LINK_LOCAL_PREFIX = "fe80::"
EUI64_PATTERN = re.compile(r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{2}ff:fe[0-9a-fA-F]{2}:[0-9a-fA-F]{1,4}$")


class NetIpv6ScannerModule(AtsModule):
    """IPv6 network scanning and host discovery module."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_ipv6_scanner",
            category=ModuleCategory.ADVANCED,
            description="IPv6 network scanning for host discovery, EUI-64 detection, and multicast enumeration",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.STRING,
                          description="IPv6 network prefix (e.g., 2001:db8::/64) or single address"),
                Parameter(name="scan_type", type=ParameterType.CHOICE,
                          description="Type of IPv6 scan to perform",
                          choices=["known_hosts", "link_local", "multicast"], default="known_hosts"),
                Parameter(name="mac_addresses", type=ParameterType.STRING,
                          description="Optional comma-separated MAC addresses for EUI-64 address generation",
                          required=False, default=""),
            ],
            outputs=[
                OutputField(name="discovered_hosts", type="list", description="Discovered IPv6 hosts"),
                OutputField(name="eui64_addresses", type="list", description="Generated EUI-64 addresses"),
                OutputField(name="multicast_groups", type="list", description="Multicast group analysis"),
                OutputField(name="statistics", type="dict", description="Scan statistics"),
            ],
            tags=["advanced", "network", "ipv6", "scanner", "discovery"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target IPv6 address or prefix is required"
        ipv6_pattern = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
        if not ipv6_pattern.match(target):
            return False, f"Invalid IPv6 format: {target}"
        return True, ""

    def _extract_prefix(self, target: str) -> str:
        """Extract the /64 prefix from a target."""
        if "/" in target:
            addr, prefix_len = target.split("/", 1)
        else:
            addr = target
        parts = addr.split(":")
        # Take first 4 groups (64 bits) for the network prefix
        prefix_parts = []
        expanded = self._expand_ipv6(addr)
        groups = expanded.split(":")
        prefix_parts = groups[:4]
        return ":".join(prefix_parts)

    def _expand_ipv6(self, addr: str) -> str:
        """Expand abbreviated IPv6 address to full form."""
        if "::" in addr:
            parts = addr.split("::")
            left = parts[0].split(":") if parts[0] else []
            right = parts[1].split(":") if parts[1] else []
            missing = 8 - len(left) - len(right)
            middle = ["0000"] * missing
            groups = left + middle + right
        else:
            groups = addr.split(":")
        expanded = [g.zfill(4) for g in groups]
        return ":".join(expanded[:8])

    def _mac_to_eui64(self, mac: str, prefix: str) -> str:
        """Convert MAC address to EUI-64 IPv6 interface identifier."""
        mac_clean = re.sub(r"[:\-.]", "", mac.strip()).lower()
        if len(mac_clean) != 12:
            return ""
        # Insert ff:fe in the middle
        eui64 = mac_clean[:6] + "fffe" + mac_clean[6:]
        # Flip the 7th bit (universal/local)
        first_byte = int(eui64[:2], 16) ^ 0x02
        eui64 = f"{first_byte:02x}" + eui64[2:]
        # Format as IPv6 suffix
        groups = [eui64[i:i+4] for i in range(0, 16, 4)]
        suffix = ":".join(groups)
        return f"{prefix}:{suffix}"

    def _generate_known_hosts(self, prefix: str) -> list[dict]:
        """Generate list of commonly-used IPv6 addresses in a prefix."""
        hosts = []
        for suffix in COMMON_HOST_SUFFIXES:
            addr = f"{prefix}{suffix}"
            hosts.append({
                "address": addr,
                "type": "common_pattern",
                "pattern": suffix,
                "description": f"Common host suffix {suffix}",
            })

        # Low-byte addresses (::1 through ::ff)
        for i in range(1, 256):
            addr = f"{prefix}::{i:x}"
            if addr not in [h["address"] for h in hosts]:
                hosts.append({
                    "address": addr,
                    "type": "low_byte",
                    "pattern": f"::{i:x}",
                    "description": f"Low-byte sequential address",
                })
                if len(hosts) >= 300:
                    break

        return hosts

    def _analyze_link_local(self, target: str, mac_addresses: list[str]) -> list[dict]:
        """Analyze link-local IPv6 address space."""
        results = []

        # Standard link-local addresses
        results.append({
            "address": "fe80::1",
            "type": "link_local",
            "description": "Default gateway (common)",
            "likelihood": "high",
        })
        results.append({
            "address": "fe80::2",
            "type": "link_local",
            "description": "Secondary router/gateway",
            "likelihood": "medium",
        })

        # Generate EUI-64 based link-local addresses from MACs
        for mac in mac_addresses:
            eui64_addr = self._mac_to_eui64(mac, "fe80:0000:0000:0000")
            if eui64_addr:
                results.append({
                    "address": eui64_addr,
                    "type": "eui64_link_local",
                    "source_mac": mac.strip(),
                    "description": f"EUI-64 link-local from MAC {mac.strip()}",
                    "likelihood": "high",
                })

        # Common vendor OUI-based patterns
        common_ouis = {
            "00:50:56": "VMware",
            "00:0c:29": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:15:5d": "Hyper-V",
            "00:16:3e": "Xen",
        }
        for oui, vendor in common_ouis.items():
            eui64_addr = self._mac_to_eui64(f"{oui}:00:00:01", "fe80:0000:0000:0000")
            if eui64_addr:
                results.append({
                    "address": eui64_addr,
                    "type": "vendor_eui64",
                    "vendor": vendor,
                    "description": f"Common {vendor} EUI-64 pattern",
                    "likelihood": "low",
                })

        return results

    def _analyze_multicast(self) -> list[dict]:
        """Analyze well-known IPv6 multicast groups."""
        groups = []
        for addr, description in WELL_KNOWN_MULTICAST.items():
            scope = "link-local" if addr.startswith("ff02") else "site-local" if addr.startswith("ff05") else "global"
            groups.append({
                "address": addr,
                "description": description,
                "scope": scope,
                "security_note": self._multicast_security_note(addr),
            })
        return groups

    def _multicast_security_note(self, addr: str) -> str:
        """Provide security context for multicast addresses."""
        notes = {
            "ff02::1": "Can be used for host discovery - responds to ICMPv6 echo",
            "ff02::2": "Router discovery - reveals router presence and configuration",
            "ff02::fb": "mDNS - can leak hostname and service information",
            "ff02::1:2": "DHCPv6 - potential for rogue DHCP server attacks",
            "ff02::1:3": "LLMNR - susceptible to name resolution poisoning",
        }
        return notes.get(addr, "Standard multicast group")

    def _detect_eui64(self, address: str) -> dict[str, Any] | None:
        """Detect if an IPv6 address uses EUI-64 and extract MAC."""
        expanded = self._expand_ipv6(address)
        groups = expanded.split(":")
        if len(groups) < 8:
            return None
        iid = "".join(groups[4:])
        if len(iid) >= 16 and iid[6:10].lower() == "fffe":
            # Extract MAC by reversing EUI-64
            first_byte = int(iid[:2], 16) ^ 0x02
            mac = f"{first_byte:02x}:{iid[2:4]}:{iid[4:6]}:{iid[10:12]}:{iid[12:14]}:{iid[14:16]}"
            return {"is_eui64": True, "derived_mac": mac.lower()}
        return None

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"].strip()
        scan_type = config.get("scan_type", "known_hosts")
        mac_raw = config.get("mac_addresses", "")
        mac_addresses = [m.strip() for m in mac_raw.split(",") if m.strip()] if mac_raw else []

        prefix = self._extract_prefix(target)
        discovered_hosts: list[dict] = []
        eui64_addresses: list[dict] = []
        multicast_groups: list[dict] = []

        if scan_type == "known_hosts":
            discovered_hosts = self._generate_known_hosts(prefix)
            # Generate EUI-64 addresses from provided MACs
            for mac in mac_addresses:
                eui64_addr = self._mac_to_eui64(mac, f"{prefix}:0000:0000:0000:0000"[:19])
                if eui64_addr:
                    eui64_addresses.append({
                        "address": eui64_addr,
                        "source_mac": mac,
                        "type": "eui64_generated",
                    })

        elif scan_type == "link_local":
            discovered_hosts = self._analyze_link_local(target, mac_addresses)

        elif scan_type == "multicast":
            multicast_groups = self._analyze_multicast()

        # Check target address for EUI-64
        eui64_check = self._detect_eui64(target)

        statistics = {
            "target": target,
            "scan_type": scan_type,
            "prefix_used": prefix,
            "hosts_generated": len(discovered_hosts),
            "eui64_addresses_generated": len(eui64_addresses),
            "multicast_groups_analyzed": len(multicast_groups),
            "mac_addresses_provided": len(mac_addresses),
            "target_eui64_detected": eui64_check is not None,
            "target_derived_mac": eui64_check.get("derived_mac") if eui64_check else None,
        }

        return {
            "discovered_hosts": discovered_hosts,
            "eui64_addresses": eui64_addresses,
            "multicast_groups": multicast_groups,
            "statistics": statistics,
        }
