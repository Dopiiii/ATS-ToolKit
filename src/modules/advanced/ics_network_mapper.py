"""ICS network topology mapper — scans IP ranges for industrial control system devices."""

import asyncio
import ipaddress
import re
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


ICS_PORT_MAP = {
    102: {"name": "Siemens S7", "type": "PLC"},
    502: {"name": "Modbus TCP", "type": "PLC/RTU"},
    789: {"name": "Red Lion Crimson", "type": "HMI"},
    1911: {"name": "Niagara Fox", "type": "BMS"},
    2222: {"name": "EtherCAT", "type": "Fieldbus"},
    4840: {"name": "OPC-UA", "type": "SCADA"},
    4000: {"name": "Emerson ROC", "type": "RTU"},
    18245: {"name": "GE SRTP", "type": "PLC"},
    20000: {"name": "DNP3", "type": "RTU"},
    44818: {"name": "EtherNet/IP", "type": "PLC"},
    47808: {"name": "BACnet/IP", "type": "BMS"},
}

QUICK_PORTS = [102, 502, 44818, 47808, 4840]
THOROUGH_PORTS = list(ICS_PORT_MAP.keys())


class IcsNetworkMapperModule(AtsModule):
    """Map ICS network topology by scanning IP ranges for common industrial protocol ports."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_network_mapper",
            category=ModuleCategory.ADVANCED,
            description="Map ICS network topology by scanning for industrial devices across an IP range",
            version="1.0.0",
            parameters=[
                Parameter(name="network_range", type=ParameterType.STRING,
                          description="CIDR network range to scan (e.g. 192.168.1.0/24)"),
                Parameter(name="scan_depth", type=ParameterType.CHOICE,
                          description="Scan depth — quick (top 5 ports) or thorough (all ICS ports)",
                          default="quick", choices=["quick", "thorough"]),
                Parameter(name="timeout", type=ParameterType.INTEGER,
                          description="Per-port timeout in seconds", default=3, min_value=1, max_value=15),
            ],
            outputs=[
                OutputField(name="topology", type="list", description="Discovered devices and their roles"),
                OutputField(name="device_count", type="integer", description="Number of ICS devices found"),
                OutputField(name="protocol_summary", type="dict", description="Protocols found and counts"),
            ],
            tags=["advanced", "ics", "scada", "network", "topology"],
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("network_range", ""):
            return False, "Network range is required"
        try:
            net = ipaddress.ip_network(config["network_range"], strict=False)
            if net.num_addresses > 1024:
                return False, "Network range too large — maximum /22 (1024 hosts)"
        except ValueError as exc:
            return False, f"Invalid CIDR notation: {exc}"
        return True, ""

    async def _check_port(self, ip: str, port: int, timeout: int) -> dict[str, Any] | None:
        """Try to connect to a single IP:port and return info if open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            info = ICS_PORT_MAP[port]
            return {"ip": ip, "port": port, "protocol": info["name"], "device_type": info["type"]}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def _scan_host(self, ip: str, ports: list[int], timeout: int) -> list[dict[str, Any]]:
        """Scan all selected ports on a single host."""
        tasks = [self._check_port(ip, port, timeout) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        hits = []
        for r in results:
            if isinstance(r, dict):
                hits.append(r)
        return hits

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        network_range = config["network_range"]
        scan_depth = config.get("scan_depth", "quick")
        timeout = int(config.get("timeout", 3))

        net = ipaddress.ip_network(network_range, strict=False)
        ports = QUICK_PORTS if scan_depth == "quick" else THOROUGH_PORTS
        hosts = [str(ip) for ip in net.hosts()]

        # Scan in batches to avoid opening too many sockets
        batch_size = 32
        all_hits: list[dict[str, Any]] = []

        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            tasks = [self._scan_host(ip, ports, timeout) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in batch_results:
                if isinstance(res, list):
                    all_hits.extend(res)

        # Build topology and summary
        device_map: dict[str, dict[str, Any]] = {}
        protocol_summary: dict[str, int] = {}

        for hit in all_hits:
            ip = hit["ip"]
            if ip not in device_map:
                device_map[ip] = {
                    "ip": ip,
                    "protocols": [],
                    "open_ports": [],
                    "device_types": set(),
                }
            device_map[ip]["protocols"].append(hit["protocol"])
            device_map[ip]["open_ports"].append(hit["port"])
            device_map[ip]["device_types"].add(hit["device_type"])
            protocol_summary[hit["protocol"]] = protocol_summary.get(hit["protocol"], 0) + 1

        topology = []
        for ip, info in sorted(device_map.items()):
            topology.append({
                "ip": info["ip"],
                "protocols": info["protocols"],
                "open_ports": sorted(info["open_ports"]),
                "device_types": sorted(info["device_types"]),
                "likely_role": info["device_types"].pop() if len(info["device_types"]) == 1 else "Multi-function",
            })

        return {
            "network_range": network_range,
            "topology": topology,
            "device_count": len(topology),
            "protocol_summary": protocol_summary,
            "hosts_scanned": len(hosts),
            "ports_per_host": len(ports),
            "scan_depth": scan_depth,
        }
