"""ICS protocol scanner for detecting industrial control system protocols on target networks."""

import asyncio
import struct
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


# Protocol definitions: port, name, identification bytes, expected response prefix
ICS_PROTOCOLS = {
    "modbus": {
        "port": 502,
        "name": "Modbus TCP",
        "probe": struct.pack(">HHHBBH", 0x0001, 0x0000, 0x0006, 0x01, 0x2B, 0x0E01),
        "resp_min": 9,
        "signature": b"\x00\x01",
    },
    "dnp3": {
        "port": 20000,
        "name": "DNP3",
        "probe": b"\x05\x64\x05\xC0\x01\x00\x00\x00\x00\x04\xE9\x21",
        "resp_min": 10,
        "signature": b"\x05\x64",
    },
    "bacnet": {
        "port": 47808,
        "name": "BACnet/IP",
        "probe": b"\x81\x04\x00\x19\x01\x00\x10\x08\x00\x02\x01\x00\x4F\x00\x61\x00\x4B\x00\x4C\x00",
        "resp_min": 4,
        "signature": b"\x81",
    },
    "ethernetip": {
        "port": 44818,
        "name": "EtherNet/IP",
        "probe": struct.pack("<HHI", 0x0063, 0x0000, 0x00000000) + b"\x00" * 20,
        "resp_min": 28,
        "signature": b"\x63\x00",
    },
}


class IcsProtocolScannerModule(AtsModule):
    """Detect ICS/SCADA protocols running on a target host by probing well-known ports."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_protocol_scanner",
            category=ModuleCategory.ADVANCED,
            description="Detect ICS protocols (Modbus, DNP3, BACnet, EtherNet/IP) on a target host",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.IP, description="Target IP address to scan"),
                Parameter(name="protocols", type=ParameterType.CHOICE, description="Which protocols to scan",
                          default="all", choices=["all", "modbus", "dnp3", "bacnet", "ethernetip"]),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Connection timeout in seconds",
                          default=5, min_value=1, max_value=30),
            ],
            outputs=[
                OutputField(name="detected_protocols", type="list", description="Protocols detected on the target"),
                OutputField(name="scan_details", type="dict", description="Per-protocol scan results"),
                OutputField(name="open_ports", type="list", description="Open ICS-related ports"),
            ],
            tags=["advanced", "ics", "scada", "protocol-detection", "network"],
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("target", ""):
            return False, "Target IP address is required"
        import re
        ip_pat = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ip_pat.match(config["target"]):
            return False, "Invalid IP address format"
        return True, ""

    async def _probe_protocol(self, target: str, proto_key: str, timeout: int) -> dict[str, Any]:
        """Probe a single protocol on the target host."""
        proto = ICS_PROTOCOLS[proto_key]
        result: dict[str, Any] = {
            "protocol": proto["name"],
            "port": proto["port"],
            "detected": False,
            "port_open": False,
            "response_bytes": 0,
            "banner": "",
            "error": None,
        }
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, proto["port"]), timeout=timeout
            )
            result["port_open"] = True
            writer.write(proto["probe"])
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            result["response_bytes"] = len(response)
            if len(response) >= proto["resp_min"]:
                if response[:len(proto["signature"])] == proto["signature"]:
                    result["detected"] = True
                result["banner"] = response[:64].hex()
            writer.close()
            await writer.wait_closed()
        except asyncio.TimeoutError:
            result["error"] = "Connection timed out"
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
        except OSError as exc:
            result["error"] = f"OS error: {exc}"
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"]
        protocols_choice = config.get("protocols", "all")
        timeout = int(config.get("timeout", 5))

        if protocols_choice == "all":
            proto_keys = list(ICS_PROTOCOLS.keys())
        else:
            proto_keys = [protocols_choice]

        tasks = [self._probe_protocol(target, pk, timeout) for pk in proto_keys]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scan_details = {}
        detected_protocols = []
        open_ports = []

        for pk, res in zip(proto_keys, results):
            if isinstance(res, Exception):
                scan_details[pk] = {"protocol": ICS_PROTOCOLS[pk]["name"], "error": str(res)}
                continue
            scan_details[pk] = res
            if res["port_open"]:
                open_ports.append(res["port"])
            if res["detected"]:
                detected_protocols.append(res["protocol"])

        return {
            "target": target,
            "detected_protocols": detected_protocols,
            "scan_details": scan_details,
            "open_ports": sorted(set(open_ports)),
            "total_probed": len(proto_keys),
            "total_detected": len(detected_protocols),
        }
