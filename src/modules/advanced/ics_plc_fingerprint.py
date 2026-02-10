"""PLC device fingerprinting module for identifying vendor, model, and firmware of ICS controllers."""

import asyncio
import struct
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


ICS_PORTS = [
    (502, "Modbus TCP"),
    (102, "Siemens S7"),
    (44818, "EtherNet/IP"),
    (20000, "DNP3"),
    (47808, "BACnet"),
    (2222, "EtherCAT"),
    (4840, "OPC-UA"),
    (1911, "Niagara Fox"),
    (789, "Red Lion Crimson"),
    (18245, "General Electric SRTP"),
]

DEVICE_SIGNATURES = [
    {"banner_pattern": b"Siemens", "vendor": "Siemens", "model_hint": "S7 Series", "protocol": "S7comm"},
    {"banner_pattern": b"Schneider", "vendor": "Schneider Electric", "model_hint": "Modicon", "protocol": "Modbus"},
    {"banner_pattern": b"Allen-Bradley", "vendor": "Rockwell Automation", "model_hint": "Allen-Bradley", "protocol": "EtherNet/IP"},
    {"banner_pattern": b"ABB", "vendor": "ABB", "model_hint": "AC500/PM5xx", "protocol": "Modbus"},
    {"banner_pattern": b"Honeywell", "vendor": "Honeywell", "model_hint": "Experion", "protocol": "OPC-UA"},
    {"banner_pattern": b"Emerson", "vendor": "Emerson", "model_hint": "DeltaV", "protocol": "OPC-UA"},
    {"banner_pattern": b"Mitsubishi", "vendor": "Mitsubishi Electric", "model_hint": "MELSEC", "protocol": "MELSOFT"},
    {"banner_pattern": b"Omron", "vendor": "Omron", "model_hint": "NJ/NX Series", "protocol": "FINS"},
    {"banner_pattern": b"GE", "vendor": "General Electric", "model_hint": "PACSystems", "protocol": "SRTP"},
    {"banner_pattern": b"Beckhoff", "vendor": "Beckhoff", "model_hint": "TwinCAT", "protocol": "ADS"},
    {"banner_pattern": b"Wago", "vendor": "WAGO", "model_hint": "PFC Series", "protocol": "Modbus"},
    {"banner_pattern": b"Phoenix", "vendor": "Phoenix Contact", "model_hint": "ILC Series", "protocol": "Modbus"},
]

PROTOCOL_PROBES = {
    502: struct.pack(">HHHBBH", 0x0001, 0x0000, 0x0006, 0x01, 0x2B, 0x0E01),
    102: b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02",
    44818: struct.pack("<HHI", 0x0063, 0x0000, 0x00000000) + b"\x00" * 20,
    20000: b"\x05\x64\x05\xC0\x01\x00\x00\x00\x00\x04\xE9\x21",
    47808: b"\x81\x04\x00\x19\x01\x00\x10\x08\x00\x02\x01\x00\x4F\x00",
}


class IcsPlcFingerprintModule(AtsModule):
    """Fingerprint PLC devices by probing ICS ports and matching response signatures."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_plc_fingerprint",
            category=ModuleCategory.ADVANCED,
            description="Fingerprint PLC devices to identify vendor, model, and protocol",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.IP, description="Target PLC IP address"),
                Parameter(name="scan_method", type=ParameterType.CHOICE,
                          description="Fingerprinting method",
                          default="all", choices=["banner", "protocol", "all"]),
                Parameter(name="timeout", type=ParameterType.INTEGER,
                          description="Per-port connection timeout in seconds",
                          default=5, min_value=1, max_value=30),
            ],
            outputs=[
                OutputField(name="device_info", type="dict", description="Identified device information"),
                OutputField(name="open_ports", type="list", description="Open ICS ports found"),
                OutputField(name="signatures_matched", type="list", description="Matched device signatures"),
            ],
            tags=["advanced", "ics", "scada", "plc", "fingerprinting"],
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("target", ""):
            return False, "Target IP address is required"
        import re
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", config["target"]):
            return False, "Invalid IP address format"
        return True, ""

    async def _probe_port(self, target: str, port: int, proto_name: str,
                          method: str, timeout: int) -> dict[str, Any]:
        """Probe a single port for banner and protocol identification."""
        result: dict[str, Any] = {
            "port": port, "protocol_name": proto_name, "open": False,
            "banner": "", "response_hex": "", "matched_vendor": None,
        }
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout)
            result["open"] = True

            # Banner grab
            if method in ("banner", "all"):
                try:
                    banner_data = await asyncio.wait_for(reader.read(512), timeout=2)
                    if banner_data:
                        result["banner"] = banner_data[:128].decode("ascii", errors="replace")
                        result["response_hex"] = banner_data[:64].hex()
                except asyncio.TimeoutError:
                    pass

            # Protocol probe
            if method in ("protocol", "all") and port in PROTOCOL_PROBES:
                writer.write(PROTOCOL_PROBES[port])
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                    if resp:
                        result["response_hex"] = resp[:64].hex()
                        result["banner"] = result["banner"] or resp[:128].decode("ascii", errors="replace")
                except asyncio.TimeoutError:
                    pass

            # Signature matching
            combined = (result.get("banner", "") + result.get("response_hex", "")).encode("utf-8", errors="replace")
            for sig in DEVICE_SIGNATURES:
                if sig["banner_pattern"].lower() in combined.lower():
                    result["matched_vendor"] = sig["vendor"]
                    result["matched_model"] = sig["model_hint"]
                    result["matched_protocol"] = sig["protocol"]
                    break

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"]
        method = config.get("scan_method", "all")
        timeout = int(config.get("timeout", 5))

        tasks = [self._probe_port(target, port, name, method, timeout) for port, name in ICS_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        signatures_matched = []
        device_info: dict[str, Any] = {"target": target, "vendor": "Unknown", "model": "Unknown",
                                        "protocols_detected": []}

        for res in results:
            if isinstance(res, Exception):
                continue
            if res["open"]:
                open_ports.append({"port": res["port"], "protocol": res["protocol_name"]})
                device_info["protocols_detected"].append(res["protocol_name"])
            if res.get("matched_vendor"):
                signatures_matched.append({
                    "vendor": res["matched_vendor"],
                    "model": res.get("matched_model", "Unknown"),
                    "port": res["port"],
                })
                device_info["vendor"] = res["matched_vendor"]
                device_info["model"] = res.get("matched_model", "Unknown")

        return {
            "device_info": device_info,
            "open_ports": open_ports,
            "signatures_matched": signatures_matched,
            "total_ports_scanned": len(ICS_PORTS),
            "total_open": len(open_ports),
        }
