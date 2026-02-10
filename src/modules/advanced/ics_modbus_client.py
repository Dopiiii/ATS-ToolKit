"""Modbus TCP client for reading registers during ICS security auditing."""

import asyncio
import struct
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


FUNCTION_CODES = {
    "read_coils": 0x01,
    "read_holding": 0x03,
    "read_input": 0x04,
}

FUNCTION_NAMES = {0x01: "Read Coils", 0x03: "Read Holding Registers", 0x04: "Read Input Registers"}


def build_modbus_tcp_frame(transaction_id: int, unit_id: int, function_code: int,
                           start_addr: int, quantity: int) -> bytes:
    """Build a Modbus TCP request frame."""
    pdu = struct.pack(">BHH", function_code, start_addr, quantity)
    mbap = struct.pack(">HHHB", transaction_id, 0x0000, len(pdu) + 1, unit_id)
    return mbap + pdu


def parse_modbus_response(data: bytes, function_code: int) -> dict[str, Any]:
    """Parse a Modbus TCP response frame into structured data."""
    if len(data) < 9:
        return {"error": "Response too short", "raw_hex": data.hex()}
    transaction_id = struct.unpack(">H", data[0:2])[0]
    protocol_id = struct.unpack(">H", data[2:4])[0]
    length = struct.unpack(">H", data[4:6])[0]
    unit_id = data[6]
    resp_fc = data[7]

    result: dict[str, Any] = {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "function_code": resp_fc,
        "is_error": bool(resp_fc & 0x80),
    }

    if resp_fc & 0x80:
        result["exception_code"] = data[8] if len(data) > 8 else None
        exception_map = {1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
                         4: "Server Device Failure", 5: "Acknowledge", 6: "Server Device Busy"}
        result["exception_text"] = exception_map.get(result["exception_code"], "Unknown")
        return result

    byte_count = data[8]
    payload = data[9:9 + byte_count]
    result["byte_count"] = byte_count

    if function_code in (0x03, 0x04):
        registers = []
        for i in range(0, len(payload), 2):
            if i + 1 < len(payload):
                registers.append(struct.unpack(">H", payload[i:i + 2])[0])
        result["registers"] = registers
    elif function_code == 0x01:
        coils = []
        for byte_val in payload:
            for bit in range(8):
                coils.append(bool(byte_val & (1 << bit)))
        result["coils"] = coils

    result["raw_hex"] = payload.hex()
    return result


class IcsModbusClientModule(AtsModule):
    """Read Modbus TCP registers from a PLC or RTU for security auditing purposes."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_modbus_client",
            category=ModuleCategory.ADVANCED,
            description="Read Modbus registers from ICS devices for security auditing",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.IP, description="Target Modbus device IP"),
                Parameter(name="port", type=ParameterType.INTEGER, description="Modbus TCP port",
                          default=502, min_value=1, max_value=65535),
                Parameter(name="register_range", type=ParameterType.STRING,
                          description="Register range to read (e.g. 0-100)", default="0-100"),
                Parameter(name="function_code", type=ParameterType.CHOICE,
                          description="Modbus function code to use",
                          default="read_holding", choices=["read_coils", "read_holding", "read_input"]),
            ],
            outputs=[
                OutputField(name="registers", type="list", description="Register values read from device"),
                OutputField(name="device_response", type="dict", description="Parsed Modbus response"),
                OutputField(name="connection_info", type="dict", description="Connection metadata"),
            ],
            tags=["advanced", "ics", "scada", "modbus", "plc"],
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("target", ""):
            return False, "Target IP address is required"
        reg_range = config.get("register_range", "0-100")
        parts = reg_range.split("-")
        if len(parts) != 2:
            return False, "Register range must be in format START-END (e.g. 0-100)"
        try:
            start, end = int(parts[0]), int(parts[1])
            if start < 0 or end < start or (end - start) > 125:
                return False, "Register range must be valid and span at most 125 registers"
        except ValueError:
            return False, "Register range must contain valid integers"
        return True, ""

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"]
        port = int(config.get("port", 502))
        reg_range = config.get("register_range", "0-100")
        fc_name = config.get("function_code", "read_holding")
        fc = FUNCTION_CODES[fc_name]

        start_addr, end_addr = [int(x) for x in reg_range.split("-")]
        quantity = end_addr - start_addr

        frame = build_modbus_tcp_frame(
            transaction_id=1, unit_id=1, function_code=fc,
            start_addr=start_addr, quantity=quantity,
        )

        connection_info: dict[str, Any] = {"target": target, "port": port, "connected": False}

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=10
            )
            connection_info["connected"] = True
            writer.write(frame)
            await writer.drain()

            response_data = await asyncio.wait_for(reader.read(2048), timeout=10)
            connection_info["response_length"] = len(response_data)

            parsed = parse_modbus_response(response_data, fc)
            writer.close()
            await writer.wait_closed()

            return {
                "registers": parsed.get("registers", parsed.get("coils", [])),
                "device_response": parsed,
                "connection_info": connection_info,
                "function_used": FUNCTION_NAMES.get(fc, fc_name),
                "register_range": reg_range,
            }
        except asyncio.TimeoutError:
            connection_info["error"] = "Connection timed out"
        except ConnectionRefusedError:
            connection_info["error"] = "Connection refused - Modbus service may not be running"
        except OSError as exc:
            connection_info["error"] = f"Network error: {exc}"

        return {
            "registers": [],
            "device_response": {},
            "connection_info": connection_info,
            "function_used": FUNCTION_NAMES.get(fc, fc_name),
            "register_range": reg_range,
        }
