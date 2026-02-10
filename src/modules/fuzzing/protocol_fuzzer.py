"""Protocol Fuzzer Module.

Fuzz network protocols by sending malformed data to TCP/UDP ports to detect service crashes.
"""

import asyncio
import random
import time
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Protocol-specific initial handshake payloads
PROTOCOL_TEMPLATES: Dict[str, List[bytes]] = {
    "http": [
        b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: target\r\n\r\n",
    ],
    "ftp": [
        b"USER anonymous\r\n",
        b"PASS anonymous@\r\n",
        b"LIST\r\n",
        b"QUIT\r\n",
    ],
    "smtp": [
        b"EHLO fuzzer\r\n",
        b"MAIL FROM:<test@test.com>\r\n",
        b"RCPT TO:<test@test.com>\r\n",
        b"QUIT\r\n",
    ],
}

# Malformed payloads to send after or instead of protocol data
MALFORMED_PAYLOADS: List[bytes] = [
    b"\x00" * 1024,
    b"\xff" * 1024,
    b"A" * 10000,
    b"\r\n" * 500,
    b"\x00\r\n" * 200,
    bytes(range(256)) * 4,
    b"GET " + b"/" * 5000 + b" HTTP/1.1\r\n\r\n",
    b"POST / HTTP/9.9\r\n\r\n",
    b"\x80\x00\x00\x00" + b"\xff" * 100,
    b"{{" * 500 + b"}}" * 500,
    b"%" + b"n" * 200,
    b"\xfe\xff" + b"\x00A" * 500,
]


class ProtocolFuzzerModule(AtsModule):
    """Fuzz network protocols with malformed data to detect service crashes."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="protocol_fuzzer",
            category=ModuleCategory.FUZZING,
            description="Fuzz network protocols by sending malformed data to TCP/UDP ports",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.STRING, description="Target host (IP or hostname)", required=True),
                Parameter(name="port", type=ParameterType.INTEGER, description="Target port number", required=True, min_value=1, max_value=65535),
                Parameter(name="protocol", type=ParameterType.CHOICE, description="Protocol to fuzz", required=False, default="http", choices=["http", "ftp", "smtp", "raw"]),
                Parameter(name="num_cases", type=ParameterType.INTEGER, description="Number of fuzz cases to send", required=False, default=30, min_value=1, max_value=500),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Connection timeout in seconds", required=False, default=5, min_value=1, max_value=30),
                Parameter(name="use_udp", type=ParameterType.BOOLEAN, description="Use UDP instead of TCP", required=False, default=False),
            ],
            outputs=[
                OutputField(name="results", type="list", description="Results of each fuzz probe"),
                OutputField(name="crashes", type="list", description="Detected crashes or unexpected responses"),
                OutputField(name="summary", type="dict", description="Fuzzing session summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "protocol", "network", "tcp", "udp"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "target is required"
        port = config.get("port")
        if port is None:
            return False, "port is required"
        return True, ""

    def _generate_payloads(self, protocol: str, num_cases: int) -> List[Dict[str, Any]]:
        """Generate fuzz payloads mixing protocol templates and malformed data."""
        payloads: List[Dict[str, Any]] = []
        templates = PROTOCOL_TEMPLATES.get(protocol, [])

        for i in range(num_cases):
            strategy = random.choice(["malformed", "template_corrupt", "random_bytes", "oversized"])

            if strategy == "malformed":
                data = random.choice(MALFORMED_PAYLOADS)
            elif strategy == "template_corrupt" and templates:
                base = bytearray(random.choice(templates))
                # Corrupt random bytes in the template
                for _ in range(random.randint(1, min(10, len(base)))):
                    pos = random.randint(0, len(base) - 1)
                    base[pos] = random.randint(0, 255)
                data = bytes(base)
            elif strategy == "random_bytes":
                length = random.randint(1, 4096)
                data = bytes(random.randint(0, 255) for _ in range(length))
            else:  # oversized
                chunk = random.choice(templates) if templates else b"A"
                data = chunk * random.randint(100, 1000)

            payloads.append({"index": i, "strategy": strategy, "data": data, "size": len(data)})

        return payloads

    async def _send_tcp(self, host: str, port: int, data: bytes, timeout: int) -> Dict[str, Any]:
        """Send data over TCP and capture the response."""
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.write(data)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            writer.close()
            await writer.wait_closed()
            return {
                "connected": True, "response_size": len(response),
                "response_preview": response[:200].hex(), "elapsed_ms": elapsed_ms,
                "error": None, "crash_indicator": False,
            }
        except ConnectionResetError:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {"connected": True, "response_size": 0, "response_preview": "", "elapsed_ms": elapsed_ms, "error": "ConnectionReset", "crash_indicator": True}
        except asyncio.TimeoutError:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {"connected": False, "response_size": 0, "response_preview": "", "elapsed_ms": elapsed_ms, "error": "Timeout", "crash_indicator": False}
        except OSError as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {"connected": False, "response_size": 0, "response_preview": "", "elapsed_ms": elapsed_ms, "error": str(exc), "crash_indicator": False}

    async def _send_udp(self, host: str, port: int, data: bytes, timeout: int) -> Dict[str, Any]:
        """Send data over UDP and capture any response."""
        start = time.perf_counter()
        loop = asyncio.get_event_loop()
        try:
            transport, _ = await asyncio.wait_for(
                loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(host, port)),
                timeout=timeout,
            )
            transport.sendto(data)
            await asyncio.sleep(min(timeout, 2))
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            transport.close()
            return {"connected": True, "response_size": 0, "response_preview": "", "elapsed_ms": elapsed_ms, "error": None, "crash_indicator": False}
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {"connected": False, "response_size": 0, "response_preview": "", "elapsed_ms": elapsed_ms, "error": type(exc).__name__, "crash_indicator": False}

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        port = config["port"]
        protocol = config.get("protocol", "http")
        num_cases = config.get("num_cases", 30)
        timeout = config.get("timeout", 5)
        use_udp = config.get("use_udp", False)

        self.logger.info("protocol_fuzz_start", target=target, port=port, protocol=protocol)

        payloads = self._generate_payloads(protocol, num_cases)
        send_fn = self._send_udp if use_udp else self._send_tcp

        results: List[Dict[str, Any]] = []
        crashes: List[Dict[str, Any]] = []

        for payload in payloads:
            res = await send_fn(target, port, payload["data"], timeout)
            entry = {
                "index": payload["index"],
                "strategy": payload["strategy"],
                "payload_size": payload["size"],
                **res,
            }
            results.append(entry)
            if res["crash_indicator"] or res["error"] == "ConnectionReset":
                crashes.append(entry)
            # Small delay between probes to avoid overwhelming the target
            await asyncio.sleep(0.05)

        summary = {
            "target": target,
            "port": port,
            "protocol": protocol,
            "transport": "UDP" if use_udp else "TCP",
            "total_probes": len(results),
            "successful_connections": sum(1 for r in results if r["connected"]),
            "crashes_detected": len(crashes),
            "errors": sum(1 for r in results if r["error"]),
        }

        self.logger.info("protocol_fuzz_complete", total=len(results), crashes=len(crashes))
        return {"results": results, "crashes": crashes, "summary": summary}
