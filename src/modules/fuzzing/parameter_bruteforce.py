"""Parameter Bruteforce Module.

Discover hidden parameters in web applications by testing common parameter names.
"""

import asyncio
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

# Common hidden parameter names
COMMON_PARAMS: List[str] = [
    "id", "page", "url", "q", "query", "search", "s", "lang", "language",
    "redirect", "next", "redir", "return", "returnTo", "goto", "continue",
    "debug", "test", "admin", "verbose", "dev", "mode", "env",
    "token", "key", "api_key", "apikey", "secret", "auth", "session",
    "user", "username", "email", "password", "pass", "passwd", "login",
    "action", "cmd", "command", "exec", "do", "type", "method",
    "file", "path", "dir", "folder", "name", "filename",
    "callback", "cb", "jsonp", "format", "output", "encoding",
    "limit", "offset", "count", "size", "start", "end", "from", "to",
    "sort", "order", "orderby", "sortby", "asc", "desc", "filter",
    "include", "exclude", "fields", "select", "expand", "embed",
    "version", "v", "ver", "api", "ref", "source", "src",
    "view", "template", "theme", "layout", "style", "css",
    "role", "permission", "access", "level", "group", "scope",
    "hidden", "internal", "private", "config", "setting", "option",
    "flag", "feature", "enable", "disable", "toggle", "switch",
    "category", "tag", "label", "status", "state", "active",
]

PARAM_VALUES: List[str] = ["1", "true", "test", "admin", "../etc/passwd", "<script>"]


class ParameterBruteforceModule(AtsModule):
    """Discover hidden parameters by brute-forcing common names against a target URL."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="parameter_bruteforce",
            category=ModuleCategory.FUZZING,
            description="Discover hidden parameters in web applications via brute-force testing",
            version="1.0.0",
            parameters=[
                Parameter(name="target_url", type=ParameterType.URL, description="Target URL to test parameters against", required=True),
                Parameter(name="method", type=ParameterType.CHOICE, description="HTTP method for parameter testing", required=False, default="GET", choices=["GET", "POST"]),
                Parameter(name="custom_params", type=ParameterType.LIST, description="Additional custom parameter names to test", required=False, default=[]),
                Parameter(name="concurrency", type=ParameterType.INTEGER, description="Number of concurrent requests", required=False, default=20, min_value=1, max_value=50),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Request timeout in seconds", required=False, default=10, min_value=1, max_value=60),
                Parameter(name="threshold", type=ParameterType.FLOAT, description="Response size difference threshold (ratio) to flag a parameter", required=False, default=0.1, min_value=0.01, max_value=1.0),
            ],
            outputs=[
                OutputField(name="discovered_params", type="list", description="Parameters that caused a response change"),
                OutputField(name="all_results", type="list", description="Full results for every parameter tested"),
                OutputField(name="summary", type="dict", description="Brute-force session summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "parameter", "bruteforce", "web", "discovery"],
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

    async def _get_baseline(self, session: aiohttp.ClientSession, url: str, method: str, timeout: int) -> Dict[str, Any]:
        """Fetch a baseline response without any extra parameters."""
        try:
            async with session.request(
                method, url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
            ) as resp:
                body = await resp.text(errors="replace")
                return {"status": resp.status, "length": len(body), "content_hash": hash(body)}
        except Exception:
            return {"status": 0, "length": 0, "content_hash": 0}

    async def _test_param(
        self, session: aiohttp.ClientSession, url: str, method: str,
        param_name: str, param_value: str, timeout: int,
    ) -> Dict[str, Any]:
        """Test a single parameter and return the response characteristics."""
        start = time.perf_counter()
        try:
            if method == "GET":
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param_name}={param_value}"
                kwargs: Dict[str, Any] = {}
            else:
                test_url = url
                kwargs = {"data": {param_name: param_value}}

            async with session.request(
                method, test_url, timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False, **kwargs,
            ) as resp:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                body = await resp.text(errors="replace")
                return {
                    "param": param_name,
                    "value": param_value,
                    "status": resp.status,
                    "length": len(body),
                    "content_hash": hash(body),
                    "elapsed_ms": elapsed_ms,
                    "error": None,
                }
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {
                "param": param_name, "value": param_value, "status": 0,
                "length": 0, "content_hash": 0, "elapsed_ms": elapsed_ms,
                "error": type(exc).__name__,
            }

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_url = config["target_url"].strip()
        method = config.get("method", "GET")
        custom_params = config.get("custom_params", [])
        concurrency = config.get("concurrency", 20)
        timeout = config.get("timeout", 10)
        threshold = config.get("threshold", 0.1)

        self.logger.info("param_brute_start", url=target_url, method=method)

        param_names = list(COMMON_PARAMS) + [p for p in custom_params if p not in COMMON_PARAMS]
        semaphore = asyncio.Semaphore(concurrency)

        all_results: List[Dict[str, Any]] = []
        discovered: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession() as session:
            # Get baseline
            baseline = await self._get_baseline(session, target_url, method, timeout)
            baseline_status = baseline["status"]
            baseline_length = baseline["length"]
            baseline_hash = baseline["content_hash"]

            async def _test(param_name: str) -> None:
                async with semaphore:
                    for value in PARAM_VALUES:
                        res = await self._test_param(session, target_url, method, param_name, value, timeout)
                        all_results.append(res)

                        if res["error"]:
                            continue

                        # Detect interesting changes
                        status_changed = res["status"] != baseline_status
                        length_diff = abs(res["length"] - baseline_length)
                        length_ratio = length_diff / max(baseline_length, 1)
                        content_changed = res["content_hash"] != baseline_hash

                        if status_changed or (content_changed and length_ratio > threshold):
                            discovered.append({
                                **res,
                                "baseline_status": baseline_status,
                                "baseline_length": baseline_length,
                                "status_changed": status_changed,
                                "length_diff": length_diff,
                                "length_ratio": round(length_ratio, 4),
                                "content_changed": content_changed,
                            })
                            break  # Found an interesting value, move on

            await asyncio.gather(*[_test(p) for p in param_names])

        # Sort discovered by length difference descending
        discovered.sort(key=lambda x: x.get("length_diff", 0), reverse=True)

        status_changes = sum(1 for d in discovered if d.get("status_changed"))
        content_changes = sum(1 for d in discovered if d.get("content_changed"))

        summary = {
            "target_url": target_url,
            "method": method,
            "params_tested": len(param_names),
            "total_requests": len(all_results),
            "params_discovered": len(discovered),
            "status_changes": status_changes,
            "content_changes": content_changes,
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "threshold": threshold,
        }

        self.logger.info("param_brute_complete", tested=len(param_names), discovered=len(discovered))
        return {"discovered_params": discovered, "all_results": all_results, "summary": summary}
