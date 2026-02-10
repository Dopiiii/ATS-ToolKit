"""API Endpoint Fuzzer Module.

Discover and fuzz API endpoints by probing common paths, methods, and content types.
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

# Common API paths to probe
COMMON_PATHS: List[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/graphql/console",
    "/rest", "/rest/v1", "/rest/api",
    "/v1", "/v2", "/v3",
    "/swagger", "/swagger.json", "/swagger/ui",
    "/openapi", "/openapi.json", "/api-docs",
    "/health", "/healthz", "/status", "/ping",
    "/admin", "/admin/api", "/internal",
    "/auth", "/auth/login", "/auth/token",
    "/users", "/users/me", "/user",
    "/config", "/settings", "/env",
    "/debug", "/debug/vars", "/debug/pprof",
    "/metrics", "/prometheus", "/.well-known",
    "/robots.txt", "/sitemap.xml",
    "/wp-json", "/wp-json/wp/v2",
    "/.git", "/.env", "/.htaccess",
]

METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

CONTENT_TYPES: List[str] = [
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
]

AUTH_HEADERS: List[Dict[str, str]] = [
    {},
    {"Authorization": "Bearer test"},
    {"Authorization": "Basic dGVzdDp0ZXN0"},
    {"X-API-Key": "test"},
    {"Cookie": "session=test; token=test"},
]


class ApiEndpointFuzzerModule(AtsModule):
    """Discover and fuzz API endpoints to find hidden or misconfigured interfaces."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="api_endpoint_fuzzer",
            category=ModuleCategory.FUZZING,
            description="Discover and fuzz API endpoints by probing common paths, methods, and content types",
            version="1.0.0",
            parameters=[
                Parameter(name="base_url", type=ParameterType.URL, description="Base URL of the target application", required=True),
                Parameter(name="custom_paths", type=ParameterType.LIST, description="Additional custom paths to test", required=False, default=[]),
                Parameter(name="test_methods", type=ParameterType.BOOLEAN, description="Test multiple HTTP methods per path", required=False, default=True),
                Parameter(name="test_auth", type=ParameterType.BOOLEAN, description="Test with various auth headers", required=False, default=True),
                Parameter(name="concurrency", type=ParameterType.INTEGER, description="Number of concurrent requests", required=False, default=15, min_value=1, max_value=50),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Request timeout in seconds", required=False, default=10, min_value=1, max_value=60),
            ],
            outputs=[
                OutputField(name="discovered", type="list", description="Discovered live API endpoints"),
                OutputField(name="anomalies", type="list", description="Anomalous responses worth investigating"),
                OutputField(name="summary", type="dict", description="Discovery summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "api", "endpoint", "discovery", "web"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        url = config.get("base_url", "").strip()
        if not url:
            return False, "base_url is required"
        if not url.startswith(("http://", "https://")):
            return False, "base_url must start with http:// or https://"
        return True, ""

    async def _probe(
        self, session: aiohttp.ClientSession, url: str, method: str,
        headers: Dict[str, str], timeout: int,
    ) -> Dict[str, Any]:
        """Probe a single endpoint."""
        start = time.perf_counter()
        try:
            async with session.request(
                method, url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
                allow_redirects=False,
            ) as resp:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                body = await resp.text(errors="replace")
                resp_headers = dict(resp.headers)
                return {
                    "url": url,
                    "method": method,
                    "status": resp.status,
                    "content_length": len(body),
                    "content_type": resp_headers.get("Content-Type", ""),
                    "server": resp_headers.get("Server", ""),
                    "elapsed_ms": elapsed_ms,
                    "has_auth_header": bool(headers),
                    "error": None,
                }
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {
                "url": url, "method": method, "status": 0,
                "content_length": 0, "content_type": "", "server": "",
                "elapsed_ms": elapsed_ms, "has_auth_header": bool(headers),
                "error": type(exc).__name__,
            }

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        base_url = config["base_url"].strip().rstrip("/")
        custom_paths = config.get("custom_paths", [])
        test_methods = config.get("test_methods", True)
        test_auth = config.get("test_auth", True)
        concurrency = config.get("concurrency", 15)
        timeout = config.get("timeout", 10)

        self.logger.info("api_fuzz_start", base_url=base_url)

        paths = list(COMMON_PATHS) + [p if p.startswith("/") else f"/{p}" for p in custom_paths]
        methods_to_test = METHODS if test_methods else ["GET"]
        auth_sets = AUTH_HEADERS if test_auth else [{}]

        # Build probe tasks: for discovered paths use GET first, then expand
        semaphore = asyncio.Semaphore(concurrency)
        discovered: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []
        all_results: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession() as session:
            # Phase 1: discover live paths with GET
            async def _discover_path(path: str) -> None:
                async with semaphore:
                    url = f"{base_url}{path}"
                    res = await self._probe(session, url, "GET", {}, timeout)
                    all_results.append(res)
                    if res["status"] not in (0, 404, 502, 503):
                        discovered.append(res)

            await asyncio.gather(*[_discover_path(p) for p in paths])

            # Phase 2: for discovered endpoints, test methods and auth
            live_urls = [d["url"] for d in discovered]

            async def _deep_probe(url: str, method: str, auth: Dict[str, str]) -> None:
                async with semaphore:
                    res = await self._probe(session, url, method, auth, timeout)
                    all_results.append(res)
                    # Detect anomalies: unusual status codes or auth bypass hints
                    if res["status"] in (200, 201, 204) and auth and res["status"] != 0:
                        anomalies.append({**res, "reason": "auth_header_accepted"})
                    elif res["status"] in (500, 502, 503):
                        anomalies.append({**res, "reason": "server_error"})
                    elif res["status"] == 405:
                        pass  # Method not allowed is expected
                    elif res["status"] in (200, 201, 301, 302) and method not in ("GET", "HEAD", "OPTIONS"):
                        anomalies.append({**res, "reason": f"{method}_accepted"})

            deep_tasks = []
            for url in live_urls:
                for method in methods_to_test:
                    if method == "GET":
                        continue  # Already tested
                    deep_tasks.append(_deep_probe(url, method, {}))
                for auth in auth_sets[1:]:  # Skip empty auth (already tested)
                    deep_tasks.append(_deep_probe(url, "GET", auth))

            if deep_tasks:
                await asyncio.gather(*deep_tasks)

        # Deduplicate anomalies by url+method
        seen = set()
        unique_anomalies = []
        for a in anomalies:
            key = f"{a['url']}:{a['method']}:{a.get('reason', '')}"
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(a)

        status_dist: Dict[int, int] = {}
        for r in all_results:
            status_dist[r["status"]] = status_dist.get(r["status"], 0) + 1

        summary = {
            "base_url": base_url,
            "paths_tested": len(paths),
            "total_requests": len(all_results),
            "endpoints_discovered": len(discovered),
            "anomalies_found": len(unique_anomalies),
            "status_distribution": status_dist,
        }

        self.logger.info("api_fuzz_complete", discovered=len(discovered), anomalies=len(unique_anomalies))
        return {"discovered": discovered, "anomalies": unique_anomalies, "summary": summary}
