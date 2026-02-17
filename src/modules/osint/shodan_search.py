"""Shodan API search for internet-connected devices and services.

Queries the Shodan API to discover hosts, open ports, running services,
and known vulnerabilities for given search criteria.
"""

import asyncio
import re
from typing import Any

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanSearchModule(AtsModule):
    """Search Shodan for internet-exposed hosts and services."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="shodan_search",
            category=ModuleCategory.OSINT,
            description="Shodan API search for hosts, open ports, services, and vulnerabilities",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="query", type=ParameterType.STRING,
                    description="Shodan search query (e.g., 'apache port:443 country:US')",
                    required=True,
                ),
                Parameter(
                    name="max_results", type=ParameterType.INTEGER,
                    description="Maximum number of results to return",
                    default=10, min_value=1, max_value=100,
                ),
                Parameter(
                    name="search_type", type=ParameterType.CHOICE,
                    description="Type of search to perform",
                    choices=["host_search", "host_lookup", "dns_resolve"], default="host_search",
                ),
            ],
            outputs=[
                OutputField(name="hosts", type="list", description="Discovered hosts with details"),
                OutputField(name="total_results", type="integer", description="Total results available"),
                OutputField(name="ports_summary", type="dict", description="Summary of open ports"),
                OutputField(name="vulns_found", type="list", description="Known vulnerabilities"),
            ],
            requires_api_key=True,
            api_key_service="shodan",
            tags=["osint", "shodan", "reconnaissance", "ports", "services"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        query = config.get("query", "").strip()
        if not query:
            return False, "Search query is required"
        if len(query) > 500:
            return False, "Query is too long (max 500 characters)"
        api_key = config.get("api_key", "").strip()
        if not api_key:
            return False, "Shodan API key is required"
        return True, ""

    async def _search_hosts(
        self, session: aiohttp.ClientSession, query: str,
        api_key: str, max_results: int,
    ) -> dict[str, Any]:
        """Perform a Shodan host search."""
        url = f"{SHODAN_API_BASE}/shodan/host/search"
        params = {"key": api_key, "query": query, "minify": "true"}
        try:
            async with session.get(
                url, params=params, timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    matches = data.get("matches", [])[:max_results]
                    return {
                        "matches": matches,
                        "total": data.get("total", 0),
                    }
                elif resp.status == 401:
                    return {"error": "Invalid Shodan API key", "matches": [], "total": 0}
                elif resp.status == 429:
                    return {"error": "Shodan API rate limit exceeded", "matches": [], "total": 0}
                else:
                    body = await resp.text()
                    return {"error": f"Shodan API error ({resp.status}): {body}", "matches": [], "total": 0}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"error": str(exc), "matches": [], "total": 0}

    async def _lookup_host(
        self, session: aiohttp.ClientSession, ip: str, api_key: str,
    ) -> dict[str, Any]:
        """Look up a specific host by IP."""
        url = f"{SHODAN_API_BASE}/shodan/host/{ip}"
        params = {"key": api_key}
        try:
            async with session.get(
                url, params=params, timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return {"error": f"No information available for {ip}"}
                else:
                    return {"error": f"Shodan API error: HTTP {resp.status}"}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"error": str(exc)}

    async def _dns_resolve(
        self, session: aiohttp.ClientSession, hostnames: str, api_key: str,
    ) -> dict[str, Any]:
        """Resolve hostnames to IPs via Shodan DNS."""
        url = f"{SHODAN_API_BASE}/dns/resolve"
        params = {"key": api_key, "hostnames": hostnames}
        try:
            async with session.get(
                url, params=params, timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"error": f"DNS resolve failed: HTTP {resp.status}"}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"error": str(exc)}

    def _process_matches(self, matches: list[dict[str, Any]]) -> dict[str, Any]:
        """Process search matches to extract summaries."""
        hosts: list[dict[str, Any]] = []
        port_counts: dict[int, int] = {}
        all_vulns: list[dict[str, str]] = []

        for match in matches:
            host_info: dict[str, Any] = {
                "ip": match.get("ip_str", ""),
                "port": match.get("port", 0),
                "transport": match.get("transport", "tcp"),
                "product": match.get("product", ""),
                "version": match.get("version", ""),
                "os": match.get("os", ""),
                "org": match.get("org", ""),
                "isp": match.get("isp", ""),
                "hostnames": match.get("hostnames", []),
                "domains": match.get("domains", []),
                "location": {
                    "country": match.get("location", {}).get("country_name", ""),
                    "city": match.get("location", {}).get("city", ""),
                },
            }

            # Count ports
            port = match.get("port", 0)
            port_counts[port] = port_counts.get(port, 0) + 1

            # Extract vulnerabilities
            vulns = match.get("vulns", {})
            if vulns:
                host_info["vulns"] = list(vulns.keys())
                for cve_id, cve_info in vulns.items():
                    all_vulns.append({
                        "cve": cve_id,
                        "host": match.get("ip_str", ""),
                        "port": port,
                    })

            # Extract SSL info if available
            ssl_data = match.get("ssl", {})
            if ssl_data:
                cert = ssl_data.get("cert", {})
                host_info["ssl"] = {
                    "subject": cert.get("subject", {}),
                    "issuer": cert.get("issuer", {}),
                    "expires": cert.get("expires", ""),
                }

            hosts.append(host_info)

        return {
            "hosts": hosts,
            "port_counts": {str(k): v for k, v in sorted(port_counts.items())},
            "vulns": all_vulns,
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        query = config["query"].strip()
        max_results = config.get("max_results", 10)
        search_type = config.get("search_type", "host_search")
        api_key = config["api_key"].strip()

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            if search_type == "host_lookup":
                host_data = await self._lookup_host(session, query, api_key)
                if "error" in host_data:
                    return {"query": query, "error": host_data["error"]}
                return {
                    "query": query,
                    "search_type": search_type,
                    "host_data": host_data,
                    "ports": host_data.get("ports", []),
                    "vulns_found": list(host_data.get("vulns", [])),
                    "total_results": 1,
                }

            if search_type == "dns_resolve":
                dns_data = await self._dns_resolve(session, query, api_key)
                return {
                    "query": query,
                    "search_type": search_type,
                    "resolved": dns_data,
                    "total_results": len(dns_data) if isinstance(dns_data, dict) else 0,
                }

            # Default: host_search
            raw = await self._search_hosts(session, query, api_key, max_results)

        if "error" in raw and raw["error"]:
            return {
                "query": query,
                "search_type": search_type,
                "error": raw["error"],
                "total_results": 0,
                "hosts": [],
            }

        processed = self._process_matches(raw.get("matches", []))

        return {
            "query": query,
            "search_type": search_type,
            "total_results": raw.get("total", 0),
            "returned_results": len(processed["hosts"]),
            "hosts": processed["hosts"],
            "ports_summary": processed["port_counts"],
            "vulns_found": processed["vulns"],
        }
