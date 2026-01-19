"""Shodan search module.

Search Shodan for hosts, services, and vulnerabilities.
"""

import asyncio
import aiohttp
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class ShodanSearchModule(AtsModule):
    """Search Shodan for Internet-connected devices and services."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="shodan_search",
            category=ModuleCategory.OSINT,
            description="Search Shodan for hosts, services, and vulnerabilities",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="query",
                    type=ParameterType.STRING,
                    description="Shodan search query or IP address",
                    required=True,
                ),
                Parameter(
                    name="search_type",
                    type=ParameterType.CHOICE,
                    description="Type of search",
                    required=False,
                    default="host",
                    choices=["host", "search", "domain"],
                ),
                Parameter(
                    name="page",
                    type=ParameterType.INTEGER,
                    description="Results page (for search)",
                    required=False,
                    default=1,
                    min_value=1,
                    max_value=10,
                ),
            ],
            outputs=[
                OutputField(name="results", type="list", description="Search results"),
                OutputField(name="total", type="integer", description="Total results"),
            ],
            requires_api_key="shodan",
            tags=["shodan", "iot", "services", "vulnerabilities", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        query = config.get("query", "").strip()
        if not query:
            return False, "Query is required"
        return True, ""

    async def _host_lookup(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        api_key: str
    ) -> Dict[str, Any]:
        """Lookup a specific IP in Shodan."""
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return {"error": "Host not found in Shodan"}
                else:
                    error = await response.text()
                    return {"error": f"Shodan API error: {error}"}
        except Exception as e:
            return {"error": str(e)}

    async def _search(
        self,
        session: aiohttp.ClientSession,
        query: str,
        api_key: str,
        page: int = 1
    ) -> Dict[str, Any]:
        """Search Shodan with a query."""
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&page={page}"

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error = await response.text()
                    return {"error": f"Shodan API error: {error}"}
        except Exception as e:
            return {"error": str(e)}

    async def _domain_lookup(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        api_key: str
    ) -> Dict[str, Any]:
        """Get information about a domain from Shodan."""
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error = await response.text()
                    return {"error": f"Shodan API error: {error}"}
        except Exception as e:
            return {"error": str(e)}

    def _parse_host_data(self, data: Dict) -> Dict[str, Any]:
        """Parse and structure host data."""
        if "error" in data:
            return data

        result = {
            "ip": data.get("ip_str"),
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "last_update": data.get("last_update"),
            "services": [],
        }

        # Parse services/banners
        for service in data.get("data", []):
            svc = {
                "port": service.get("port"),
                "transport": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
                "module": service.get("_shodan", {}).get("module"),
            }

            # Add SSL info if present
            if "ssl" in service:
                ssl_data = service["ssl"]
                svc["ssl"] = {
                    "cert_issued_to": ssl_data.get("cert", {}).get("subject", {}).get("CN"),
                    "cert_issuer": ssl_data.get("cert", {}).get("issuer", {}).get("CN"),
                    "cipher": ssl_data.get("cipher", {}).get("name"),
                }

            # Add HTTP info if present
            if "http" in service:
                http_data = service["http"]
                svc["http"] = {
                    "title": http_data.get("title"),
                    "server": http_data.get("server"),
                    "status": http_data.get("status"),
                }

            result["services"].append(svc)

        return result

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        query = config["query"].strip()
        search_type = config.get("search_type", "host")
        page = config.get("page", 1)

        api_key = self.get_api_key()
        if not api_key:
            return {"error": "Shodan API key not configured"}

        self.logger.info("starting_shodan_search", query=query, type=search_type)

        results = {
            "query": query,
            "search_type": search_type,
            "results": [],
            "total": 0,
        }

        async with aiohttp.ClientSession() as session:
            if search_type == "host":
                # Direct IP lookup
                data = await self._host_lookup(session, query, api_key)
                if "error" not in data:
                    results["results"] = [self._parse_host_data(data)]
                    results["total"] = 1
                else:
                    results["error"] = data["error"]

            elif search_type == "search":
                # Search query
                data = await self._search(session, query, api_key, page)
                if "error" not in data:
                    results["total"] = data.get("total", 0)
                    for match in data.get("matches", []):
                        results["results"].append({
                            "ip": match.get("ip_str"),
                            "port": match.get("port"),
                            "org": match.get("org"),
                            "hostnames": match.get("hostnames", []),
                            "product": match.get("product"),
                            "location": {
                                "country": match.get("location", {}).get("country_name"),
                                "city": match.get("location", {}).get("city"),
                            }
                        })
                else:
                    results["error"] = data["error"]

            elif search_type == "domain":
                # Domain lookup
                data = await self._domain_lookup(session, query, api_key)
                if "error" not in data:
                    results["domain"] = query
                    results["subdomains"] = data.get("subdomains", [])
                    results["total"] = len(results["subdomains"])

                    # Process DNS records
                    results["dns"] = {
                        "A": [],
                        "AAAA": [],
                        "CNAME": [],
                        "MX": [],
                        "NS": [],
                        "TXT": [],
                    }
                    for record in data.get("data", []):
                        rtype = record.get("type")
                        if rtype in results["dns"]:
                            results["dns"][rtype].append({
                                "subdomain": record.get("subdomain"),
                                "value": record.get("value"),
                            })
                else:
                    results["error"] = data["error"]

        self.logger.info(
            "shodan_search_complete",
            query=query,
            results=results.get("total", 0)
        )

        return results
