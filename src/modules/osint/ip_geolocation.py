"""IP Geolocation module.

Get geolocation and network information for IP addresses.
"""

import asyncio
import socket
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


class IpGeolocationModule(AtsModule):
    """Get geolocation and ASN information for IP addresses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ip_geolocation",
            category=ModuleCategory.OSINT,
            description="Get geolocation, ASN, and network info for IPs",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="IP address or domain to lookup",
                    required=True,
                ),
                Parameter(
                    name="detailed",
                    type=ParameterType.BOOLEAN,
                    description="Get detailed information",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="ip", type="string", description="IP address"),
                OutputField(name="location", type="dict", description="Geolocation data"),
                OutputField(name="network", type="dict", description="Network/ASN info"),
            ],
            tags=["ip", "geolocation", "asn", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target is required"
        return True, ""

    async def _resolve_to_ip(self, target: str) -> str:
        """Resolve domain to IP if needed."""
        # Check if already an IP
        try:
            socket.inet_aton(target)
            return target
        except:
            pass

        # Try to resolve domain
        try:
            ip = socket.gethostbyname(target)
            return ip
        except Exception as e:
            raise ValueError(f"Could not resolve {target}: {e}")

    async def _query_ipapi(
        self,
        session: aiohttp.ClientSession,
        ip: str
    ) -> Dict[str, Any]:
        """Query ip-api.com for geolocation."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=66846719"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            self.logger.warning("ipapi_query_failed", error=str(e))
        return {}

    async def _query_ipinfo(
        self,
        session: aiohttp.ClientSession,
        ip: str
    ) -> Dict[str, Any]:
        """Query ipinfo.io for additional info."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            self.logger.warning("ipinfo_query_failed", error=str(e))
        return {}

    async def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS for IP."""
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except:
            return None

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        detailed = config.get("detailed", True)

        self.logger.info("starting_geolocation", target=target)

        # Resolve to IP
        ip = await self._resolve_to_ip(target)

        results = {
            "original_target": target,
            "ip": ip,
            "location": {},
            "network": {},
            "reverse_dns": None,
        }

        async with aiohttp.ClientSession() as session:
            # Query multiple sources
            ipapi_data = await self._query_ipapi(session, ip)

            if ipapi_data.get("status") == "success":
                results["location"] = {
                    "country": ipapi_data.get("country"),
                    "country_code": ipapi_data.get("countryCode"),
                    "region": ipapi_data.get("regionName"),
                    "region_code": ipapi_data.get("region"),
                    "city": ipapi_data.get("city"),
                    "zip": ipapi_data.get("zip"),
                    "latitude": ipapi_data.get("lat"),
                    "longitude": ipapi_data.get("lon"),
                    "timezone": ipapi_data.get("timezone"),
                }

                results["network"] = {
                    "isp": ipapi_data.get("isp"),
                    "org": ipapi_data.get("org"),
                    "as": ipapi_data.get("as"),
                    "asname": ipapi_data.get("asname"),
                    "mobile": ipapi_data.get("mobile"),
                    "proxy": ipapi_data.get("proxy"),
                    "hosting": ipapi_data.get("hosting"),
                }

            if detailed:
                # Get additional info from ipinfo
                ipinfo_data = await self._query_ipinfo(session, ip)
                if ipinfo_data:
                    if not results["location"].get("city"):
                        results["location"]["city"] = ipinfo_data.get("city")
                    results["network"]["hostname"] = ipinfo_data.get("hostname")

                    # Parse org to get ASN
                    org = ipinfo_data.get("org", "")
                    if org and not results["network"].get("as"):
                        parts = org.split(" ", 1)
                        if len(parts) == 2:
                            results["network"]["as"] = parts[0]
                            results["network"]["org"] = parts[1]

                # Reverse DNS
                results["reverse_dns"] = await self._get_reverse_dns(ip)

        # Privacy analysis
        results["privacy"] = {
            "is_proxy": results["network"].get("proxy", False),
            "is_hosting": results["network"].get("hosting", False),
            "is_mobile": results["network"].get("mobile", False),
        }

        self.logger.info(
            "geolocation_complete",
            ip=ip,
            country=results["location"].get("country")
        )

        return results
