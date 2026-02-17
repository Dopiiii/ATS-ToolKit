"""IP geolocation and ASN information lookup.

Queries the ip-api.com free API to retrieve geographic location, ISP,
organization, and autonomous system information for an IP address.
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


class IpGeolocationModule(AtsModule):
    """Look up IP geolocation, ISP, and ASN information."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ip_geolocation",
            category=ModuleCategory.OSINT,
            description="IP geolocation and ASN lookup via ip-api.com",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="ip", type=ParameterType.IP,
                    description="IP address to geolocate", required=True,
                ),
                Parameter(
                    name="include_asn", type=ParameterType.BOOLEAN,
                    description="Include ASN and ISP information", default=True,
                ),
                Parameter(
                    name="include_reverse_dns", type=ParameterType.BOOLEAN,
                    description="Include reverse DNS lookup", default=False,
                ),
            ],
            outputs=[
                OutputField(name="country", type="string", description="Country name"),
                OutputField(name="city", type="string", description="City name"),
                OutputField(name="isp", type="string", description="Internet service provider"),
                OutputField(name="org", type="string", description="Organization"),
                OutputField(name="as_number", type="string", description="Autonomous system number"),
                OutputField(name="coordinates", type="dict", description="Latitude and longitude"),
            ],
            tags=["osint", "ip", "geolocation", "asn"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        ip = config.get("ip", "").strip()
        if not ip:
            return False, "IP address is required"
        # IPv4 validation
        ipv4 = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip)
        if ipv4:
            octets = [int(ipv4.group(i)) for i in range(1, 5)]
            if all(0 <= o <= 255 for o in octets):
                return True, ""
            return False, "Invalid IPv4 address: octets must be 0-255"
        # IPv6 basic validation
        if re.match(r'^[0-9a-fA-F:]+$', ip) and ":" in ip:
            return True, ""
        return False, "Invalid IP address format"

    async def _query_ip_api(
        self, session: aiohttp.ClientSession, ip: str, include_asn: bool,
    ) -> dict[str, Any]:
        """Query ip-api.com for geolocation data."""
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,currency"
        if include_asn:
            fields += ",isp,org,as,asname,mobile,proxy,hosting"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"status": "fail", "message": f"HTTP {resp.status}"}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"status": "fail", "message": str(exc)}

    async def _query_reverse_dns(
        self, session: aiohttp.ClientSession, ip: str,
    ) -> dict[str, Any]:
        """Perform reverse DNS lookup via DNS-over-HTTPS."""
        result: dict[str, Any] = {"ip": ip, "hostnames": []}
        # Convert IP to reverse form for PTR lookup
        if ":" not in ip:  # IPv4
            octets = ip.split(".")
            ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"
        else:  # IPv6
            result["note"] = "IPv6 reverse DNS not implemented"
            return result

        try:
            url = f"https://dns.google/resolve?name={ptr_name}&type=PTR"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    result["hostnames"] = [a.get("data", "").rstrip(".") for a in answers]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            result["error"] = "Reverse DNS lookup failed"
        return result

    async def _check_threat_indicators(self, data: dict[str, Any]) -> dict[str, Any]:
        """Assess threat indicators from ip-api response."""
        indicators: dict[str, Any] = {"risk_flags": [], "risk_level": "low"}
        risk_score = 0

        if data.get("proxy"):
            indicators["risk_flags"].append("Detected as proxy/VPN")
            risk_score += 30
        if data.get("hosting"):
            indicators["risk_flags"].append("Hosted/datacenter IP")
            risk_score += 10
        if data.get("mobile"):
            indicators["risk_flags"].append("Mobile carrier IP")

        if risk_score >= 30:
            indicators["risk_level"] = "medium"
        if risk_score >= 50:
            indicators["risk_level"] = "high"
        indicators["risk_score"] = risk_score
        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        ip = config["ip"].strip()
        include_asn = config.get("include_asn", True)
        include_reverse_dns = config.get("include_reverse_dns", False)

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Run queries concurrently
            tasks = [self._query_ip_api(session, ip, include_asn)]
            if include_reverse_dns:
                tasks.append(self._query_reverse_dns(session, ip))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        geo_data = results[0] if not isinstance(results[0], Exception) else {"status": "fail"}
        reverse_dns = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else None

        if geo_data.get("status") == "fail":
            return {
                "ip": ip,
                "error": geo_data.get("message", "Geolocation lookup failed"),
                "success": False,
            }

        # Assess threat indicators
        threat_info = await self._check_threat_indicators(geo_data)

        result: dict[str, Any] = {
            "ip": ip,
            "country": geo_data.get("country", ""),
            "country_code": geo_data.get("countryCode", ""),
            "region": geo_data.get("regionName", ""),
            "city": geo_data.get("city", ""),
            "zip_code": geo_data.get("zip", ""),
            "timezone": geo_data.get("timezone", ""),
            "coordinates": {
                "latitude": geo_data.get("lat", 0),
                "longitude": geo_data.get("lon", 0),
            },
            "threat_indicators": threat_info,
        }

        if include_asn:
            result["isp"] = geo_data.get("isp", "")
            result["org"] = geo_data.get("org", "")
            result["as_number"] = geo_data.get("as", "")
            result["as_name"] = geo_data.get("asname", "")
            result["is_proxy"] = geo_data.get("proxy", False)
            result["is_hosting"] = geo_data.get("hosting", False)
            result["is_mobile"] = geo_data.get("mobile", False)

        if reverse_dns:
            result["reverse_dns"] = reverse_dns

        return result
