"""WHOIS information lookup for domains and IP addresses.

Connects to WHOIS servers directly via TCP port 43 to retrieve registrar
information, registration dates, nameservers, and contact details.
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

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "me": "whois.nic.me",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "default": "whois.iana.org",
}

IP_WHOIS_SERVERS = {
    "arin": "whois.arin.net",
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}


class WhoisLookupModule(AtsModule):
    """Perform WHOIS lookups for domains and IP addresses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="whois_lookup",
            category=ModuleCategory.OSINT,
            description="WHOIS lookup for domains and IPs: registrar, dates, nameservers, contacts",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target", type=ParameterType.STRING,
                    description="Domain name or IP address to look up", required=True,
                ),
                Parameter(
                    name="query_type", type=ParameterType.CHOICE,
                    description="Type of WHOIS query",
                    choices=["domain", "ip", "auto"], default="auto",
                ),
                Parameter(
                    name="follow_referral", type=ParameterType.BOOLEAN,
                    description="Follow referral WHOIS servers for more detail",
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="parsed_data", type="dict", description="Parsed WHOIS fields"),
                OutputField(name="raw_response", type="string", description="Raw WHOIS response text"),
                OutputField(name="whois_server", type="string", description="WHOIS server queried"),
            ],
            tags=["osint", "whois", "domain", "ip", "registrar"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target domain or IP is required"
        if len(target) > 255:
            return False, "Target is too long"
        return True, ""

    def _detect_type(self, target: str) -> str:
        """Auto-detect whether target is a domain or IP."""
        ip_v4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
        if ip_v4:
            return "ip"
        ip_v6 = re.match(r'^[0-9a-fA-F:]+$', target) and ":" in target
        if ip_v6:
            return "ip"
        return "domain"

    def _get_whois_server(self, target: str, query_type: str) -> str:
        """Determine the appropriate WHOIS server."""
        if query_type == "ip":
            return IP_WHOIS_SERVERS["arin"]
        tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
        return WHOIS_SERVERS.get(tld, WHOIS_SERVERS["default"])

    async def _query_whois(self, server: str, query: str, timeout: int = 10) -> str:
        """Connect to a WHOIS server and retrieve the response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 43),
                timeout=timeout,
            )
            writer.write(f"{query}\r\n".encode("utf-8"))
            await writer.drain()

            response_data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                response_data += chunk

            writer.close()
            await writer.wait_closed()
            return response_data.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
            return f"Error querying {server}: {str(exc)}"

    def _parse_whois_response(self, raw: str, query_type: str) -> dict[str, Any]:
        """Parse raw WHOIS response into structured data."""
        parsed: dict[str, Any] = {}

        field_mappings = {
            "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
            "creation_date": [
                r"Creation Date:\s*(.+)", r"created:\s*(.+)",
                r"Registration Date:\s*(.+)", r"Created:\s*(.+)",
            ],
            "expiration_date": [
                r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)",
                r"paid-till:\s*(.+)", r"Expiration Date:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)", r"Last Modified:\s*(.+)",
                r"last-modified:\s*(.+)",
            ],
            "registrant_name": [
                r"Registrant Name:\s*(.+)", r"registrant:\s*(.+)",
            ],
            "registrant_org": [
                r"Registrant Organization:\s*(.+)", r"org:\s*(.+)",
            ],
            "registrant_country": [
                r"Registrant Country:\s*(.+)", r"country:\s*(.+)",
            ],
            "admin_email": [
                r"Admin Email:\s*(.+)", r"admin-c:\s*(.+)",
            ],
            "tech_email": [
                r"Tech Email:\s*(.+)", r"tech-c:\s*(.+)",
            ],
            "dnssec": [r"DNSSEC:\s*(.+)"],
        }

        for field, patterns in field_mappings.items():
            for pattern in patterns:
                match = re.search(pattern, raw, re.IGNORECASE)
                if match:
                    parsed[field] = match.group(1).strip()
                    break

        # Extract nameservers
        ns_matches = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)
        if not ns_matches:
            ns_matches = re.findall(r"nserver:\s*(.+)", raw, re.IGNORECASE)
        parsed["nameservers"] = [ns.strip().lower() for ns in ns_matches]

        # Extract status
        status_matches = re.findall(r"Status:\s*(.+)", raw, re.IGNORECASE)
        if not status_matches:
            status_matches = re.findall(r"Domain Status:\s*(.+)", raw, re.IGNORECASE)
        parsed["status"] = [s.strip() for s in status_matches]

        # Extract referral server
        referral_match = re.search(r"Referral URL:\s*(.+)", raw, re.IGNORECASE)
        if not referral_match:
            referral_match = re.search(r"refer:\s*(.+)", raw, re.IGNORECASE)
        if referral_match:
            parsed["referral_server"] = referral_match.group(1).strip()

        # IP-specific fields
        if query_type == "ip":
            for field, pattern in [
                ("netname", r"NetName:\s*(.+)"),
                ("netrange", r"NetRange:\s*(.+)"),
                ("cidr", r"CIDR:\s*(.+)"),
                ("org_name", r"OrgName:\s*(.+)"),
                ("org_id", r"OrgId:\s*(.+)"),
            ]:
                match = re.search(pattern, raw, re.IGNORECASE)
                if match:
                    parsed[field] = match.group(1).strip()

        return parsed

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"].strip().lower()
        query_type = config.get("query_type", "auto")
        follow_referral = config.get("follow_referral", True)

        if query_type == "auto":
            query_type = self._detect_type(target)

        server = self._get_whois_server(target, query_type)
        raw_response = await self._query_whois(server, target)
        parsed_data = self._parse_whois_response(raw_response, query_type)

        # Follow referral if available
        referral = parsed_data.get("referral_server", "")
        if follow_referral and referral:
            # Clean up referral URL to get hostname
            referral_host = referral.replace("http://", "").replace("https://", "").split("/")[0]
            if referral_host and referral_host != server:
                referral_raw = await self._query_whois(referral_host, target)
                referral_parsed = self._parse_whois_response(referral_raw, query_type)
                # Merge referral data (more detailed) over initial data
                for key, value in referral_parsed.items():
                    if value and (key not in parsed_data or not parsed_data[key]):
                        parsed_data[key] = value
                raw_response += f"\n\n--- Referral from {referral_host} ---\n{referral_raw}"
                server = f"{server} -> {referral_host}"

        return {
            "target": target,
            "query_type": query_type,
            "whois_server": server,
            "parsed_data": parsed_data,
            "raw_response": raw_response[:5000],  # Truncate long responses
        }
