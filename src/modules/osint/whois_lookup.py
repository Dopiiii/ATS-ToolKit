"""WHOIS lookup module.

Query WHOIS information for domains and IP addresses.
"""

import asyncio
import socket
import re
from typing import Any, Dict, Tuple, Optional
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# WHOIS servers by TLD
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "ai": "whois.nic.ai",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "nl": "whois.domain-registry.nl",
    "ru": "whois.tcinet.ru",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
}


class WhoisLookupModule(AtsModule):
    """Perform WHOIS lookups for domains and IPs."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="whois_lookup",
            category=ModuleCategory.OSINT,
            description="Query WHOIS information for domains and IPs",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Domain or IP address to lookup",
                    required=True,
                ),
                Parameter(
                    name="follow_referral",
                    type=ParameterType.BOOLEAN,
                    description="Follow referral WHOIS servers",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="raw", type="string", description="Raw WHOIS response"),
                OutputField(name="parsed", type="dict", description="Parsed WHOIS data"),
                OutputField(name="registrar", type="string", description="Domain registrar"),
                OutputField(name="dates", type="dict", description="Important dates"),
            ],
            tags=["whois", "domain", "ip", "registration", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target is required"
        return True, ""

    def _get_whois_server(self, domain: str) -> str:
        """Get WHOIS server for domain TLD."""
        tld = domain.split(".")[-1].lower()
        return WHOIS_SERVERS.get(tld, "whois.iana.org")

    async def _query_whois(
        self,
        target: str,
        server: str,
        port: int = 43
    ) -> str:
        """Query a WHOIS server."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, port),
                timeout=10
            )

            query = f"{target}\r\n"
            writer.write(query.encode())
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(65535),
                timeout=10
            )

            writer.close()
            await writer.wait_closed()

            return response.decode('utf-8', errors='ignore')

        except asyncio.TimeoutError:
            return f"Error: Timeout connecting to {server}"
        except Exception as e:
            return f"Error: {str(e)}"

    def _parse_whois(self, raw: str) -> Dict[str, Any]:
        """Parse WHOIS response into structured data."""
        parsed = {
            "registrar": None,
            "registrant": {},
            "admin": {},
            "tech": {},
            "nameservers": [],
            "status": [],
            "dates": {},
        }

        # Common field patterns
        patterns = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Registrar Name:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"Registration Date:\s*(.+)",
            ],
            "expiration_date": [
                r"Registry Expiry Date:\s*(.+)",
                r"Expiration Date:\s*(.+)",
                r"Expiry Date:\s*(.+)",
                r"Expires:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Updated:\s*(.+)",
                r"Modified:\s*(.+)",
            ],
            "nameserver": [
                r"Name Server:\s*(.+)",
                r"Nameserver:\s*(.+)",
                r"nserver:\s*(.+)",
            ],
            "status": [
                r"Domain Status:\s*(.+)",
                r"Status:\s*(.+)",
            ],
            "registrant_name": [
                r"Registrant Name:\s*(.+)",
                r"Registrant:\s*(.+)",
            ],
            "registrant_org": [
                r"Registrant Organization:\s*(.+)",
                r"Registrant Organisation:\s*(.+)",
            ],
            "registrant_email": [
                r"Registrant Email:\s*(.+)",
            ],
            "registrant_country": [
                r"Registrant Country:\s*(.+)",
            ],
        }

        for line in raw.split('\n'):
            line = line.strip()

            # Registrar
            if not parsed["registrar"]:
                for pattern in patterns["registrar"]:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        parsed["registrar"] = match.group(1).strip()
                        break

            # Dates
            for date_type in ["creation_date", "expiration_date", "updated_date"]:
                if date_type not in parsed["dates"]:
                    for pattern in patterns[date_type]:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            parsed["dates"][date_type] = match.group(1).strip()
                            break

            # Nameservers
            for pattern in patterns["nameserver"]:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    ns = match.group(1).strip().lower()
                    if ns and ns not in parsed["nameservers"]:
                        parsed["nameservers"].append(ns)
                    break

            # Status
            for pattern in patterns["status"]:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    status = match.group(1).strip()
                    if status and status not in parsed["status"]:
                        parsed["status"].append(status)
                    break

            # Registrant info
            for field in ["registrant_name", "registrant_org", "registrant_email", "registrant_country"]:
                key = field.replace("registrant_", "")
                if key not in parsed["registrant"]:
                    for pattern in patterns[field]:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            parsed["registrant"][key] = match.group(1).strip()
                            break

        return parsed

    def _find_referral_server(self, raw: str) -> Optional[str]:
        """Find referral WHOIS server in response."""
        patterns = [
            r"Registrar WHOIS Server:\s*(.+)",
            r"Whois Server:\s*(.+)",
            r"ReferralServer:\s*whois://(.+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                server = match.group(1).strip()
                # Clean up server URL
                server = server.replace("whois://", "").split("/")[0]
                return server

        return None

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip().lower()
        follow_referral = config.get("follow_referral", True)

        self.logger.info("starting_whois_lookup", target=target)

        # Determine if IP or domain
        is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)

        if is_ip:
            # Use ARIN for IP lookups
            server = "whois.arin.net"
        else:
            server = self._get_whois_server(target)

        # Initial query
        raw_response = await self._query_whois(target, server)

        # Follow referral if enabled
        if follow_referral and not is_ip:
            referral_server = self._find_referral_server(raw_response)
            if referral_server and referral_server != server:
                self.logger.debug("following_referral", server=referral_server)
                referral_response = await self._query_whois(target, referral_server)
                if not referral_response.startswith("Error"):
                    raw_response = referral_response

        # Parse response
        parsed = self._parse_whois(raw_response)

        # Calculate domain age and expiry
        analysis = {}
        if parsed["dates"].get("creation_date"):
            try:
                # Try common date formats
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"]:
                    try:
                        created = datetime.strptime(
                            parsed["dates"]["creation_date"][:19],
                            fmt
                        )
                        analysis["domain_age_days"] = (datetime.now() - created).days
                        break
                    except:
                        continue
            except:
                pass

        self.logger.info(
            "whois_lookup_complete",
            target=target,
            registrar=parsed.get("registrar")
        )

        return {
            "target": target,
            "whois_server": server,
            "raw": raw_response,
            "parsed": parsed,
            "registrar": parsed.get("registrar"),
            "dates": parsed.get("dates", {}),
            "nameservers": parsed.get("nameservers", []),
            "status": parsed.get("status", []),
            "registrant": parsed.get("registrant", {}),
            "analysis": analysis,
        }
