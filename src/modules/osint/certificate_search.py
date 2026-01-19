"""Certificate transparency search module.

Search certificate transparency logs for domain certificates.
"""

import asyncio
import aiohttp
from typing import Any, Dict, List, Tuple
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class CertificateSearchModule(AtsModule):
    """Search certificate transparency logs."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="certificate_search",
            category=ModuleCategory.OSINT,
            description="Search CT logs for domain certificates",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain",
                    type=ParameterType.DOMAIN,
                    description="Domain to search",
                    required=True,
                ),
                Parameter(
                    name="include_subdomains",
                    type=ParameterType.BOOLEAN,
                    description="Include subdomain certificates",
                    required=False,
                    default=True,
                ),
                Parameter(
                    name="exclude_expired",
                    type=ParameterType.BOOLEAN,
                    description="Exclude expired certificates",
                    required=False,
                    default=False,
                ),
            ],
            outputs=[
                OutputField(name="certificates", type="list", description="Found certificates"),
                OutputField(name="subdomains", type="list", description="Discovered subdomains"),
            ],
            tags=["certificate", "ct", "ssl", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        if not domain or "." not in domain:
            return False, "Invalid domain format"
        return True, ""

    async def _search_crtsh(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        include_subdomains: bool
    ) -> List[Dict[str, Any]]:
        """Search crt.sh for certificates."""
        certificates = []

        query = f"%.{domain}" if include_subdomains else domain

        try:
            url = f"https://crt.sh/?q={query}&output=json"
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    for entry in data:
                        cert = {
                            "id": entry.get("id"),
                            "logged_at": entry.get("entry_timestamp"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "common_name": entry.get("common_name"),
                            "name_value": entry.get("name_value"),
                            "issuer_name": entry.get("issuer_name"),
                            "issuer_ca_id": entry.get("issuer_ca_id"),
                            "serial_number": entry.get("serial_number"),
                        }

                        # Check if expired
                        if cert["not_after"]:
                            try:
                                expiry = datetime.fromisoformat(
                                    cert["not_after"].replace("Z", "+00:00")
                                )
                                cert["expired"] = expiry < datetime.now(expiry.tzinfo)
                            except:
                                cert["expired"] = None

                        certificates.append(cert)

        except Exception as e:
            self.logger.warning("crtsh_search_failed", error=str(e))

        return certificates

    async def _search_certspotter(
        self,
        session: aiohttp.ClientSession,
        domain: str
    ) -> List[Dict[str, Any]]:
        """Search Cert Spotter for certificates."""
        certificates = []

        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    for entry in data:
                        cert = {
                            "id": entry.get("id"),
                            "tbs_sha256": entry.get("tbs_sha256"),
                            "dns_names": entry.get("dns_names", []),
                            "pubkey_sha256": entry.get("pubkey_sha256"),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "source": "certspotter",
                        }
                        certificates.append(cert)

        except Exception as e:
            self.logger.warning("certspotter_search_failed", error=str(e))

        return certificates

    def _extract_subdomains(
        self,
        certificates: List[Dict],
        domain: str
    ) -> List[str]:
        """Extract unique subdomains from certificates."""
        subdomains = set()

        for cert in certificates:
            # From name_value (crt.sh)
            name_value = cert.get("name_value", "")
            if name_value:
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)

            # From common_name
            cn = cert.get("common_name", "")
            if cn:
                cn = cn.lstrip("*.")
                if cn.endswith(domain) and cn != domain:
                    subdomains.add(cn)

            # From dns_names (certspotter)
            for dns_name in cert.get("dns_names", []):
                dns_name = dns_name.lstrip("*.")
                if dns_name.endswith(domain) and dns_name != domain:
                    subdomains.add(dns_name)

        return sorted(list(subdomains))

    def _analyze_certificates(
        self,
        certificates: List[Dict]
    ) -> Dict[str, Any]:
        """Analyze certificate data."""
        analysis = {
            "total": len(certificates),
            "expired": 0,
            "valid": 0,
            "issuers": {},
            "wildcard_count": 0,
            "unique_domains": set(),
        }

        for cert in certificates:
            # Count expired
            if cert.get("expired"):
                analysis["expired"] += 1
            elif cert.get("expired") is False:
                analysis["valid"] += 1

            # Count issuers
            issuer = cert.get("issuer_name", "Unknown")
            if len(issuer) > 50:
                issuer = issuer[:50] + "..."
            analysis["issuers"][issuer] = analysis["issuers"].get(issuer, 0) + 1

            # Count wildcards
            cn = cert.get("common_name", "")
            if cn.startswith("*."):
                analysis["wildcard_count"] += 1

            # Collect unique domains
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name:
                    analysis["unique_domains"].add(name)

        analysis["unique_domains"] = len(analysis["unique_domains"])

        return analysis

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower().strip()
        include_subdomains = config.get("include_subdomains", True)
        exclude_expired = config.get("exclude_expired", False)

        self.logger.info(
            "starting_certificate_search",
            domain=domain,
            include_subdomains=include_subdomains
        )

        results = {
            "domain": domain,
            "certificates": [],
            "subdomains": [],
            "analysis": {},
        }

        async with aiohttp.ClientSession() as session:
            # Search crt.sh
            crtsh_certs = await self._search_crtsh(session, domain, include_subdomains)
            results["certificates"].extend(crtsh_certs)

        # Filter expired if requested
        if exclude_expired:
            results["certificates"] = [
                c for c in results["certificates"]
                if not c.get("expired")
            ]

        # Remove duplicates (by id)
        seen_ids = set()
        unique_certs = []
        for cert in results["certificates"]:
            cert_id = cert.get("id")
            if cert_id and cert_id not in seen_ids:
                seen_ids.add(cert_id)
                unique_certs.append(cert)
        results["certificates"] = unique_certs

        # Extract subdomains
        results["subdomains"] = self._extract_subdomains(results["certificates"], domain)

        # Analyze
        results["analysis"] = self._analyze_certificates(results["certificates"])

        self.logger.info(
            "certificate_search_complete",
            domain=domain,
            certificates=len(results["certificates"]),
            subdomains=len(results["subdomains"])
        )

        return results
