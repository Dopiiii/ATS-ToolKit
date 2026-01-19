"""Domain reconnaissance module.

Comprehensive domain information gathering including DNS, WHOIS, and more.
"""

import asyncio
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

import dns.resolver
import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class DomainReconModule(AtsModule):
    """Comprehensive domain reconnaissance."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="domain_recon",
            category=ModuleCategory.OSINT,
            description="Comprehensive domain reconnaissance (DNS, SSL, headers)",
            version="1.0.0",
            parameters=[
                Parameter(name="domain", type=ParameterType.DOMAIN, description="Target domain", required=True),
                Parameter(name="depth", type=ParameterType.CHOICE, description="Reconnaissance depth", required=False, default="standard", choices=["quick", "standard", "deep"]),
            ],
            outputs=[
                OutputField(name="dns", type="dict", description="DNS records"),
                OutputField(name="ssl", type="dict", description="SSL certificate info"),
                OutputField(name="headers", type="dict", description="HTTP headers"),
                OutputField(name="ips", type="list", description="Resolved IP addresses"),
            ],
            tags=["domain", "dns", "ssl", "recon", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        if not domain or len(domain) < 4:
            return False, "Invalid domain"
        return True, ""

    async def _resolve_dns(self, domain: str, record_types: List[str]) -> Dict[str, List]:
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except:
                results[rtype] = []
        return results

    async def _get_ssl_info(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": cert.get('notBefore'),
                        "valid_until": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', []),
                    }
        except Exception as e:
            self.logger.warning("ssl_info_failed", domain=domain, error=str(e))
            return None

    async def _get_http_headers(self, session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
        results = {"https": None, "security_headers": {}, "server": None}
        security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']

        try:
            async with session.get(f"https://{domain}", timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as response:
                headers = dict(response.headers)
                results["https"] = {"status": response.status, "headers": headers, "final_url": str(response.url)}
                results["server"] = headers.get('Server')
                for sh in security_headers:
                    if sh in headers:
                        results["security_headers"][sh] = headers[sh]
        except:
            pass
        return results

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower().strip()
        depth = config.get("depth", "standard")

        self.logger.info("starting_domain_recon", domain=domain, depth=depth)

        record_types = ["A", "AAAA", "MX"] if depth == "quick" else ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] if depth == "standard" else ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

        results = {"domain": domain, "dns": {}, "ips": [], "ssl": None, "http": {}}

        dns_results = await self._resolve_dns(domain, record_types)
        results["dns"] = dns_results
        results["ips"] = dns_results.get("A", []) + dns_results.get("AAAA", [])

        results["ssl"] = await self._get_ssl_info(domain)

        async with aiohttp.ClientSession() as session:
            results["http"] = await self._get_http_headers(session, domain)

        self.logger.info("domain_recon_complete", domain=domain, ips_found=len(results["ips"]))
        return results
