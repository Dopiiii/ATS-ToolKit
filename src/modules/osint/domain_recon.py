"""Comprehensive domain reconnaissance module.

Performs DNS resolution, SSL certificate inspection, HTTP header analysis,
and security header checks for a target domain.
"""

import asyncio
import ssl
import re
from datetime import datetime
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

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DomainReconModule(AtsModule):
    """Perform comprehensive domain reconnaissance."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="domain_recon",
            category=ModuleCategory.OSINT,
            description="Comprehensive domain recon: DNS, SSL, HTTP headers, security analysis",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain for reconnaissance", required=True,
                ),
                Parameter(
                    name="depth", type=ParameterType.CHOICE,
                    description="Depth of reconnaissance",
                    choices=["quick", "standard", "deep"], default="standard",
                ),
                Parameter(
                    name="follow_redirects", type=ParameterType.BOOLEAN,
                    description="Follow HTTP redirects during analysis", default=True,
                ),
            ],
            outputs=[
                OutputField(name="dns", type="dict", description="DNS resolution results"),
                OutputField(name="ssl_info", type="dict", description="SSL certificate information"),
                OutputField(name="headers", type="dict", description="HTTP response headers"),
                OutputField(name="ips", type="list", description="Resolved IP addresses"),
                OutputField(name="security_analysis", type="dict", description="Security header analysis"),
            ],
            tags=["osint", "domain", "reconnaissance", "dns", "ssl"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        domain = config.get("domain", "").strip()
        if not domain:
            return False, "Domain is required"
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', domain):
            return False, "Invalid domain format"
        return True, ""

    async def _resolve_dns(
        self, session: aiohttp.ClientSession, domain: str, record_types: list[str],
    ) -> dict[str, Any]:
        """Resolve DNS records via Google DNS-over-HTTPS."""
        dns_results: dict[str, Any] = {}
        for rtype in record_types:
            try:
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        answers = data.get("Answer", [])
                        dns_results[rtype] = [a.get("data", "") for a in answers]
                    else:
                        dns_results[rtype] = []
            except (aiohttp.ClientError, asyncio.TimeoutError):
                dns_results[rtype] = []
        return dns_results

    async def _get_ssl_info(self, domain: str) -> dict[str, Any]:
        """Retrieve SSL certificate details for the domain."""
        ssl_info: dict[str, Any] = {"valid": False}
        try:
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=ctx),
                timeout=10,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    ssl_info["valid"] = True
                    ssl_info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    ssl_info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    ssl_info["serial_number"] = cert.get("serialNumber", "")
                    ssl_info["not_before"] = cert.get("notBefore", "")
                    ssl_info["not_after"] = cert.get("notAfter", "")
                    ssl_info["version"] = cert.get("version", 0)

                    san_entries = cert.get("subjectAltName", ())
                    ssl_info["san"] = [entry[1] for entry in san_entries]

                    # Check expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            ssl_info["days_until_expiry"] = (expiry - datetime.utcnow()).days
                            ssl_info["expired"] = ssl_info["days_until_expiry"] < 0
                        except ValueError:
                            ssl_info["days_until_expiry"] = None

                    ssl_info["protocol"] = ssl_obj.version()
                    ssl_info["cipher"] = ssl_obj.cipher()
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            ssl_info["error"] = str(exc)
        return ssl_info

    async def _get_http_info(
        self, session: aiohttp.ClientSession, domain: str, follow_redirects: bool,
    ) -> dict[str, Any]:
        """Fetch HTTP headers and analyze security posture."""
        http_info: dict[str, Any] = {"headers": {}, "security": {}}
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=follow_redirects,
                ) as resp:
                    headers = dict(resp.headers)
                    http_info["status_code"] = resp.status
                    http_info["url"] = str(resp.url)
                    http_info["headers"] = headers
                    http_info["server"] = headers.get("Server", "unknown")

                    # Security header analysis
                    present: list[str] = []
                    missing: list[str] = []
                    for hdr in SECURITY_HEADERS:
                        if hdr.lower() in {k.lower() for k in headers}:
                            present.append(hdr)
                        else:
                            missing.append(hdr)
                    score = int((len(present) / len(SECURITY_HEADERS)) * 100)
                    http_info["security"] = {
                        "present": present,
                        "missing": missing,
                        "score": score,
                        "grade": "A" if score >= 80 else "B" if score >= 60
                                 else "C" if score >= 40 else "D" if score >= 20 else "F",
                    }
                    break  # Success on first scheme
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        return http_info

    async def _reverse_ip_lookup(
        self, session: aiohttp.ClientSession, ip: str,
    ) -> dict[str, Any]:
        """Perform reverse IP lookup for additional context."""
        result: dict[str, Any] = {"ip": ip}
        try:
            url = f"https://dns.google/resolve?name={ip}&type=PTR"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    result["ptr"] = [a.get("data", "") for a in answers]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            result["ptr"] = []
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        depth = config.get("depth", "standard")
        follow_redirects = config.get("follow_redirects", True)

        record_types = ["A", "AAAA", "MX", "NS"]
        if depth in ("standard", "deep"):
            record_types.extend(["TXT", "CNAME", "SOA"])

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            dns_task = self._resolve_dns(session, domain, record_types)
            http_task = self._get_http_info(session, domain, follow_redirects)
            ssl_task = self._get_ssl_info(domain)

            dns_results, http_info, ssl_info = await asyncio.gather(
                dns_task, http_task, ssl_task,
            )

            # Extract IPs
            ips = dns_results.get("A", []) + dns_results.get("AAAA", [])

            # Deep mode: reverse IP lookup
            reverse_lookups: list[dict[str, Any]] = []
            if depth == "deep" and ips:
                rev_tasks = [self._reverse_ip_lookup(session, ip) for ip in ips[:5]]
                reverse_lookups = await asyncio.gather(*rev_tasks)

        return {
            "domain": domain,
            "dns": dns_results,
            "ssl_info": ssl_info,
            "headers": http_info.get("headers", {}),
            "ips": ips,
            "security_analysis": http_info.get("security", {}),
            "server": http_info.get("server", "unknown"),
            "http_status": http_info.get("status_code"),
            "reverse_lookups": reverse_lookups if depth == "deep" else None,
        }
