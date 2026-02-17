"""Certificate Transparency log search for OSINT investigations.

Queries Certificate Transparency (CT) logs via crt.sh and other public APIs
to discover certificates issued for a domain, revealing subdomains, issuing CAs,
certificate validity periods, and potential shadow IT or unauthorized certificates.
"""

import asyncio
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

CRT_SH_BASE = "https://crt.sh"
CERTSPOTTER_BASE = "https://api.certspotter.com/v1"


class CertificateSearchModule(AtsModule):
    """Search Certificate Transparency logs for certificates issued to domains."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="certificate_search",
            category=ModuleCategory.OSINT,
            description="Search CT logs for certificates issued to domains, discovering subdomains and CA details",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain to search CT logs for",
                    required=True,
                ),
                Parameter(
                    name="include_subdomains", type=ParameterType.BOOLEAN,
                    description="Include wildcard search for subdomains",
                    default=True, required=False,
                ),
                Parameter(
                    name="exclude_expired", type=ParameterType.BOOLEAN,
                    description="Exclude certificates that have already expired",
                    default=False, required=False,
                ),
                Parameter(
                    name="max_results", type=ParameterType.INTEGER,
                    description="Maximum number of certificate entries to return",
                    default=100, min_value=10, max_value=500, required=False,
                ),
                Parameter(
                    name="source", type=ParameterType.CHOICE,
                    description="CT log data source to query",
                    choices=["crtsh", "certspotter", "both"],
                    default="crtsh", required=False,
                ),
            ],
            outputs=[
                OutputField(name="certificates", type="list", description="Certificate entries with details"),
                OutputField(name="unique_domains", type="list", description="Unique domain names found in certificates"),
                OutputField(name="issuers", type="dict", description="Certificate Authority summary"),
                OutputField(name="timeline", type="list", description="Certificate issuance timeline"),
                OutputField(name="total_certificates", type="integer", description="Total certificates found"),
            ],
            tags=["osint", "certificates", "ct-logs", "subdomain", "tls", "ssl"],
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

    async def _query_crtsh(
        self, session: aiohttp.ClientSession, domain: str,
        include_subdomains: bool, max_results: int,
    ) -> list[dict[str, Any]]:
        """Query crt.sh for CT log entries."""
        query = f"%.{domain}" if include_subdomains else domain
        url = f"{CRT_SH_BASE}/?q={query}&output=json"

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0)"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        return data[:max_results]
                    return []
                elif resp.status == 429:
                    return [{"error": "crt.sh rate limit exceeded"}]
                else:
                    return [{"error": f"crt.sh returned HTTP {resp.status}"}]
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return [{"error": f"crt.sh query failed: {str(exc)}"}]

    async def _query_certspotter(
        self, session: aiohttp.ClientSession, domain: str,
        include_subdomains: bool,
    ) -> list[dict[str, Any]]:
        """Query Cert Spotter API for CT log entries."""
        url = f"{CERTSPOTTER_BASE}/issuances"
        params: dict[str, str] = {"domain": domain, "expand": "dns_names"}
        if include_subdomains:
            params["include_subdomains"] = "true"

        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0)"},
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 429:
                    return [{"error": "CertSpotter rate limit exceeded"}]
                else:
                    return [{"error": f"CertSpotter returned HTTP {resp.status}"}]
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return [{"error": f"CertSpotter query failed: {str(exc)}"}]

    def _parse_crtsh_entries(
        self, raw_entries: list[dict[str, Any]], exclude_expired: bool,
    ) -> list[dict[str, Any]]:
        """Parse and normalize crt.sh JSON entries."""
        certificates: list[dict[str, Any]] = []
        now = datetime.utcnow()

        for entry in raw_entries:
            if "error" in entry:
                continue

            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")

            # Check expiration
            is_expired = False
            if not_after:
                try:
                    expiry = datetime.fromisoformat(not_after.replace("T", " ").split(".")[0])
                    is_expired = expiry < now
                except (ValueError, TypeError):
                    pass

            if exclude_expired and is_expired:
                continue

            common_name = entry.get("common_name", "")
            name_value = entry.get("name_value", "")
            # name_value can contain multiple names separated by newlines
            san_names = [n.strip() for n in name_value.split("\n") if n.strip()] if name_value else []

            cert_entry = {
                "id": entry.get("id"),
                "serial_number": entry.get("serial_number", ""),
                "common_name": common_name,
                "san_names": san_names,
                "issuer_name": entry.get("issuer_name", ""),
                "issuer_ca_id": entry.get("issuer_ca_id"),
                "not_before": not_before,
                "not_after": not_after,
                "is_expired": is_expired,
                "entry_timestamp": entry.get("entry_timestamp", ""),
                "source": "crt.sh",
            }
            certificates.append(cert_entry)

        return certificates

    def _parse_certspotter_entries(
        self, raw_entries: list[dict[str, Any]], exclude_expired: bool,
    ) -> list[dict[str, Any]]:
        """Parse and normalize CertSpotter API entries."""
        certificates: list[dict[str, Any]] = []
        now = datetime.utcnow()

        for entry in raw_entries:
            if "error" in entry:
                continue

            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")

            is_expired = False
            if not_after:
                try:
                    expiry = datetime.fromisoformat(not_after.replace("T", " ").split("+")[0].split("Z")[0])
                    is_expired = expiry < now
                except (ValueError, TypeError):
                    pass

            if exclude_expired and is_expired:
                continue

            dns_names = entry.get("dns_names", [])
            common_name = dns_names[0] if dns_names else ""

            cert_entry = {
                "id": entry.get("id"),
                "serial_number": entry.get("tbs_sha256", "")[:16],
                "common_name": common_name,
                "san_names": dns_names,
                "issuer_name": entry.get("issuer", {}).get("name", "") if isinstance(entry.get("issuer"), dict) else "",
                "not_before": not_before,
                "not_after": not_after,
                "is_expired": is_expired,
                "source": "certspotter",
            }
            certificates.append(cert_entry)

        return certificates

    def _extract_unique_domains(self, certificates: list[dict[str, Any]]) -> list[str]:
        """Extract and deduplicate all domain names from certificates."""
        domains: set[str] = set()
        for cert in certificates:
            cn = cert.get("common_name", "")
            if cn:
                domains.add(cn.lower().lstrip("*."))
            for name in cert.get("san_names", []):
                if name:
                    domains.add(name.lower().lstrip("*."))
        return sorted(domains)

    def _summarize_issuers(self, certificates: list[dict[str, Any]]) -> dict[str, Any]:
        """Summarize certificate issuers (CAs)."""
        issuer_counts: dict[str, int] = {}
        for cert in certificates:
            issuer = cert.get("issuer_name", "Unknown")
            # Simplify issuer name
            if "Let's Encrypt" in issuer:
                issuer = "Let's Encrypt"
            elif "DigiCert" in issuer:
                issuer = "DigiCert"
            elif "Comodo" in issuer or "Sectigo" in issuer:
                issuer = "Sectigo (Comodo)"
            elif "GlobalSign" in issuer:
                issuer = "GlobalSign"
            elif "GeoTrust" in issuer:
                issuer = "GeoTrust"
            elif "Google" in issuer:
                issuer = "Google Trust Services"
            elif "Amazon" in issuer:
                issuer = "Amazon Trust Services"
            elif "Cloudflare" in issuer:
                issuer = "Cloudflare"
            elif "ZeroSSL" in issuer:
                issuer = "ZeroSSL"

            issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1

        return {
            "issuers": issuer_counts,
            "total_issuers": len(issuer_counts),
            "primary_issuer": max(issuer_counts, key=issuer_counts.get) if issuer_counts else "Unknown",
        }

    def _build_timeline(self, certificates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build a certificate issuance timeline grouped by year-month."""
        timeline: dict[str, int] = {}
        for cert in certificates:
            not_before = cert.get("not_before", "")
            if not_before:
                try:
                    dt = datetime.fromisoformat(not_before.replace("T", " ").split(".")[0].split("+")[0].split("Z")[0])
                    key = dt.strftime("%Y-%m")
                    timeline[key] = timeline.get(key, 0) + 1
                except (ValueError, TypeError):
                    pass

        sorted_timeline = sorted(timeline.items())
        return [{"period": k, "count": v} for k, v in sorted_timeline]

    def _analyze_findings(
        self, certificates: list[dict[str, Any]], domain: str,
    ) -> list[dict[str, str]]:
        """Analyze certificates for noteworthy OSINT findings."""
        findings: list[dict[str, str]] = []

        # Check for wildcard certificates
        wildcards = [c for c in certificates if any(
            n.startswith("*.") for n in c.get("san_names", [])
        )]
        if wildcards:
            findings.append({
                "type": "wildcard_certs",
                "detail": f"Found {len(wildcards)} wildcard certificate(s) - may cover hidden subdomains",
            })

        # Check for multiple CAs (could indicate shadow IT)
        issuers = set()
        for cert in certificates:
            issuers.add(cert.get("issuer_name", ""))
        if len(issuers) > 3:
            findings.append({
                "type": "multiple_cas",
                "detail": f"Certificates from {len(issuers)} different CAs detected - possible decentralized certificate management",
            })

        # Check for recently expired certs
        now = datetime.utcnow()
        recently_expired = []
        for cert in certificates:
            if cert.get("is_expired"):
                try:
                    exp = cert.get("not_after", "")
                    expiry = datetime.fromisoformat(exp.replace("T", " ").split(".")[0].split("+")[0].split("Z")[0])
                    days_ago = (now - expiry).days
                    if 0 < days_ago < 30:
                        recently_expired.append(cert.get("common_name", ""))
                except (ValueError, TypeError):
                    pass

        if recently_expired:
            findings.append({
                "type": "recently_expired",
                "detail": f"{len(recently_expired)} certificate(s) expired in the last 30 days",
            })

        # Check for unusual subdomains
        all_names = set()
        for cert in certificates:
            for name in cert.get("san_names", []):
                cleaned = name.lower().lstrip("*.")
                if cleaned.endswith(f".{domain}"):
                    subdomain = cleaned[: -(len(domain) + 1)]
                    if subdomain:
                        all_names.add(subdomain)

        interesting_keywords = ["dev", "staging", "test", "internal", "admin", "vpn", "mail", "api", "beta"]
        interesting_found = [s for s in all_names if any(kw in s for kw in interesting_keywords)]
        if interesting_found:
            findings.append({
                "type": "interesting_subdomains",
                "detail": f"Notable subdomains found: {', '.join(sorted(interesting_found)[:15])}",
            })

        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        include_subdomains = config.get("include_subdomains", True)
        exclude_expired = config.get("exclude_expired", False)
        max_results = config.get("max_results", 100)
        source = config.get("source", "crtsh")

        all_certificates: list[dict[str, Any]] = []
        errors: list[str] = []

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []

            if source in ("crtsh", "both"):
                tasks.append(self._query_crtsh(session, domain, include_subdomains, max_results))

            if source in ("certspotter", "both"):
                tasks.append(self._query_certspotter(session, domain, include_subdomains))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Parse results based on source
        task_idx = 0
        if source in ("crtsh", "both"):
            if task_idx < len(results):
                res = results[task_idx]
                if isinstance(res, Exception):
                    errors.append(f"crt.sh error: {str(res)}")
                else:
                    # Check for error entries
                    error_entries = [e for e in res if "error" in e]
                    for err in error_entries:
                        errors.append(err["error"])
                    parsed = self._parse_crtsh_entries(res, exclude_expired)
                    all_certificates.extend(parsed)
                task_idx += 1

        if source in ("certspotter", "both"):
            if task_idx < len(results):
                res = results[task_idx]
                if isinstance(res, Exception):
                    errors.append(f"CertSpotter error: {str(res)}")
                else:
                    error_entries = [e for e in res if "error" in e]
                    for err in error_entries:
                        errors.append(err["error"])
                    parsed = self._parse_certspotter_entries(res, exclude_expired)
                    all_certificates.extend(parsed)

        # Deduplicate by serial number
        seen_serials: set[str] = set()
        unique_certs: list[dict[str, Any]] = []
        for cert in all_certificates:
            serial = cert.get("serial_number", "")
            cn = cert.get("common_name", "")
            key = f"{serial}:{cn}"
            if key not in seen_serials:
                seen_serials.add(key)
                unique_certs.append(cert)

        unique_domains = self._extract_unique_domains(unique_certs)
        issuer_summary = self._summarize_issuers(unique_certs)
        timeline = self._build_timeline(unique_certs)
        findings = self._analyze_findings(unique_certs, domain)

        result: dict[str, Any] = {
            "domain": domain,
            "certificates": unique_certs,
            "unique_domains": unique_domains,
            "unique_domain_count": len(unique_domains),
            "issuers": issuer_summary,
            "timeline": timeline,
            "findings": findings,
            "total_certificates": len(unique_certs),
            "source": source,
        }

        if errors:
            result["warnings"] = errors

        return result
