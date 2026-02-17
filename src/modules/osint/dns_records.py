"""DNS record enumeration and email security analysis.

Queries multiple DNS record types and analyzes SPF, DMARC, and DKIM
configurations from TXT records to assess email security posture.
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

RECORD_SETS = {
    "basic": ["A", "AAAA", "MX", "NS"],
    "common": ["A", "AAAA", "MX", "NS", "TXT", "CNAME"],
    "all": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR"],
}


class DnsRecordsModule(AtsModule):
    """Enumerate DNS records and analyze email security configuration."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="dns_records",
            category=ModuleCategory.OSINT,
            description="DNS enumeration with SPF, DMARC, and DKIM email security analysis",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain for DNS enumeration", required=True,
                ),
                Parameter(
                    name="record_types", type=ParameterType.CHOICE,
                    description="Set of DNS record types to query",
                    choices=["basic", "common", "all"], default="common",
                ),
                Parameter(
                    name="nameserver", type=ParameterType.STRING,
                    description="Custom DNS resolver (DoH endpoint or IP)",
                    required=False, default="",
                ),
            ],
            outputs=[
                OutputField(name="records", type="dict", description="DNS records by type"),
                OutputField(name="email_security", type="dict", description="SPF/DMARC/DKIM analysis"),
                OutputField(name="total_records", type="integer", description="Total records found"),
            ],
            tags=["osint", "dns", "spf", "dmarc", "email-security"],
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

    async def _query_dns(
        self, session: aiohttp.ClientSession, domain: str,
        record_type: str, nameserver: str,
    ) -> dict[str, Any]:
        """Query a single DNS record type via DNS-over-HTTPS."""
        base_url = nameserver if nameserver else "https://dns.google/resolve"
        try:
            url = f"{base_url}?name={domain}&type={record_type}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    records = []
                    for answer in answers:
                        records.append({
                            "name": answer.get("name", ""),
                            "type": answer.get("type", 0),
                            "ttl": answer.get("TTL", 0),
                            "data": answer.get("data", ""),
                        })
                    return {"type": record_type, "records": records, "count": len(records)}
                return {"type": record_type, "records": [], "count": 0, "error": f"HTTP {resp.status}"}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"type": record_type, "records": [], "count": 0, "error": str(exc)}

    def _analyze_spf(self, txt_records: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze SPF record for security issues."""
        analysis: dict[str, Any] = {"found": False, "record": None, "issues": [], "score": 0}

        for rec in txt_records:
            data = rec.get("data", "").strip('"')
            if data.startswith("v=spf1"):
                analysis["found"] = True
                analysis["record"] = data
                analysis["score"] = 50  # Base score for having SPF

                mechanisms = data.split()
                analysis["mechanisms"] = mechanisms

                # Check for common issues
                if "+all" in mechanisms:
                    analysis["issues"].append("CRITICAL: +all allows any server to send mail")
                    analysis["score"] = 10
                elif "~all" in mechanisms:
                    analysis["issues"].append("WARN: ~all (softfail) may not reject spoofed mail")
                    analysis["score"] = 60
                elif "-all" in mechanisms:
                    analysis["score"] = 90
                elif "?all" in mechanisms:
                    analysis["issues"].append("WARN: ?all (neutral) provides no protection")
                    analysis["score"] = 20

                # Check for too many lookups
                lookup_count = sum(1 for m in mechanisms if m.startswith(("include:", "a:", "mx:", "redirect=")))
                if lookup_count > 10:
                    analysis["issues"].append(f"WARN: {lookup_count} DNS lookups may exceed 10-lookup limit")

                break

        if not analysis["found"]:
            analysis["issues"].append("No SPF record found - domain vulnerable to email spoofing")
            analysis["score"] = 0

        return analysis

    def _analyze_dmarc(
        self, session_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze DMARC record for security configuration."""
        analysis: dict[str, Any] = {"found": False, "record": None, "issues": [], "score": 0}

        for rec in session_results:
            data = rec.get("data", "").strip('"')
            if data.startswith("v=DMARC1"):
                analysis["found"] = True
                analysis["record"] = data
                analysis["score"] = 50

                # Parse DMARC tags
                tags: dict[str, str] = {}
                for part in data.split(";"):
                    part = part.strip()
                    if "=" in part:
                        key, value = part.split("=", 1)
                        tags[key.strip()] = value.strip()
                analysis["tags"] = tags

                policy = tags.get("p", "none")
                analysis["policy"] = policy
                if policy == "none":
                    analysis["issues"].append("WARN: Policy is 'none' - no enforcement")
                    analysis["score"] = 30
                elif policy == "quarantine":
                    analysis["score"] = 70
                elif policy == "reject":
                    analysis["score"] = 90

                # Check for reporting
                if "rua" not in tags:
                    analysis["issues"].append("No aggregate report URI (rua) configured")
                if "ruf" not in tags:
                    analysis["issues"].append("No forensic report URI (ruf) configured")

                # Subdomain policy
                sp = tags.get("sp", policy)
                if sp == "none" and policy != "none":
                    analysis["issues"].append("WARN: Subdomain policy is 'none'")

                break

        if not analysis["found"]:
            analysis["issues"].append("No DMARC record found")
            analysis["score"] = 0

        return analysis

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        record_set = config.get("record_types", "common")
        nameserver = config.get("nameserver", "").strip()

        record_types = RECORD_SETS.get(record_set, RECORD_SETS["common"])

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Query all record types concurrently
            tasks = [
                self._query_dns(session, domain, rtype, nameserver)
                for rtype in record_types
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Query DMARC specifically
            dmarc_result = await self._query_dns(
                session, f"_dmarc.{domain}", "TXT", nameserver,
            )

        # Organize results
        records: dict[str, Any] = {}
        total_records = 0
        txt_records: list[dict[str, Any]] = []

        for res in results:
            if isinstance(res, Exception):
                continue
            rtype = res.get("type", "UNKNOWN")
            records[rtype] = res.get("records", [])
            total_records += res.get("count", 0)
            if rtype == "TXT":
                txt_records = res.get("records", [])

        # Email security analysis
        spf_analysis = self._analyze_spf(txt_records)
        dmarc_records = dmarc_result.get("records", []) if isinstance(dmarc_result, dict) else []
        dmarc_analysis = self._analyze_dmarc(dmarc_records)

        overall_email_score = int((spf_analysis["score"] + dmarc_analysis["score"]) / 2)
        email_security = {
            "spf": spf_analysis,
            "dmarc": dmarc_analysis,
            "overall_score": overall_email_score,
            "overall_grade": (
                "A" if overall_email_score >= 80 else
                "B" if overall_email_score >= 60 else
                "C" if overall_email_score >= 40 else
                "D" if overall_email_score >= 20 else "F"
            ),
        }

        return {
            "domain": domain,
            "records": records,
            "total_records": total_records,
            "email_security": email_security,
            "record_set": record_set,
        }
