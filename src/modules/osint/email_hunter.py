"""Email address discovery for a target domain.

Generates common email patterns and optionally verifies them via the Hunter.io API
to discover valid email addresses associated with a domain.
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

COMMON_FIRST_NAMES = [
    "james", "john", "robert", "michael", "david", "william", "richard", "joseph",
    "thomas", "charles", "mary", "patricia", "jennifer", "linda", "elizabeth",
    "barbara", "susan", "jessica", "sarah", "karen", "admin", "info", "contact",
    "support", "sales", "hr", "marketing", "billing", "help", "webmaster",
]

COMMON_LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
    "rodriguez", "martinez", "anderson", "taylor", "thomas", "moore", "jackson",
]

EMAIL_PATTERNS = [
    "{first}@{domain}",
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
    "{last}.{first}@{domain}",
    "{f}.{last}@{domain}",
]


class EmailHunterModule(AtsModule):
    """Discover email addresses associated with a target domain."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="email_hunter",
            category=ModuleCategory.OSINT,
            description="Discover email addresses for a domain using pattern generation and Hunter.io API",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain to discover emails for", required=True,
                ),
                Parameter(
                    name="depth", type=ParameterType.CHOICE,
                    description="Search depth: quick uses fewer patterns, thorough uses all",
                    choices=["quick", "thorough"], default="quick",
                ),
                Parameter(
                    name="verify", type=ParameterType.BOOLEAN,
                    description="Attempt to verify discovered emails via MX/SMTP check",
                    default=False,
                ),
            ],
            outputs=[
                OutputField(name="emails", type="list", description="Discovered email addresses"),
                OutputField(name="patterns", type="list", description="Email patterns identified"),
                OutputField(name="sources", type="list", description="Sources that returned data"),
                OutputField(name="total_found", type="integer", description="Total emails found"),
            ],
            requires_api_key=True,
            api_key_service="hunter",
            tags=["osint", "email", "discovery", "domain"],
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

    def _generate_emails(self, domain: str, depth: str) -> list[dict[str, str]]:
        """Generate candidate email addresses from common patterns."""
        emails: list[dict[str, str]] = []
        first_names = COMMON_FIRST_NAMES[:10] if depth == "quick" else COMMON_FIRST_NAMES
        last_names = COMMON_LAST_NAMES[:5] if depth == "quick" else COMMON_LAST_NAMES
        patterns = EMAIL_PATTERNS[:4] if depth == "quick" else EMAIL_PATTERNS

        for first in first_names:
            if "@" not in first:
                for pattern in patterns:
                    if "{last}" in pattern or "{l}" in pattern:
                        for last in last_names:
                            email = pattern.format(
                                first=first, last=last, f=first[0],
                                l=last[0], domain=domain,
                            )
                            emails.append({"email": email, "pattern": pattern, "source": "generated"})
                    else:
                        email = pattern.format(first=first, domain=domain, f=first[0],
                                               last="", l="")
                        emails.append({"email": email, "pattern": pattern, "source": "generated"})

        # Add role-based emails
        role_emails = [
            f"info@{domain}", f"contact@{domain}", f"admin@{domain}",
            f"support@{domain}", f"sales@{domain}", f"hr@{domain}",
            f"marketing@{domain}", f"billing@{domain}", f"security@{domain}",
            f"abuse@{domain}", f"postmaster@{domain}", f"webmaster@{domain}",
            f"noreply@{domain}", f"hello@{domain}", f"office@{domain}",
        ]
        for email in role_emails:
            emails.append({"email": email, "pattern": "role-based", "source": "generated"})

        return emails

    async def _query_hunter_api(
        self, session: aiohttp.ClientSession, domain: str, api_key: str,
    ) -> list[dict[str, Any]]:
        """Query Hunter.io API for domain emails."""
        results: list[dict[str, Any]] = []
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    api_data = data.get("data", {})
                    for email_entry in api_data.get("emails", []):
                        results.append({
                            "email": email_entry.get("value", ""),
                            "type": email_entry.get("type", "unknown"),
                            "confidence": email_entry.get("confidence", 0),
                            "first_name": email_entry.get("first_name", ""),
                            "last_name": email_entry.get("last_name", ""),
                            "source": "hunter_api",
                        })
                elif resp.status == 401:
                    results.append({"error": "Invalid Hunter.io API key"})
                elif resp.status == 429:
                    results.append({"error": "Hunter.io API rate limit exceeded"})
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            results.append({"error": f"Hunter.io API error: {str(exc)}"})
        return results

    async def _verify_email_mx(
        self, session: aiohttp.ClientSession, domain: str,
    ) -> dict[str, Any]:
        """Check if domain has valid MX records via DNS-over-HTTPS."""
        result: dict[str, Any] = {"domain": domain, "has_mx": False}
        try:
            url = f"https://dns.google/resolve?name={domain}&type=MX"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    mx_records = [a for a in answers if a.get("type") == 15]
                    if mx_records:
                        result["has_mx"] = True
                        result["mx_records"] = [a.get("data", "") for a in mx_records]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            result["error"] = "MX lookup failed"
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        depth = config.get("depth", "quick")
        verify = config.get("verify", False)
        api_key = config.get("api_key", "")

        generated = self._generate_emails(domain, depth)
        sources: list[str] = ["pattern_generation"]
        api_results: list[dict[str, Any]] = []

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            if api_key:
                api_results = await self._query_hunter_api(session, domain, api_key)
                sources.append("hunter_api")

            mx_info: dict[str, Any] = {}
            if verify:
                mx_info = await self._verify_email_mx(session, domain)

        # Deduplicate emails
        seen: set[str] = set()
        unique_emails: list[dict[str, Any]] = []
        for entry in api_results + generated:
            email = entry.get("email", "")
            if email and email not in seen:
                seen.add(email)
                unique_emails.append(entry)

        # Identify dominant patterns
        pattern_counts: dict[str, int] = {}
        for entry in unique_emails:
            p = entry.get("pattern", "unknown")
            pattern_counts[p] = pattern_counts.get(p, 0) + 1

        return {
            "domain": domain,
            "emails": unique_emails,
            "total_found": len(unique_emails),
            "patterns": pattern_counts,
            "sources": sources,
            "mx_verification": mx_info if verify else None,
            "depth": depth,
        }
