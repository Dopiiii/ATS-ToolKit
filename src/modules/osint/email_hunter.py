"""Email discovery and verification module.

Find email addresses associated with a domain and verify their validity.
"""

import asyncio
import re
import dns.resolver
import aiohttp
from typing import Any, Dict, List, Tuple, Optional

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class EmailHunterModule(AtsModule):
    """Find and verify email addresses for a domain."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="email_hunter",
            category=ModuleCategory.OSINT,
            description="Discover and verify email addresses for a domain",
            version="1.0.0",
            parameters=[
                Parameter(name="domain", type=ParameterType.DOMAIN, description="Target domain to find emails for", required=True),
                Parameter(name="verify", type=ParameterType.BOOLEAN, description="Verify email addresses via MX lookup", required=False, default=True),
                Parameter(name="patterns", type=ParameterType.CHOICE, description="Email pattern generation", required=False, default="common", choices=["common", "extended", "none"]),
            ],
            outputs=[
                OutputField(name="emails", type="list", description="Discovered email addresses"),
                OutputField(name="patterns", type="list", description="Detected email patterns"),
                OutputField(name="mx_records", type="list", description="MX records for domain"),
            ],
            requires_api_key="hunter",
            tags=["email", "domain", "osint", "enumeration"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return False, f"Invalid domain format: {domain}"
        return True, ""

    async def _get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(domain, 'MX')
            mx_records = [{"host": str(rdata.exchange).rstrip('.'), "priority": rdata.preference} for rdata in answers]
            return sorted(mx_records, key=lambda x: x["priority"])
        except Exception as e:
            self.logger.warning("mx_lookup_failed", domain=domain, error=str(e))
            return []

    def _generate_email_patterns(self, domain: str, pattern_type: str) -> List[str]:
        common_prefixes = ["info", "contact", "admin", "support", "hello", "sales", "hr", "jobs", "careers", "press", "media", "help", "service", "team", "office"]
        extended_prefixes = common_prefixes + ["webmaster", "postmaster", "abuse", "security", "billing", "accounts", "marketing", "legal", "privacy", "feedback", "inquiries", "noreply"]
        if pattern_type == "none":
            return []
        prefixes = common_prefixes if pattern_type == "common" else extended_prefixes
        return [f"{prefix}@{domain}" for prefix in prefixes]

    async def _use_hunter_api(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        api_key = self.get_api_key("hunter")
        if not api_key:
            return []
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [{"email": e.get("value"), "type": e.get("type"), "confidence": e.get("confidence"), "first_name": e.get("first_name"), "last_name": e.get("last_name"), "position": e.get("position"), "source": "hunter.io"} for e in data.get("data", {}).get("emails", [])]
        except Exception as e:
            self.logger.warning("hunter_api_failed", error=str(e))
        return []

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower()
        verify = config.get("verify", True)
        pattern_type = config.get("patterns", "common")

        self.logger.info("starting_email_hunt", domain=domain)

        results = {"domain": domain, "emails": [], "patterns": [], "mx_records": [], "verification": {"can_receive_email": False, "mx_verified": False}}

        mx_records = await self._get_mx_records(domain)
        results["mx_records"] = mx_records

        if verify and mx_records:
            results["verification"]["mx_verified"] = True
            results["verification"]["can_receive_email"] = True

        results["patterns"] = self._generate_email_patterns(domain, pattern_type)

        async with aiohttp.ClientSession() as session:
            hunter_results = await self._use_hunter_api(session, domain)
            if hunter_results:
                results["emails"].extend(hunter_results)

        self.logger.info("email_hunt_complete", found=len(results["emails"]), patterns=len(results["patterns"]))
        return results
