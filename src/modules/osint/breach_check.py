"""Breach check module.

Check if an email or domain has been involved in data breaches.
"""

import asyncio
import hashlib
import aiohttp
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class BreachCheckModule(AtsModule):
    """Check for data breaches using Have I Been Pwned API."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="breach_check",
            category=ModuleCategory.OSINT,
            description="Check if email/domain appears in known data breaches",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Email address or domain to check",
                    required=True,
                ),
                Parameter(
                    name="check_type",
                    type=ParameterType.CHOICE,
                    description="Type of check",
                    required=False,
                    default="email",
                    choices=["email", "domain", "password"],
                ),
                Parameter(
                    name="include_unverified",
                    type=ParameterType.BOOLEAN,
                    description="Include unverified breaches",
                    required=False,
                    default=False,
                ),
            ],
            outputs=[
                OutputField(name="breaches", type="list", description="Found breaches"),
                OutputField(name="pastes", type="list", description="Found pastes"),
            ],
            requires_api_key="hibp",  # Optional - works with some features without it
            tags=["breach", "pwned", "osint", "security"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = config.get("target", "").strip()
        check_type = config.get("check_type", "email")

        if not target:
            return False, "Target is required"

        if check_type == "email" and "@" not in target:
            return False, "Invalid email format"

        return True, ""

    async def _check_pwned_password(
        self,
        session: aiohttp.ClientSession,
        password: str
    ) -> Dict[str, Any]:
        """Check if password appears in breaches using k-anonymity."""
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    text = await response.text()
                    hashes = text.split('\r\n')

                    for h in hashes:
                        hash_suffix, count = h.split(':')
                        if hash_suffix == suffix:
                            return {
                                "pwned": True,
                                "count": int(count),
                                "message": f"Password found in {count} breaches"
                            }

                    return {
                        "pwned": False,
                        "count": 0,
                        "message": "Password not found in known breaches"
                    }

        except Exception as e:
            return {"error": str(e)}

        return {"pwned": False, "count": 0}

    async def _check_breaches(
        self,
        session: aiohttp.ClientSession,
        email: str,
        api_key: str = None
    ) -> List[Dict[str, Any]]:
        """Check email against Have I Been Pwned breaches."""
        breaches = []

        headers = {
            "User-Agent": "ATS-Toolkit-Breach-Checker",
        }
        if api_key:
            headers["hibp-api-key"] = api_key

        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    for breach in data:
                        breaches.append({
                            "name": breach.get("Name"),
                            "title": breach.get("Title"),
                            "domain": breach.get("Domain"),
                            "breach_date": breach.get("BreachDate"),
                            "added_date": breach.get("AddedDate"),
                            "pwn_count": breach.get("PwnCount"),
                            "description": breach.get("Description"),
                            "data_classes": breach.get("DataClasses", []),
                            "is_verified": breach.get("IsVerified"),
                            "is_sensitive": breach.get("IsSensitive"),
                        })
                elif response.status == 404:
                    pass  # No breaches found
                elif response.status == 401:
                    return [{"error": "API key required for this endpoint"}]
                elif response.status == 429:
                    return [{"error": "Rate limit exceeded"}]

        except Exception as e:
            return [{"error": str(e)}]

        return breaches

    async def _check_domain_breaches(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        api_key: str = None
    ) -> List[Dict[str, Any]]:
        """Check domain for breaches (requires API key)."""
        if not api_key:
            return [{"error": "HIBP API key required for domain search"}]

        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "ATS-Toolkit-Breach-Checker",
        }

        try:
            url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return []
                else:
                    return [{"error": f"API returned status {response.status}"}]

        except Exception as e:
            return [{"error": str(e)}]

    async def _get_all_breaches(
        self,
        session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Get list of all known breaches."""
        try:
            url = "https://haveibeenpwned.com/api/v3/breaches"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    return await response.json()
        except:
            pass
        return []

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip().lower()
        check_type = config.get("check_type", "email")
        include_unverified = config.get("include_unverified", False)

        api_key = self.get_api_key("hibp")

        self.logger.info("starting_breach_check", target=target[:20] + "...", type=check_type)

        results = {
            "target": target if check_type != "password" else "[REDACTED]",
            "check_type": check_type,
            "breaches": [],
            "pastes": [],
            "summary": {},
        }

        async with aiohttp.ClientSession() as session:
            if check_type == "password":
                # Password check (k-anonymity, no API key needed)
                pwd_result = await self._check_pwned_password(session, target)
                results["password_check"] = pwd_result
                results["summary"] = {
                    "pwned": pwd_result.get("pwned", False),
                    "exposure_count": pwd_result.get("count", 0),
                }

            elif check_type == "email":
                # Email breach check
                breaches = await self._check_breaches(session, target, api_key)

                if not include_unverified:
                    breaches = [b for b in breaches if b.get("is_verified", True)]

                results["breaches"] = breaches
                results["summary"] = {
                    "breach_count": len(breaches),
                    "total_records_exposed": sum(b.get("pwn_count", 0) for b in breaches),
                    "data_types_exposed": list(set(
                        dt for b in breaches for dt in b.get("data_classes", [])
                    )),
                    "earliest_breach": min(
                        (b.get("breach_date") for b in breaches if b.get("breach_date")),
                        default=None
                    ),
                    "latest_breach": max(
                        (b.get("breach_date") for b in breaches if b.get("breach_date")),
                        default=None
                    ),
                }

            elif check_type == "domain":
                # Domain breach check
                breaches = await self._check_domain_breaches(session, target, api_key)
                results["breaches"] = breaches
                results["summary"] = {
                    "breach_count": len(breaches) if isinstance(breaches, list) else 0,
                }

        self.logger.info(
            "breach_check_complete",
            type=check_type,
            breaches_found=len(results.get("breaches", []))
        )

        return results
