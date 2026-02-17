"""Data breach checker for OSINT investigations.

Checks if email addresses or domains appear in known data breaches using
the Have I Been Pwned (HIBP) API and supplementary breach databases.
Provides breach details, exposed data types, and risk assessment.
"""

import asyncio
import hashlib
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

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com"

# Severity weights for different data classes exposed in breaches
DATA_CLASS_SEVERITY: dict[str, int] = {
    "Passwords": 10,
    "Password hints": 7,
    "Credit cards": 10,
    "Bank account numbers": 10,
    "Social security numbers": 10,
    "Dates of birth": 6,
    "Phone numbers": 5,
    "Physical addresses": 6,
    "IP addresses": 4,
    "Email addresses": 3,
    "Usernames": 3,
    "Names": 2,
    "Genders": 1,
    "Auth tokens": 9,
    "Security questions and answers": 8,
    "Government issued IDs": 10,
    "Passport numbers": 10,
    "Driver's licenses": 10,
    "Biometric data": 10,
    "Medical records": 9,
    "Financial investments": 8,
    "Employment": 4,
    "Education details": 3,
    "Browser user agent details": 2,
    "Device information": 3,
    "Geographic locations": 4,
    "Chat logs": 5,
    "Private messages": 6,
    "Photos": 5,
}


class BreachCheckModule(AtsModule):
    """Check if emails or domains appear in known data breaches."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="breach_check",
            category=ModuleCategory.OSINT,
            description="Check emails and domains against known data breaches via HIBP API",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target", type=ParameterType.STRING,
                    description="Email address or domain to check for breaches",
                    required=True,
                ),
                Parameter(
                    name="target_type", type=ParameterType.CHOICE,
                    description="Type of target: email checks a single address, domain checks all breaches for a domain",
                    choices=["email", "domain", "auto"],
                    default="auto", required=False,
                ),
                Parameter(
                    name="include_unverified", type=ParameterType.BOOLEAN,
                    description="Include unverified breaches in results",
                    default=False, required=False,
                ),
                Parameter(
                    name="check_pastes", type=ParameterType.BOOLEAN,
                    description="Also check for appearances in paste sites (email only)",
                    default=True, required=False,
                ),
                Parameter(
                    name="check_password", type=ParameterType.STRING,
                    description="Optional: check if a password has been seen in breaches (uses k-anonymity, safe)",
                    required=False, default="",
                ),
            ],
            outputs=[
                OutputField(name="breaches", type="list", description="List of breaches the target appears in"),
                OutputField(name="pastes", type="list", description="Paste site appearances"),
                OutputField(name="risk_assessment", type="dict", description="Overall risk assessment"),
                OutputField(name="exposed_data_types", type="list", description="Types of data exposed across all breaches"),
                OutputField(name="total_breaches", type="integer", description="Total number of breaches found"),
            ],
            requires_api_key=True,
            api_key_service="hibp",
            tags=["osint", "breach", "hibp", "email", "password", "data-leak"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target email or domain is required"

        target_type = config.get("target_type", "auto")
        if target_type == "auto":
            target_type = "email" if "@" in target else "domain"

        if target_type == "email":
            if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', target):
                return False, "Invalid email address format"
        elif target_type == "domain":
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', target):
                return False, "Invalid domain format"

        api_key = config.get("api_key", "").strip()
        if not api_key:
            return False, "HIBP API key is required (get one at https://haveibeenpwned.com/API/Key)"

        return True, ""

    async def _check_breaches(
        self, session: aiohttp.ClientSession, target: str,
        target_type: str, api_key: str, include_unverified: bool,
    ) -> list[dict[str, Any]]:
        """Query HIBP API for breaches affecting the target."""
        if target_type == "email":
            url = f"{HIBP_API_BASE}/breachedaccount/{target}"
        else:
            url = f"{HIBP_API_BASE}/breaches"

        params: dict[str, str] = {"truncateResponse": "false"}
        if not include_unverified:
            params["includeUnverified"] = "false"
        if target_type == "domain":
            params["domain"] = target

        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "ATS-Toolkit-BreachChecker",
        }

        try:
            async with session.get(
                url,
                params=params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return []  # No breaches found
                elif resp.status == 401:
                    return [{"error": "Invalid HIBP API key"}]
                elif resp.status == 429:
                    retry_after = resp.headers.get("Retry-After", "2")
                    return [{"error": f"HIBP rate limited, retry after {retry_after}s"}]
                elif resp.status == 403:
                    return [{"error": "HIBP API access denied - check your subscription"}]
                else:
                    return [{"error": f"HIBP API returned HTTP {resp.status}"}]
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return [{"error": f"HIBP API request failed: {str(exc)}"}]

    async def _check_pastes(
        self, session: aiohttp.ClientSession, email: str, api_key: str,
    ) -> list[dict[str, Any]]:
        """Check if an email appears in paste site dumps."""
        url = f"{HIBP_API_BASE}/pasteaccount/{email}"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "ATS-Toolkit-BreachChecker",
        }

        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return []
                elif resp.status == 429:
                    return [{"error": "HIBP paste check rate limited"}]
                else:
                    return [{"error": f"HIBP paste API returned HTTP {resp.status}"}]
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return [{"error": f"HIBP paste check failed: {str(exc)}"}]

    async def _check_password_pwned(
        self, session: aiohttp.ClientSession, password: str,
    ) -> dict[str, Any]:
        """Check if a password has appeared in breaches using k-anonymity model.

        Only the first 5 characters of the SHA-1 hash are sent to the API.
        The full hash is compared locally against returned suffixes.
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f"{HIBP_PASSWORD_API}/range/{prefix}"

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "ATS-Toolkit-BreachChecker"},
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        parts = line.strip().split(":")
                        if len(parts) == 2 and parts[0] == suffix:
                            return {
                                "pwned": True,
                                "count": int(parts[1]),
                                "message": f"Password found {parts[1]} times in breach databases",
                            }
                    return {
                        "pwned": False,
                        "count": 0,
                        "message": "Password not found in known breach databases",
                    }
                else:
                    return {"error": f"Password API returned HTTP {resp.status}"}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"error": f"Password check failed: {str(exc)}"}

    def _parse_breaches(self, raw_breaches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse and normalize breach data."""
        breaches: list[dict[str, Any]] = []

        for breach in raw_breaches:
            if "error" in breach:
                continue

            data_classes = breach.get("DataClasses", [])
            breach_entry = {
                "name": breach.get("Name", ""),
                "title": breach.get("Title", ""),
                "domain": breach.get("Domain", ""),
                "breach_date": breach.get("BreachDate", ""),
                "added_date": breach.get("AddedDate", ""),
                "modified_date": breach.get("ModifiedDate", ""),
                "pwn_count": breach.get("PwnCount", 0),
                "description": self._strip_html(breach.get("Description", "")),
                "data_classes": data_classes,
                "is_verified": breach.get("IsVerified", False),
                "is_fabricated": breach.get("IsFabricated", False),
                "is_sensitive": breach.get("IsSensitive", False),
                "is_retired": breach.get("IsRetired", False),
                "is_spam_list": breach.get("IsSpamList", False),
                "is_malware": breach.get("IsMalware", False),
                "severity_score": self._calculate_breach_severity(data_classes, breach.get("PwnCount", 0)),
            }
            breaches.append(breach_entry)

        # Sort by severity score descending
        breaches.sort(key=lambda b: b["severity_score"], reverse=True)
        return breaches

    def _strip_html(self, text: str) -> str:
        """Remove HTML tags from breach descriptions."""
        clean = re.sub(r"<[^>]+>", "", text)
        return clean.strip()

    def _calculate_breach_severity(self, data_classes: list[str], pwn_count: int) -> int:
        """Calculate a severity score for a breach based on exposed data types and scale."""
        score = 0

        # Data class severity
        for dc in data_classes:
            score += DATA_CLASS_SEVERITY.get(dc, 2)

        # Scale factor based on number of records
        if pwn_count > 100_000_000:
            score += 15
        elif pwn_count > 10_000_000:
            score += 10
        elif pwn_count > 1_000_000:
            score += 7
        elif pwn_count > 100_000:
            score += 4
        elif pwn_count > 10_000:
            score += 2

        return min(score, 100)  # Cap at 100

    def _parse_pastes(self, raw_pastes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse and normalize paste data."""
        pastes: list[dict[str, Any]] = []
        for paste in raw_pastes:
            if "error" in paste:
                continue
            pastes.append({
                "source": paste.get("Source", ""),
                "id": paste.get("Id", ""),
                "title": paste.get("Title", ""),
                "date": paste.get("Date", ""),
                "email_count": paste.get("EmailCount", 0),
            })
        return pastes

    def _assess_risk(
        self, breaches: list[dict[str, Any]], pastes: list[dict[str, Any]],
        password_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Generate an overall risk assessment."""
        risk: dict[str, Any] = {
            "risk_level": "LOW",
            "risk_score": 0,
            "summary": [],
            "recommendations": [],
        }

        num_breaches = len(breaches)
        num_pastes = len(pastes)

        # Score based on breach count
        if num_breaches == 0:
            risk["risk_score"] = 0
            risk["summary"].append("No breaches found")
        elif num_breaches <= 2:
            risk["risk_score"] = 30
            risk["summary"].append(f"Found in {num_breaches} breach(es)")
        elif num_breaches <= 5:
            risk["risk_score"] = 55
            risk["summary"].append(f"Found in {num_breaches} breaches - moderate exposure")
        else:
            risk["risk_score"] = 75
            risk["summary"].append(f"Found in {num_breaches} breaches - significant exposure")

        # Adjust for severity of exposed data
        all_data_classes: set[str] = set()
        for breach in breaches:
            for dc in breach.get("data_classes", []):
                all_data_classes.add(dc)

        critical_types = {"Passwords", "Credit cards", "Social security numbers",
                          "Bank account numbers", "Government issued IDs", "Auth tokens"}
        critical_exposed = critical_types & all_data_classes
        if critical_exposed:
            risk["risk_score"] = min(risk["risk_score"] + 20, 100)
            risk["summary"].append(f"Critical data types exposed: {', '.join(critical_exposed)}")

        # Adjust for paste exposure
        if num_pastes > 0:
            risk["risk_score"] = min(risk["risk_score"] + 10, 100)
            risk["summary"].append(f"Found in {num_pastes} paste(s)")

        # Adjust for password check
        if password_result and password_result.get("pwned"):
            risk["risk_score"] = min(risk["risk_score"] + 15, 100)
            risk["summary"].append(f"Password exposed {password_result['count']} times")

        # Determine risk level
        score = risk["risk_score"]
        if score >= 75:
            risk["risk_level"] = "CRITICAL"
        elif score >= 50:
            risk["risk_level"] = "HIGH"
        elif score >= 25:
            risk["risk_level"] = "MEDIUM"
        else:
            risk["risk_level"] = "LOW"

        # Recommendations
        if "Passwords" in all_data_classes:
            risk["recommendations"].append("Change passwords immediately on all affected services")
            risk["recommendations"].append("Enable two-factor authentication on all accounts")
        if critical_exposed:
            risk["recommendations"].append("Monitor financial accounts and credit reports for suspicious activity")
        if num_breaches > 0:
            risk["recommendations"].append("Use a unique password for every service")
            risk["recommendations"].append("Consider using a password manager")
        if num_pastes > 0:
            risk["recommendations"].append("Email address is circulating in paste dumps - watch for phishing")
        if password_result and password_result.get("pwned"):
            risk["recommendations"].append("The checked password is compromised - never use it anywhere")

        # Check recency of breaches
        now = datetime.utcnow()
        for breach in breaches:
            breach_date = breach.get("breach_date", "")
            try:
                bd = datetime.fromisoformat(breach_date)
                days_ago = (now - bd).days
                if days_ago < 365:
                    risk["summary"].append(f"Recent breach: {breach['name']} ({breach_date})")
                    risk["recommendations"].append(
                        f"Urgently review account on {breach.get('domain', breach['name'])}"
                    )
                    break
            except (ValueError, TypeError):
                pass

        return risk

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"].strip().lower()
        target_type = config.get("target_type", "auto")
        include_unverified = config.get("include_unverified", False)
        check_pastes = config.get("check_pastes", True)
        check_password = config.get("check_password", "").strip()
        api_key = config["api_key"].strip()

        # Auto-detect target type
        if target_type == "auto":
            target_type = "email" if "@" in target else "domain"

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Query breaches
            raw_breaches = await self._check_breaches(
                session, target, target_type, api_key, include_unverified,
            )

            # Check for API errors
            errors = [e["error"] for e in raw_breaches if "error" in e]
            if errors:
                return {
                    "target": target,
                    "target_type": target_type,
                    "error": errors[0],
                    "breaches": [],
                    "pastes": [],
                    "risk_assessment": {"risk_level": "UNKNOWN"},
                    "exposed_data_types": [],
                    "total_breaches": 0,
                }

            # Rate limit pause before next call
            await asyncio.sleep(1.6)

            # Check pastes (email only)
            raw_pastes: list[dict[str, Any]] = []
            if check_pastes and target_type == "email":
                raw_pastes = await self._check_pastes(session, target, api_key)

            # Check password
            password_result: dict[str, Any] | None = None
            if check_password:
                password_result = await self._check_password_pwned(session, check_password)

        # Parse results
        breaches = self._parse_breaches(raw_breaches)
        pastes = self._parse_pastes(raw_pastes)

        # Collect all exposed data types
        all_data_types: set[str] = set()
        for breach in breaches:
            for dc in breach.get("data_classes", []):
                all_data_types.add(dc)

        # Risk assessment
        risk_assessment = self._assess_risk(breaches, pastes, password_result)

        result: dict[str, Any] = {
            "target": target,
            "target_type": target_type,
            "breaches": breaches,
            "pastes": pastes,
            "risk_assessment": risk_assessment,
            "exposed_data_types": sorted(all_data_types),
            "total_breaches": len(breaches),
            "total_pastes": len(pastes),
            "total_records_exposed": sum(b.get("pwn_count", 0) for b in breaches),
        }

        if password_result:
            result["password_check"] = password_result

        return result
