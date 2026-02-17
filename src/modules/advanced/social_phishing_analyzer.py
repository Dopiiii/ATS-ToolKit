"""Analyze emails for phishing indicators and social engineering tactics.

Scores email content for urgency language, authority impersonation,
suspicious URLs, embedded forms, and grammar anomalies.
"""

import asyncio
import re
import math
import hashlib
from typing import Any
from urllib.parse import urlparse

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

URGENCY_WORDS = [
    "immediately", "urgent", "suspended", "verify", "expire", "deactivate",
    "locked", "unauthorized", "alert", "confirm", "asap", "deadline",
    "within 24 hours", "act now", "limited time", "final notice",
]

AUTHORITY_PHRASES = [
    "ceo", "cfo", "cto", "chief", "director", "president", "it department",
    "security team", "helpdesk", "administrator", "bank", "paypal", "microsoft",
    "apple", "google", "irs", "tax", "police", "fbi", "legal department",
]

GRAMMAR_PATTERNS = [
    (r"\b(kindly|do the needful|revert back|please to)\b", "Non-native phrasing"),
    (r"\b(recieve|seperate|occured|adress)\b", "Common misspelling"),
    (r"[A-Z]{2,}\s+[a-z]", "Inconsistent capitalization"),
    (r"\s{3,}", "Excessive whitespace"),
    (r"[!]{2,}", "Multiple exclamation marks"),
]

SUSPICIOUS_TLD = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click", ".link", ".info"}


class SocialPhishingAnalyzerModule(AtsModule):
    """Analyze email content for phishing indicators."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_phishing_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze emails for phishing indicators including urgency, impersonation, and suspicious URLs",
            version="1.0.0",
            parameters=[
                Parameter(name="email_content", type=ParameterType.STRING,
                          description="Full email content including headers if available", required=True),
                Parameter(name="check_depth", type=ParameterType.CHOICE,
                          description="Analysis depth",
                          choices=["headers", "content", "links", "all"], default="all"),
            ],
            outputs=[
                OutputField(name="risk_score", type="float",
                            description="Phishing risk score 0-100"),
                OutputField(name="indicators", type="list",
                            description="Detected phishing indicators"),
                OutputField(name="matched_patterns", type="dict",
                            description="Categorized pattern matches"),
                OutputField(name="recommendation", type="string",
                            description="Action recommendation"),
            ],
            tags=["advanced", "social", "phishing", "email", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("email_content", "").strip():
            return False, "Email content is required"
        return True, ""

    def _extract_urls(self, text: str) -> list[str]:
        """Extract all URLs from text."""
        url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
        return url_pattern.findall(text)

    def _analyze_headers(self, text: str) -> list[dict[str, Any]]:
        """Analyze email headers for spoofing indicators."""
        indicators: list[dict[str, Any]] = []
        # Sender mismatch: display name vs actual email
        from_match = re.search(r'From:\s*"?([^"<\n]+)"?\s*<([^>]+)>', text, re.IGNORECASE)
        if from_match:
            display_name = from_match.group(1).strip().lower()
            email_addr = from_match.group(2).strip().lower()
            domain = email_addr.split("@")[-1] if "@" in email_addr else ""
            # Check display name impersonation
            for auth in AUTHORITY_PHRASES:
                if auth in display_name and auth not in domain:
                    indicators.append({"type": "sender_impersonation", "severity": "high",
                                       "detail": f"Display name contains '{auth}' but domain is '{domain}'"})
                    break

        # Reply-To mismatch
        reply_to = re.search(r'Reply-To:\s*<?([^\s<>]+)>?', text, re.IGNORECASE)
        from_email = re.search(r'From:.*<([^>]+)>', text, re.IGNORECASE)
        if reply_to and from_email:
            rt_domain = reply_to.group(1).split("@")[-1] if "@" in reply_to.group(1) else ""
            fr_domain = from_email.group(1).split("@")[-1] if "@" in from_email.group(1) else ""
            if rt_domain and fr_domain and rt_domain != fr_domain:
                indicators.append({"type": "reply_to_mismatch", "severity": "high",
                                   "detail": f"Reply-To domain '{rt_domain}' differs from From '{fr_domain}'"})

        # Missing SPF/DKIM
        if "received-spf: fail" in text.lower() or "dkim=fail" in text.lower():
            indicators.append({"type": "auth_failure", "severity": "high",
                               "detail": "SPF or DKIM authentication failed"})
        return indicators

    def _analyze_content(self, text: str) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Analyze body content for phishing signals."""
        indicators: list[dict[str, Any]] = []
        urgency_matches: list[str] = []
        authority_matches: list[str] = []
        text_lower = text.lower()

        for word in URGENCY_WORDS:
            if word in text_lower:
                urgency_matches.append(word)
        if urgency_matches:
            indicators.append({"type": "urgency_language", "severity": "medium",
                               "detail": f"Found {len(urgency_matches)} urgency terms: {', '.join(urgency_matches[:5])}"})

        for phrase in AUTHORITY_PHRASES:
            if phrase in text_lower:
                authority_matches.append(phrase)
        if authority_matches:
            indicators.append({"type": "authority_impersonation", "severity": "high",
                               "detail": f"Authority references: {', '.join(authority_matches[:5])}"})

        # Grammar and spelling
        for pattern, desc in GRAMMAR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append({"type": "grammar_anomaly", "severity": "low", "detail": desc})

        # Embedded form elements
        if re.search(r'<form[\s>]', text, re.IGNORECASE):
            indicators.append({"type": "embedded_form", "severity": "high",
                               "detail": "HTML form detected in email body"})
        if re.search(r'<input[\s>]', text, re.IGNORECASE):
            indicators.append({"type": "input_field", "severity": "high",
                               "detail": "Input field detected in email body"})

        # Attachment references
        attachment_patterns = re.findall(r'\b(\.exe|\.scr|\.bat|\.cmd|\.vbs|\.js|\.hta|\.pif)\b', text_lower)
        if attachment_patterns:
            indicators.append({"type": "dangerous_attachment_ref", "severity": "high",
                               "detail": f"References to executable attachments: {', '.join(set(attachment_patterns))}"})

        return indicators, urgency_matches, authority_matches

    def _analyze_urls(self, urls: list[str]) -> list[dict[str, Any]]:
        """Analyze extracted URLs for phishing patterns."""
        indicators: list[dict[str, Any]] = []
        for url in urls[:20]:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            issues: list[str] = []

            # IP-based URL
            if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
                issues.append("IP-based URL")
            # Extremely long URL
            if len(url) > 200:
                issues.append(f"Very long URL ({len(url)} chars)")
            # Suspicious TLD
            for tld in SUSPICIOUS_TLD:
                if hostname.endswith(tld):
                    issues.append(f"Suspicious TLD: {tld}")
                    break
            # Lookalike domain patterns
            if re.search(r'(paypa1|g00gle|micros0ft|amaz0n|app1e|faceb00k)', hostname):
                issues.append("Lookalike domain (homoglyph substitution)")
            # URL with @ symbol (credential trick)
            if "@" in url:
                issues.append("URL contains @ sign (credential-based redirect)")
            # Excessive subdomains
            if hostname.count(".") > 3:
                issues.append(f"Excessive subdomains ({hostname.count('.')} dots)")
            # Data URI
            if url.lower().startswith("data:"):
                issues.append("Data URI scheme")

            if issues:
                indicators.append({"type": "suspicious_url", "severity": "high",
                                   "url": url[:120], "issues": issues})
        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        content = config["email_content"].strip()
        depth = config.get("check_depth", "all")

        all_indicators: list[dict[str, Any]] = []
        urgency_matches: list[str] = []
        authority_matches: list[str] = []
        url_indicators: list[dict[str, Any]] = []

        if depth in ("headers", "all"):
            all_indicators.extend(self._analyze_headers(content))

        if depth in ("content", "all"):
            content_ind, urgency_matches, authority_matches = self._analyze_content(content)
            all_indicators.extend(content_ind)

        if depth in ("links", "all"):
            urls = self._extract_urls(content)
            url_indicators = self._analyze_urls(urls)
            all_indicators.extend(url_indicators)

        # Compute risk score (0-100)
        severity_weights = {"high": 15, "medium": 8, "low": 3}
        raw_score = sum(severity_weights.get(ind["severity"], 5) for ind in all_indicators)
        risk_score = round(min(100.0, raw_score), 1)

        if risk_score >= 70:
            recommendation = "HIGH RISK: Likely phishing. Do not click links or open attachments. Report to security team."
        elif risk_score >= 40:
            recommendation = "MEDIUM RISK: Suspicious indicators detected. Verify sender through independent channel."
        elif risk_score >= 15:
            recommendation = "LOW RISK: Minor anomalies detected. Exercise standard caution."
        else:
            recommendation = "MINIMAL RISK: No significant phishing indicators detected."

        matched_patterns = {
            "urgency_terms": urgency_matches,
            "authority_references": authority_matches,
            "suspicious_urls": [u["url"] for u in url_indicators if "url" in u],
            "header_issues": [i["detail"] for i in all_indicators if i["type"] in ("sender_impersonation", "reply_to_mismatch", "auth_failure")],
        }

        return {
            "risk_score": risk_score,
            "indicators": all_indicators,
            "indicator_count": len(all_indicators),
            "matched_patterns": matched_patterns,
            "recommendation": recommendation,
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
        }
