"""Monitor brand impersonation across domains, social platforms, and apps.

Generates lookalike brand variations using typos, homoglyphs, and common
impersonation prefixes/suffixes, then scores risk per variant.
"""

import asyncio
import re
import math
import hashlib
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "@", "aa"], "b": ["d", "6"], "c": ["k", "("],
    "e": ["3"], "g": ["9", "q"], "i": ["1", "l", "|"],
    "l": ["1", "i", "|"], "o": ["0"], "s": ["5", "$"],
    "t": ["7"], "u": ["v"], "rn": ["m"],
}

IMPERSONATION_PREFIXES = [
    "secure-", "login-", "my-", "account-", "auth-", "verify-",
    "update-", "official-", "real-", "support-", "help-",
]

IMPERSONATION_SUFFIXES = [
    "-login", "-secure", "-support", "-help", "-verify", "-official",
    "-online", "-portal", "-app", "-service", "-team", "-accounts",
]

SOCIAL_PATTERNS = [
    "@{brand}_official", "@{brand}support", "@{brand}_help",
    "@{brand}team", "@official_{brand}", "@{brand}_real",
    "@{brand}hq", "@{brand}_service", "@the{brand}",
    "@{brand}app", "{brand}.support", "{brand}.official",
]

APP_PATTERNS = [
    "{brand} Official", "{brand} - Login", "{brand} Mobile",
    "{brand} Secure", "{brand} Wallet", "{brand} Verify",
    "My {brand}", "{brand} Pro", "{brand} Manager",
]

KEYBOARD_ADJACENT: dict[str, str] = {
    "q": "wa", "w": "qe", "e": "wr", "r": "et", "t": "ry",
    "y": "tu", "u": "yi", "i": "uo", "o": "ip", "p": "ol",
    "a": "qs", "s": "ad", "d": "sf", "f": "dg", "g": "fh",
    "h": "gj", "j": "hk", "k": "jl", "l": "kp",
    "z": "ax", "x": "zc", "c": "xv", "v": "cb", "b": "vn",
    "n": "bm", "m": "nj",
}

COMMON_TLDS = [".com", ".net", ".org", ".co", ".io", ".app", ".xyz", ".info", ".biz"]


class SocialBrandMonitorModule(AtsModule):
    """Monitor brand impersonation across domains and platforms."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_brand_monitor",
            category=ModuleCategory.ADVANCED,
            description="Detect brand impersonation via lookalike domains, social accounts, and app names",
            version="1.0.0",
            parameters=[
                Parameter(name="brand_name", type=ParameterType.STRING,
                          description="Brand name to monitor for impersonation", required=True),
                Parameter(name="platforms", type=ParameterType.CHOICE,
                          description="Platforms to generate variants for",
                          choices=["all", "domains", "social", "apps"], default="all"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity (affects number of variants)",
                          choices=["low", "medium", "high"], default="medium"),
            ],
            outputs=[
                OutputField(name="variants", type="list",
                            description="Generated impersonation variants with platform and technique"),
                OutputField(name="risk_scores", type="dict",
                            description="Risk score summary per variant category"),
                OutputField(name="monitoring_recommendations", type="list",
                            description="Actionable monitoring recommendations"),
            ],
            tags=["advanced", "social", "brand", "monitoring", "impersonation"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("brand_name", "").strip():
            return False, "Brand name is required"
        brand = config["brand_name"].strip()
        if len(brand) < 2:
            return False, "Brand name must be at least 2 characters"
        return True, ""

    def _typo_variants(self, name: str) -> list[str]:
        """Generate keyboard typo variants."""
        variants: list[str] = []
        for i, ch in enumerate(name):
            if ch.lower() in KEYBOARD_ADJACENT:
                for adj in KEYBOARD_ADJACENT[ch.lower()]:
                    variants.append(name[:i] + adj + name[i + 1:])
        # Swapped adjacent characters
        for i in range(len(name) - 1):
            variants.append(name[:i] + name[i + 1] + name[i] + name[i + 2:])
        # Missing character
        for i in range(len(name)):
            v = name[:i] + name[i + 1:]
            if v:
                variants.append(v)
        # Doubled character
        for i, ch in enumerate(name):
            if ch.isalpha():
                variants.append(name[:i] + ch + ch + name[i + 1:])
        return list(set(v for v in variants if v and v != name))

    def _homoglyph_variants(self, name: str) -> list[str]:
        """Generate homoglyph substitution variants."""
        variants: list[str] = []
        for i, ch in enumerate(name):
            if ch.lower() in HOMOGLYPHS:
                for rep in HOMOGLYPHS[ch.lower()]:
                    if len(rep) == 1:
                        variants.append(name[:i] + rep + name[i + 1:])
        # Multi-char substitutions
        for pattern, reps in HOMOGLYPHS.items():
            if len(pattern) > 1:
                idx = name.lower().find(pattern)
                while idx != -1:
                    for rep in reps:
                        variants.append(name[:idx] + rep + name[idx + len(pattern):])
                    idx = name.lower().find(pattern, idx + 1)
        return list(set(v for v in variants if v and v != name))

    def _domain_variants(self, brand: str, sensitivity: str) -> list[dict[str, Any]]:
        """Generate impersonation domain variants."""
        results: list[dict[str, Any]] = []
        brand_clean = re.sub(r"[^a-z0-9]", "", brand.lower())

        # Prefix/suffix combos
        for prefix in IMPERSONATION_PREFIXES:
            for tld in COMMON_TLDS[:4]:
                d = f"{prefix}{brand_clean}{tld}"
                results.append({"variant": d, "platform": "domain", "technique": "prefix",
                                "risk": self._score_domain_risk(d, brand_clean)})
        for suffix in IMPERSONATION_SUFFIXES:
            for tld in COMMON_TLDS[:4]:
                d = f"{brand_clean}{suffix}{tld}"
                results.append({"variant": d, "platform": "domain", "technique": "suffix",
                                "risk": self._score_domain_risk(d, brand_clean)})

        # Typo domains
        typo_limit = {"low": 5, "medium": 15, "high": 30}.get(sensitivity, 15)
        for typo in self._typo_variants(brand_clean)[:typo_limit]:
            for tld in COMMON_TLDS[:3]:
                d = f"{typo}{tld}"
                results.append({"variant": d, "platform": "domain", "technique": "typo",
                                "risk": self._score_domain_risk(d, brand_clean)})

        # Homoglyph domains
        homo_limit = {"low": 3, "medium": 8, "high": 20}.get(sensitivity, 8)
        for homo in self._homoglyph_variants(brand_clean)[:homo_limit]:
            for tld in COMMON_TLDS[:2]:
                d = f"{homo}{tld}"
                results.append({"variant": d, "platform": "domain", "technique": "homoglyph",
                                "risk": self._score_domain_risk(d, brand_clean)})

        return results

    def _social_variants(self, brand: str) -> list[dict[str, Any]]:
        """Generate social media impersonation variants."""
        results: list[dict[str, Any]] = []
        brand_clean = re.sub(r"[^a-z0-9]", "", brand.lower())

        for pattern in SOCIAL_PATTERNS:
            handle = pattern.format(brand=brand_clean)
            risk = 0.7 if "official" in handle or "support" in handle else 0.5
            results.append({"variant": handle, "platform": "social_media",
                            "technique": "impersonation_handle", "risk": round(risk, 2)})

        # Typo handles
        for typo in self._typo_variants(brand_clean)[:8]:
            results.append({"variant": f"@{typo}", "platform": "social_media",
                            "technique": "typo_handle", "risk": 0.6})
        return results

    def _app_variants(self, brand: str) -> list[dict[str, Any]]:
        """Generate fake app name variants."""
        results: list[dict[str, Any]] = []
        for pattern in APP_PATTERNS:
            app_name = pattern.format(brand=brand)
            risk = 0.8 if "Login" in app_name or "Wallet" in app_name else 0.5
            results.append({"variant": app_name, "platform": "app_store",
                            "technique": "fake_app_name", "risk": round(risk, 2)})
        return results

    def _score_domain_risk(self, domain: str, original: str) -> float:
        """Score how risky a domain variant is (0-1)."""
        score = 0.3
        # More similar = more dangerous
        domain_name = domain.split(".")[0].replace("-", "")
        original_clean = original.replace("-", "")
        if len(domain_name) == 0 or len(original_clean) == 0:
            return score
        # Levenshtein-like ratio
        common = sum(1 for a, b in zip(domain_name, original_clean) if a == b)
        similarity = common / max(len(domain_name), len(original_clean))
        score += similarity * 0.4
        # High-value TLDs increase risk
        if domain.endswith(".com") or domain.endswith(".org"):
            score += 0.15
        # Prefix/suffix with security terms
        if any(kw in domain for kw in ["secure", "login", "verify", "auth", "official"]):
            score += 0.15
        return round(min(1.0, score), 2)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        brand = config["brand_name"].strip()
        platforms = config.get("platforms", "all")
        sensitivity = config.get("sensitivity", "medium")

        all_variants: list[dict[str, Any]] = []

        if platforms in ("all", "domains"):
            all_variants.extend(self._domain_variants(brand, sensitivity))
        if platforms in ("all", "social"):
            all_variants.extend(self._social_variants(brand))
        if platforms in ("all", "apps"):
            all_variants.extend(self._app_variants(brand))

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for v in all_variants:
            key = v["variant"]
            if key not in seen:
                seen.add(key)
                unique.append(v)

        # Risk score summaries
        platform_risks: dict[str, list[float]] = {}
        for v in unique:
            plat = v["platform"]
            platform_risks.setdefault(plat, []).append(v["risk"])

        risk_scores: dict[str, Any] = {}
        for plat, risks in platform_risks.items():
            risk_scores[plat] = {
                "count": len(risks),
                "avg_risk": round(sum(risks) / len(risks), 3),
                "max_risk": round(max(risks), 3),
                "high_risk_count": sum(1 for r in risks if r >= 0.7),
            }

        # Recommendations
        recommendations: list[str] = []
        if risk_scores.get("domain", {}).get("high_risk_count", 0) > 0:
            recommendations.append("Register defensive domain variants for high-risk lookalikes")
            recommendations.append("Set up domain monitoring alerts for new registrations matching patterns")
        if risk_scores.get("social_media", {}).get("count", 0) > 0:
            recommendations.append("Claim official brand handles on all major platforms")
            recommendations.append("Report impersonation accounts through platform abuse channels")
        if risk_scores.get("app_store", {}).get("count", 0) > 0:
            recommendations.append("Monitor app stores for unauthorized use of brand name")
            recommendations.append("Register brand with app store brand protection programs")
        recommendations.append("Implement DMARC, SPF, and DKIM to prevent email spoofing")
        recommendations.append("Conduct periodic brand impersonation sweeps")

        return {
            "brand": brand,
            "platforms_checked": platforms,
            "sensitivity": sensitivity,
            "variants": unique,
            "total_variants": len(unique),
            "risk_scores": risk_scores,
            "monitoring_recommendations": recommendations,
        }
