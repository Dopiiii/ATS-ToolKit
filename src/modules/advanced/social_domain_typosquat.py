"""Generate typosquatting domain variants for brand protection analysis.

Produces domain permutations using adjacent-key typos, character omissions,
doubled characters, swaps, homoglyph substitution, TLD swaps, and hyphenation.
"""

import asyncio
import re
import math
import hashlib
from typing import Any
from itertools import product

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

KEYBOARD_ADJACENT: dict[str, str] = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yijh", "i": "uojk", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd", "g": "tyhbvf",
    "h": "yujnbg", "j": "uikmnh", "k": "iolmj", "l": "opk",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "@"], "b": ["d", "6"], "c": ["(", "k"], "d": ["b", "cl"],
    "e": ["3"], "g": ["9", "q"], "i": ["1", "l", "|"], "l": ["1", "i", "|"],
    "o": ["0"], "q": ["g", "9"], "r": ["n"], "s": ["5", "$"], "t": ["7"],
    "u": ["v"], "v": ["u"], "w": ["vv"], "z": ["2"],
    "rn": ["m"], "cl": ["d"], "nn": ["m"],
}

COMMON_TLDS = [".com", ".net", ".org", ".co", ".io", ".info", ".biz", ".us", ".xyz", ".app", ".dev"]


class SocialDomainTyposquatModule(AtsModule):
    """Generate typosquatting domain permutations for security analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_domain_typosquat",
            category=ModuleCategory.ADVANCED,
            description="Generate typosquatting domain variants using typos, homoglyphs, TLD swaps, and more",
            version="1.0.0",
            parameters=[
                Parameter(name="domain", type=ParameterType.DOMAIN,
                          description="Legitimate domain to generate variants for", required=True),
                Parameter(name="techniques", type=ParameterType.CHOICE,
                          description="Generation techniques to apply",
                          choices=["all", "homoglyph", "typo", "tld", "combo"], default="all"),
                Parameter(name="max_results", type=ParameterType.INTEGER,
                          description="Maximum number of variants to return",
                          default=50, min_value=5, max_value=500),
            ],
            outputs=[
                OutputField(name="variants", type="list",
                            description="Generated domain variants with technique labels"),
                OutputField(name="total_generated", type="integer",
                            description="Total number of unique variants"),
                OutputField(name="technique_counts", type="dict",
                            description="Count of variants per technique"),
            ],
            tags=["advanced", "social", "typosquatting", "brand-protection", "domain"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        domain = config.get("domain", "").strip()
        if not domain:
            return False, "Domain is required"
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", domain):
            return False, "Invalid domain format"
        return True, ""

    def _split_domain(self, domain: str) -> tuple[str, str]:
        """Split domain into name and TLD."""
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            return parts[0], "." + parts[1]
        return domain, ""

    def _adjacent_key_typos(self, name: str) -> list[dict[str, str]]:
        """Generate adjacent keyboard key replacements."""
        variants: list[dict[str, str]] = []
        for i, ch in enumerate(name):
            if ch.lower() in KEYBOARD_ADJACENT:
                for adj in KEYBOARD_ADJACENT[ch.lower()]:
                    variant = name[:i] + adj + name[i + 1:]
                    variants.append({"variant": variant, "technique": "adjacent_key",
                                     "detail": f"'{ch}' -> '{adj}' at position {i}"})
        return variants

    def _missing_chars(self, name: str) -> list[dict[str, str]]:
        """Generate variants with one character removed."""
        variants: list[dict[str, str]] = []
        for i in range(len(name)):
            if name[i] == ".":
                continue
            variant = name[:i] + name[i + 1:]
            if variant and variant != name:
                variants.append({"variant": variant, "technique": "missing_char",
                                 "detail": f"Removed '{name[i]}' at position {i}"})
        return variants

    def _doubled_chars(self, name: str) -> list[dict[str, str]]:
        """Generate variants with one character doubled."""
        variants: list[dict[str, str]] = []
        for i, ch in enumerate(name):
            if ch.isalpha():
                variant = name[:i] + ch + ch + name[i + 1:]
                variants.append({"variant": variant, "technique": "doubled_char",
                                 "detail": f"Doubled '{ch}' at position {i}"})
        return variants

    def _swapped_chars(self, name: str) -> list[dict[str, str]]:
        """Generate variants with adjacent characters swapped."""
        variants: list[dict[str, str]] = []
        for i in range(len(name) - 1):
            if name[i] == "." or name[i + 1] == ".":
                continue
            variant = name[:i] + name[i + 1] + name[i] + name[i + 2:]
            if variant != name:
                variants.append({"variant": variant, "technique": "swapped_chars",
                                 "detail": f"Swapped '{name[i]}' and '{name[i+1]}' at position {i}"})
        return variants

    def _homoglyph_variants(self, name: str) -> list[dict[str, str]]:
        """Generate homoglyph substitution variants."""
        variants: list[dict[str, str]] = []
        # Single character substitutions
        for i, ch in enumerate(name):
            if ch.lower() in HOMOGLYPHS:
                for replacement in HOMOGLYPHS[ch.lower()]:
                    if len(replacement) <= 2:
                        variant = name[:i] + replacement + name[i + 1:]
                        variants.append({"variant": variant, "technique": "homoglyph",
                                         "detail": f"'{ch}' -> '{replacement}' at position {i}"})
        # Multi-character substitutions (rn->m, cl->d)
        for pattern, replacements in HOMOGLYPHS.items():
            if len(pattern) > 1:
                idx = name.find(pattern)
                while idx != -1:
                    for rep in replacements:
                        variant = name[:idx] + rep + name[idx + len(pattern):]
                        variants.append({"variant": variant, "technique": "homoglyph_multi",
                                         "detail": f"'{pattern}' -> '{rep}' at position {idx}"})
                    idx = name.find(pattern, idx + 1)
        return variants

    def _tld_swaps(self, name: str, original_tld: str) -> list[dict[str, str]]:
        """Generate TLD swap variants."""
        variants: list[dict[str, str]] = []
        for tld in COMMON_TLDS:
            if tld != original_tld:
                variants.append({"variant": name + tld, "technique": "tld_swap",
                                 "detail": f"TLD changed from '{original_tld}' to '{tld}'"})
        return variants

    def _hyphen_variants(self, name: str) -> list[dict[str, str]]:
        """Generate hyphenation variants."""
        variants: list[dict[str, str]] = []
        # Split name at various points with hyphen
        dot_parts = name.split(".")
        main = dot_parts[0]
        rest = "." + ".".join(dot_parts[1:]) if len(dot_parts) > 1 else ""
        for i in range(1, len(main)):
            if main[i - 1] != "-" and main[i] != "-":
                variant = main[:i] + "-" + main[i:] + rest
                variants.append({"variant": variant, "technique": "hyphenation",
                                 "detail": f"Hyphen inserted at position {i}"})
        # Remove existing hyphens
        if "-" in main:
            variant = main.replace("-", "") + rest
            variants.append({"variant": variant, "technique": "hyphen_removal",
                             "detail": "All hyphens removed"})
        return variants

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        techniques = config.get("techniques", "all")
        max_results = config.get("max_results", 50)

        name, tld = self._split_domain(domain)
        all_variants: list[dict[str, str]] = []

        if techniques in ("all", "typo", "combo"):
            all_variants.extend(self._adjacent_key_typos(name))
            all_variants.extend(self._missing_chars(name))
            all_variants.extend(self._doubled_chars(name))
            all_variants.extend(self._swapped_chars(name))
            all_variants.extend(self._hyphen_variants(name))

        if techniques in ("all", "homoglyph", "combo"):
            all_variants.extend(self._homoglyph_variants(name))

        if techniques in ("all", "tld", "combo"):
            all_variants.extend(self._tld_swaps(name, tld))

        # Add TLD to variants that don't have one yet (non-tld-swap)
        for v in all_variants:
            if v["technique"] != "tld_swap" and not any(v["variant"].endswith(t) for t in COMMON_TLDS):
                v["variant"] = v["variant"] + tld

        # Deduplicate by variant name, keep first occurrence
        seen: set[str] = set()
        unique: list[dict[str, str]] = []
        for v in all_variants:
            key = v["variant"]
            if key not in seen and key != domain:
                seen.add(key)
                unique.append(v)

        # Count by technique
        technique_counts: dict[str, int] = {}
        for v in unique:
            tech = v["technique"]
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

        # Limit results
        limited = unique[:max_results]

        return {
            "original_domain": domain,
            "variants": limited,
            "total_generated": len(unique),
            "returned_count": len(limited),
            "technique_counts": technique_counts,
        }
