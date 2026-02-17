"""AI model evasion testing module.

Generates adversarial inputs to test ML model robustness using
techniques like homoglyph substitution, unicode manipulation,
invisible character injection, and whitespace obfuscation.
"""

import re
import json
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

HOMOGLYPH_MAP: dict[str, list[str]] = {
    "a": ["\u0430", "\u00e0", "\u00e1", "\u1ea1"],  # Cyrillic a, à, á, ạ
    "e": ["\u0435", "\u00e8", "\u00e9", "\u1eb9"],  # Cyrillic e, è, é, ẹ
    "o": ["\u043e", "\u00f2", "\u00f3", "\u1ecd"],  # Cyrillic o, ò, ó, ọ
    "i": ["\u0456", "\u00ec", "\u00ed", "\u1ecb"],  # Cyrillic i, ì, í, ị
    "c": ["\u0441", "\u00e7"],                        # Cyrillic c, ç
    "p": ["\u0440"],                                   # Cyrillic p
    "s": ["\u0455", "\u015f"],                         # Cyrillic s, ş
    "x": ["\u0445"],                                   # Cyrillic x
    "y": ["\u0443", "\u00fd"],                         # Cyrillic y, ý
    "n": ["\u0578", "\u00f1"],                         # Armenian n, ñ
    "d": ["\u0501"],                                   # Cyrillic d
    "h": ["\u04bb"],                                   # Cyrillic h
    "l": ["\u04cf", "\u0131"],                         # Cyrillic l, dotless i
    "g": ["\u0261"],                                   # Latin small g
    "t": ["\u0442"],                                   # Cyrillic t
    "w": ["\u0461"],                                   # Cyrillic w
}

UNICODE_CONFUSABLES = {
    " ": ["\u00a0", "\u2000", "\u2001", "\u2002", "\u2003", "\u200a", "\u205f"],
    "-": ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\ufe58"],
    ".": ["\u2024", "\ufe52"],
    "/": ["\u2044", "\u2215"],
    ",": ["\u201a", "\ufe50"],
}

INVISIBLE_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u180e",  # Mongolian vowel separator
    "\u00ad",  # Soft hyphen
]

WHITESPACE_OBFUSCATIONS = [
    "\t",      # Tab
    "\u000b",  # Vertical tab
    "\u000c",  # Form feed
    "\u00a0",  # Non-breaking space
    "\u1680",  # Ogham space
    "\u2028",  # Line separator
    "\u2029",  # Paragraph separator
]


class AiModelEvasionModule(AtsModule):
    """Generate adversarial inputs to test ML model robustness against evasion techniques."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ai_model_evasion",
            category=ModuleCategory.ADVANCED,
            description="Generate adversarial inputs using homoglyph, unicode, and whitespace techniques to test ML models",
            version="1.0.0",
            parameters=[
                Parameter(name="input_data", type=ParameterType.STRING,
                          description="Original input text to generate adversarial variants from", required=True),
                Parameter(name="model_type", type=ParameterType.CHOICE,
                          description="Type of ML model being tested",
                          choices=["text_classifier", "image", "spam_filter"], default="text_classifier"),
                Parameter(name="technique", type=ParameterType.CHOICE,
                          description="Evasion technique to apply",
                          choices=["homoglyph", "unicode", "whitespace", "all"], default="all"),
                Parameter(name="max_variants", type=ParameterType.INTEGER,
                          description="Maximum number of variants to generate per technique",
                          default=5),
            ],
            outputs=[
                OutputField(name="variants", type="list", description="Generated adversarial variants"),
                OutputField(name="techniques_applied", type="list", description="Techniques that were applied"),
                OutputField(name="total_variants", type="integer", description="Total number of variants generated"),
            ],
            tags=["advanced", "ai", "adversarial", "evasion", "ml", "homoglyph"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("input_data", "").strip()
        if not data:
            return False, "Input data is required"
        if len(data) < 2:
            return False, "Input data too short for meaningful evasion testing"
        return True, ""

    def _apply_homoglyph(self, text: str, max_variants: int) -> list[dict[str, Any]]:
        """Generate homoglyph-substituted variants."""
        variants: list[dict[str, Any]] = []
        replaceable = [(i, c) for i, c in enumerate(text.lower()) if c in HOMOGLYPH_MAP]

        if not replaceable:
            return variants

        # Single character substitutions
        for idx, char in replaceable:
            if len(variants) >= max_variants:
                break
            for replacement in HOMOGLYPH_MAP[char][:1]:
                modified = list(text)
                modified[idx] = replacement
                variant = "".join(modified)
                variants.append({
                    "text": variant,
                    "technique": "homoglyph",
                    "description": f"Replaced '{char}' at position {idx} with '{replacement}' (U+{ord(replacement):04X})",
                    "positions_modified": [idx],
                })
                if len(variants) >= max_variants:
                    break

        # Multi-character substitution (all at once)
        if len(variants) < max_variants and len(replaceable) > 1:
            modified = list(text)
            positions = []
            for idx, char in replaceable:
                if HOMOGLYPH_MAP.get(char.lower()):
                    modified[idx] = HOMOGLYPH_MAP[char.lower()][0]
                    positions.append(idx)
            variant = "".join(modified)
            if variant != text:
                variants.append({
                    "text": variant,
                    "technique": "homoglyph_full",
                    "description": f"Replaced {len(positions)} characters with homoglyphs",
                    "positions_modified": positions,
                })

        return variants

    def _apply_unicode(self, text: str, max_variants: int) -> list[dict[str, Any]]:
        """Generate unicode-confusable variants."""
        variants: list[dict[str, Any]] = []

        # Insert invisible characters between every character
        for invis in INVISIBLE_CHARS[:max_variants]:
            variant = invis.join(text)
            char_name = f"U+{ord(invis):04X}"
            variants.append({
                "text": variant,
                "technique": "unicode_invisible",
                "description": f"Inserted invisible char {char_name} between every character",
                "char_used": char_name,
            })
            if len(variants) >= max_variants:
                break

        # Replace spaces and punctuation with confusables
        for orig, replacements in UNICODE_CONFUSABLES.items():
            if orig in text and len(variants) < max_variants:
                for repl in replacements[:1]:
                    variant = text.replace(orig, repl)
                    variants.append({
                        "text": variant,
                        "technique": "unicode_confusable",
                        "description": f"Replaced '{orig}' with confusable U+{ord(repl):04X}",
                        "char_used": f"U+{ord(repl):04X}",
                    })
                    if len(variants) >= max_variants:
                        break

        return variants[:max_variants]

    def _apply_whitespace(self, text: str, max_variants: int) -> list[dict[str, Any]]:
        """Generate whitespace-obfuscated variants."""
        variants: list[dict[str, Any]] = []
        words = text.split()

        if len(words) < 2:
            # Single word: insert whitespace chars inside
            for ws in WHITESPACE_OBFUSCATIONS[:max_variants]:
                mid = len(text) // 2
                variant = text[:mid] + ws + text[mid:]
                variants.append({
                    "text": variant,
                    "technique": "whitespace_insert",
                    "description": f"Inserted whitespace U+{ord(ws):04X} at midpoint",
                    "char_used": f"U+{ord(ws):04X}",
                })
            return variants[:max_variants]

        # Replace spaces with unusual whitespace
        for ws in WHITESPACE_OBFUSCATIONS[:max_variants]:
            variant = ws.join(words)
            variants.append({
                "text": variant,
                "technique": "whitespace_replace",
                "description": f"Replaced spaces with U+{ord(ws):04X}",
                "char_used": f"U+{ord(ws):04X}",
            })

        # Add trailing/leading invisible whitespace
        if len(variants) < max_variants:
            variant = "\u200b" + text + "\u200b"
            variants.append({
                "text": variant,
                "technique": "whitespace_padding",
                "description": "Added zero-width spaces at start and end",
                "char_used": "U+200B",
            })

        return variants[:max_variants]

    def _get_model_specific_tips(self, model_type: str,
                                  techniques: list[str]) -> list[str]:
        """Provide model-type-specific evasion notes."""
        tips: list[str] = []
        if model_type == "text_classifier":
            tips.append("Text classifiers often normalize unicode; homoglyphs may bypass character-level models")
            if "unicode" in techniques or "all" in techniques:
                tips.append("Zero-width characters can split tokens, breaking tokenizer-based models")
        elif model_type == "spam_filter":
            tips.append("Spam filters may use regex patterns; unicode confusables bypass exact matches")
            tips.append("Invisible characters between letters evade keyword-based filters")
        elif model_type == "image":
            tips.append("For image models, text-based evasion applies to OCR preprocessing")
            tips.append("Homoglyphs are effective against OCR-to-text pipeline classifiers")
        return tips

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        input_data = config["input_data"].strip()
        model_type = config.get("model_type", "text_classifier")
        technique = config.get("technique", "all")
        max_variants = config.get("max_variants", 5)

        all_variants: list[dict[str, Any]] = []
        techniques_applied: list[str] = []

        technique_map = {
            "homoglyph": self._apply_homoglyph,
            "unicode": self._apply_unicode,
            "whitespace": self._apply_whitespace,
        }

        techniques_to_run = list(technique_map.keys()) if technique == "all" else [technique]

        for tech in techniques_to_run:
            if tech in technique_map:
                variants = technique_map[tech](input_data, max_variants)
                if variants:
                    all_variants.extend(variants)
                    techniques_applied.append(tech)

        tips = self._get_model_specific_tips(model_type, techniques_to_run)

        return {
            "original_input": input_data,
            "model_type": model_type,
            "technique_requested": technique,
            "techniques_applied": techniques_applied,
            "variants": all_variants,
            "total_variants": len(all_variants),
            "model_tips": tips,
        }
