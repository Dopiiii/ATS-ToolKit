"""Analyze cryptographic key strength and compliance.

Detects key format, measures effective bit length, assesses strength
against NIST SP 800-131A standards, and checks for known weak patterns.
"""

import asyncio
import base64
import binascii
import math
import re
import hashlib
from typing import Any
from collections import Counter

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

PEM_PATTERN = re.compile(r"-----BEGIN ([A-Z ]+)-----\s*([\s\S]+?)\s*-----END \1-----")
HEX_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]+$")

NIST_RSA_MIN = 2048
NIST_EC_MIN = 256
WEAK_KEY_PATTERNS = [
    bytes(32),           # all zeros
    bytes([0xFF] * 32),  # all ones
    bytes(range(32)),    # sequential
]


class CryptoKeyAnalyzerModule(AtsModule):
    """Analyze cryptographic key strength and format compliance."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_key_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze cryptographic key strength, format, and NIST compliance",
            version="1.0.0",
            parameters=[
                Parameter(name="key_data", type=ParameterType.STRING,
                          description="Cryptographic key data (PEM, hex, or base64)", required=True),
                Parameter(name="key_type", type=ParameterType.CHOICE,
                          description="Expected key type",
                          choices=["rsa", "aes", "ec", "auto"], default="auto"),
            ],
            outputs=[
                OutputField(name="key_info", type="dict",
                            description="Detected key format, type, and length"),
                OutputField(name="strength_assessment", type="dict",
                            description="NIST compliance and strength rating"),
                OutputField(name="recommendations", type="list",
                            description="Security recommendations"),
            ],
            tags=["advanced", "crypto", "key-analysis", "nist"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("key_data", "").strip():
            return False, "Key data is required"
        return True, ""

    def _detect_format(self, data: str) -> tuple[str, bytes, str]:
        """Detect key format and extract raw bytes. Returns (format, raw_bytes, pem_label)."""
        stripped = data.strip()
        # PEM format
        pem_match = PEM_PATTERN.search(stripped)
        if pem_match:
            label = pem_match.group(1)
            b64_body = pem_match.group(2).replace("\n", "").replace("\r", "").replace(" ", "")
            try:
                raw = base64.b64decode(b64_body)
                return "PEM", raw, label
            except (binascii.Error, ValueError):
                return "PEM_invalid", b"", label

        # Hex format
        hex_clean = re.sub(r"[\s:0x]", "", stripped)
        if HEX_KEY_PATTERN.fullmatch(hex_clean) and len(hex_clean) >= 16 and len(hex_clean) % 2 == 0:
            try:
                raw = bytes.fromhex(hex_clean)
                return "hex", raw, ""
            except ValueError:
                pass

        # Base64
        b64_clean = stripped.replace("\n", "").replace("\r", "")
        if re.fullmatch(r"[A-Za-z0-9+/=]+", b64_clean) and len(b64_clean) >= 8:
            try:
                raw = base64.b64decode(b64_clean, validate=True)
                return "base64", raw, ""
            except (binascii.Error, ValueError):
                pass

        return "raw", stripped.encode("utf-8", errors="replace"), ""

    def _detect_key_type(self, fmt: str, raw: bytes, pem_label: str, hint: str) -> str:
        """Infer the key type from format clues and user hint."""
        if hint != "auto":
            return hint
        label_lower = pem_label.lower()
        if "rsa" in label_lower:
            return "rsa"
        if "ec" in label_lower or "ecdsa" in label_lower:
            return "ec"
        if "private key" in label_lower or "public key" in label_lower:
            # Heuristic: RSA keys are typically > 256 bytes, EC keys < 256 bytes
            return "rsa" if len(raw) > 200 else "ec"
        bit_len = len(raw) * 8
        if bit_len in (128, 192, 256):
            return "aes"
        if bit_len >= 1024:
            return "rsa"
        if bit_len in (256, 384, 521):
            return "ec"
        return "unknown"

    def _entropy(self, data: bytes) -> float:
        """Shannon entropy of key material."""
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)

    def _check_weak_patterns(self, raw: bytes) -> list[str]:
        """Check key bytes against known weak patterns."""
        issues: list[str] = []
        if all(b == 0 for b in raw):
            issues.append("Key is all zeros")
        if all(b == 0xFF for b in raw):
            issues.append("Key is all 0xFF bytes")
        if raw == bytes(range(len(raw))):
            issues.append("Key is sequential bytes")
        # Check low entropy
        if len(raw) >= 8:
            unique_ratio = len(set(raw)) / len(raw)
            if unique_ratio < 0.1:
                issues.append(f"Extremely low byte diversity ({len(set(raw))} unique of {len(raw)})")
        # Repeated pattern check
        if len(raw) >= 4:
            half = len(raw) // 2
            if raw[:half] == raw[half:half * 2]:
                issues.append("Key contains repeated halves")
        return issues

    def _assess_strength(self, key_type: str, bit_length: int) -> dict[str, Any]:
        """Assess key strength against NIST standards."""
        rating = "unknown"
        nist_compliant = False
        security_bits = 0

        if key_type == "rsa":
            security_bits = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}.get(bit_length, 0)
            if security_bits == 0 and bit_length > 0:
                security_bits = int(math.log2(bit_length) * 10)  # rough estimate
            if bit_length < 1024:
                rating = "critically_weak"
            elif bit_length < NIST_RSA_MIN:
                rating = "weak"
            elif bit_length < 3072:
                rating = "acceptable"
                nist_compliant = True
            else:
                rating = "strong"
                nist_compliant = True

        elif key_type == "aes":
            security_bits = bit_length
            if bit_length < 128:
                rating = "weak"
            elif bit_length == 128:
                rating = "acceptable"
                nist_compliant = True
            elif bit_length == 192:
                rating = "strong"
                nist_compliant = True
            elif bit_length >= 256:
                rating = "very_strong"
                nist_compliant = True

        elif key_type == "ec":
            security_bits = bit_length // 2
            if bit_length < NIST_EC_MIN:
                rating = "weak"
            elif bit_length == 256:
                rating = "strong"
                nist_compliant = True
            elif bit_length >= 384:
                rating = "very_strong"
                nist_compliant = True

        return {
            "rating": rating,
            "nist_compliant": nist_compliant,
            "effective_security_bits": security_bits,
            "standard_reference": "NIST SP 800-131A Rev.2",
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = config["key_data"].strip()
        hint = config.get("key_type", "auto")

        fmt, raw, pem_label = self._detect_format(data)
        key_type = self._detect_key_type(fmt, raw, pem_label, hint)
        bit_length = len(raw) * 8
        entropy = self._entropy(raw)
        weak_patterns = self._check_weak_patterns(raw)
        strength = self._assess_strength(key_type, bit_length)
        key_hash = hashlib.sha256(raw).hexdigest()[:16] if raw else "N/A"

        key_info = {
            "format": fmt,
            "pem_label": pem_label if pem_label else None,
            "detected_type": key_type,
            "bit_length": bit_length,
            "byte_length": len(raw),
            "entropy": entropy,
            "key_fingerprint_sha256": key_hash,
        }

        recommendations: list[str] = []
        if strength["rating"] in ("critically_weak", "weak"):
            recommendations.append(f"Upgrade {key_type.upper()} key to at least NIST-recommended minimum length")
        if key_type == "rsa" and bit_length < 3072:
            recommendations.append("Consider RSA-3072 or higher for post-2030 security")
        if key_type == "aes" and bit_length < 256:
            recommendations.append("Consider AES-256 for maximum symmetric key strength")
        if key_type == "ec" and bit_length < 384:
            recommendations.append("Consider P-384 or P-521 curves for higher security margin")
        if weak_patterns:
            recommendations.append("CRITICAL: Key material has weak patterns - regenerate immediately")
        if entropy < 4.0 and len(raw) >= 16:
            recommendations.append("Low entropy detected in key material - possible weak RNG")

        return {
            "key_info": key_info,
            "strength_assessment": strength,
            "weak_patterns": weak_patterns,
            "recommendations": recommendations,
        }
