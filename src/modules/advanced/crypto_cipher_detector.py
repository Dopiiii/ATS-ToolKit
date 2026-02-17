"""Identify encryption algorithms from ciphertext analysis.

Performs statistical analysis, pattern matching, and encoding detection
to determine the likely cipher type used to produce given ciphertext.
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

KNOWN_HEADERS = {
    b"Salted__": "OpenSSL (AES-CBC likely)",
    b"\x00\x00\x00": "Possible SSH/binary format",
}

PGP_PATTERN = re.compile(r"-----BEGIN PGP (MESSAGE|PUBLIC KEY|PRIVATE KEY)-----")
SSH_PATTERN = re.compile(r"ssh-(rsa|ed25519|ecdsa)\s+")
JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


class CryptoCipherDetectorModule(AtsModule):
    """Identify encryption type from ciphertext via statistical and pattern analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_cipher_detector",
            category=ModuleCategory.ADVANCED,
            description="Identify encryption algorithm from ciphertext using entropy, frequency, and pattern analysis",
            version="1.0.0",
            parameters=[
                Parameter(name="data", type=ParameterType.STRING,
                          description="Ciphertext data to analyze (raw, hex, or base64)", required=True),
                Parameter(name="analysis_mode", type=ParameterType.CHOICE,
                          description="Analysis approach",
                          choices=["statistical", "pattern", "all"], default="all"),
            ],
            outputs=[
                OutputField(name="detected_type", type="string",
                            description="Most likely cipher or encoding type"),
                OutputField(name="entropy", type="float",
                            description="Shannon entropy of the data"),
                OutputField(name="distribution_analysis", type="dict",
                            description="Byte frequency distribution analysis"),
                OutputField(name="confidence", type="float",
                            description="Detection confidence 0-1"),
            ],
            tags=["advanced", "crypto", "cipher", "detection", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("data", "").strip():
            return False, "Ciphertext data is required"
        return True, ""

    def _to_bytes(self, data: str) -> tuple[bytes, str]:
        """Attempt to decode the input into raw bytes and identify encoding."""
        stripped = data.strip()
        # Try hex
        hex_clean = re.sub(r"[\s:0x]", "", stripped)
        if re.fullmatch(r"[0-9a-fA-F]+", hex_clean) and len(hex_clean) >= 4 and len(hex_clean) % 2 == 0:
            try:
                return bytes.fromhex(hex_clean), "hex"
            except ValueError:
                pass
        # Try base64
        b64_clean = stripped.replace("\n", "").replace("\r", "")
        if re.fullmatch(r"[A-Za-z0-9+/=]+", b64_clean) and len(b64_clean) >= 8:
            try:
                raw = base64.b64decode(b64_clean, validate=True)
                if len(raw) >= 4:
                    return raw, "base64"
            except (binascii.Error, ValueError):
                pass
        return stripped.encode("utf-8", errors="replace"), "raw"

    def _shannon_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _chi_squared(self, data: bytes) -> float:
        """Chi-squared test for uniform byte distribution."""
        if not data:
            return 0.0
        freq = Counter(data)
        expected = len(data) / 256.0
        chi2 = sum((freq.get(b, 0) - expected) ** 2 / expected for b in range(256))
        return round(chi2, 2)

    def _detect_ecb_mode(self, data: bytes, block_size: int = 16) -> dict[str, Any]:
        """Check for ECB mode by detecting repeated blocks."""
        if len(data) < block_size * 2:
            return {"ecb_detected": False, "repeated_blocks": 0}
        blocks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
        block_counts = Counter(blocks)
        repeated = sum(1 for c in block_counts.values() if c > 1)
        return {"ecb_detected": repeated > 0, "repeated_blocks": repeated,
                "total_blocks": len(blocks), "unique_blocks": len(block_counts)}

    def _detect_patterns(self, raw_text: str) -> list[dict[str, Any]]:
        """Detect known cipher markers from the raw text."""
        findings: list[dict[str, Any]] = []
        if PGP_PATTERN.search(raw_text):
            match = PGP_PATTERN.search(raw_text)
            findings.append({"type": f"PGP {match.group(1)}", "confidence": 0.95})
        if SSH_PATTERN.search(raw_text):
            findings.append({"type": "SSH public key", "confidence": 0.90})
        if JWT_PATTERN.match(raw_text.strip()):
            findings.append({"type": "JWT token", "confidence": 0.92})
        if raw_text.strip().startswith("U2FsdGVkX1"):
            findings.append({"type": "OpenSSL AES (Salted)", "confidence": 0.93})
        if re.search(r"^\$2[aby]\$\d{2}\$", raw_text.strip()):
            findings.append({"type": "bcrypt hash", "confidence": 0.95})
        if re.fullmatch(r"[a-f0-9]{32}", raw_text.strip()):
            findings.append({"type": "MD5 hash", "confidence": 0.70})
        if re.fullmatch(r"[a-f0-9]{40}", raw_text.strip()):
            findings.append({"type": "SHA-1 hash", "confidence": 0.70})
        if re.fullmatch(r"[a-f0-9]{64}", raw_text.strip()):
            findings.append({"type": "SHA-256 hash", "confidence": 0.70})
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        raw_text = config["data"].strip()
        mode = config.get("analysis_mode", "all")

        raw_bytes, encoding = self._to_bytes(raw_text)
        results: dict[str, Any] = {"input_encoding": encoding, "data_length": len(raw_bytes)}
        detected_type = "unknown"
        confidence = 0.0

        # Statistical analysis
        if mode in ("statistical", "all"):
            entropy = self._shannon_entropy(raw_bytes)
            chi2 = self._chi_squared(raw_bytes)
            ecb = self._detect_ecb_mode(raw_bytes)

            # Uniformity score: how close chi2 is to expected for uniform distribution (256)
            expected_chi2 = 256.0
            uniformity = max(0.0, 1.0 - abs(chi2 - expected_chi2) / (expected_chi2 * 10))

            results["entropy"] = entropy
            results["chi_squared"] = chi2
            results["uniformity_score"] = round(uniformity, 4)
            results["ecb_analysis"] = ecb

            # Classify based on entropy and distribution
            if entropy >= 7.5 and uniformity > 0.6:
                detected_type = "block_cipher (AES/3DES likely)"
                confidence = max(confidence, 0.75 + uniformity * 0.2)
                if ecb["ecb_detected"]:
                    detected_type = "block_cipher_ECB_mode"
                    confidence = max(confidence, 0.85)
            elif entropy >= 7.0:
                detected_type = "stream_cipher_or_compressed"
                confidence = max(confidence, 0.55)
            elif entropy >= 5.0:
                detected_type = "weak_encryption_or_encoding"
                confidence = max(confidence, 0.40)
            elif entropy < 3.0:
                detected_type = "plaintext_or_low_entropy"
                confidence = max(confidence, 0.60)

            # Byte frequency distribution summary
            freq = Counter(raw_bytes)
            top_bytes = freq.most_common(10)
            null_ratio = freq.get(0, 0) / max(len(raw_bytes), 1)
            results["distribution_analysis"] = {
                "unique_bytes": len(freq),
                "top_10_bytes": [{"byte": b, "count": c, "freq": round(c / len(raw_bytes), 4)} for b, c in top_bytes],
                "null_byte_ratio": round(null_ratio, 4),
            }

        # Pattern analysis
        if mode in ("pattern", "all"):
            header_matches = []
            for header, desc in KNOWN_HEADERS.items():
                if raw_bytes[:len(header)] == header:
                    header_matches.append({"header": header.hex(), "description": desc})
            results["header_matches"] = header_matches

            pattern_findings = self._detect_patterns(raw_text)
            results["pattern_findings"] = pattern_findings

            if pattern_findings:
                best = max(pattern_findings, key=lambda p: p["confidence"])
                if best["confidence"] > confidence:
                    detected_type = best["type"]
                    confidence = best["confidence"]
            if header_matches and confidence < 0.9:
                detected_type = header_matches[0]["description"]
                confidence = max(confidence, 0.80)

        results["detected_type"] = detected_type
        results["confidence"] = round(min(1.0, confidence), 3)

        if "entropy" not in results:
            results["entropy"] = self._shannon_entropy(raw_bytes)
        if "distribution_analysis" not in results:
            results["distribution_analysis"] = {}

        return results
