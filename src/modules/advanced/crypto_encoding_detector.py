"""Detect and decode various data encoding schemes.

Identifies base64, hex, URL encoding, ROT13, and binary encodings,
then attempts decoding with confidence scoring for each result.
"""

import asyncio
import base64
import binascii
import re
import codecs
from typing import Any
from urllib.parse import unquote

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
HEX_PATTERN = re.compile(r'^(?:0x)?[0-9a-fA-F]+$')
URL_ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
BINARY_PATTERN = re.compile(r'^[01\s]+$')


class CryptoEncodingDetectorModule(AtsModule):
    """Detect and decode encoded data across multiple encoding schemes."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_encoding_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect and decode base64, hex, URL, ROT13, and binary encoded data",
            version="1.0.0",
            parameters=[
                Parameter(name="data", type=ParameterType.STRING,
                          description="Encoded data string to analyze", required=True),
                Parameter(name="try_all", type=ParameterType.BOOLEAN,
                          description="Attempt all decoding methods even after first match",
                          default=True),
                Parameter(name="max_depth", type=ParameterType.INTEGER,
                          description="Maximum nested decoding depth", default=3,
                          min_value=1, max_value=10),
            ],
            outputs=[
                OutputField(name="detected_encodings", type="list",
                            description="Detected encoding types with confidence"),
                OutputField(name="decoded_results", type="list",
                            description="Successful decode attempts"),
                OutputField(name="best_match", type="dict",
                            description="Highest confidence decoding result"),
            ],
            tags=["advanced", "crypto", "encoding", "detection"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("data", "").strip():
            return False, "Data string is required"
        return True, ""

    def _detect_base64(self, data: str) -> dict[str, Any] | None:
        """Attempt base64 decoding with confidence scoring."""
        cleaned = data.strip()
        if len(cleaned) < 4:
            return None
        if not BASE64_PATTERN.match(cleaned):
            return None
        if len(cleaned) % 4 != 0:
            padded = cleaned + "=" * (4 - len(cleaned) % 4)
        else:
            padded = cleaned
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded_text if c.isprintable() or c in '\n\r\t') / max(len(decoded_text), 1)
            confidence = min(1.0, 0.4 + printable_ratio * 0.5 + (0.1 if len(cleaned) % 4 == 0 else 0.0))
            return {"encoding": "base64", "decoded": decoded_text, "confidence": round(confidence, 3),
                    "decoded_length": len(decoded_bytes), "printable_ratio": round(printable_ratio, 3)}
        except (binascii.Error, ValueError):
            return None

    def _detect_hex(self, data: str) -> dict[str, Any] | None:
        """Attempt hex decoding."""
        cleaned = data.strip().lower().replace("0x", "").replace(" ", "").replace(":", "")
        if not HEX_PATTERN.match(cleaned) or len(cleaned) < 2:
            return None
        if len(cleaned) % 2 != 0:
            return None
        try:
            decoded_bytes = bytes.fromhex(cleaned)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded_text if c.isprintable()) / max(len(decoded_text), 1)
            confidence = 0.3 + printable_ratio * 0.5
            if all(c in "0123456789abcdef" for c in cleaned):
                confidence += 0.1
            return {"encoding": "hex", "decoded": decoded_text, "confidence": round(min(1.0, confidence), 3),
                    "decoded_length": len(decoded_bytes), "printable_ratio": round(printable_ratio, 3)}
        except (ValueError, UnicodeDecodeError):
            return None

    def _detect_url_encoding(self, data: str) -> dict[str, Any] | None:
        """Attempt URL decoding."""
        matches = URL_ENCODED_PATTERN.findall(data)
        if not matches:
            return None
        decoded = unquote(data)
        if decoded == data:
            return None
        encoded_ratio = len(matches) * 3 / max(len(data), 1)
        confidence = min(1.0, 0.6 + encoded_ratio * 0.4)
        return {"encoding": "url", "decoded": decoded, "confidence": round(confidence, 3),
                "encoded_sequences": len(matches)}

    def _detect_rot13(self, data: str) -> dict[str, Any] | None:
        """Attempt ROT13 decoding with English word heuristic."""
        cleaned = data.strip()
        if not cleaned or not any(c.isalpha() for c in cleaned):
            return None
        decoded = codecs.decode(cleaned, "rot_13")
        common_words = {"the", "and", "for", "are", "but", "not", "you", "all", "can",
                        "her", "was", "one", "our", "out", "has", "have", "from", "this",
                        "that", "with", "they", "been", "said", "each", "which", "their",
                        "will", "other", "about", "many", "then", "them", "some", "what"}
        decoded_lower_words = set(re.findall(r'[a-z]{3,}', decoded.lower()))
        original_lower_words = set(re.findall(r'[a-z]{3,}', cleaned.lower()))
        decoded_hits = len(decoded_lower_words & common_words)
        original_hits = len(original_lower_words & common_words)
        if decoded_hits <= original_hits:
            return None
        confidence = min(1.0, 0.3 + decoded_hits * 0.15)
        return {"encoding": "rot13", "decoded": decoded, "confidence": round(confidence, 3),
                "english_word_matches": decoded_hits}

    def _detect_binary(self, data: str) -> dict[str, Any] | None:
        """Attempt binary string decoding."""
        cleaned = data.strip().replace(" ", "")
        if not BINARY_PATTERN.match(cleaned) or len(cleaned) < 8:
            return None
        if len(cleaned) % 8 != 0:
            return None
        try:
            chars = [chr(int(cleaned[i:i+8], 2)) for i in range(0, len(cleaned), 8)]
            decoded = "".join(chars)
            printable_ratio = sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1)
            confidence = min(1.0, 0.4 + printable_ratio * 0.5)
            return {"encoding": "binary", "decoded": decoded, "confidence": round(confidence, 3),
                    "bit_length": len(cleaned)}
        except (ValueError, OverflowError):
            return None

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = config["data"].strip()
        try_all = config.get("try_all", True)
        max_depth = config.get("max_depth", 3)

        detectors = [
            self._detect_base64,
            self._detect_hex,
            self._detect_url_encoding,
            self._detect_rot13,
            self._detect_binary,
        ]

        all_results: list[dict[str, Any]] = []
        current_data = data

        for depth in range(max_depth):
            found_at_depth = False
            for detector in detectors:
                result = detector(current_data)
                if result:
                    result["depth"] = depth
                    all_results.append(result)
                    found_at_depth = True
                    if not try_all:
                        break
            if not found_at_depth or not try_all:
                break
            best_at_depth = max(
                [r for r in all_results if r["depth"] == depth],
                key=lambda x: x["confidence"], default=None
            )
            if best_at_depth and best_at_depth["decoded"] != current_data:
                current_data = best_at_depth["decoded"]
            else:
                break

        all_results.sort(key=lambda x: x["confidence"], reverse=True)
        detected_encodings = list({r["encoding"] for r in all_results})
        best_match = all_results[0] if all_results else {"encoding": "unknown", "confidence": 0.0}

        return {
            "original_data": data[:200],
            "original_length": len(data),
            "detected_encodings": detected_encodings,
            "decoded_results": all_results,
            "best_match": best_match,
            "total_detections": len(all_results),
        }
