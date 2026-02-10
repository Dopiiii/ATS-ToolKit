"""Payload detection module for identifying malicious content.

Detect SQL injection, XSS, command injection, encoded payloads, and
high-entropy obfuscated data using pattern matching and Shannon entropy.
"""

import asyncio
import re
import math
import base64
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

# Detection pattern sets with descriptions and base severity
PAYLOAD_SIGNATURES = {
    "sql_injection": {
        "patterns": [
            (r"(?i)('\s*(OR|AND)\s+'?\d*'?\s*=\s*'?\d*)", "Tautology-based SQLi"),
            (r"(?i)(UNION\s+(ALL\s+)?SELECT)", "UNION SELECT injection"),
            (r"(?i)(;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s)", "Stacked query injection"),
            (r"(?i)(--\s*$|/\*.*\*/|#\s*$)", "SQL comment injection"),
            (r"(?i)(SLEEP\s*\(\d+\)|BENCHMARK\s*\(\d+)", "Time-based blind SQLi"),
            (r"(?i)(CHAR\s*\(\d+\)|CONCAT\s*\()", "Function-based SQLi"),
            (r"(?i)(LOAD_FILE|INTO\s+(OUT|DUMP)FILE)", "File operation SQLi"),
            (r"(?i)(0x[0-9a-fA-F]{8,})", "Hex-encoded SQLi"),
        ],
        "severity": "high",
    },
    "xss": {
        "patterns": [
            (r"<script[\s>]", "Script tag injection"),
            (r"(?i)on(error|load|click|mouseover|focus|blur)\s*=", "Event handler XSS"),
            (r"(?i)javascript\s*:", "Javascript URI scheme"),
            (r"(?i)<(img|svg|iframe|object|embed|video|audio)\b[^>]*(onerror|onload)", "Tag-based XSS"),
            (r"(?i)(document\.(cookie|write|location)|window\.location)", "DOM manipulation XSS"),
            (r"(?i)(alert|confirm|prompt)\s*\(", "Alert/confirm/prompt call"),
            (r"(?i)<\w+[^>]*\bstyle\s*=\s*[\"'][^\"']*expression\s*\(", "CSS expression XSS"),
        ],
        "severity": "high",
    },
    "command_injection": {
        "patterns": [
            (r"[;&|`]\s*(cat|ls|id|whoami|uname|pwd|curl|wget|nc|ncat)\b", "OS command appending"),
            (r"\$\((.*)\)|\$\{.*\}", "Shell substitution"),
            (r"(?i)(;|\||&&)\s*(rm|chmod|chown|kill|shutdown|reboot)\b", "Destructive command chain"),
            (r"(?i)/etc/(passwd|shadow|hosts)", "Sensitive file path reference"),
            (r"(?i)(\.\./){2,}", "Directory traversal"),
            (r"(?i)(eval|exec|system|passthru|popen|proc_open)\s*\(", "Code execution function"),
        ],
        "severity": "critical",
    },
    "encoded_payload": {
        "patterns": [
            (r"(?i)%(?:25)?(?:3[cCeE]|2[27fF]|3[bBdD])", "URL-encoded special chars"),
            (r"(?i)&#x?[0-9a-fA-F]+;", "HTML entity encoding"),
            (r"\\x[0-9a-fA-F]{2}", "Hex escape sequence"),
            (r"\\u[0-9a-fA-F]{4}", "Unicode escape sequence"),
            (r"[A-Za-z0-9+/]{40,}={0,2}", "Possible base64 blob"),
        ],
        "severity": "medium",
    },
}

MODE_THRESHOLDS = {
    "strict": {"min_confidence": 0.15, "entropy_threshold": 4.0},
    "balanced": {"min_confidence": 0.3, "entropy_threshold": 5.0},
    "permissive": {"min_confidence": 0.5, "entropy_threshold": 5.5},
}


class PayloadDetectorModule(AtsModule):
    """Detect malicious payloads using pattern matching and entropy analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="payload_detector",
            category=ModuleCategory.ML_DETECTION,
            description="Detect malicious payloads (SQLi, XSS, command injection, encoded data) via pattern matching and entropy",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="data",
                    type=ParameterType.STRING,
                    description="Input text or data to scan for malicious payloads",
                    required=True,
                ),
                Parameter(
                    name="scan_mode",
                    type=ParameterType.CHOICE,
                    description="Scan strictness: strict (most alerts), balanced, permissive (fewest alerts)",
                    required=False,
                    default="balanced",
                    choices=["strict", "balanced", "permissive"],
                ),
                Parameter(
                    name="check_encoding",
                    type=ParameterType.BOOLEAN,
                    description="Attempt to decode base64/hex and scan decoded content",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="is_malicious", type="boolean", description="Whether any payload was detected"),
                OutputField(name="detections", type="list", description="List of detections with type, confidence, and details"),
                OutputField(name="entropy", type="float", description="Shannon entropy of the input"),
                OutputField(name="risk_level", type="string", description="Overall risk: critical/high/medium/low/none"),
            ],
            tags=["ml", "detection", "payload", "injection", "xss", "sqli"],
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("data", "")
        if not data or not data.strip():
            return False, "data is required"
        mode = config.get("scan_mode", "balanced")
        if mode not in MODE_THRESHOLDS:
            return False, f"scan_mode must be one of: {list(MODE_THRESHOLDS.keys())}"
        return True, ""

    def _shannon_entropy(self, text: str) -> float:
        """Compute Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _try_decode_base64(self, data: str) -> list[str]:
        """Find and decode base64 segments within the data."""
        decoded_parts = []
        for match in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", data):
            candidate = match.group(0)
            try:
                raw = base64.b64decode(candidate, validate=True)
                text = raw.decode("utf-8", errors="ignore")
                if text and any(c.isprintable() for c in text):
                    decoded_parts.append(text)
            except Exception:
                continue
        return decoded_parts

    def _scan_patterns(self, data: str) -> list[dict[str, Any]]:
        """Scan data against all payload signatures."""
        detections = []
        for category, info in PAYLOAD_SIGNATURES.items():
            matched_count = 0
            total = len(info["patterns"])
            matched_details = []
            for regex, description in info["patterns"]:
                matches = re.findall(regex, data)
                if matches:
                    matched_count += 1
                    matched_details.append({
                        "pattern_description": description,
                        "match_count": len(matches),
                        "sample": str(matches[0])[:100] if matches else "",
                    })
            if matched_count > 0:
                confidence = matched_count / total
                detections.append({
                    "type": category,
                    "severity": info["severity"],
                    "confidence": round(confidence, 4),
                    "matched_patterns": matched_count,
                    "total_patterns": total,
                    "details": matched_details,
                })
        return detections

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = config["data"]
        scan_mode = config.get("scan_mode", "balanced")
        check_encoding = config.get("check_encoding", True)
        thresholds = MODE_THRESHOLDS[scan_mode]

        self.logger.info("starting_payload_detection", mode=scan_mode, data_length=len(data))

        # Primary scan
        detections = self._scan_patterns(data)

        # Optionally decode and re-scan encoded content
        decoded_detections = []
        if check_encoding:
            decoded_parts = self._try_decode_base64(data)
            for part in decoded_parts:
                extra = self._scan_patterns(part)
                for d in extra:
                    d["source"] = "decoded_base64"
                    d["confidence"] = round(d["confidence"] * 0.85, 4)  # slight confidence reduction
                decoded_detections.extend(extra)

        all_detections = detections + decoded_detections

        # Filter by confidence threshold
        filtered = [d for d in all_detections if d["confidence"] >= thresholds["min_confidence"]]

        # Entropy analysis
        entropy = self._shannon_entropy(data)
        high_entropy = entropy > thresholds["entropy_threshold"]
        if high_entropy:
            filtered.append({
                "type": "high_entropy_data",
                "severity": "medium",
                "confidence": round(min((entropy - thresholds["entropy_threshold"]) / 2.0, 1.0), 4),
                "details": [{"pattern_description": f"Shannon entropy {entropy:.2f} exceeds threshold {thresholds['entropy_threshold']}"}],
            })

        # Determine overall risk level
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = 0
        for d in filtered:
            sev = severity_order.get(d.get("severity", "low"), 1)
            if sev > max_severity:
                max_severity = sev
        risk_map = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        risk_level = risk_map.get(max_severity, "none")

        is_malicious = len(filtered) > 0

        # Sort detections by confidence descending
        filtered.sort(key=lambda d: d.get("confidence", 0), reverse=True)

        self.logger.info(
            "payload_detection_complete",
            is_malicious=is_malicious,
            detection_count=len(filtered),
            risk_level=risk_level,
        )

        return {
            "is_malicious": is_malicious,
            "risk_level": risk_level,
            "detection_count": len(filtered),
            "detections": filtered,
            "entropy": round(entropy, 4),
            "high_entropy": high_entropy,
            "scan_mode": scan_mode,
            "data_length": len(data),
        }
