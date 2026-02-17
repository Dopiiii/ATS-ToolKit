"""Detect steganography indicators in files.

Performs statistical analysis, LSB pattern detection, metadata anomaly checks,
and file size ratio analysis to identify potential hidden data.
"""

import asyncio
import math
import os
import re
import struct
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

IMAGE_SIGNATURES = {
    b'\x89PNG': 'png', b'\xff\xd8\xff': 'jpeg',
    b'GIF87a': 'gif', b'GIF89a': 'gif', b'BM': 'bmp',
    b'RIFF': 'webp',
}

KNOWN_STEGO_MARKERS = [
    (b'openstego', 'OpenStego tool signature'),
    (b'steghide', 'Steghide tool signature'),
    (b'JPHIDE', 'JPHide tool signature'),
    (b'\x23\x21\x2f', 'Embedded script shebang'),
]


class CryptoSteganographyModule(AtsModule):
    """Detect steganography indicators in image and media files."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_steganography",
            category=ModuleCategory.ADVANCED,
            description="Detect steganography indicators using statistical, LSB, and metadata analysis",
            version="1.0.0",
            parameters=[
                Parameter(name="file_path", type=ParameterType.FILE,
                          description="Path to the file to analyze", required=True),
                Parameter(name="detection_method", type=ParameterType.CHOICE,
                          description="Detection method to apply",
                          choices=["statistical", "lsb", "metadata", "all"], default="all"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity level",
                          choices=["low", "medium", "high"], default="medium"),
            ],
            outputs=[
                OutputField(name="file_type", type="string", description="Detected file type"),
                OutputField(name="indicators", type="list", description="Steganography indicators found"),
                OutputField(name="risk_score", type="float", description="Stego likelihood score 0-10"),
            ],
            tags=["advanced", "crypto", "steganography", "forensics"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        file_path = config.get("file_path", "").strip()
        if not file_path:
            return False, "File path is required"
        if not os.path.isfile(file_path):
            return False, f"File not found: {file_path}"
        return True, ""

    def _detect_file_type(self, header: bytes) -> str:
        """Identify file type from magic bytes."""
        for sig, ftype in IMAGE_SIGNATURES.items():
            if header.startswith(sig):
                return ftype
        return "unknown"

    def _chi_square_test(self, data: bytes) -> dict[str, Any]:
        """Perform chi-square test on byte distribution for randomness detection."""
        if len(data) < 256:
            return {"chi_square": 0.0, "p_suspicious": False, "note": "Insufficient data"}
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        expected = len(data) / 256.0
        chi_sq = sum((f - expected) ** 2 / expected for f in freq)
        dof = 255
        normalized = chi_sq / dof
        suspicious = 0.9 < normalized < 1.1
        return {
            "chi_square": round(chi_sq, 2),
            "normalized": round(normalized, 4),
            "p_suspicious": suspicious,
            "note": "Near-perfect uniformity suggests encrypted/random payload" if suspicious
                    else "Distribution appears natural",
        }

    def _lsb_analysis(self, data: bytes) -> dict[str, Any]:
        """Analyze least significant bit patterns for anomalies."""
        if len(data) < 64:
            return {"lsb_ratio": 0.5, "suspicious": False}
        lsb_bits = [b & 1 for b in data]
        ones_count = sum(lsb_bits)
        total = len(lsb_bits)
        ratio = ones_count / total
        sequential_same = 0
        for i in range(1, min(len(lsb_bits), 10000)):
            if lsb_bits[i] == lsb_bits[i - 1]:
                sequential_same += 1
        seq_ratio = sequential_same / max(min(len(lsb_bits) - 1, 9999), 1)
        pair_patterns = {}
        for i in range(0, min(len(lsb_bits) - 1, 10000), 2):
            pair = (lsb_bits[i], lsb_bits[i + 1])
            pair_patterns[pair] = pair_patterns.get(pair, 0) + 1
        pair_count = sum(pair_patterns.values())
        pair_entropy = 0.0
        for count in pair_patterns.values():
            p = count / max(pair_count, 1)
            if p > 0:
                pair_entropy -= p * math.log2(p)
        suspicious = abs(ratio - 0.5) < 0.01 and abs(seq_ratio - 0.5) < 0.05
        return {
            "lsb_ratio": round(ratio, 4),
            "sequential_correlation": round(seq_ratio, 4),
            "pair_entropy": round(pair_entropy, 4),
            "max_pair_entropy": 2.0,
            "suspicious": suspicious,
            "note": "LSB distribution is suspiciously uniform" if suspicious
                    else "LSB pattern appears natural",
        }

    def _metadata_analysis(self, data: bytes, file_type: str) -> dict[str, Any]:
        """Check for metadata anomalies that may indicate hidden data."""
        indicators = []
        for marker, desc in KNOWN_STEGO_MARKERS:
            if marker in data:
                indicators.append({"type": "tool_signature", "description": desc})
        if file_type == "jpeg":
            app_markers = [i for i in range(len(data) - 1) if data[i] == 0xFF and data[i+1] in range(0xE0, 0xF0)]
            if len(app_markers) > 5:
                indicators.append({"type": "excessive_markers",
                                   "description": f"Found {len(app_markers)} APP markers (unusual)"})
            comment_markers = [i for i in range(len(data) - 1) if data[i] == 0xFF and data[i+1] == 0xFE]
            for pos in comment_markers:
                if pos + 4 < len(data):
                    length = struct.unpack('>H', data[pos+2:pos+4])[0]
                    if length > 1000:
                        indicators.append({"type": "large_comment",
                                           "description": f"Large JPEG comment block: {length} bytes"})
        if file_type == "png":
            chunk_pos = 8
            while chunk_pos < len(data) - 8:
                try:
                    chunk_len = struct.unpack('>I', data[chunk_pos:chunk_pos+4])[0]
                    chunk_type = data[chunk_pos+4:chunk_pos+8].decode('ascii', errors='replace')
                    if chunk_type not in ('IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt',
                                          'iTXt', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'pHYs',
                                          'sBIT', 'bKGD', 'hIST', 'tRNS', 'tIME'):
                        indicators.append({"type": "unknown_chunk",
                                           "description": f"Non-standard PNG chunk: {chunk_type} ({chunk_len} bytes)"})
                    chunk_pos += 12 + chunk_len
                except (struct.error, UnicodeDecodeError):
                    break
        trailing_data_pos = data.rfind(b'\xff\xd9') if file_type == "jpeg" else data.rfind(b'IEND')
        if trailing_data_pos > 0 and trailing_data_pos < len(data) - 20:
            trailing_size = len(data) - trailing_data_pos - (2 if file_type == "jpeg" else 12)
            if trailing_size > 0:
                indicators.append({"type": "trailing_data",
                                   "description": f"Data appended after file end marker: {trailing_size} bytes",
                                   "size": trailing_size})
        return {"indicators": indicators, "count": len(indicators)}

    def _file_size_analysis(self, data: bytes, file_type: str) -> dict[str, Any]:
        """Analyze file size ratio for anomalies."""
        size = len(data)
        if file_type == "jpeg":
            width_guess = 1920
            height_guess = 1080
            expected_range = (width_guess * height_guess * 0.1, width_guess * height_guess * 0.5)
        elif file_type == "png":
            expected_range = (1000, 50_000_000)
        else:
            expected_range = (100, 100_000_000)
        oversized = size > expected_range[1]
        compression_bytes = sum(1 for b in data if b == 0x00)
        null_ratio = compression_bytes / max(size, 1)
        return {
            "file_size": size,
            "null_byte_ratio": round(null_ratio, 4),
            "oversized": oversized,
            "note": "High null-byte ratio may indicate padding/hidden data" if null_ratio > 0.3
                    else "File size appears normal",
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        file_path = config["file_path"].strip()
        method = config.get("detection_method", "all")
        sensitivity = config.get("sensitivity", "medium")

        with open(file_path, "rb") as f:
            data = f.read()

        file_type = self._detect_file_type(data[:16])
        indicators = []
        risk_score = 0.0
        sensitivity_mult = {"low": 0.7, "medium": 1.0, "high": 1.3}.get(sensitivity, 1.0)

        if method in ("statistical", "all"):
            chi_result = self._chi_square_test(data)
            indicators.append({"method": "chi_square", **chi_result})
            if chi_result["p_suspicious"]:
                risk_score += 3.0 * sensitivity_mult

        if method in ("lsb", "all"):
            lsb_result = self._lsb_analysis(data)
            indicators.append({"method": "lsb_analysis", **lsb_result})
            if lsb_result["suspicious"]:
                risk_score += 3.5 * sensitivity_mult

        if method in ("metadata", "all"):
            meta_result = self._metadata_analysis(data, file_type)
            indicators.append({"method": "metadata", **meta_result})
            risk_score += min(3.0, meta_result["count"] * 1.0) * sensitivity_mult

        size_result = self._file_size_analysis(data, file_type)
        indicators.append({"method": "size_analysis", **size_result})
        if size_result["oversized"] or size_result["null_byte_ratio"] > 0.3:
            risk_score += 1.5 * sensitivity_mult

        risk_score = round(min(10.0, risk_score), 2)

        return {
            "file_path": file_path,
            "file_type": file_type,
            "file_size": len(data),
            "detection_method": method,
            "sensitivity": sensitivity,
            "indicators": indicators,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 8 else "high" if risk_score >= 6
                          else "medium" if risk_score >= 3 else "low",
            "stego_likely": risk_score >= 5.0,
        }
