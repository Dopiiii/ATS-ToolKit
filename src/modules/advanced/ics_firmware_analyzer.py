"""Firmware image analyzer for ICS devices — extracts strings, calculates entropy, checks headers."""

import math
import re
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


KNOWN_FIRMWARE_HEADERS = [
    {"name": "uImage (U-Boot)", "magic": b"\x27\x05\x19\x56", "offset": 0},
    {"name": "gzip compressed", "magic": b"\x1f\x8b\x08", "offset": 0},
    {"name": "ELF executable", "magic": b"\x7fELF", "offset": 0},
    {"name": "JFFS2 filesystem", "magic": b"\x85\x19\x01\x00", "offset": 0},
    {"name": "SquashFS (LE)", "magic": b"hsqs", "offset": 0},
    {"name": "SquashFS (BE)", "magic": b"sqsh", "offset": 0},
    {"name": "CramFS", "magic": b"\x45\x3d\xcd\x28", "offset": 0},
    {"name": "ZIP archive", "magic": b"PK\x03\x04", "offset": 0},
    {"name": "Intel HEX", "magic": b":10", "offset": 0},
    {"name": "Motorola S-Record", "magic": b"S0", "offset": 0},
    {"name": "PE executable", "magic": b"MZ", "offset": 0},
]

SENSITIVE_PATTERNS = [
    (re.compile(rb"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE), "password"),
    (re.compile(rb"https?://\S+", re.IGNORECASE), "url"),
    (re.compile(rb"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE), "api_key"),
    (re.compile(rb"(?:secret|token)\s*[:=]\s*\S+", re.IGNORECASE), "secret"),
    (re.compile(rb"(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)", re.IGNORECASE), "private_key"),
    (re.compile(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "ip_address"),
    (re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE), "email"),
    (re.compile(rb"(?:root|admin|default)\s*[:=]\s*\S+", re.IGNORECASE), "default_cred"),
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_printable_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Extract printable ASCII strings of at least min_length characters."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


class IcsFirmwareAnalyzerModule(AtsModule):
    """Analyze firmware images for security-relevant artifacts: strings, entropy, headers."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_firmware_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze ICS firmware images for strings, entropy anomalies, and known headers",
            version="1.0.0",
            parameters=[
                Parameter(name="file_path", type=ParameterType.FILE,
                          description="Path to the firmware image file"),
                Parameter(name="analysis_type", type=ParameterType.CHOICE,
                          description="Type of analysis to perform",
                          default="strings", choices=["strings", "entropy", "headers"]),
                Parameter(name="block_size", type=ParameterType.INTEGER,
                          description="Block size in bytes for entropy analysis",
                          default=4096, min_value=256, max_value=65536),
            ],
            outputs=[
                OutputField(name="file_info", type="dict", description="Basic file information"),
                OutputField(name="findings", type="list", description="Security-relevant findings"),
                OutputField(name="entropy_map", type="list", description="Per-block entropy values"),
            ],
            tags=["advanced", "ics", "firmware", "reverse-engineering"],
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("file_path", ""):
            return False, "Firmware file path is required"
        return True, ""

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        file_path = config["file_path"]
        analysis_type = config.get("analysis_type", "strings")
        block_size = int(config.get("block_size", 4096))

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return {"error": f"File not found: {file_path}", "findings": [], "entropy_map": []}
        except PermissionError:
            return {"error": f"Permission denied: {file_path}", "findings": [], "entropy_map": []}

        file_info = {
            "path": file_path,
            "size_bytes": len(data),
            "size_human": f"{len(data) / 1024:.1f} KB" if len(data) < 1048576 else f"{len(data) / 1048576:.2f} MB",
            "overall_entropy": calculate_entropy(data),
            "md5_first_16": data[:16].hex(),
        }

        findings: list[dict[str, Any]] = []
        entropy_map: list[dict[str, Any]] = []

        # Header detection runs always as a baseline
        for hdr in KNOWN_FIRMWARE_HEADERS:
            idx = data.find(hdr["magic"])
            if idx != -1:
                findings.append({
                    "type": "header_match",
                    "name": hdr["name"],
                    "offset": idx,
                    "offset_hex": hex(idx),
                })

        if analysis_type in ("strings", "headers"):
            raw_strings = extract_printable_strings(data)
            sensitive_hits: list[dict[str, str]] = []
            for pattern, label in SENSITIVE_PATTERNS:
                for match in pattern.finditer(data):
                    sensitive_hits.append({
                        "category": label,
                        "value": match.group().decode("ascii", errors="replace")[:120],
                        "offset": match.start(),
                    })
            findings.append({
                "type": "string_extraction",
                "total_strings": len(raw_strings),
                "sensitive_count": len(sensitive_hits),
                "sensitive_items": sensitive_hits[:100],
                "sample_strings": raw_strings[:30],
            })

        if analysis_type in ("entropy", "headers"):
            high_entropy_blocks = 0
            for offset in range(0, len(data), block_size):
                block = data[offset:offset + block_size]
                ent = calculate_entropy(block)
                entry = {"offset": offset, "offset_hex": hex(offset), "entropy": ent, "size": len(block)}
                if ent > 7.5:
                    entry["flag"] = "high_entropy_encrypted_or_compressed"
                    high_entropy_blocks += 1
                elif ent < 1.0 and len(block) == block_size:
                    entry["flag"] = "low_entropy_padding_or_empty"
                entropy_map.append(entry)
            findings.append({
                "type": "entropy_analysis",
                "total_blocks": len(entropy_map),
                "high_entropy_blocks": high_entropy_blocks,
                "avg_entropy": round(sum(e["entropy"] for e in entropy_map) / max(len(entropy_map), 1), 4),
            })

        return {"file_info": file_info, "findings": findings, "entropy_map": entropy_map}
