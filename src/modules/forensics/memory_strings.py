"""Memory strings extraction module.

Extract readable strings from binary files and memory dumps.
Detect URLs, emails, IPs, file paths, and credential patterns.
Supports ASCII and UTF-16 encoding extraction.
"""

import asyncio
import os
import re
from typing import Any, Dict, List, Tuple
from collections import Counter

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Patterns for interesting strings
INTERESTING_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]{5,200}", re.IGNORECASE),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"),
    "file_path_win": re.compile(r"[A-Z]:\\(?:[^\\\s\"<>|*?]{1,100}\\)*[^\\\s\"<>|*?]{1,100}"),
    "file_path_unix": re.compile(r"/(?:[a-zA-Z0-9._-]+/){1,20}[a-zA-Z0-9._-]+"),
    "registry_key": re.compile(r"HKEY_[A-Z_]+\\[^\s\"]{5,200}", re.IGNORECASE),
    "credential_pattern": re.compile(
        r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.){1,5}(?:com|net|org|io|gov|edu|info|biz|co\.uk|de|fr|ru|cn)\b", re.IGNORECASE),
    "base64_blob": re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
    "hex_string": re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b"),
}


class MemoryStringsModule(AtsModule):
    """Extract readable strings from binary and memory dump files."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="memory_strings",
            category=ModuleCategory.FORENSICS,
            description="Extract readable strings from binary/memory dump files including URLs, emails, IPs, file paths, and credential patterns",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="file_path",
                    type=ParameterType.FILE,
                    description="Path to the binary file or memory dump",
                    required=True,
                ),
                Parameter(
                    name="min_length",
                    type=ParameterType.INTEGER,
                    description="Minimum string length to extract",
                    required=False,
                    default=4,
                    min_value=2,
                    max_value=100,
                ),
                Parameter(
                    name="encoding",
                    type=ParameterType.CHOICE,
                    description="String encoding to search for",
                    required=False,
                    default="both",
                    choices=["ascii", "utf16", "both"],
                ),
                Parameter(
                    name="max_strings",
                    type=ParameterType.INTEGER,
                    description="Maximum number of strings to collect (0 = unlimited)",
                    required=False,
                    default=50000,
                    min_value=0,
                    max_value=1000000,
                ),
                Parameter(
                    name="filter_interesting",
                    type=ParameterType.BOOLEAN,
                    description="Only return strings matching interesting patterns (URLs, IPs, emails, etc.)",
                    required=False,
                    default=False,
                ),
            ],
            outputs=[
                OutputField(name="total_strings", type="integer", description="Total strings extracted"),
                OutputField(name="interesting_strings", type="dict", description="Strings categorized by type"),
                OutputField(name="string_stats", type="dict", description="Statistics about extracted strings"),
                OutputField(name="all_strings", type="list", description="All extracted strings (if filter_interesting is False)"),
            ],
            tags=["forensics", "memory", "strings", "binary-analysis", "dump"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        file_path = config.get("file_path", "").strip()
        if not file_path:
            return False, "file_path is required"
        if not os.path.isfile(file_path):
            return False, f"File not found: {file_path}"
        return True, ""

    def _extract_ascii_strings(self, data: bytes, min_length: int) -> List[Tuple[int, str]]:
        """Extract ASCII printable strings from binary data."""
        results = []
        current = []
        start_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte < 127:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    results.append((start_offset, "".join(current)))
                current = []

        if len(current) >= min_length:
            results.append((start_offset, "".join(current)))

        return results

    def _extract_utf16_strings(self, data: bytes, min_length: int) -> List[Tuple[int, str]]:
        """Extract UTF-16LE strings from binary data."""
        results = []
        current = []
        start_offset = 0

        i = 0
        while i < len(data) - 1:
            lo = data[i]
            hi = data[i + 1]
            if hi == 0 and 32 <= lo < 127:
                if not current:
                    start_offset = i
                current.append(chr(lo))
                i += 2
            else:
                if len(current) >= min_length:
                    results.append((start_offset, "".join(current)))
                current = []
                i += 1

        if len(current) >= min_length:
            results.append((start_offset, "".join(current)))

        return results

    def _classify_string(self, s: str) -> List[Tuple[str, str]]:
        """Classify a string against known interesting patterns."""
        findings = []
        for category, pattern in INTERESTING_PATTERNS.items():
            matches = pattern.findall(s)
            for m in matches:
                findings.append((category, m if isinstance(m, str) else s))
        return findings

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        file_path = config["file_path"].strip()
        min_length = config.get("min_length", 4)
        encoding = config.get("encoding", "both")
        max_strings = config.get("max_strings", 50000)
        filter_interesting = config.get("filter_interesting", False)

        self.logger.info("extracting_strings", file=file_path, encoding=encoding)

        file_size = os.path.getsize(file_path)
        loop = asyncio.get_event_loop()

        all_strings: List[Dict[str, Any]] = []
        interesting: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in INTERESTING_PATTERNS}
        length_distribution = Counter()

        def _process():
            # Read in chunks for large files
            chunk_size = 64 * 1024 * 1024  # 64MB
            offset = 0
            collected = 0

            with open(file_path, "rb") as fh:
                while True:
                    if max_strings and collected >= max_strings:
                        break

                    # Read with overlap to avoid splitting strings at boundaries
                    data = fh.read(chunk_size)
                    if not data:
                        break

                    raw_strings: List[Tuple[int, str]] = []

                    if encoding in ("ascii", "both"):
                        raw_strings.extend(self._extract_ascii_strings(data, min_length))

                    if encoding in ("utf16", "both"):
                        raw_strings.extend(self._extract_utf16_strings(data, min_length))

                    # Deduplicate within chunk but keep offset info
                    seen = set()
                    for str_offset, s in raw_strings:
                        if max_strings and collected >= max_strings:
                            break

                        abs_offset = offset + str_offset
                        length_distribution[len(s)] += 1

                        # Classify string
                        classifications = self._classify_string(s)

                        if classifications:
                            for category, matched_value in classifications:
                                key = f"{category}:{matched_value}"
                                if key not in seen:
                                    seen.add(key)
                                    interesting[category].append({
                                        "value": matched_value,
                                        "offset": abs_offset,
                                        "context": s[:200],
                                    })

                        if not filter_interesting:
                            if s not in seen:
                                seen.add(s)
                                all_strings.append({
                                    "offset": abs_offset,
                                    "value": s[:500],
                                    "length": len(s),
                                })
                                collected += 1

                    offset += len(data)

        await loop.run_in_executor(None, _process)

        # Deduplicate interesting strings by value
        deduped_interesting = {}
        for category, items in interesting.items():
            seen_values = set()
            unique = []
            for item in items:
                val = item["value"]
                if val not in seen_values:
                    seen_values.add(val)
                    unique.append(item)
            if unique:
                deduped_interesting[category] = unique[:500]

        # Compute stats
        total_interesting = sum(len(v) for v in deduped_interesting.values())
        avg_length = 0
        if length_distribution:
            total_lengths = sum(k * v for k, v in length_distribution.items())
            total_count = sum(length_distribution.values())
            avg_length = total_lengths / total_count if total_count > 0 else 0

        stats = {
            "file_size": file_size,
            "total_extracted": sum(length_distribution.values()),
            "total_interesting": total_interesting,
            "average_length": round(avg_length, 1),
            "categories_found": list(deduped_interesting.keys()),
            "encoding_used": encoding,
        }

        self.logger.info(
            "string_extraction_complete",
            total=stats["total_extracted"],
            interesting=total_interesting,
        )

        return {
            "file_path": file_path,
            "total_strings": stats["total_extracted"],
            "interesting_strings": deduped_interesting,
            "string_stats": stats,
            "all_strings": all_strings[:max_strings] if not filter_interesting else [],
        }
