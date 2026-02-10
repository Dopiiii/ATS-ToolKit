"""File Format Fuzzer Module.

Generate malformed files in various formats to test parsers and file-handling code.
"""

import asyncio
import base64
import json
import random
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class FileFormatFuzzerModule(AtsModule):
    """Generate malformed files for format-testing parsers and applications."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="file_format_fuzzer",
            category=ModuleCategory.FUZZING,
            description="Generate malformed files (PDF, XML, JSON, CSV) for format testing",
            version="1.0.0",
            parameters=[
                Parameter(name="format", type=ParameterType.CHOICE, description="File format to fuzz", required=True, choices=["pdf", "xml", "json", "csv"]),
                Parameter(name="num_cases", type=ParameterType.INTEGER, description="Number of malformed files to generate", required=False, default=20, min_value=1, max_value=200),
                Parameter(name="severity", type=ParameterType.CHOICE, description="Corruption severity level", required=False, default="medium", choices=["low", "medium", "high"]),
                Parameter(name="seed", type=ParameterType.INTEGER, description="Random seed for reproducibility", required=False, default=None),
            ],
            outputs=[
                OutputField(name="test_cases", type="list", description="Generated malformed file test cases"),
                OutputField(name="summary", type="dict", description="Generation summary"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["fuzzing", "file", "format", "pdf", "xml", "json", "csv"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        fmt = config.get("format", "")
        if fmt not in ("pdf", "xml", "json", "csv"):
            return False, "format must be one of: pdf, xml, json, csv"
        return True, ""

    # ---- PDF generators ----
    def _fuzz_pdf(self, severity: str) -> List[Dict[str, Any]]:
        cases: List[Dict[str, Any]] = []
        valid_header = b"%PDF-1.4\n"
        valid_body = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        valid_trailer = b"trailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n0\n%%EOF"

        mutations = [
            ("invalid_header", b"%PDF-99.99\n" + valid_body + valid_trailer, "Invalid PDF version"),
            ("missing_eof", valid_header + valid_body + b"trailer\n<< >>", "Missing %%EOF marker"),
            ("corrupt_xref", valid_header + valid_body + b"xref\n0 9999\n" + b"\xff" * 200, "Corrupted xref table"),
            ("oversized_object", valid_header + b"1 0 obj\n" + b"A" * 50000 + b"\nendobj\n" + valid_trailer, "Oversized object data"),
            ("null_bytes", valid_header + b"\x00" * 500 + valid_trailer, "Null bytes in body"),
            ("nested_objects", valid_header + (b"1 0 obj\n<< >>\nendobj\n") * 500 + valid_trailer, "Deeply nested objects"),
            ("truncated", valid_header + valid_body[:len(valid_body) // 3], "Truncated file"),
            ("bad_stream", valid_header + b"1 0 obj\n<< /Length 999 >>\nstream\n" + b"\xff" * 50 + b"\nendstream\nendobj\n" + valid_trailer, "Bad stream length"),
        ]
        if severity == "high":
            mutations.append(("random_binary", bytes(random.randint(0, 255) for _ in range(4096)), "Completely random binary"))
            mutations.append(("giant_header", b"%PDF-1.4\n" + b"%" * 100000, "Giant comment header"))

        for name, data, desc in mutations:
            cases.append({"mutation": name, "description": desc, "size": len(data), "data_b64": base64.b64encode(data).decode()})
        return cases

    # ---- XML generators ----
    def _fuzz_xml(self, severity: str) -> List[Dict[str, Any]]:
        cases: List[Dict[str, Any]] = []
        mutations = [
            ("unclosed_tag", b"<?xml version='1.0'?><root><child>data</root>", "Unclosed child tag"),
            ("xxe_entity", b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "XXE entity injection"),
            ("billion_laughs", b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;">]><root>&lol3;</root>', "Billion laughs variant"),
            ("invalid_encoding", b"<?xml version='1.0' encoding='INVALID-999'?><root/>", "Invalid encoding declaration"),
            ("deep_nesting", b"<?xml version='1.0'?>" + b"<a>" * 500 + b"data" + b"</a>" * 500, "Deeply nested elements"),
            ("oversized_attr", b"<?xml version='1.0'?><root attr='" + b"A" * 50000 + b"'/>", "Oversized attribute value"),
            ("null_in_content", b"<?xml version='1.0'?><root>\x00\x00\x00</root>", "Null bytes in content"),
            ("malformed_cdata", b"<?xml version='1.0'?><root><![CDATA[" + b"\xff" * 200 + b"</root>", "Malformed CDATA section"),
        ]
        if severity == "high":
            mutations.append(("namespace_bomb", b"<?xml version='1.0'?><root " + b" ".join(b'xmlns:ns%d="http://x.com/%d"' % (i, i) for i in range(200)) + b"/>", "Namespace bomb"))

        for name, data, desc in mutations:
            cases.append({"mutation": name, "description": desc, "size": len(data), "data_b64": base64.b64encode(data).decode()})
        return cases

    # ---- JSON generators ----
    def _fuzz_json(self, severity: str) -> List[Dict[str, Any]]:
        cases: List[Dict[str, Any]] = []
        mutations = [
            ("trailing_comma", b'{"key": "value",}', "Trailing comma in object"),
            ("single_quotes", b"{'key': 'value'}", "Single quotes instead of double"),
            ("deep_nesting", b"[" * 500 + b"1" + b"]" * 500, "Deeply nested arrays"),
            ("huge_number", b'{"num": ' + b"9" * 1000 + b"}", "Extremely large number"),
            ("duplicate_keys", b'{"a":1,"a":2,"a":3}', "Duplicate keys"),
            ("unicode_escape", b'{"key": "\\uD800\\uDFFF"}', "Invalid surrogate pair"),
            ("null_key", b'{"\x00": "value"}', "Null byte in key"),
            ("truncated", b'{"key": "value", "arr": [1, 2,', "Truncated JSON"),
            ("mixed_types", b'{"a": [1, "two", true, null, {"b": []}]}', "Complex mixed types"),
        ]
        if severity == "high":
            huge_obj = b"{" + b",".join(b'"k%d":%d' % (i, i) for i in range(5000)) + b"}"
            mutations.append(("huge_object", huge_obj, "Object with 5000 keys"))

        for name, data, desc in mutations:
            cases.append({"mutation": name, "description": desc, "size": len(data), "data_b64": base64.b64encode(data).decode()})
        return cases

    # ---- CSV generators ----
    def _fuzz_csv(self, severity: str) -> List[Dict[str, Any]]:
        cases: List[Dict[str, Any]] = []
        mutations = [
            ("unbalanced_quotes", b'name,value\n"unclosed,field\nnext,row', "Unbalanced quotes"),
            ("null_bytes", b"a,b,c\n1,\x00,3\n4,5,6", "Null bytes in fields"),
            ("mixed_delimiters", b"a,b;c\td\n1,2;3\t4", "Mixed delimiters"),
            ("oversized_field", b"a,b\n" + b"X" * 100000 + b",value", "Oversized single field"),
            ("excessive_columns", b",".join(b"col%d" % i for i in range(1000)) + b"\n" + b",".join(b"%d" % i for i in range(1000)), "1000 columns"),
            ("newlines_in_field", b'a,b\n"line1\nline2\nline3",value', "Newlines inside quoted field"),
            ("formula_injection", b"a,b\n=CMD('calc'),value\n+1+1,test", "Formula injection payloads"),
            ("empty_rows", b"a,b\n\n\n\n1,2\n\n\n", "Many empty rows"),
        ]
        if severity == "high":
            big = b"a,b\n" + b"\n".join(b"%d,%d" % (i, i * 2) for i in range(10000))
            mutations.append(("massive_rows", big, "10000-row CSV"))

        for name, data, desc in mutations:
            cases.append({"mutation": name, "description": desc, "size": len(data), "data_b64": base64.b64encode(data).decode()})
        return cases

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        fmt = config["format"]
        num_cases = config.get("num_cases", 20)
        severity = config.get("severity", "medium")
        seed = config.get("seed")

        if seed is not None:
            random.seed(seed)

        self.logger.info("file_fuzz_start", format=fmt, count=num_cases, severity=severity)

        generator_map = {
            "pdf": self._fuzz_pdf,
            "xml": self._fuzz_xml,
            "json": self._fuzz_json,
            "csv": self._fuzz_csv,
        }

        all_cases = generator_map[fmt](severity)
        random.shuffle(all_cases)
        test_cases = all_cases[:num_cases]

        # Add index to each case
        for i, tc in enumerate(test_cases):
            tc["index"] = i

        summary = {
            "format": fmt,
            "severity": severity,
            "total_generated": len(test_cases),
            "total_available": len(all_cases),
            "avg_size": sum(tc["size"] for tc in test_cases) / len(test_cases) if test_cases else 0,
            "max_size": max(tc["size"] for tc in test_cases) if test_cases else 0,
        }

        self.logger.info("file_fuzz_complete", format=fmt, generated=len(test_cases))
        return {"test_cases": test_cases, "summary": summary}
