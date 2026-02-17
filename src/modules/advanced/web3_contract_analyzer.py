"""Smart contract source code vulnerability analyzer.

Performs static analysis on Solidity smart contract source code to detect
common vulnerability patterns including reentrancy, integer overflow,
unchecked external calls, tx.origin misuse, and delegatecall risks.
"""

import re
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

VULNERABILITY_PATTERNS: dict[str, list[dict[str, str]]] = {
    "reentrancy": [
        {"pattern": r"\.call\{value:", "desc": "Low-level call with value before state change"},
        {"pattern": r"\.call\.value\(", "desc": "Legacy call.value pattern (reentrancy risk)"},
        {"pattern": r"\.send\(", "desc": "send() usage without reentrancy guard"},
        {"pattern": r"\.transfer\(", "desc": "transfer() usage (limited gas but still notable)"},
    ],
    "integer_overflow": [
        {"pattern": r"(?<!\busing\b\s{1,20}\bSafeMath\b)[^\n]*\b\w+\s*\+\s*\w+", "desc": "Addition without SafeMath (pre-0.8.0 risk)"},
        {"pattern": r"(?<!\busing\b\s{1,20}\bSafeMath\b)[^\n]*\b\w+\s*\*\s*\w+", "desc": "Multiplication without SafeMath"},
        {"pattern": r"unchecked\s*\{", "desc": "Unchecked arithmetic block"},
    ],
    "unchecked_calls": [
        {"pattern": r"\.call\(", "desc": "Low-level call without return value check"},
        {"pattern": r"\.delegatecall\(", "desc": "delegatecall usage (code execution risk)"},
        {"pattern": r"\.staticcall\(", "desc": "staticcall without return check"},
    ],
    "tx_origin": [
        {"pattern": r"tx\.origin", "desc": "tx.origin used (phishing vulnerability)"},
        {"pattern": r"require\s*\(\s*tx\.origin\s*==", "desc": "tx.origin in access control (critical)"},
    ],
    "delegatecall": [
        {"pattern": r"\.delegatecall\(", "desc": "delegatecall to potentially untrusted code"},
        {"pattern": r"delegatecall\(abi\.encodeWithSignature", "desc": "delegatecall with encoded signature"},
    ],
    "access_control": [
        {"pattern": r"function\s+\w+\s*\([^)]*\)\s*public(?!\s+view)(?!\s+pure)", "desc": "Public function without access modifier"},
        {"pattern": r"selfdestruct\s*\(", "desc": "selfdestruct present (can destroy contract)"},
        {"pattern": r"suicide\s*\(", "desc": "Deprecated suicide() call"},
    ],
    "front_running": [
        {"pattern": r"block\.timestamp", "desc": "block.timestamp dependency (miner manipulation)"},
        {"pattern": r"block\.number", "desc": "block.number dependency"},
        {"pattern": r"blockhash\s*\(", "desc": "blockhash as randomness source (predictable)"},
    ],
}

SEVERITY_MAP = {
    "reentrancy": "critical",
    "integer_overflow": "high",
    "unchecked_calls": "high",
    "tx_origin": "critical",
    "delegatecall": "critical",
    "access_control": "high",
    "front_running": "medium",
}


class Web3ContractAnalyzerModule(AtsModule):
    """Analyze Solidity smart contract source code for vulnerability patterns."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_contract_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze smart contract source code for common vulnerability patterns",
            version="1.0.0",
            parameters=[
                Parameter(name="source_code", type=ParameterType.STRING,
                          description="Solidity smart contract source code to analyze", required=True),
                Parameter(name="chain", type=ParameterType.CHOICE,
                          description="Target blockchain for context-specific checks",
                          choices=["ethereum", "bsc", "polygon"], default="ethereum"),
                Parameter(name="check_categories", type=ParameterType.STRING,
                          description="Comma-separated vuln categories (all, reentrancy, overflow, unchecked, tx_origin, delegatecall, access, frontrun)",
                          default="all"),
            ],
            outputs=[
                OutputField(name="vulnerabilities", type="list", description="Detected vulnerabilities with severity"),
                OutputField(name="risk_score", type="integer", description="Overall risk score 0-100"),
                OutputField(name="summary", type="dict", description="Counts per vulnerability category"),
            ],
            tags=["advanced", "web3", "smart-contract", "solidity", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        source = config.get("source_code", "").strip()
        if not source:
            return False, "Source code is required"
        if len(source) < 20:
            return False, "Source code appears too short to be a valid contract"
        return True, ""

    def _detect_compiler_version(self, source: str) -> str | None:
        """Extract the Solidity pragma version from source."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else None

    def _is_pre_080(self, version_pragma: str | None) -> bool:
        """Check if the compiler version is before 0.8.0 (no built-in overflow checks)."""
        if not version_pragma:
            return True  # assume vulnerable if unknown
        match = re.search(r"0\.(\d+)\.", version_pragma)
        if match:
            minor = int(match.group(1))
            return minor < 8
        return True

    def _scan_category(self, source: str, category: str) -> list[dict[str, Any]]:
        """Scan source code for a specific vulnerability category."""
        findings: list[dict[str, Any]] = []
        patterns = VULNERABILITY_PATTERNS.get(category, [])
        for entry in patterns:
            matches = list(re.finditer(entry["pattern"], source))
            if matches:
                lines_hit = set()
                for m in matches:
                    line_no = source[:m.start()].count("\n") + 1
                    lines_hit.add(line_no)
                findings.append({
                    "category": category,
                    "severity": SEVERITY_MAP.get(category, "info"),
                    "description": entry["desc"],
                    "occurrences": len(matches),
                    "lines": sorted(lines_hit),
                })
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        source = config["source_code"].strip()
        chain = config.get("chain", "ethereum")
        check_input = config.get("check_categories", "all").strip().lower()

        category_map = {
            "all": list(VULNERABILITY_PATTERNS.keys()),
            "reentrancy": ["reentrancy"],
            "overflow": ["integer_overflow"],
            "unchecked": ["unchecked_calls"],
            "tx_origin": ["tx_origin"],
            "delegatecall": ["delegatecall"],
            "access": ["access_control"],
            "frontrun": ["front_running"],
        }

        if check_input == "all":
            categories = list(VULNERABILITY_PATTERNS.keys())
        else:
            categories = []
            for token in check_input.split(","):
                token = token.strip()
                categories.extend(category_map.get(token, []))
            if not categories:
                categories = list(VULNERABILITY_PATTERNS.keys())

        compiler_version = self._detect_compiler_version(source)
        is_pre_080 = self._is_pre_080(compiler_version)

        all_findings: list[dict[str, Any]] = []
        summary: dict[str, int] = {}

        for category in categories:
            # Skip integer overflow for Solidity >= 0.8.0 (built-in checks)
            if category == "integer_overflow" and not is_pre_080:
                unchecked_findings = []
                for entry in VULNERABILITY_PATTERNS["integer_overflow"]:
                    if "unchecked" in entry["pattern"]:
                        unchecked_findings.extend(self._scan_category(source, category))
                if unchecked_findings:
                    all_findings.extend(unchecked_findings)
                    summary[category] = len(unchecked_findings)
                continue

            findings = self._scan_category(source, category)
            all_findings.extend(findings)
            if findings:
                summary[category] = len(findings)

        # Calculate risk score
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        risk_score = 0
        for f in all_findings:
            weight = severity_weights.get(f["severity"], 1)
            risk_score += weight * f.get("occurrences", 1)
        risk_score = min(risk_score, 100)

        # Chain-specific notes
        chain_notes: list[str] = []
        if chain == "bsc" and any(f["category"] == "front_running" for f in all_findings):
            chain_notes.append("BSC has faster block times; front-running is easier")
        if chain == "polygon" and any(f["category"] == "reentrancy" for f in all_findings):
            chain_notes.append("Polygon L2 may have different gas economics for reentrancy attacks")

        return {
            "chain": chain,
            "compiler_version": compiler_version,
            "is_pre_080": is_pre_080,
            "vulnerabilities": all_findings,
            "risk_score": risk_score,
            "summary": summary,
            "total_issues": len(all_findings),
            "chain_notes": chain_notes,
        }
