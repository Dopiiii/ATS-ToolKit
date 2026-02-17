"""DeFi protocol risk scanner.

Scans DeFi smart contract code and configurations for common attack patterns
including rug pulls, flash loan vulnerabilities, and oracle manipulation risks.
"""

import re
import json
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

RUGPULL_PATTERNS = [
    {"pattern": r"function\s+set(Fee|Tax)\s*\(", "desc": "Mutable fee/tax function (can be set to 100%)", "severity": "high"},
    {"pattern": r"function\s+(pause|unpause|blacklist|freeze)\s*\(", "desc": "Admin can pause/blacklist transfers", "severity": "high"},
    {"pattern": r"onlyOwner[^}]*transfer\(", "desc": "Owner can transfer arbitrary tokens", "severity": "critical"},
    {"pattern": r"function\s+withdraw\w*\s*\([^)]*\)\s*(external|public)\s+onlyOwner", "desc": "Owner-only withdrawal function", "severity": "high"},
    {"pattern": r"renounce\s*Ownership.*revert", "desc": "renounceOwnership is blocked (fake renounce)", "severity": "critical"},
    {"pattern": r"_maxTxAmount\s*=\s*1\b", "desc": "Max transaction amount can be set to 1 (freeze trading)", "severity": "high"},
    {"pattern": r"function\s+setMaxTx", "desc": "Admin can change max transaction limit", "severity": "medium"},
]

FLASH_LOAN_PATTERNS = [
    {"pattern": r"flashLoan|flashMint", "desc": "Flash loan/mint functionality present", "severity": "info"},
    {"pattern": r"getReserves\(\).*swap", "desc": "Reserve check before swap (potential flash loan target)", "severity": "medium"},
    {"pattern": r"balanceOf\([^)]+\)\s*[><=]+\s*\w+\s*;[^}]*transfer", "desc": "Balance check followed by transfer (flash loan manipulable)", "severity": "high"},
    {"pattern": r"slot0\(\)|latestRoundData\(\)", "desc": "Direct price feed query (oracle manipulation risk)", "severity": "medium"},
]

ORACLE_PATTERNS = [
    {"pattern": r"getReserves\(\)", "desc": "Using AMM reserves as price source (easily manipulated)", "severity": "high"},
    {"pattern": r"balanceOf\([^)]+\)\s*/\s*totalSupply", "desc": "Share price from balance ratio (flash loan manipulable)", "severity": "high"},
    {"pattern": r"latestRoundData", "desc": "Chainlink oracle usage (check staleness handling)", "severity": "info"},
    {"pattern": r"twap|TWAP|timeWeightedAverage", "desc": "TWAP oracle (more resistant to manipulation)", "severity": "info"},
    {"pattern": r"block\.timestamp\s*-\s*\w+\s*[<>]", "desc": "Time-based oracle staleness check present", "severity": "info"},
]

GENERAL_DEFI_RISKS = [
    {"pattern": r"approve\([^,]+,\s*type\(uint256\)\.max", "desc": "Infinite approval pattern", "severity": "medium"},
    {"pattern": r"delegatecall", "desc": "Delegatecall in DeFi context (proxy risk)", "severity": "high"},
    {"pattern": r"selfdestruct", "desc": "Self-destruct capability in DeFi contract", "severity": "critical"},
    {"pattern": r"assembly\s*\{", "desc": "Inline assembly usage (hard to audit)", "severity": "medium"},
    {"pattern": r"abi\.encodePacked\([^)]*,\s*[^)]*\)", "desc": "encodePacked with multiple args (hash collision risk)", "severity": "medium"},
]


class Web3DefiScannerModule(AtsModule):
    """Scan DeFi protocol contracts for common attack patterns and risks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_defi_scanner",
            category=ModuleCategory.ADVANCED,
            description="Scan DeFi protocol contracts for rug pull, flash loan, and oracle attack patterns",
            version="1.0.0",
            parameters=[
                Parameter(name="protocol_address", type=ParameterType.STRING,
                          description="DeFi contract source code or protocol address to analyze", required=True),
                Parameter(name="risk_checks", type=ParameterType.CHOICE,
                          description="Categories of risk to check",
                          choices=["all", "rugpull", "flash_loan", "oracle"], default="all"),
                Parameter(name="include_info", type=ParameterType.BOOLEAN,
                          description="Include informational (non-risk) findings", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Detected risk patterns"),
                OutputField(name="risk_score", type="integer", description="Overall risk score 0-100"),
                OutputField(name="risk_breakdown", type="dict", description="Findings count per category"),
            ],
            tags=["advanced", "web3", "defi", "flash-loan", "rugpull", "oracle"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("protocol_address", "").strip()
        if not target:
            return False, "Protocol address or source code is required"
        return True, ""

    def _scan_patterns(self, source: str, patterns: list[dict[str, str]],
                       category: str, include_info: bool) -> list[dict[str, Any]]:
        """Scan source for a list of regex patterns."""
        findings: list[dict[str, Any]] = []
        for entry in patterns:
            if not include_info and entry["severity"] == "info":
                continue
            matches = list(re.finditer(entry["pattern"], source))
            if matches:
                lines = set()
                for m in matches:
                    line_no = source[:m.start()].count("\n") + 1
                    lines.add(line_no)
                findings.append({
                    "category": category,
                    "severity": entry["severity"],
                    "description": entry["desc"],
                    "occurrences": len(matches),
                    "lines": sorted(lines),
                })
        return findings

    def _calculate_risk_score(self, findings: list[dict[str, Any]]) -> int:
        """Calculate aggregate risk score from findings."""
        weights = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}
        score = 0
        for f in findings:
            w = weights.get(f["severity"], 0)
            score += w * min(f.get("occurrences", 1), 5)
        return min(score, 100)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        source = config["protocol_address"].strip()
        risk_checks = config.get("risk_checks", "all")
        include_info = config.get("include_info", True)

        all_findings: list[dict[str, Any]] = []
        risk_breakdown: dict[str, int] = {}

        scan_map = {
            "rugpull": ("rugpull", RUGPULL_PATTERNS),
            "flash_loan": ("flash_loan", FLASH_LOAN_PATTERNS),
            "oracle": ("oracle", ORACLE_PATTERNS),
        }

        categories_to_scan = list(scan_map.keys()) if risk_checks == "all" else [risk_checks]

        for cat_key in categories_to_scan:
            if cat_key in scan_map:
                cat_name, patterns = scan_map[cat_key]
                findings = self._scan_patterns(source, patterns, cat_name, include_info)
                all_findings.extend(findings)
                if findings:
                    risk_breakdown[cat_name] = len(findings)

        # Always scan general DeFi risks
        general = self._scan_patterns(source, GENERAL_DEFI_RISKS, "general", include_info)
        all_findings.extend(general)
        if general:
            risk_breakdown["general"] = len(general)

        risk_score = self._calculate_risk_score(all_findings)

        # Determine overall risk level
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high"
        elif risk_score >= 15:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_checks": risk_checks,
            "findings": all_findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_breakdown": risk_breakdown,
            "total_findings": len(all_findings),
        }
