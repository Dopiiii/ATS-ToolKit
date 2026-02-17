"""ERC-20 token smart contract auditor.

Audits ERC-20 token source code for honeypot mechanisms, hidden fees,
blacklist/whitelist functions, and other token-specific vulnerabilities.
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

HONEYPOT_PATTERNS = [
    {"pattern": r"function\s+_transfer\b[^}]*require\s*\([^)]*(?:_isExcluded|isBot|blacklist|_blocked)",
     "desc": "Transfer restriction based on blacklist (honeypot mechanism)", "severity": "critical"},
    {"pattern": r"function\s+setMaxSell\s*\(|maxSellAmount\s*=\s*0",
     "desc": "Adjustable or zero max sell amount (can block selling)", "severity": "critical"},
    {"pattern": r"tradingEnabled\s*=\s*false|tradingOpen\s*=\s*false",
     "desc": "Trading can be disabled by admin", "severity": "critical"},
    {"pattern": r"function\s+(?:enable|open|start)Trading\s*\(",
     "desc": "Trading toggle function (check if it can be reversed)", "severity": "high"},
    {"pattern": r"cooldown|_cooldownTime|cooldownEnabled",
     "desc": "Cooldown mechanism on trades (can be used to trap)", "severity": "medium"},
    {"pattern": r"require\s*\(\s*(?:from|to|sender|recipient)\s*!=\s*(?:pair|uniswapV2Pair)",
     "desc": "Direct DEX pair interaction blocked for certain addresses", "severity": "critical"},
]

HIDDEN_FEE_PATTERNS = [
    {"pattern": r"(?:_tax|_fee|_buyFee|_sellFee)\s*=\s*(\d+)",
     "desc": "Fee/tax variable found", "severity": "medium"},
    {"pattern": r"function\s+set(?:Buy|Sell|Transfer)?(?:Fee|Tax)\s*\(",
     "desc": "Admin can change fee/tax amounts", "severity": "high"},
    {"pattern": r"(?:buyTax|sellTax|_totalFee)\s*>\s*(?:25|30|50|90|100)",
     "desc": "Fee check allows excessively high values", "severity": "critical"},
    {"pattern": r"function\s+_transfer[^}]*(?:fee|tax)[^}]*(?:fee|tax)[^}]*(?:fee|tax)",
     "desc": "Multiple fee layers in transfer function", "severity": "high"},
    {"pattern": r"liquidityFee|marketingFee|devFee|burnFee|reflectionFee",
     "desc": "Multiple fee types detected (check total)", "severity": "medium"},
    {"pattern": r"swapAndLiquify|swapTokensForEth",
     "desc": "Auto-swap mechanism (can cause price impact on sells)", "severity": "medium"},
]

BLACKLIST_PATTERNS = [
    {"pattern": r"mapping\s*\([^)]*\)\s*(?:public|private|internal)\s+(?:_?is)?[Bb]lacklist",
     "desc": "Blacklist mapping present", "severity": "high"},
    {"pattern": r"function\s+(?:add|set)?[Bb]lacklist\s*\(",
     "desc": "Blacklist management function", "severity": "high"},
    {"pattern": r"function\s+(?:add|set)?[Ww]hitelist\s*\(",
     "desc": "Whitelist management function", "severity": "medium"},
    {"pattern": r"isBot\[|_bots\[|antibotEnabled",
     "desc": "Anti-bot mechanism (can be used against normal users)", "severity": "high"},
    {"pattern": r"require\s*\(\s*!(?:isBlacklisted|_blacklist|bots)\[",
     "desc": "Transfer blocked by blacklist check", "severity": "high"},
]

SUPPLY_PATTERNS = [
    {"pattern": r"function\s+mint\s*\([^)]*\)\s*(?:external|public)",
     "desc": "Public minting function (can inflate supply)", "severity": "high"},
    {"pattern": r"_mint\(\s*(?:msg\.sender|owner\(\))",
     "desc": "Minting directly to admin", "severity": "high"},
    {"pattern": r"MAX_SUPPLY|maxSupply|_cap", "desc": "Supply cap defined", "severity": "info"},
    {"pattern": r"function\s+burn\s*\(", "desc": "Burn function present", "severity": "info"},
]


class Web3TokenAuditorModule(AtsModule):
    """Audit ERC-20 token source code for honeypot, hidden fees, and blacklist risks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_token_auditor",
            category=ModuleCategory.ADVANCED,
            description="Audit ERC-20 token contracts for honeypot patterns, hidden fees, and blacklist functions",
            version="1.0.0",
            parameters=[
                Parameter(name="source_code", type=ParameterType.STRING,
                          description="ERC-20 token contract source code to audit", required=True),
                Parameter(name="audit_level", type=ParameterType.CHOICE,
                          description="Depth of audit to perform",
                          choices=["basic", "thorough"], default="thorough"),
                Parameter(name="extract_fees", type=ParameterType.BOOLEAN,
                          description="Attempt to extract configured fee percentages", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Audit findings with severity"),
                OutputField(name="honeypot_risk", type="string", description="Honeypot risk level"),
                OutputField(name="fee_info", type="dict", description="Extracted fee/tax information"),
                OutputField(name="risk_score", type="integer", description="Overall risk score 0-100"),
            ],
            tags=["advanced", "web3", "erc20", "token", "honeypot", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        source = config.get("source_code", "").strip()
        if not source:
            return False, "Token source code is required"
        if len(source) < 30:
            return False, "Source code too short for a valid ERC-20 contract"
        return True, ""

    def _scan_patterns(self, source: str, patterns: list[dict[str, str]],
                       category: str) -> list[dict[str, Any]]:
        """Match regex patterns against source code."""
        findings: list[dict[str, Any]] = []
        for entry in patterns:
            matches = list(re.finditer(entry["pattern"], source, re.DOTALL))
            if matches:
                lines = set()
                for m in matches:
                    lines.add(source[:m.start()].count("\n") + 1)
                findings.append({
                    "category": category,
                    "severity": entry["severity"],
                    "description": entry["desc"],
                    "occurrences": len(matches),
                    "lines": sorted(lines),
                })
        return findings

    def _extract_fee_values(self, source: str) -> dict[str, Any]:
        """Try to extract fee/tax percentage values from source."""
        fee_info: dict[str, Any] = {"fees_found": [], "total_estimated": None}
        fee_patterns = [
            (r"(?:_?buyFee|buyTax|_buyTax)\s*=\s*(\d+)", "buy_fee"),
            (r"(?:_?sellFee|sellTax|_sellTax)\s*=\s*(\d+)", "sell_fee"),
            (r"(?:_?transferFee|transferTax)\s*=\s*(\d+)", "transfer_fee"),
            (r"(?:_?liquidityFee)\s*=\s*(\d+)", "liquidity_fee"),
            (r"(?:_?marketingFee)\s*=\s*(\d+)", "marketing_fee"),
            (r"(?:_?devFee)\s*=\s*(\d+)", "dev_fee"),
            (r"(?:_?totalFee|_totalTax)\s*=\s*(\d+)", "total_fee"),
        ]
        total = 0
        for pattern, name in fee_patterns:
            match = re.search(pattern, source)
            if match:
                value = int(match.group(1))
                fee_info["fees_found"].append({"name": name, "value": value})
                if "total" not in name:
                    total += value
                else:
                    fee_info["total_estimated"] = value

        if fee_info["total_estimated"] is None and total > 0:
            fee_info["total_estimated"] = total

        if fee_info["total_estimated"] and fee_info["total_estimated"] > 25:
            fee_info["warning"] = "Total fees exceed 25% - possible honeypot"

        return fee_info

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        source = config["source_code"].strip()
        audit_level = config.get("audit_level", "thorough")
        extract_fees = config.get("extract_fees", True)

        all_findings: list[dict[str, Any]] = []

        # Always check honeypot patterns
        all_findings.extend(self._scan_patterns(source, HONEYPOT_PATTERNS, "honeypot"))
        all_findings.extend(self._scan_patterns(source, HIDDEN_FEE_PATTERNS, "hidden_fees"))

        if audit_level == "thorough":
            all_findings.extend(self._scan_patterns(source, BLACKLIST_PATTERNS, "blacklist"))
            all_findings.extend(self._scan_patterns(source, SUPPLY_PATTERNS, "supply"))

        # Extract fee info
        fee_info: dict[str, Any] = {}
        if extract_fees:
            fee_info = self._extract_fee_values(source)

        # Honeypot risk assessment
        honeypot_findings = [f for f in all_findings if f["category"] == "honeypot"]
        critical_honeypot = any(f["severity"] == "critical" for f in honeypot_findings)
        if critical_honeypot:
            honeypot_risk = "critical"
        elif len(honeypot_findings) >= 2:
            honeypot_risk = "high"
        elif honeypot_findings:
            honeypot_risk = "medium"
        else:
            honeypot_risk = "low"

        # Risk score
        weights = {"critical": 25, "high": 14, "medium": 6, "low": 2, "info": 0}
        risk_score = 0
        for f in all_findings:
            risk_score += weights.get(f["severity"], 0) * min(f.get("occurrences", 1), 5)
        risk_score = min(risk_score, 100)

        return {
            "audit_level": audit_level,
            "findings": all_findings,
            "honeypot_risk": honeypot_risk,
            "fee_info": fee_info,
            "risk_score": risk_score,
            "total_findings": len(all_findings),
            "risk_level": "critical" if risk_score >= 65 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low",
        }
