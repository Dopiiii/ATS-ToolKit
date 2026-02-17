"""NFT smart contract analyzer.

Analyzes NFT (ERC-721/ERC-1155) contracts for hidden minting functions,
metadata manipulation vulnerabilities, ownership concentration, and
other NFT-specific security issues.
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

HIDDEN_MINT_PATTERNS = [
    {"pattern": r"function\s+\w*[Mm]int\w*\s*\([^)]*\)\s*(external|public)\s+onlyOwner",
     "desc": "Owner-only minting function (can inflate supply)", "severity": "high"},
    {"pattern": r"_mint\([^)]*\)\s*;(?!.*require\s*\(\s*totalSupply)",
     "desc": "Minting without supply cap check", "severity": "high"},
    {"pattern": r"_mint\([^)]*msg\.sender",
     "desc": "Direct minting to msg.sender (check for hidden admin mints)", "severity": "medium"},
    {"pattern": r"function\s+airdrop\s*\(", "desc": "Airdrop function (potential stealth mint)", "severity": "medium"},
    {"pattern": r"batchMint|mintBatch|bulkMint",
     "desc": "Batch minting capability (large supply inflation risk)", "severity": "medium"},
    {"pattern": r"maxSupply\s*=\s*type\(uint256\)\.max",
     "desc": "Max supply set to uint256 max (effectively unlimited)", "severity": "high"},
]

METADATA_PATTERNS = [
    {"pattern": r"function\s+setBaseURI\s*\(", "desc": "Mutable base URI (metadata can be changed post-reveal)", "severity": "high"},
    {"pattern": r"function\s+setTokenURI\s*\(", "desc": "Individual token URI can be modified", "severity": "high"},
    {"pattern": r"function\s+set(Contract|Collection)URI\s*\(",
     "desc": "Collection metadata URI is mutable", "severity": "medium"},
    {"pattern": r"_baseTokenURI\s*=|baseURI\s*=",
     "desc": "Base URI stored in mutable state variable", "severity": "medium"},
    {"pattern": r"function\s+freeze\w*[Mm]etadata",
     "desc": "Metadata freeze function present (positive if called)", "severity": "info"},
    {"pattern": r"revealed\s*=\s*false|isRevealed\s*=\s*false",
     "desc": "Reveal mechanism detected (ensure it cannot be re-hidden)", "severity": "medium"},
]

OWNERSHIP_PATTERNS = [
    {"pattern": r"function\s+withdraw\w*\s*\([^)]*\)\s*(external|public)(?:\s+onlyOwner)?",
     "desc": "Withdrawal function (check fund destination)", "severity": "medium"},
    {"pattern": r"payable\(owner\(\)\)\.transfer|payable\(msg\.sender\)\.transfer",
     "desc": "Funds sent to owner/sender", "severity": "medium"},
    {"pattern": r"setApprovalForAll\([^,]+,\s*true\)",
     "desc": "Blanket approval in contract code (potential theft vector)", "severity": "high"},
    {"pattern": r"transferOwnership\s*\([^)]*\)\s*public(?!\s+onlyOwner)",
     "desc": "Ownership transfer without access control", "severity": "critical"},
    {"pattern": r"renounceOwnership.*revert", "desc": "Blocked renounceOwnership (fake decentralization)", "severity": "high"},
]

ROYALTY_PATTERNS = [
    {"pattern": r"function\s+setRoyalty\w*\s*\(", "desc": "Mutable royalty settings", "severity": "medium"},
    {"pattern": r"royaltyInfo\s*\(", "desc": "EIP-2981 royalty standard implemented", "severity": "info"},
    {"pattern": r"_setDefaultRoyalty\(", "desc": "Default royalty setter called", "severity": "info"},
    {"pattern": r"royalty.*(?:100|10000|_denominator)", "desc": "Royalty percentage config present", "severity": "info"},
]


class Web3NftAnalyzerModule(AtsModule):
    """Analyze NFT smart contracts for hidden minting, metadata manipulation, and ownership risks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_nft_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze NFT contracts for hidden minting, metadata manipulation, and ownership issues",
            version="1.0.0",
            parameters=[
                Parameter(name="contract_address", type=ParameterType.STRING,
                          description="NFT contract source code to analyze", required=True),
                Parameter(name="checks", type=ParameterType.CHOICE,
                          description="Category of checks to perform",
                          choices=["metadata", "ownership", "hidden_mint", "all"], default="all"),
                Parameter(name="include_royalty", type=ParameterType.BOOLEAN,
                          description="Include royalty configuration analysis", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Detected issues with severity"),
                OutputField(name="risk_score", type="integer", description="Overall risk score 0-100"),
                OutputField(name="nft_standard", type="string", description="Detected NFT standard (ERC-721/ERC-1155)"),
            ],
            tags=["advanced", "web3", "nft", "erc721", "erc1155", "metadata"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("contract_address", "").strip()
        if not target:
            return False, "Contract source code is required"
        if len(target) < 20:
            return False, "Input too short to be valid contract code"
        return True, ""

    def _detect_nft_standard(self, source: str) -> str:
        """Detect whether the contract implements ERC-721 or ERC-1155."""
        has_721 = bool(re.search(r"ERC721|IERC721|ERC721Enumerable|ERC721URIStorage", source))
        has_1155 = bool(re.search(r"ERC1155|IERC1155", source))
        if has_721 and has_1155:
            return "ERC-721 + ERC-1155 (multi-standard)"
        if has_1155:
            return "ERC-1155"
        if has_721:
            return "ERC-721"
        return "unknown"

    def _scan_patterns(self, source: str, patterns: list[dict[str, str]],
                       category: str) -> list[dict[str, Any]]:
        """Scan source against a pattern list."""
        findings: list[dict[str, Any]] = []
        for entry in patterns:
            matches = list(re.finditer(entry["pattern"], source))
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

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        source = config["contract_address"].strip()
        checks = config.get("checks", "all")
        include_royalty = config.get("include_royalty", True)

        nft_standard = self._detect_nft_standard(source)
        all_findings: list[dict[str, Any]] = []
        breakdown: dict[str, int] = {}

        scan_categories: dict[str, list[dict[str, str]]] = {}
        if checks in ("all", "hidden_mint"):
            scan_categories["hidden_mint"] = HIDDEN_MINT_PATTERNS
        if checks in ("all", "metadata"):
            scan_categories["metadata"] = METADATA_PATTERNS
        if checks in ("all", "ownership"):
            scan_categories["ownership"] = OWNERSHIP_PATTERNS
        if include_royalty:
            scan_categories["royalty"] = ROYALTY_PATTERNS

        for cat_name, patterns in scan_categories.items():
            findings = self._scan_patterns(source, patterns, cat_name)
            all_findings.extend(findings)
            if findings:
                breakdown[cat_name] = len(findings)

        # Risk scoring
        weights = {"critical": 28, "high": 16, "medium": 7, "low": 3, "info": 0}
        risk_score = 0
        for f in all_findings:
            risk_score += weights.get(f["severity"], 0) * min(f.get("occurrences", 1), 4)
        risk_score = min(risk_score, 100)

        risk_level = "critical" if risk_score >= 65 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low"

        return {
            "nft_standard": nft_standard,
            "checks_performed": checks,
            "findings": all_findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "total_findings": len(all_findings),
        }
