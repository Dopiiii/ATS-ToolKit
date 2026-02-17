"""Web3 phishing detection module.

Detects Web3-specific phishing patterns in URLs, contract addresses,
and approval requests including fake dApps, suspicious token approvals,
and known phishing signatures.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

PHISHING_URL_PATTERNS = [
    {"pattern": r"(?:metamask|uniswap|opensea|aave|compound|pancakeswap)[_\-]?(?:app|dapp|swap|io|finance|org)\.",
     "desc": "Domain impersonates known Web3 project", "severity": "critical"},
    {"pattern": r"(?:airdrop|claim|reward|free[\-_]?mint|free[\-_]?nft)[\-_.]",
     "desc": "Domain contains phishing bait keywords (airdrop/claim/free)", "severity": "high"},
    {"pattern": r"connect[\-_]?wallet|verify[\-_]?wallet|sync[\-_]?wallet",
     "desc": "Wallet connection phishing pattern in domain", "severity": "critical"},
    {"pattern": r"(?:\.tk|\.ml|\.ga|\.cf|\.gq)$",
     "desc": "Free TLD commonly used in phishing", "severity": "high"},
    {"pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
     "desc": "IP address in URL (legitimate dApps use domains)", "severity": "high"},
    {"pattern": r"(?:bit\.ly|tinyurl|t\.co|short\.io|is\.gd)",
     "desc": "URL shortener (hiding actual destination)", "severity": "medium"},
]

PHISHING_CONTRACT_PATTERNS = [
    {"pattern": r"setApprovalForAll\s*\(",
     "desc": "setApprovalForAll request (grants full collection access)", "severity": "high"},
    {"pattern": r"approve\s*\([^,]+,\s*(?:type\(uint256\)\.max|115792089237316195423570985008687907853269984665640564039457584007913129639935|0xffffff)",
     "desc": "Unlimited token approval (infinite allowance)", "severity": "critical"},
    {"pattern": r"transferFrom\s*\([^)]+\)",
     "desc": "transferFrom call (moving user assets)", "severity": "high"},
    {"pattern": r"function\s+(?:claim|airdrop|reward)\s*\([^)]*\)\s*(?:external|public)\s+payable",
     "desc": "Payable claim/airdrop function (likely phishing contract)", "severity": "critical"},
    {"pattern": r"function\s+\w+\s*\([^)]*\)[^{]*\{\s*(?:selfdestruct|suicide)",
     "desc": "Function with immediate self-destruct (grab and run pattern)", "severity": "critical"},
    {"pattern": r"permit\s*\(",
     "desc": "EIP-2612 permit call (gasless approval - can be phished via signature)", "severity": "high"},
]

SUSPICIOUS_APPROVAL_KEYWORDS = [
    "setApprovalForAll", "approve(address,uint256)", "increaseAllowance",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
]

LEGITIMATE_DOMAINS = {
    "uniswap.org", "app.uniswap.org", "opensea.io", "metamask.io",
    "aave.com", "app.aave.com", "compound.finance", "curve.fi",
    "pancakeswap.finance", "sushi.com", "etherscan.io", "polygonscan.com",
    "bscscan.com",
}


class Web3PhishingDetectorModule(AtsModule):
    """Detect Web3 phishing patterns in URLs, contracts, and approval requests."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_phishing_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect Web3 phishing patterns in URLs, smart contracts, and token approvals",
            version="1.0.0",
            parameters=[
                Parameter(name="url_or_address", type=ParameterType.STRING,
                          description="URL, contract address, or contract source to analyze", required=True),
                Parameter(name="check_type", type=ParameterType.CHOICE,
                          description="Type of phishing check to perform",
                          choices=["website", "contract", "both"], default="both"),
                Parameter(name="include_approval_check", type=ParameterType.BOOLEAN,
                          description="Check for suspicious approval patterns", default=True),
            ],
            outputs=[
                OutputField(name="is_phishing", type="boolean", description="Whether phishing indicators were found"),
                OutputField(name="confidence", type="string", description="Detection confidence level"),
                OutputField(name="findings", type="list", description="Specific phishing indicators found"),
            ],
            tags=["advanced", "web3", "phishing", "scam", "approval", "security"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("url_or_address", "").strip()
        if not target:
            return False, "URL or contract address/source is required"
        return True, ""

    def _analyze_url(self, target: str) -> list[dict[str, Any]]:
        """Analyze a URL for phishing patterns."""
        findings: list[dict[str, Any]] = []

        # Try to parse as URL
        if "://" not in target:
            target_url = "https://" + target
        else:
            target_url = target

        try:
            parsed = urlparse(target_url)
            domain = parsed.hostname or ""
        except Exception:
            domain = target.lower()

        # Check against known legitimate domains
        if domain in LEGITIMATE_DOMAINS:
            findings.append({"category": "website", "severity": "info",
                             "description": f"Domain {domain} matches known legitimate project"})
            return findings

        # Homoglyph detection
        homoglyphs = {"0": "o", "1": "l", "rn": "m", "vv": "w", "cl": "d"}
        for fake, real in homoglyphs.items():
            if fake in domain:
                possible_real = domain.replace(fake, real)
                if possible_real in LEGITIMATE_DOMAINS or any(possible_real in ld for ld in LEGITIMATE_DOMAINS):
                    findings.append({"category": "website", "severity": "critical",
                                     "description": f"Homoglyph attack: '{domain}' mimics '{possible_real}'"})

        # Pattern matching
        for entry in PHISHING_URL_PATTERNS:
            if re.search(entry["pattern"], domain, re.IGNORECASE):
                findings.append({"category": "website", "severity": entry["severity"],
                                 "description": entry["desc"]})

        # Check for excessive subdomains (common in phishing)
        parts = domain.split(".")
        if len(parts) > 4:
            findings.append({"category": "website", "severity": "medium",
                             "description": f"Excessive subdomains ({len(parts)} levels) - common in phishing"})

        # Check for suspicious path patterns
        path = parsed.path.lower() if hasattr(parsed, 'path') and parsed.path else ""
        if any(kw in path for kw in ["claim", "airdrop", "verify", "connect-wallet", "validate"]):
            findings.append({"category": "website", "severity": "high",
                             "description": f"Suspicious path keywords detected: {path}"})

        return findings

    def _analyze_contract(self, source: str) -> list[dict[str, Any]]:
        """Analyze contract source for phishing patterns."""
        findings: list[dict[str, Any]] = []

        for entry in PHISHING_CONTRACT_PATTERNS:
            matches = list(re.finditer(entry["pattern"], source))
            if matches:
                lines = set()
                for m in matches:
                    lines.add(source[:m.start()].count("\n") + 1)
                findings.append({"category": "contract", "severity": entry["severity"],
                                 "description": entry["desc"],
                                 "occurrences": len(matches), "lines": sorted(lines)})

        return findings

    def _check_approvals(self, source: str) -> list[dict[str, Any]]:
        """Check for suspicious approval patterns."""
        findings: list[dict[str, Any]] = []
        for keyword in SUSPICIOUS_APPROVAL_KEYWORDS:
            escaped = re.escape(keyword).replace(r"\(", r"\(").replace(r"\)", r"\)")
            if re.search(escaped, source):
                findings.append({"category": "approval", "severity": "high",
                                 "description": f"Suspicious approval pattern: {keyword}"})
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["url_or_address"].strip()
        check_type = config.get("check_type", "both")
        include_approval = config.get("include_approval_check", True)

        all_findings: list[dict[str, Any]] = []

        # Determine if input looks like a URL or contract code
        is_url = bool(re.match(r'^(?:https?://|www\.|\w+\.\w{2,})', target))
        is_eth_address = bool(re.match(r'^0x[0-9a-fA-F]{40}$', target))

        if check_type in ("website", "both") and (is_url or is_eth_address):
            all_findings.extend(self._analyze_url(target))

        if check_type in ("contract", "both") and not is_url:
            all_findings.extend(self._analyze_contract(target))

        if include_approval and not is_url:
            all_findings.extend(self._check_approvals(target))

        # Calculate phishing confidence
        critical_count = sum(1 for f in all_findings if f["severity"] == "critical")
        high_count = sum(1 for f in all_findings if f["severity"] == "high")

        if critical_count >= 2:
            confidence = "very_high"
            is_phishing = True
        elif critical_count >= 1 or high_count >= 2:
            confidence = "high"
            is_phishing = True
        elif high_count >= 1:
            confidence = "medium"
            is_phishing = True
        elif all_findings and any(f["severity"] != "info" for f in all_findings):
            confidence = "low"
            is_phishing = True
        else:
            confidence = "none"
            is_phishing = False

        return {
            "target": target,
            "check_type": check_type,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "findings": all_findings,
            "total_findings": len(all_findings),
        }
