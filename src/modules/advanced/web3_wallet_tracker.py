"""Blockchain wallet address analyzer and tracker.

Validates wallet address formats, generates block explorer URLs,
and analyzes address patterns for Ethereum and Bitcoin chains.
"""

import re
import hashlib
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

EXPLORER_URLS = {
    "ethereum": {
        "mainnet": "https://etherscan.io/address/{address}",
        "tx": "https://etherscan.io/tx/{tx}",
        "api": "https://api.etherscan.io/api?module=account&action=balance&address={address}",
    },
    "bitcoin": {
        "mainnet": "https://www.blockchain.com/btc/address/{address}",
        "tx": "https://www.blockchain.com/btc/tx/{tx}",
        "api": "https://blockchain.info/rawaddr/{address}",
    },
}

KNOWN_PATTERNS = {
    "ethereum": {
        "null_address": "0x0000000000000000000000000000000000000000",
        "burn_addresses": [
            "0x000000000000000000000000000000000000dead",
            "0x0000000000000000000000000000000000000000",
        ],
        "common_contracts": {
            "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT (Tether)",
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (Circle)",
            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
            "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router",
            "0x7be8076f4ea4a4ad08075c2508e481d6c946d12b": "OpenSea (legacy)",
        },
    },
    "bitcoin": {
        "genesis_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "known_addresses": {
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Satoshi (Genesis Block)",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "Example P2SH address",
        },
    },
}


class Web3WalletTrackerModule(AtsModule):
    """Analyze and track blockchain wallet addresses across chains."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_wallet_tracker",
            category=ModuleCategory.ADVANCED,
            description="Analyze blockchain wallet addresses, validate formats, and generate explorer URLs",
            version="1.0.0",
            parameters=[
                Parameter(name="address", type=ParameterType.STRING,
                          description="Wallet address to analyze", required=True),
                Parameter(name="chain", type=ParameterType.CHOICE,
                          description="Blockchain network",
                          choices=["ethereum", "bitcoin"], default="ethereum"),
                Parameter(name="deep_analysis", type=ParameterType.BOOLEAN,
                          description="Perform deeper pattern analysis on address", default=True),
            ],
            outputs=[
                OutputField(name="valid", type="boolean", description="Whether the address format is valid"),
                OutputField(name="address_type", type="string", description="Type of address detected"),
                OutputField(name="explorer_urls", type="dict", description="Block explorer links"),
                OutputField(name="risk_indicators", type="list", description="Potential risk flags"),
            ],
            tags=["advanced", "web3", "wallet", "blockchain", "tracking"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        address = config.get("address", "").strip()
        if not address:
            return False, "Wallet address is required"
        if len(address) < 10:
            return False, "Address is too short to be valid"
        return True, ""

    def _validate_eth_address(self, address: str) -> tuple[bool, str]:
        """Validate an Ethereum address including EIP-55 checksum."""
        if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
            return False, "invalid_format"
        # Check EIP-55 checksum if mixed case
        if address != address.lower() and address != address.upper():
            addr_no_prefix = address[2:]
            addr_hash = hashlib.sha3_256(addr_no_prefix.lower().encode()).hexdigest()
            for i, char in enumerate(addr_no_prefix):
                if char.isalpha():
                    expected_upper = int(addr_hash[i], 16) >= 8
                    if expected_upper and char.islower():
                        return False, "checksum_invalid"
                    if not expected_upper and char.isupper():
                        return False, "checksum_invalid"
            return True, "eip55_checksummed"
        if address == address.lower():
            return True, "lowercase"
        return True, "uppercase"

    def _validate_btc_address(self, address: str) -> tuple[bool, str]:
        """Validate a Bitcoin address format."""
        if re.match(r'^1[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
            return True, "p2pkh"
        if re.match(r'^3[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
            return True, "p2sh"
        if re.match(r'^bc1[a-zA-HJ-NP-Z0-9]{25,89}$', address):
            return True, "bech32"
        if re.match(r'^bc1p[a-zA-HJ-NP-Z0-9]{25,89}$', address):
            return True, "taproot"
        return False, "invalid_format"

    def _analyze_eth_patterns(self, address: str) -> list[dict[str, str]]:
        """Analyze Ethereum address for known patterns and risks."""
        indicators: list[dict[str, str]] = []
        addr_lower = address.lower()

        if addr_lower in KNOWN_PATTERNS["ethereum"]["burn_addresses"]:
            indicators.append({"type": "burn_address", "severity": "info",
                               "detail": "This is a known burn/null address"})

        known = KNOWN_PATTERNS["ethereum"]["common_contracts"].get(addr_lower)
        if known:
            indicators.append({"type": "known_contract", "severity": "info",
                               "detail": f"Known contract: {known}"})

        zero_count = addr_lower[2:].count("0")
        if zero_count > 30:
            indicators.append({"type": "vanity_zeros", "severity": "warning",
                               "detail": f"High zero count ({zero_count}/40) - possible vanity/burn address"})

        if re.match(r'^0x[0-9a-f]{4}0{32}[0-9a-f]{4}$', addr_lower):
            indicators.append({"type": "create2_pattern", "severity": "info",
                               "detail": "Address pattern resembles CREATE2 deployed contract"})

        prefix = addr_lower[2:8]
        if len(set(prefix)) <= 2:
            indicators.append({"type": "vanity_prefix", "severity": "info",
                               "detail": f"Vanity prefix detected: 0x{prefix}..."})

        return indicators

    def _analyze_btc_patterns(self, address: str) -> list[dict[str, str]]:
        """Analyze Bitcoin address for known patterns and risks."""
        indicators: list[dict[str, str]] = []

        known = KNOWN_PATTERNS["bitcoin"]["known_addresses"].get(address)
        if known:
            indicators.append({"type": "known_address", "severity": "info",
                               "detail": f"Known address: {known}"})

        if address.startswith("1"):
            indicators.append({"type": "legacy_format", "severity": "info",
                               "detail": "Legacy P2PKH format - consider using SegWit for lower fees"})

        if address.startswith("bc1p"):
            indicators.append({"type": "taproot", "severity": "info",
                               "detail": "Taproot address (latest format with enhanced privacy)"})

        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        address = config["address"].strip()
        chain = config.get("chain", "ethereum")
        deep_analysis = config.get("deep_analysis", True)

        # Validate address
        if chain == "ethereum":
            valid, addr_type = self._validate_eth_address(address)
        else:
            valid, addr_type = self._validate_btc_address(address)

        # Generate explorer URLs
        explorer_urls = {}
        if valid and chain in EXPLORER_URLS:
            urls = EXPLORER_URLS[chain]
            explorer_urls = {
                "address_page": urls["mainnet"].format(address=address),
                "api_endpoint": urls["api"].format(address=address),
            }

        # Risk analysis
        risk_indicators: list[dict[str, str]] = []
        if valid and deep_analysis:
            if chain == "ethereum":
                risk_indicators = self._analyze_eth_patterns(address)
            else:
                risk_indicators = self._analyze_btc_patterns(address)

        # Determine overall risk
        risk_level = "info"
        for indicator in risk_indicators:
            if indicator["severity"] == "critical":
                risk_level = "critical"
                break
            if indicator["severity"] == "warning" and risk_level != "critical":
                risk_level = "warning"

        return {
            "address": address,
            "chain": chain,
            "valid": valid,
            "address_type": addr_type,
            "explorer_urls": explorer_urls,
            "risk_indicators": risk_indicators,
            "risk_level": risk_level,
            "analysis_depth": "deep" if deep_analysis else "basic",
        }
