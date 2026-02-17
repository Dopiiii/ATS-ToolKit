"""Cross-chain bridge security analyzer.

Analyzes bridge configuration JSON for security risks including
validator counts, multisig thresholds, timelock settings, and
architecture-specific vulnerabilities by bridge type.
"""

import json
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

BRIDGE_RISK_CHECKS = {
    "validator_count": {
        "min_safe": 5,
        "desc": "Minimum number of validators for acceptable decentralization",
    },
    "multisig_threshold": {
        "min_ratio": 0.6,
        "desc": "Minimum M-of-N ratio for multisig security (e.g. 3-of-5 = 0.6)",
    },
    "timelock_seconds": {
        "min_safe": 86400,
        "desc": "Minimum timelock delay in seconds (24 hours recommended)",
    },
}


class Web3BridgeScannerModule(AtsModule):
    """Analyze cross-chain bridge configuration for security vulnerabilities."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_bridge_scanner",
            category=ModuleCategory.ADVANCED,
            description="Analyze cross-chain bridge configurations for validator, multisig, and timelock security",
            version="1.0.0",
            parameters=[
                Parameter(name="bridge_config", type=ParameterType.STRING,
                          description="Bridge configuration as JSON string", required=True),
                Parameter(name="bridge_type", type=ParameterType.CHOICE,
                          description="Type of bridge architecture",
                          choices=["lock_mint", "burn_mint", "atomic"], default="lock_mint"),
                Parameter(name="strict_mode", type=ParameterType.BOOLEAN,
                          description="Apply stricter security thresholds", default=False),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Security findings for the bridge"),
                OutputField(name="risk_score", type="integer", description="Overall risk score 0-100"),
                OutputField(name="bridge_analysis", type="dict", description="Detailed bridge architecture analysis"),
            ],
            tags=["advanced", "web3", "bridge", "cross-chain", "validator", "multisig"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("bridge_config", "").strip()
        if not raw:
            return False, "Bridge configuration JSON is required"
        try:
            json.loads(raw)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in bridge_config: {e}"
        return True, ""

    def _check_validators(self, bridge: dict[str, Any], strict: bool) -> list[dict[str, Any]]:
        """Check validator configuration for risks."""
        findings: list[dict[str, Any]] = []
        validators = bridge.get("validators", [])
        validator_count = bridge.get("validator_count", len(validators))
        min_safe = BRIDGE_RISK_CHECKS["validator_count"]["min_safe"]
        if strict:
            min_safe = 10

        if validator_count == 0 and not validators:
            findings.append({"category": "validators", "severity": "critical",
                             "description": "No validator information provided"})
        elif validator_count < 3:
            findings.append({"category": "validators", "severity": "critical",
                             "description": f"Only {validator_count} validators - extremely centralized"})
        elif validator_count < min_safe:
            findings.append({"category": "validators", "severity": "high",
                             "description": f"{validator_count} validators below minimum {min_safe}"})
        else:
            findings.append({"category": "validators", "severity": "info",
                             "description": f"{validator_count} validators (acceptable)"})

        # Check for duplicate or suspicious validator addresses
        if validators:
            seen = set()
            for v in validators:
                addr = v if isinstance(v, str) else v.get("address", "")
                if addr in seen:
                    findings.append({"category": "validators", "severity": "critical",
                                     "description": f"Duplicate validator address: {addr[:16]}..."})
                seen.add(addr)

        return findings

    def _check_multisig(self, bridge: dict[str, Any], strict: bool) -> list[dict[str, Any]]:
        """Check multisig threshold configuration."""
        findings: list[dict[str, Any]] = []
        multisig = bridge.get("multisig", {})
        threshold = multisig.get("threshold", 0)
        total = multisig.get("total", multisig.get("signers", 0))
        min_ratio = BRIDGE_RISK_CHECKS["multisig_threshold"]["min_ratio"]
        if strict:
            min_ratio = 0.75

        if not multisig:
            findings.append({"category": "multisig", "severity": "high",
                             "description": "No multisig configuration found"})
            return findings

        if total == 0:
            findings.append({"category": "multisig", "severity": "critical",
                             "description": "Multisig has zero total signers"})
            return findings

        ratio = threshold / total if total > 0 else 0
        if threshold <= 1:
            findings.append({"category": "multisig", "severity": "critical",
                             "description": f"Multisig threshold is {threshold}-of-{total} (single point of failure)"})
        elif ratio < min_ratio:
            findings.append({"category": "multisig", "severity": "high",
                             "description": f"Multisig ratio {threshold}/{total} ({ratio:.0%}) below minimum {min_ratio:.0%}"})
        else:
            findings.append({"category": "multisig", "severity": "info",
                             "description": f"Multisig {threshold}-of-{total} ({ratio:.0%}) meets threshold"})

        return findings

    def _check_timelock(self, bridge: dict[str, Any], strict: bool) -> list[dict[str, Any]]:
        """Check timelock configuration."""
        findings: list[dict[str, Any]] = []
        timelock = bridge.get("timelock", {})
        delay = timelock.get("delay", timelock.get("delay_seconds", 0))
        min_safe = BRIDGE_RISK_CHECKS["timelock_seconds"]["min_safe"]
        if strict:
            min_safe = 172800  # 48 hours

        if not timelock:
            findings.append({"category": "timelock", "severity": "high",
                             "description": "No timelock configuration found"})
        elif delay == 0:
            findings.append({"category": "timelock", "severity": "critical",
                             "description": "Timelock delay is zero (instant admin actions)"})
        elif delay < 3600:
            findings.append({"category": "timelock", "severity": "critical",
                             "description": f"Timelock delay {delay}s (less than 1 hour)"})
        elif delay < min_safe:
            hours = delay / 3600
            findings.append({"category": "timelock", "severity": "high",
                             "description": f"Timelock delay {hours:.1f}h below recommended {min_safe / 3600:.0f}h"})
        else:
            findings.append({"category": "timelock", "severity": "info",
                             "description": f"Timelock delay {delay / 3600:.1f}h meets minimum"})

        return findings

    def _check_bridge_type_risks(self, bridge: dict[str, Any],
                                  bridge_type: str) -> list[dict[str, Any]]:
        """Check architecture-specific risks based on bridge type."""
        findings: list[dict[str, Any]] = []

        if bridge_type == "lock_mint":
            if not bridge.get("reserve_audit", False):
                findings.append({"category": "architecture", "severity": "high",
                                 "description": "Lock-mint bridge has no proof of reserves/audit"})
            if not bridge.get("emergency_pause", False):
                findings.append({"category": "architecture", "severity": "medium",
                                 "description": "No emergency pause mechanism for locked funds"})

        elif bridge_type == "burn_mint":
            if not bridge.get("supply_cap", False):
                findings.append({"category": "architecture", "severity": "high",
                                 "description": "Burn-mint bridge has no supply cap on minted tokens"})
            if not bridge.get("burn_verification", False):
                findings.append({"category": "architecture", "severity": "high",
                                 "description": "No cross-chain burn verification before minting"})

        elif bridge_type == "atomic":
            timeout = bridge.get("swap_timeout", 0)
            if timeout == 0:
                findings.append({"category": "architecture", "severity": "critical",
                                 "description": "Atomic swap has no timeout (funds can be locked forever)"})
            elif timeout < 600:
                findings.append({"category": "architecture", "severity": "high",
                                 "description": f"Atomic swap timeout {timeout}s too short (race condition risk)"})

        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        raw = config["bridge_config"].strip()
        bridge = json.loads(raw)
        bridge_type = config.get("bridge_type", "lock_mint")
        strict = config.get("strict_mode", False)

        all_findings: list[dict[str, Any]] = []
        all_findings.extend(self._check_validators(bridge, strict))
        all_findings.extend(self._check_multisig(bridge, strict))
        all_findings.extend(self._check_timelock(bridge, strict))
        all_findings.extend(self._check_bridge_type_risks(bridge, bridge_type))

        # Risk score
        weights = {"critical": 25, "high": 14, "medium": 7, "low": 2, "info": 0}
        risk_score = sum(weights.get(f["severity"], 0) for f in all_findings)
        risk_score = min(risk_score, 100)

        risk_level = "critical" if risk_score >= 60 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low"

        bridge_analysis = {
            "bridge_type": bridge_type,
            "strict_mode": strict,
            "validator_count": bridge.get("validator_count", len(bridge.get("validators", []))),
            "has_multisig": bool(bridge.get("multisig")),
            "has_timelock": bool(bridge.get("timelock")),
        }

        return {
            "findings": all_findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "bridge_analysis": bridge_analysis,
            "total_findings": len(all_findings),
        }
