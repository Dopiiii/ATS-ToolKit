"""DAO governance security auditor.

Audits DAO governance configurations for voting threshold issues,
timelock bypass risks, flash loan governance attacks, and
centralization concerns based on the DAO type.
"""

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


class Web3GovernanceAuditModule(AtsModule):
    """Audit DAO governance configurations for security and centralization risks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="web3_governance_audit",
            category=ModuleCategory.ADVANCED,
            description="Audit DAO governance for voting thresholds, timelock, and flash loan attack risks",
            version="1.0.0",
            parameters=[
                Parameter(name="governance_config", type=ParameterType.STRING,
                          description="Governance configuration as JSON string", required=True),
                Parameter(name="dao_type", type=ParameterType.CHOICE,
                          description="Type of DAO governance model",
                          choices=["token", "nft", "multisig"], default="token"),
                Parameter(name="check_flash_loan", type=ParameterType.BOOLEAN,
                          description="Check for flash loan governance attack vectors", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Governance audit findings"),
                OutputField(name="risk_score", type="integer", description="Governance risk score 0-100"),
                OutputField(name="governance_summary", type="dict", description="Summary of governance parameters"),
            ],
            tags=["advanced", "web3", "governance", "dao", "voting", "timelock"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("governance_config", "").strip()
        if not raw:
            return False, "Governance configuration JSON is required"
        try:
            json.loads(raw)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _check_voting_thresholds(self, gov: dict[str, Any],
                                  dao_type: str) -> list[dict[str, Any]]:
        """Analyze voting and quorum thresholds."""
        findings: list[dict[str, Any]] = []
        voting = gov.get("voting", {})

        quorum = voting.get("quorum_percentage", voting.get("quorum", 0))
        proposal_threshold = voting.get("proposal_threshold", 0)
        voting_period = voting.get("voting_period_seconds", voting.get("voting_period", 0))

        # Quorum checks
        if quorum == 0:
            findings.append({"category": "voting", "severity": "critical",
                             "description": "No quorum requirement - proposals pass with minimal votes"})
        elif quorum < 4:
            findings.append({"category": "voting", "severity": "high",
                             "description": f"Quorum {quorum}% is dangerously low"})
        elif quorum < 10:
            findings.append({"category": "voting", "severity": "medium",
                             "description": f"Quorum {quorum}% is below recommended minimum of 10%"})
        else:
            findings.append({"category": "voting", "severity": "info",
                             "description": f"Quorum {quorum}% is acceptable"})

        # Proposal threshold
        if dao_type == "token":
            if proposal_threshold == 0:
                findings.append({"category": "voting", "severity": "high",
                                 "description": "No proposal threshold - anyone can propose (spam risk)"})
            elif proposal_threshold < 0.1:
                findings.append({"category": "voting", "severity": "medium",
                                 "description": f"Proposal threshold {proposal_threshold}% very low"})

        # Voting period
        if voting_period > 0:
            hours = voting_period / 3600
            if hours < 24:
                findings.append({"category": "voting", "severity": "high",
                                 "description": f"Voting period {hours:.1f}h too short (less than 24h)"})
            elif hours < 72:
                findings.append({"category": "voting", "severity": "medium",
                                 "description": f"Voting period {hours:.1f}h below recommended 72h"})
        elif voting_period == 0 and "voting_period" not in str(gov):
            findings.append({"category": "voting", "severity": "high",
                             "description": "No voting period defined"})

        return findings

    def _check_timelock(self, gov: dict[str, Any]) -> list[dict[str, Any]]:
        """Check timelock configuration."""
        findings: list[dict[str, Any]] = []
        timelock = gov.get("timelock", {})

        if not timelock:
            findings.append({"category": "timelock", "severity": "critical",
                             "description": "No timelock - proposals execute immediately after vote"})
            return findings

        delay = timelock.get("delay", timelock.get("delay_seconds", 0))
        if delay == 0:
            findings.append({"category": "timelock", "severity": "critical",
                             "description": "Timelock delay is zero"})
        elif delay < 3600:
            findings.append({"category": "timelock", "severity": "high",
                             "description": f"Timelock {delay}s (less than 1 hour)"})
        elif delay < 86400:
            findings.append({"category": "timelock", "severity": "medium",
                             "description": f"Timelock {delay / 3600:.1f}h below 24h recommended"})
        else:
            findings.append({"category": "timelock", "severity": "info",
                             "description": f"Timelock {delay / 3600:.1f}h is adequate"})

        # Check for guardian/cancel role
        if not timelock.get("guardian") and not timelock.get("canceller"):
            findings.append({"category": "timelock", "severity": "medium",
                             "description": "No guardian/canceller role to stop malicious proposals"})

        return findings

    def _check_flash_loan_risks(self, gov: dict[str, Any],
                                 dao_type: str) -> list[dict[str, Any]]:
        """Check for flash loan governance attack vectors."""
        findings: list[dict[str, Any]] = []

        if dao_type != "token":
            findings.append({"category": "flash_loan", "severity": "info",
                             "description": f"Flash loan risk is lower for {dao_type}-based governance"})
            return findings

        voting = gov.get("voting", {})
        snapshot = voting.get("vote_snapshot", voting.get("snapshot_block", None))
        delegation = voting.get("delegation_required", False)
        vote_delay = voting.get("vote_delay", voting.get("delay_before_vote", 0))

        if not snapshot:
            findings.append({"category": "flash_loan", "severity": "critical",
                             "description": "No snapshot mechanism - flash loan can acquire votes at proposal time"})
        else:
            findings.append({"category": "flash_loan", "severity": "info",
                             "description": "Snapshot mechanism present (mitigates flash loan voting)"})

        if not delegation:
            findings.append({"category": "flash_loan", "severity": "medium",
                             "description": "No delegation requirement - tokens vote directly without prior commitment"})

        if vote_delay == 0:
            findings.append({"category": "flash_loan", "severity": "high",
                             "description": "No delay between proposal and voting start (flash loan window)"})
        elif vote_delay < 3600:
            findings.append({"category": "flash_loan", "severity": "medium",
                             "description": f"Vote delay {vote_delay}s may be insufficient against flash loans"})

        return findings

    def _check_centralization(self, gov: dict[str, Any],
                               dao_type: str) -> list[dict[str, Any]]:
        """Check for centralization risks."""
        findings: list[dict[str, Any]] = []
        admin = gov.get("admin", gov.get("owner", {}))

        if isinstance(admin, str) and admin:
            findings.append({"category": "centralization", "severity": "high",
                             "description": "Single admin address controls governance"})
        elif isinstance(admin, dict):
            if admin.get("is_multisig", False):
                findings.append({"category": "centralization", "severity": "info",
                                 "description": "Admin is a multisig (better than single address)"})
            else:
                findings.append({"category": "centralization", "severity": "high",
                                 "description": "Admin configuration suggests single entity control"})

        # Check for veto power
        if gov.get("veto_power", False):
            findings.append({"category": "centralization", "severity": "high",
                             "description": "Veto power exists - can override community votes"})

        # Token distribution for token DAOs
        if dao_type == "token":
            top_holder = gov.get("top_holder_percentage", 0)
            if top_holder > 50:
                findings.append({"category": "centralization", "severity": "critical",
                                 "description": f"Top holder owns {top_holder}% - governance is centralized"})
            elif top_holder > 20:
                findings.append({"category": "centralization", "severity": "high",
                                 "description": f"Top holder owns {top_holder}% - significant influence"})

        if dao_type == "multisig":
            signers = gov.get("multisig", {}).get("signers", 0)
            threshold = gov.get("multisig", {}).get("threshold", 0)
            if signers > 0 and signers < 3:
                findings.append({"category": "centralization", "severity": "critical",
                                 "description": f"Only {signers} multisig signers"})
            if threshold > 0 and signers > 0 and threshold / signers < 0.5:
                findings.append({"category": "centralization", "severity": "high",
                                 "description": f"Multisig threshold {threshold}/{signers} too low"})

        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        raw = config["governance_config"].strip()
        gov = json.loads(raw)
        dao_type = config.get("dao_type", "token")
        check_flash = config.get("check_flash_loan", True)

        all_findings: list[dict[str, Any]] = []
        all_findings.extend(self._check_voting_thresholds(gov, dao_type))
        all_findings.extend(self._check_timelock(gov))
        all_findings.extend(self._check_centralization(gov, dao_type))

        if check_flash:
            all_findings.extend(self._check_flash_loan_risks(gov, dao_type))

        # Risk score
        weights = {"critical": 25, "high": 14, "medium": 7, "low": 2, "info": 0}
        risk_score = sum(weights.get(f["severity"], 0) for f in all_findings)
        risk_score = min(risk_score, 100)

        risk_level = "critical" if risk_score >= 60 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low"

        governance_summary = {
            "dao_type": dao_type,
            "has_timelock": bool(gov.get("timelock")),
            "has_snapshot": bool(gov.get("voting", {}).get("vote_snapshot")),
            "quorum": gov.get("voting", {}).get("quorum_percentage", "not set"),
            "categories_checked": list({f["category"] for f in all_findings}),
        }

        return {
            "findings": all_findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "governance_summary": governance_summary,
            "total_findings": len(all_findings),
        }
