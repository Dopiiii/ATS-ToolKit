"""Firewall rule auditor for detecting misconfigurations and security gaps.

Analyzes firewall rule sets for overly permissive rules, shadowed rules,
conflicting allow/deny entries, and missing egress filtering.
"""

import asyncio
import json
import re
from typing import Any
from collections import defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

RISKY_PORTS = {21, 23, 25, 69, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900}
RISKY_PORT_NAMES = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 69: "TFTP", 135: "RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
}


class NetFirewallAuditorModule(AtsModule):
    """Audit firewall rule sets for misconfigurations and security weaknesses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_firewall_auditor",
            category=ModuleCategory.ADVANCED,
            description="Audit firewall rules for permissive, shadowed, and conflicting configurations",
            version="1.0.0",
            parameters=[
                Parameter(name="rules_data", type=ParameterType.STRING,
                          description="JSON array of firewall rules with action, src, dst, port, proto, direction"),
                Parameter(name="audit_type", type=ParameterType.CHOICE,
                          description="Type of audit to perform",
                          choices=["permissive", "shadowed", "conflicts", "all"], default="all"),
                Parameter(name="strict_mode", type=ParameterType.BOOLEAN,
                          description="Enable strict auditing with lower tolerance", default=False),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Audit findings"),
                OutputField(name="risk_score", type="float", description="Overall risk score 0-100"),
                OutputField(name="recommendations", type="list", description="Remediation recommendations"),
            ],
            tags=["advanced", "network", "firewall", "audit", "compliance"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("rules_data", "").strip()
        if not raw:
            return False, "Firewall rules data is required"
        try:
            rules = json.loads(raw)
            if not isinstance(rules, list):
                return False, "Rules data must be a JSON array"
            if len(rules) == 0:
                return False, "Rules array is empty"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in rules_data: {e}"
        return True, ""

    def _is_wildcard(self, value: str) -> bool:
        """Check if a value represents a wildcard/any."""
        return value.lower().strip() in ("any", "*", "0.0.0.0/0", "::/0", "all", "")

    def _parse_port_range(self, port_str: str) -> set[int]:
        """Parse port string into a set of port numbers."""
        port_str = str(port_str).strip()
        if self._is_wildcard(port_str):
            return set()  # represents all ports
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    ports.update(range(int(start), int(end) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    pass
        return ports

    def _check_permissive_rules(self, rules: list[dict], strict: bool) -> list[dict]:
        """Identify overly permissive firewall rules."""
        findings = []
        for idx, rule in enumerate(rules):
            action = rule.get("action", "").lower()
            if action not in ("allow", "permit", "accept"):
                continue
            src = str(rule.get("src", "any"))
            dst = str(rule.get("dst", "any"))
            port = str(rule.get("port", "any"))
            proto = str(rule.get("proto", "any")).lower()

            src_wild = self._is_wildcard(src)
            dst_wild = self._is_wildcard(dst)
            port_wild = self._is_wildcard(port)

            if src_wild and dst_wild and port_wild:
                findings.append({
                    "rule_index": idx, "type": "permissive",
                    "severity": "critical", "rule": rule,
                    "issue": "Rule allows ANY source to ANY destination on ANY port",
                    "recommendation": "Replace with specific source/destination/port restrictions",
                })
            elif src_wild and dst_wild:
                findings.append({
                    "rule_index": idx, "type": "permissive",
                    "severity": "high", "rule": rule,
                    "issue": f"Rule allows ANY source to ANY destination on port {port}",
                    "recommendation": "Restrict source and destination addresses",
                })
            elif src_wild and port_wild:
                findings.append({
                    "rule_index": idx, "type": "permissive",
                    "severity": "high", "rule": rule,
                    "issue": f"Rule allows ANY source to {dst} on ANY port",
                    "recommendation": "Restrict source addresses and port ranges",
                })
            elif src_wild and strict:
                findings.append({
                    "rule_index": idx, "type": "permissive",
                    "severity": "medium", "rule": rule,
                    "issue": f"Rule allows ANY source (strict mode)",
                    "recommendation": "Define specific source addresses or ranges",
                })

            # Check for risky ports exposed
            if action in ("allow", "permit", "accept"):
                parsed_ports = self._parse_port_range(port)
                if not parsed_ports and not port_wild:
                    continue
                exposed_risky = parsed_ports & RISKY_PORTS if parsed_ports else RISKY_PORTS
                if port_wild:
                    exposed_risky = RISKY_PORTS
                for rp in exposed_risky:
                    if src_wild:
                        findings.append({
                            "rule_index": idx, "type": "risky_port_exposed",
                            "severity": "high", "rule": rule,
                            "issue": f"Risky port {rp} ({RISKY_PORT_NAMES.get(rp, 'Unknown')}) exposed to any source",
                            "recommendation": f"Restrict access to port {rp} to specific sources",
                        })

        return findings

    def _check_shadowed_rules(self, rules: list[dict]) -> list[dict]:
        """Detect rules that are shadowed by earlier rules."""
        findings = []
        for i, rule_b in enumerate(rules):
            for j in range(i):
                rule_a = rules[j]
                if self._rule_shadows(rule_a, rule_b):
                    findings.append({
                        "rule_index": i, "shadowed_by": j,
                        "type": "shadowed", "severity": "medium",
                        "rule": rule_b, "shadowing_rule": rule_a,
                        "issue": f"Rule {i} is shadowed by earlier rule {j}",
                        "recommendation": "Remove or reorder shadowed rules",
                    })
                    break
        return findings

    def _rule_shadows(self, rule_a: dict, rule_b: dict) -> bool:
        """Check if rule_a completely shadows rule_b."""
        src_a_wild = self._is_wildcard(str(rule_a.get("src", "any")))
        dst_a_wild = self._is_wildcard(str(rule_a.get("dst", "any")))
        port_a_wild = self._is_wildcard(str(rule_a.get("port", "any")))
        src_match = src_a_wild or str(rule_a.get("src", "")) == str(rule_b.get("src", ""))
        dst_match = dst_a_wild or str(rule_a.get("dst", "")) == str(rule_b.get("dst", ""))
        port_match = port_a_wild or str(rule_a.get("port", "")) == str(rule_b.get("port", ""))
        proto_a = str(rule_a.get("proto", "any")).lower()
        proto_b = str(rule_b.get("proto", "any")).lower()
        proto_match = proto_a in ("any", "*") or proto_a == proto_b
        return src_match and dst_match and port_match and proto_match

    def _check_conflicts(self, rules: list[dict]) -> list[dict]:
        """Detect conflicting allow/deny rules for the same traffic."""
        findings = []
        for i in range(len(rules)):
            for j in range(i + 1, len(rules)):
                ra, rb = rules[i], rules[j]
                action_a = ra.get("action", "").lower()
                action_b = rb.get("action", "").lower()
                allow_set = {"allow", "permit", "accept"}
                deny_set = {"deny", "drop", "reject"}
                if (action_a in allow_set and action_b in deny_set) or \
                   (action_a in deny_set and action_b in allow_set):
                    if self._rules_overlap(ra, rb):
                        findings.append({
                            "rule_indices": [i, j], "type": "conflict",
                            "severity": "high", "rules": [ra, rb],
                            "issue": f"Rules {i} ({action_a}) and {j} ({action_b}) conflict on overlapping traffic",
                            "recommendation": "Resolve conflicting rules by consolidation or reordering",
                        })
        return findings

    def _rules_overlap(self, ra: dict, rb: dict) -> bool:
        """Check if two rules match overlapping traffic."""
        src_overlap = (self._is_wildcard(str(ra.get("src", "any"))) or
                       self._is_wildcard(str(rb.get("src", "any"))) or
                       str(ra.get("src", "")) == str(rb.get("src", "")))
        dst_overlap = (self._is_wildcard(str(ra.get("dst", "any"))) or
                       self._is_wildcard(str(rb.get("dst", "any"))) or
                       str(ra.get("dst", "")) == str(rb.get("dst", "")))
        port_overlap = (self._is_wildcard(str(ra.get("port", "any"))) or
                        self._is_wildcard(str(rb.get("port", "any"))) or
                        str(ra.get("port", "")) == str(rb.get("port", "")))
        return src_overlap and dst_overlap and port_overlap

    def _check_egress_filtering(self, rules: list[dict]) -> list[dict]:
        """Check for missing egress filtering."""
        findings = []
        has_egress = any(
            str(r.get("direction", "")).lower() in ("outbound", "egress", "out")
            for r in rules
        )
        if not has_egress:
            findings.append({
                "type": "missing_egress", "severity": "high",
                "issue": "No egress filtering rules detected",
                "recommendation": "Implement egress filtering to control outbound traffic and prevent data exfiltration",
            })
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        rules = json.loads(config["rules_data"])
        audit_type = config.get("audit_type", "all")
        strict = config.get("strict_mode", False)

        all_findings = []
        recommendations = set()

        if audit_type in ("permissive", "all"):
            permissive = self._check_permissive_rules(rules, strict)
            all_findings.extend(permissive)

        if audit_type in ("shadowed", "all"):
            shadowed = self._check_shadowed_rules(rules)
            all_findings.extend(shadowed)

        if audit_type in ("conflicts", "all"):
            conflicts = self._check_conflicts(rules)
            all_findings.extend(conflicts)

        if audit_type == "all":
            egress = self._check_egress_filtering(rules)
            all_findings.extend(egress)

        for f in all_findings:
            if f.get("recommendation"):
                recommendations.add(f["recommendation"])

        severity_weights = {"critical": 25, "high": 12, "medium": 5, "low": 2}
        risk_score = sum(severity_weights.get(f.get("severity", "low"), 0) for f in all_findings)
        risk_score = min(round(float(risk_score), 1), 100.0)

        return {
            "audit_type": audit_type,
            "rules_analyzed": len(rules),
            "findings": all_findings,
            "finding_count": len(all_findings),
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 15 else "low",
            "recommendations": sorted(recommendations),
        }
