"""Cloud infrastructure CIS benchmark compliance auditor.

Audits cloud configurations against CIS benchmark rules, scoring compliance
and identifying gaps across AWS, Azure, and GCP environments.
"""

import asyncio
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

CIS_RULES = {
    "aws": {
        "cis_level1": [
            {"id": "1.1", "title": "Avoid root account usage", "field": "root_account_used",
             "check": "equals", "expected": False, "severity": "critical"},
            {"id": "1.4", "title": "Ensure MFA is enabled for root", "field": "root_mfa_enabled",
             "check": "equals", "expected": True, "severity": "critical"},
            {"id": "1.5", "title": "Ensure MFA for IAM users with console access", "field": "iam_mfa_percentage",
             "check": "gte", "expected": 100, "severity": "high"},
            {"id": "1.10", "title": "Ensure password policy requires minimum length", "field": "password_min_length",
             "check": "gte", "expected": 14, "severity": "medium"},
            {"id": "1.11", "title": "Ensure password policy prevents reuse", "field": "password_reuse_prevention",
             "check": "gte", "expected": 24, "severity": "medium"},
            {"id": "2.1", "title": "Ensure CloudTrail is enabled", "field": "cloudtrail_enabled",
             "check": "equals", "expected": True, "severity": "critical"},
            {"id": "2.6", "title": "Ensure S3 bucket access logging is enabled", "field": "s3_access_logging",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "3.1", "title": "Ensure VPC flow logging is enabled", "field": "vpc_flow_logs_enabled",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "4.1", "title": "Ensure no SGs allow ingress 0.0.0.0/0 to port 22", "field": "sg_ssh_restricted",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "4.2", "title": "Ensure no SGs allow ingress 0.0.0.0/0 to port 3389", "field": "sg_rdp_restricted",
             "check": "equals", "expected": True, "severity": "high"},
        ],
        "cis_level2": [
            {"id": "1.16", "title": "Ensure IAM policies are attached to groups only", "field": "iam_policies_on_groups",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "2.2", "title": "Ensure CloudTrail log file validation is enabled", "field": "cloudtrail_log_validation",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "2.7", "title": "Ensure CloudTrail logs are encrypted with KMS", "field": "cloudtrail_kms_encrypted",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "3.3", "title": "Ensure AWS Config is enabled in all regions", "field": "config_all_regions",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "4.3", "title": "Ensure default security group restricts all traffic", "field": "default_sg_restricted",
             "check": "equals", "expected": True, "severity": "medium"},
        ],
    },
    "azure": {
        "cis_level1": [
            {"id": "1.1", "title": "Ensure MFA is enabled for all privileged users", "field": "privileged_mfa",
             "check": "equals", "expected": True, "severity": "critical"},
            {"id": "1.3", "title": "Ensure guest users are reviewed monthly", "field": "guest_review_enabled",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "2.1", "title": "Ensure Azure Defender is enabled", "field": "azure_defender_enabled",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "3.1", "title": "Ensure storage account requires HTTPS", "field": "storage_https_only",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "4.1", "title": "Ensure Network Security Groups restrict SSH", "field": "nsg_ssh_restricted",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "5.1", "title": "Ensure diagnostic logging is enabled", "field": "diagnostic_logging",
             "check": "equals", "expected": True, "severity": "medium"},
        ],
        "cis_level2": [
            {"id": "3.7", "title": "Ensure storage account uses CMK encryption", "field": "storage_cmk_encryption",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "4.5", "title": "Ensure Network Watcher is enabled", "field": "network_watcher_enabled",
             "check": "equals", "expected": True, "severity": "medium"},
        ],
    },
    "gcp": {
        "cis_level1": [
            {"id": "1.1", "title": "Ensure corporate login credentials are used", "field": "corporate_login",
             "check": "equals", "expected": True, "severity": "high"},
            {"id": "1.4", "title": "Ensure service account keys are rotated", "field": "sa_key_rotation_days",
             "check": "lte", "expected": 90, "severity": "medium"},
            {"id": "2.1", "title": "Ensure Cloud Audit Logging is enabled", "field": "audit_logging_enabled",
             "check": "equals", "expected": True, "severity": "critical"},
            {"id": "3.1", "title": "Ensure default network is deleted", "field": "default_network_exists",
             "check": "equals", "expected": False, "severity": "high"},
            {"id": "4.1", "title": "Ensure instances do not use default service account", "field": "default_sa_used",
             "check": "equals", "expected": False, "severity": "high"},
        ],
        "cis_level2": [
            {"id": "2.5", "title": "Ensure log sinks are configured for all log entries", "field": "log_sink_all",
             "check": "equals", "expected": True, "severity": "medium"},
            {"id": "3.6", "title": "Ensure SSH access is restricted from internet", "field": "ssh_restricted",
             "check": "equals", "expected": True, "severity": "high"},
        ],
    },
}


class CloudComplianceAuditModule(AtsModule):
    """Audit cloud infrastructure against CIS benchmarks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_compliance_audit",
            category=ModuleCategory.ADVANCED,
            description="Audit cloud infrastructure against CIS benchmark compliance rules",
            version="1.0.0",
            parameters=[
                Parameter(name="provider", type=ParameterType.CHOICE,
                          description="Cloud provider", choices=["aws", "azure", "gcp"], default="aws"),
                Parameter(name="config_data", type=ParameterType.STRING,
                          description="Cloud configuration data JSON to audit", required=True),
                Parameter(name="benchmark", type=ParameterType.CHOICE,
                          description="CIS benchmark level",
                          choices=["cis_level1", "cis_level2"], default="cis_level1"),
            ],
            outputs=[
                OutputField(name="compliance_score", type="float", description="Compliance percentage"),
                OutputField(name="passed", type="list", description="Passed checks"),
                OutputField(name="failed", type="list", description="Failed checks"),
            ],
            tags=["advanced", "cloud", "compliance", "cis", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("config_data", "").strip()
        if not data:
            return False, "Configuration data JSON is required"
        try:
            json.loads(data)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _evaluate_rule(self, rule: dict, config_data: dict) -> dict:
        """Evaluate a single CIS rule against configuration data."""
        field = rule["field"]
        check = rule["check"]
        expected = rule["expected"]
        actual = config_data.get(field)

        result = {"rule_id": rule["id"], "title": rule["title"],
                  "severity": rule["severity"], "field": field,
                  "expected": expected, "actual": actual, "passed": False}

        if actual is None:
            result["status"] = "not_evaluated"
            result["reason"] = f"Field '{field}' not found in configuration data"
            return result

        if check == "equals":
            result["passed"] = actual == expected
        elif check == "gte":
            result["passed"] = actual >= expected
        elif check == "lte":
            result["passed"] = actual <= expected
        elif check == "contains":
            result["passed"] = expected in str(actual)
        elif check == "not_empty":
            result["passed"] = bool(actual)

        result["status"] = "passed" if result["passed"] else "failed"
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        provider = config.get("provider", "aws")
        config_data = json.loads(config["config_data"])
        benchmark = config.get("benchmark", "cis_level1")

        provider_rules = CIS_RULES.get(provider, {})
        rules = list(provider_rules.get("cis_level1", []))
        if benchmark == "cis_level2":
            rules.extend(provider_rules.get("cis_level2", []))

        passed = []
        failed = []
        not_evaluated = []

        for rule in rules:
            result = self._evaluate_rule(rule, config_data)
            if result["status"] == "passed":
                passed.append(result)
            elif result["status"] == "failed":
                failed.append(result)
            else:
                not_evaluated.append(result)

        evaluated = len(passed) + len(failed)
        compliance_score = (len(passed) / evaluated * 100) if evaluated > 0 else 0.0

        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in failed:
            severity_breakdown[f["severity"]] = severity_breakdown.get(f["severity"], 0) + 1

        return {
            "provider": provider,
            "benchmark": benchmark,
            "total_rules": len(rules),
            "evaluated": evaluated,
            "compliance_score": round(compliance_score, 1),
            "passed": passed,
            "passed_count": len(passed),
            "failed": failed,
            "failed_count": len(failed),
            "not_evaluated": not_evaluated,
            "severity_breakdown": severity_breakdown,
            "compliant": compliance_score >= 80.0,
        }
