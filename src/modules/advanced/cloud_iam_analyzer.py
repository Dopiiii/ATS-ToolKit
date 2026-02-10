"""Cloud IAM policy analyzer for overprivileged access detection.

Parses IAM policy JSON documents and identifies risky permissions, wildcard usage, and missing conditions.
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

DANGEROUS_AWS_ACTIONS = [
    "iam:*", "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "sts:AssumeRole", "s3:*", "ec2:*", "lambda:*", "kms:Decrypt",
    "secretsmanager:GetSecretValue", "ssm:GetParameter", "iam:PassRole",
    "iam:CreateAccessKey", "iam:UpdateLoginProfile", "organizations:*",
]

DANGEROUS_AZURE_ACTIONS = [
    "*/write", "*/delete", "Microsoft.Authorization/*",
    "Microsoft.Compute/virtualMachines/*", "Microsoft.KeyVault/vaults/secrets/*",
    "Microsoft.Storage/storageAccounts/listKeys/*",
]

DANGEROUS_GCP_PERMISSIONS = [
    "iam.serviceAccounts.actAs", "iam.serviceAccountKeys.create",
    "compute.instances.create", "storage.objects.*",
    "cloudfunctions.functions.create", "run.services.create",
]


class CloudIamAnalyzerModule(AtsModule):
    """Analyze IAM policies for overprivileged access patterns."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_iam_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze IAM policies for overprivileged access and risky permissions",
            version="1.0.0",
            parameters=[
                Parameter(name="policy_json", type=ParameterType.STRING,
                          description="IAM policy JSON document to analyze", required=True),
                Parameter(name="framework", type=ParameterType.CHOICE,
                          description="Cloud provider framework",
                          choices=["aws", "azure", "gcp"], default="aws"),
                Parameter(name="strict_mode", type=ParameterType.BOOLEAN,
                          description="Enable strict analysis with lower thresholds", default=False),
            ],
            outputs=[
                OutputField(name="risk_score", type="float", description="Overall risk score 0-100"),
                OutputField(name="findings", type="list", description="Identified policy issues"),
                OutputField(name="recommendations", type="list", description="Remediation steps"),
            ],
            tags=["advanced", "cloud", "iam", "policy", "security"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        policy_json = config.get("policy_json", "").strip()
        if not policy_json:
            return False, "Policy JSON is required"
        try:
            json.loads(policy_json)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _analyze_aws_policy(self, policy: dict, strict: bool) -> tuple[list, list, float]:
        """Analyze an AWS IAM policy document."""
        findings = []
        recommendations = []
        risk_score = 0.0

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            condition = stmt.get("Condition", {})
            principal = stmt.get("Principal", "")

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if effect == "Allow":
                for action in actions:
                    if action == "*":
                        findings.append({
                            "severity": "critical", "statement": idx,
                            "issue": "Wildcard action (*) grants all permissions",
                            "action": action,
                        })
                        risk_score += 30
                        recommendations.append("Replace wildcard (*) actions with specific service actions")
                    elif action.endswith(":*"):
                        service = action.split(":")[0]
                        findings.append({
                            "severity": "high", "statement": idx,
                            "issue": f"Full service wildcard on {service}",
                            "action": action,
                        })
                        risk_score += 15
                        recommendations.append(f"Restrict {service} to specific actions needed")
                    elif action in DANGEROUS_AWS_ACTIONS:
                        findings.append({
                            "severity": "high", "statement": idx,
                            "issue": f"Dangerous action: {action}",
                            "action": action,
                        })
                        risk_score += 10

                for resource in resources:
                    if resource == "*":
                        findings.append({
                            "severity": "high", "statement": idx,
                            "issue": "Wildcard resource (*) - no resource scoping",
                            "resource": resource,
                        })
                        risk_score += 15
                        recommendations.append("Scope resources to specific ARNs")

                if not condition and strict:
                    findings.append({
                        "severity": "medium", "statement": idx,
                        "issue": "No conditions attached to Allow statement",
                    })
                    risk_score += 5
                    recommendations.append(f"Add conditions (e.g., IP restriction, MFA) to statement {idx}")

                if principal == "*":
                    findings.append({
                        "severity": "critical", "statement": idx,
                        "issue": "Principal is wildcard (*) - anyone can use this policy",
                    })
                    risk_score += 25

            if effect == "Deny" and not condition:
                if strict:
                    findings.append({
                        "severity": "low", "statement": idx,
                        "issue": "Deny statement without conditions may be overly broad",
                    })

        admin_patterns = [a for a in (stmt.get("Action", []) if isinstance(stmt.get("Action", []), list)
                                       else [stmt.get("Action", "")])
                          for stmt in statements
                          if stmt.get("Effect") == "Allow"]
        if any(a == "*" for a in admin_patterns) and any(r == "*" for stmt in statements
                                                          for r in (stmt.get("Resource", [])
                                                                    if isinstance(stmt.get("Resource", []), list)
                                                                    else [stmt.get("Resource", "")])):
            findings.append({"severity": "critical", "issue": "Full admin access detected (Action:* + Resource:*)"})
            risk_score += 20

        return findings, list(set(recommendations)), min(risk_score, 100.0)

    def _analyze_azure_policy(self, policy: dict, strict: bool) -> tuple[list, list, float]:
        """Analyze Azure role definition."""
        findings = []
        recommendations = []
        risk_score = 0.0

        permissions = policy.get("permissions", policy.get("Properties", {}).get("permissions", []))
        for perm in permissions:
            actions = perm.get("actions", [])
            not_actions = perm.get("notActions", [])
            for action in actions:
                if action == "*":
                    findings.append({"severity": "critical", "issue": "Wildcard action grants full access"})
                    risk_score += 30
                elif any(action.startswith(d.replace("*", "")) for d in DANGEROUS_AZURE_ACTIONS):
                    findings.append({"severity": "high", "issue": f"Dangerous action: {action}"})
                    risk_score += 10
            if not not_actions and "*" in actions:
                recommendations.append("Use notActions to exclude dangerous permissions from wildcard")

        assignable_scopes = policy.get("assignableScopes", policy.get("Properties", {}).get("assignableScopes", []))
        for scope in assignable_scopes:
            if scope == "/":
                findings.append({"severity": "critical", "issue": "Assignable at root scope"})
                risk_score += 20

        return findings, list(set(recommendations)), min(risk_score, 100.0)

    def _analyze_gcp_policy(self, policy: dict, strict: bool) -> tuple[list, list, float]:
        """Analyze GCP IAM policy binding."""
        findings = []
        recommendations = []
        risk_score = 0.0

        bindings = policy.get("bindings", [])
        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            condition = binding.get("condition", {})

            if "admin" in role.lower() or "owner" in role.lower():
                findings.append({"severity": "high", "issue": f"Privileged role assigned: {role}"})
                risk_score += 15
            if "editor" in role.lower() and not condition:
                findings.append({"severity": "medium", "issue": f"Editor role without conditions: {role}"})
                risk_score += 8

            for member in members:
                if member == "allUsers":
                    findings.append({"severity": "critical", "issue": f"Public access via allUsers on {role}"})
                    risk_score += 30
                elif member == "allAuthenticatedUsers":
                    findings.append({"severity": "high",
                                     "issue": f"All authenticated users have access to {role}"})
                    risk_score += 20

            if not condition and strict:
                findings.append({"severity": "medium", "issue": f"No conditions on binding for {role}"})
                risk_score += 5
                recommendations.append(f"Add IAM conditions to restrict {role} binding")

        return findings, list(set(recommendations)), min(risk_score, 100.0)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        policy = json.loads(config["policy_json"])
        framework = config.get("framework", "aws")
        strict = config.get("strict_mode", False)

        if framework == "aws":
            findings, recommendations, risk_score = self._analyze_aws_policy(policy, strict)
        elif framework == "azure":
            findings, recommendations, risk_score = self._analyze_azure_policy(policy, strict)
        else:
            findings, recommendations, risk_score = self._analyze_gcp_policy(policy, strict)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "framework": framework,
            "risk_score": round(risk_score, 1),
            "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 20 else "low",
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "recommendations": recommendations,
        }
