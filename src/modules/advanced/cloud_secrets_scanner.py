"""Cloud secrets scanner for exposed credentials in configurations.

Scans text data for exposed AWS keys, Azure tokens, GCP service accounts,
generic passwords, and private keys using regex pattern matching.
"""

import asyncio
import re
import json
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

SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "pattern": r"(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "description": "AWS Secret Access Key",
    },
    "azure_storage_key": {
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "severity": "critical",
        "description": "Azure Storage Account Connection String",
    },
    "azure_sas_token": {
        "pattern": r"[?&]sig=[A-Za-z0-9%+/=]{43,}",
        "severity": "high",
        "description": "Azure SAS Token",
    },
    "azure_client_secret": {
        "pattern": r"(?:client_secret|clientSecret)\s*[:=]\s*['\"]?([A-Za-z0-9~._\-]{34,})['\"]?",
        "severity": "critical",
        "description": "Azure Client Secret",
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "description": "GCP Service Account JSON Key",
    },
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z_\-]{35}",
        "severity": "high",
        "description": "Google API Key",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Key",
    },
    "generic_password": {
        "pattern": r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,64})['\"]?",
        "severity": "high",
        "description": "Generic Password",
    },
    "generic_token": {
        "pattern": r"(?:token|api_key|apikey|api-key|access_token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{20,})['\"]?",
        "severity": "high",
        "description": "Generic API Token",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "severity": "high",
        "description": "JWT Token",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "severity": "high",
        "description": "Slack Webhook URL",
    },
    "github_token": {
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",
        "severity": "critical",
        "description": "GitHub Personal Access Token",
    },
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",
        "severity": "critical",
        "description": "Stripe API Key",
    },
    "database_url": {
        "pattern": r"(?:mongodb|postgres|mysql|redis|amqp)(?:\+\w+)?://[^\s'\"]{10,}",
        "severity": "high",
        "description": "Database Connection URL",
    },
    "sendgrid_key": {
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "severity": "high",
        "description": "SendGrid API Key",
    },
}

ENV_VAR_PATTERN = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$", re.MULTILINE)


class CloudSecretsScannerModule(AtsModule):
    """Scan for exposed secrets in cloud configurations and data."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_secrets_scanner",
            category=ModuleCategory.ADVANCED,
            description="Scan for exposed secrets, credentials, and tokens in cloud configurations",
            version="1.0.0",
            parameters=[
                Parameter(name="data", type=ParameterType.STRING,
                          description="Text data to scan for secrets", required=True),
                Parameter(name="scan_scope", type=ParameterType.CHOICE,
                          description="Scope of secret scanning",
                          choices=["env_vars", "config_files", "all"], default="all"),
                Parameter(name="mask_secrets", type=ParameterType.BOOLEAN,
                          description="Mask discovered secrets in output", default=True),
            ],
            outputs=[
                OutputField(name="secrets_found", type="integer", description="Number of secrets found"),
                OutputField(name="findings", type="list", description="Secret findings"),
                OutputField(name="severity_summary", type="dict", description="Findings by severity"),
            ],
            tags=["advanced", "cloud", "secrets", "credentials", "scanner"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("data", "").strip()
        if not data:
            return False, "Data to scan is required"
        if len(data) < 5:
            return False, "Data too short to contain meaningful secrets"
        return True, ""

    def _mask_secret(self, value: str) -> str:
        """Mask a secret value, preserving first and last 2 characters."""
        if len(value) <= 8:
            return value[:2] + "****" + value[-1:]
        return value[:4] + "*" * (len(value) - 6) + value[-2:]

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        from math import log2
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum((count / length) * log2(count / length) for count in freq.values())

    def _scan_for_secrets(self, data: str, scope: str) -> list[dict]:
        """Scan data against all secret patterns."""
        findings = []
        seen_hashes = set()

        for secret_name, config in SECRET_PATTERNS.items():
            matches = re.finditer(config["pattern"], data, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(0)
                value_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]

                if value_hash in seen_hashes:
                    continue
                seen_hashes.add(value_hash)

                line_start = data.rfind("\n", 0, match.start()) + 1
                line_end = data.find("\n", match.end())
                if line_end == -1:
                    line_end = len(data)
                context_line = data[line_start:line_end].strip()

                line_number = data[:match.start()].count("\n") + 1

                findings.append({
                    "type": secret_name,
                    "description": config["description"],
                    "severity": config["severity"],
                    "line": line_number,
                    "value_hash": value_hash,
                    "matched_text": secret_value,
                    "context": context_line[:120],
                    "entropy": round(self._calculate_entropy(secret_value), 2),
                })

        if scope in ("env_vars", "all"):
            for match in ENV_VAR_PATTERN.finditer(data):
                var_name = match.group(1)
                var_value = match.group(2).strip().strip("'\"")
                sensitive_names = ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH"]
                if any(s in var_name for s in sensitive_names):
                    value_hash = hashlib.sha256(var_value.encode()).hexdigest()[:16]
                    if value_hash not in seen_hashes:
                        seen_hashes.add(value_hash)
                        entropy = self._calculate_entropy(var_value)
                        if entropy > 3.0 or len(var_value) > 10:
                            findings.append({
                                "type": "env_variable_secret",
                                "description": f"Sensitive env var: {var_name}",
                                "severity": "high",
                                "line": data[:match.start()].count("\n") + 1,
                                "value_hash": value_hash,
                                "matched_text": f"{var_name}={var_value}",
                                "context": match.group(0)[:120],
                                "entropy": round(entropy, 2),
                            })

        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = config["data"]
        scope = config.get("scan_scope", "all")
        mask = config.get("mask_secrets", True)

        findings = self._scan_for_secrets(data, scope)

        if mask:
            for finding in findings:
                finding["matched_text"] = self._mask_secret(finding["matched_text"])
                finding["context"] = self._mask_secret(finding["context"])

        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_summary[f["severity"]] = severity_summary.get(f["severity"], 0) + 1

        findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

        return {
            "scan_scope": scope,
            "data_length": len(data),
            "secrets_found": len(findings),
            "findings": findings,
            "severity_summary": severity_summary,
            "risk_level": "critical" if severity_summary["critical"] > 0 else
                         "high" if severity_summary["high"] > 0 else "low",
        }
