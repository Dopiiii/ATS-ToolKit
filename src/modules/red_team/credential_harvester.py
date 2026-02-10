"""Credential Harvester Module.

Detect credential exposure by scanning memory dumps, configuration files,
and environment variables for secret patterns such as API keys, tokens,
passwords, and connection strings.
"""

import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Regex patterns for detecting various credential types
CREDENTIAL_PATTERNS = {
    "aws_access_key": {
        "pattern": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
        "description": "AWS Secret Access Key",
        "severity": "critical",
    },
    "github_token": {
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "generic_api_key": {
        "pattern": re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{20,}['\"]?", re.IGNORECASE),
        "description": "Generic API Key",
        "severity": "high",
    },
    "generic_secret": {
        "pattern": re.compile(r"(?:secret|SECRET)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{16,}['\"]?"),
        "description": "Generic Secret Value",
        "severity": "high",
    },
    "password_in_config": {
        "pattern": re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}['\"]?", re.IGNORECASE),
        "description": "Password in Configuration",
        "severity": "critical",
    },
    "connection_string": {
        "pattern": re.compile(r"(?:mongodb|mysql|postgres|redis|amqp)://[^\s'\"]{10,}", re.IGNORECASE),
        "description": "Database Connection String",
        "severity": "critical",
    },
    "private_key_header": {
        "pattern": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----"),
        "description": "Private Key",
        "severity": "critical",
    },
    "jwt_token": {
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "description": "JWT Token",
        "severity": "high",
    },
    "slack_token": {
        "pattern": re.compile(r"xox[bpors]-[A-Za-z0-9\-]{10,}"),
        "description": "Slack Token",
        "severity": "critical",
    },
    "azure_client_secret": {
        "pattern": re.compile(r"(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.~]{30,}['\"]?", re.IGNORECASE),
        "description": "Azure Client Secret",
        "severity": "critical",
    },
    "gcp_service_account": {
        "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
        "description": "GCP Service Account JSON Key",
        "severity": "critical",
    },
    "basic_auth_header": {
        "pattern": re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
        "description": "HTTP Basic Auth Header",
        "severity": "high",
    },
    "bearer_token": {
        "pattern": re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9\-_.~+/=]{20,}", re.IGNORECASE),
        "description": "HTTP Bearer Token",
        "severity": "high",
    },
}

# Sensitive file paths commonly containing credentials
SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production",
    "wp-config.php", "config.php", "settings.py",
    "application.yml", "application.properties",
    "credentials.json", "service-account.json",
    "id_rsa", "id_ed25519", ".pgpass", ".netrc",
    "web.config", "appsettings.json",
    ".git-credentials", ".docker/config.json",
]


class CredentialHarvesterModule(AtsModule):
    """Detect credential exposure in text data, configs, and memory dumps."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="credential_harvester",
            category=ModuleCategory.RED_TEAM,
            description="Detect credential exposure by scanning text data for API keys, tokens, passwords, and connection strings",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target system or application identifier",
                    required=True,
                ),
                Parameter(
                    name="text_data",
                    type=ParameterType.LIST,
                    description="List of text content blocks to scan (file contents, env vars, memory dump strings)",
                    required=True,
                ),
                Parameter(
                    name="file_names",
                    type=ParameterType.LIST,
                    description="List of filenames corresponding to each text_data block (for reporting)",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="scan_patterns",
                    type=ParameterType.LIST,
                    description="Specific pattern names to scan for (empty = all patterns)",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="redact_values",
                    type=ParameterType.BOOLEAN,
                    description="Redact actual credential values in output (show only first/last 4 chars)",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="credentials_found", type="list", description="Detected credential exposures"),
                OutputField(name="sensitive_files", type="list", description="Known sensitive filenames detected"),
                OutputField(name="summary", type="dict", description="Scan summary with statistics"),
            ],
            tags=["red_team", "credentials", "secrets", "harvesting", "exposure"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target identifier is required"
        if not config.get("text_data"):
            return False, "At least one text data block is required"
        return True, ""

    def _redact(self, value: str, enabled: bool) -> str:
        """Redact a credential value, showing only first and last 4 characters."""
        if not enabled or len(value) <= 8:
            return "****" if enabled else value
        return f"{value[:4]}...{value[-4:]}"

    def _scan_block(self, text: str, block_index: int, filename: str,
                    patterns: Dict[str, Dict], redact: bool) -> List[Dict[str, Any]]:
        """Scan a single text block for credential patterns."""
        findings = []
        lines = text.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_info in patterns.items():
                for match in pattern_info["pattern"].finditer(line):
                    matched_text = match.group(0)
                    findings.append({
                        "pattern": pattern_name,
                        "description": pattern_info["description"],
                        "severity": pattern_info["severity"],
                        "matched_value": self._redact(matched_text, redact),
                        "source_file": filename,
                        "block_index": block_index,
                        "line_number": line_num,
                        "line_preview": self._redact(line.strip()[:120], redact),
                    })
        return findings

    def _check_sensitive_filenames(self, file_names: List[str]) -> List[Dict[str, Any]]:
        """Check if any provided filenames match known sensitive file patterns."""
        hits = []
        for fname in file_names:
            fname_lower = fname.strip().lower()
            basename = fname_lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            for sensitive in SENSITIVE_FILE_PATTERNS:
                if basename == sensitive.lower() or fname_lower.endswith(sensitive.lower()):
                    hits.append({
                        "filename": fname.strip(),
                        "matched_pattern": sensitive,
                        "severity": "high",
                        "description": f"Sensitive file detected: {sensitive}",
                    })
                    break
        return hits

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        text_data = config["text_data"]
        file_names = config.get("file_names", []) or []
        scan_patterns = config.get("scan_patterns", []) or []
        redact = config.get("redact_values", True)

        self.logger.info("credential_scan_start", target=target, blocks=len(text_data))

        # Filter patterns if specific ones were requested
        if scan_patterns:
            patterns = {k: v for k, v in CREDENTIAL_PATTERNS.items() if k in scan_patterns}
        else:
            patterns = CREDENTIAL_PATTERNS

        # Ensure file_names list matches text_data length
        while len(file_names) < len(text_data):
            file_names.append(f"block_{len(file_names)}")

        # Scan all blocks concurrently via executor
        loop = asyncio.get_event_loop()
        tasks = []
        for idx, block in enumerate(text_data):
            fname = file_names[idx] if idx < len(file_names) else f"block_{idx}"
            tasks.append(loop.run_in_executor(None, self._scan_block, block, idx, fname, patterns, redact))

        results = await asyncio.gather(*tasks)
        all_credentials = []
        for block_findings in results:
            all_credentials.extend(block_findings)

        # Check sensitive filenames
        sensitive_files = self._check_sensitive_filenames(file_names)

        # Statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        pattern_counts: Dict[str, int] = {}
        for cred in all_credentials:
            sev = cred.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            pname = cred.get("pattern", "unknown")
            pattern_counts[pname] = pattern_counts.get(pname, 0) + 1

        summary = {
            "target": target,
            "blocks_scanned": len(text_data),
            "patterns_used": len(patterns),
            "total_credentials_found": len(all_credentials),
            "sensitive_files_found": len(sensitive_files),
            "severity_breakdown": severity_counts,
            "findings_by_pattern": pattern_counts,
            "redacted": redact,
            "scanned_at": datetime.utcnow().isoformat(),
        }

        self.logger.info("credential_scan_complete", target=target, found=len(all_credentials))

        return {
            "credentials_found": all_credentials,
            "sensitive_files": sensitive_files,
            "summary": summary,
        }
