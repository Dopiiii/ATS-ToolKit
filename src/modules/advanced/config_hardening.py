"""Configuration hardening module for common services.

Generates hardened configurations for nginx, Apache, SSH, MySQL, and Docker
based on CIS, NSA, or custom security standards.
"""

import asyncio
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

HARDENING_RULES: dict[str, dict[str, list[dict]]] = {
    "ssh": {
        "cis": [
            {"directive": "PermitRootLogin", "value": "no", "reason": "CIS 5.2.10 - Disable root SSH login"},
            {"directive": "MaxAuthTries", "value": "3", "reason": "CIS 5.2.7 - Limit authentication attempts"},
            {"directive": "PasswordAuthentication", "value": "no", "reason": "CIS 5.2.12 - Use key-based authentication"},
            {"directive": "PermitEmptyPasswords", "value": "no", "reason": "CIS 5.2.11 - Deny empty passwords"},
            {"directive": "X11Forwarding", "value": "no", "reason": "CIS 5.2.6 - Disable X11 forwarding"},
            {"directive": "Protocol", "value": "2", "reason": "CIS 5.2.4 - Use SSH Protocol 2 only"},
            {"directive": "ClientAliveInterval", "value": "300", "reason": "CIS 5.2.13 - Set idle timeout"},
            {"directive": "ClientAliveCountMax", "value": "2", "reason": "CIS 5.2.13 - Limit keepalive count"},
            {"directive": "LoginGraceTime", "value": "60", "reason": "CIS 5.2.16 - Limit login grace time"},
            {"directive": "AllowAgentForwarding", "value": "no", "reason": "Disable agent forwarding"},
        ],
        "nsa": [
            {"directive": "PermitRootLogin", "value": "no", "reason": "NSA - Disable root SSH login"},
            {"directive": "MaxAuthTries", "value": "3", "reason": "NSA - Limit authentication retries"},
            {"directive": "PasswordAuthentication", "value": "no", "reason": "NSA - Enforce key authentication"},
            {"directive": "Ciphers", "value": "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr", "reason": "NSA - Use strong ciphers only"},
            {"directive": "MACs", "value": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com", "reason": "NSA - Use strong MACs"},
            {"directive": "KexAlgorithms", "value": "curve25519-sha256,diffie-hellman-group16-sha512", "reason": "NSA - Use strong key exchange"},
        ],
    },
    "nginx": {
        "cis": [
            {"directive": "server_tokens", "value": "off", "reason": "CIS 2.5.1 - Hide server version"},
            {"directive": "add_header X-Frame-Options", "value": "SAMEORIGIN", "reason": "CIS 4.1 - Clickjacking protection"},
            {"directive": "add_header X-Content-Type-Options", "value": "nosniff", "reason": "CIS 4.1 - MIME sniffing protection"},
            {"directive": "add_header X-XSS-Protection", "value": "\"1; mode=block\"", "reason": "CIS 4.1 - XSS filter"},
            {"directive": "add_header Strict-Transport-Security", "value": "\"max-age=31536000; includeSubDomains\"", "reason": "CIS 4.1 - Enforce HTTPS"},
            {"directive": "ssl_protocols", "value": "TLSv1.2 TLSv1.3", "reason": "CIS 4.1.6 - Disable weak TLS versions"},
            {"directive": "ssl_prefer_server_ciphers", "value": "on", "reason": "CIS 4.1.7 - Server cipher preference"},
            {"directive": "client_max_body_size", "value": "10m", "reason": "CIS 5.2 - Limit request body size"},
            {"directive": "limit_req_zone", "value": "$binary_remote_addr zone=ratelimit:10m rate=10r/s", "reason": "Rate limiting"},
        ],
    },
    "apache": {
        "cis": [
            {"directive": "ServerTokens", "value": "Prod", "reason": "CIS 3.3 - Minimize server info"},
            {"directive": "ServerSignature", "value": "Off", "reason": "CIS 3.4 - Disable server signature"},
            {"directive": "TraceEnable", "value": "Off", "reason": "CIS 5.8 - Disable TRACE method"},
            {"directive": "Header set X-Frame-Options", "value": "SAMEORIGIN", "reason": "CIS 10.1 - Clickjacking protection"},
            {"directive": "Header set X-Content-Type-Options", "value": "nosniff", "reason": "CIS 10.2 - MIME protection"},
            {"directive": "Timeout", "value": "60", "reason": "CIS 6.1 - Set request timeout"},
            {"directive": "MaxKeepAliveRequests", "value": "100", "reason": "CIS 6.3 - Limit keepalive requests"},
            {"directive": "SSLProtocol", "value": "all -SSLv3 -TLSv1 -TLSv1.1", "reason": "CIS 9.1 - Strong TLS only"},
        ],
    },
    "mysql": {
        "cis": [
            {"directive": "bind-address", "value": "127.0.0.1", "reason": "CIS 3.4 - Bind to localhost only"},
            {"directive": "local-infile", "value": "0", "reason": "CIS 4.6 - Disable local infile"},
            {"directive": "skip-symbolic-links", "value": "yes", "reason": "CIS 4.3 - Disable symbolic links"},
            {"directive": "log-error", "value": "/var/log/mysql/error.log", "reason": "CIS 6.1 - Enable error logging"},
            {"directive": "general-log", "value": "0", "reason": "CIS 6.2 - Disable general query log in production"},
            {"directive": "max_connect_errors", "value": "5", "reason": "Limit connection errors before blocking"},
            {"directive": "default_password_lifetime", "value": "90", "reason": "CIS 7.7 - Password expiry policy"},
        ],
    },
    "docker": {
        "cis": [
            {"directive": "userns-remap", "value": "default", "reason": "CIS 2.8 - Enable user namespace remapping"},
            {"directive": "no-new-privileges", "value": "true", "reason": "CIS 5.25 - Restrict new privileges"},
            {"directive": "icc", "value": "false", "reason": "CIS 2.1 - Disable inter-container communication"},
            {"directive": "log-driver", "value": "json-file", "reason": "CIS 2.12 - Configure centralized logging"},
            {"directive": "log-opts max-size", "value": "10m", "reason": "CIS 2.12 - Limit log file size"},
            {"directive": "log-opts max-file", "value": "3", "reason": "CIS 2.12 - Limit log file count"},
            {"directive": "live-restore", "value": "true", "reason": "CIS 2.14 - Enable live restore"},
        ],
    },
}


class ConfigHardeningModule(AtsModule):
    """Generate hardened configurations for common services."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="config_hardening",
            category=ModuleCategory.ADVANCED,
            description="Generate hardened service configurations based on CIS, NSA, or custom security standards",
            version="1.0.0",
            parameters=[
                Parameter(name="service", type=ParameterType.CHOICE,
                          description="Target service to harden",
                          choices=["nginx", "apache", "ssh", "mysql", "docker"]),
                Parameter(name="current_config", type=ParameterType.STRING,
                          description="Current configuration text to diff against (optional)",
                          required=False, default=""),
                Parameter(name="standard", type=ParameterType.CHOICE,
                          description="Hardening standard to apply",
                          choices=["cis", "nsa", "custom"], default="cis"),
            ],
            outputs=[
                OutputField(name="hardened_config", type="string", description="Generated hardened configuration"),
                OutputField(name="changes_needed", type="list", description="List of changes from current config"),
                OutputField(name="compliance_score", type="float", description="Compliance score 0-100"),
            ],
            tags=["advanced", "hardening", "configuration", "cis", "compliance"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        service = config.get("service", "")
        if service not in HARDENING_RULES:
            return False, f"Unsupported service '{service}'"
        standard = config.get("standard", "cis")
        if standard == "nsa" and service not in ("ssh",):
            # Fall back to CIS for services without NSA-specific rules
            pass
        return True, ""

    def _get_rules(self, service: str, standard: str) -> list[dict]:
        """Get hardening rules for a service and standard."""
        svc_rules = HARDENING_RULES.get(service, {})
        rules = svc_rules.get(standard, svc_rules.get("cis", []))
        return rules

    def _generate_config(self, service: str, rules: list[dict]) -> str:
        """Generate a hardened configuration block."""
        lines = [f"# Hardened {service.upper()} Configuration", f"# Standard: Security Hardening Best Practices", ""]
        for rule in rules:
            lines.append(f"# {rule['reason']}")
            if service in ("ssh",):
                lines.append(f"{rule['directive']} {rule['value']}")
            elif service in ("nginx",):
                lines.append(f"{rule['directive']} {rule['value']};")
            elif service in ("apache",):
                lines.append(f"{rule['directive']} {rule['value']}")
            elif service in ("mysql",):
                lines.append(f"{rule['directive']} = {rule['value']}")
            elif service in ("docker",):
                lines.append(f"\"{rule['directive']}\": {rule['value']}")
            lines.append("")
        return "\n".join(lines)

    def _diff_config(self, current: str, rules: list[dict], service: str) -> tuple[list[dict], float]:
        """Compare current config against hardening rules, return changes and score."""
        if not current.strip():
            changes = [{"directive": r["directive"], "expected": r["value"],
                        "current": "NOT SET", "status": "missing", "reason": r["reason"]} for r in rules]
            return changes, 0.0

        current_lower = current.lower()
        compliant = 0
        changes = []
        for rule in rules:
            directive_lower = rule["directive"].lower()
            pattern = re.compile(re.escape(directive_lower) + r"\s+(.+?)(?:\s*[;#]|$)", re.MULTILINE | re.IGNORECASE)
            match = pattern.search(current)
            if match:
                current_val = match.group(1).strip().rstrip(";").strip()
                if current_val.lower() == rule["value"].lower():
                    compliant += 1
                    changes.append({"directive": rule["directive"], "expected": rule["value"],
                                    "current": current_val, "status": "compliant", "reason": rule["reason"]})
                else:
                    changes.append({"directive": rule["directive"], "expected": rule["value"],
                                    "current": current_val, "status": "non_compliant", "reason": rule["reason"]})
            else:
                changes.append({"directive": rule["directive"], "expected": rule["value"],
                                "current": "NOT SET", "status": "missing", "reason": rule["reason"]})

        score = round((compliant / len(rules)) * 100, 1) if rules else 100.0
        return changes, score

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        service = config["service"]
        current_config = config.get("current_config", "")
        standard = config.get("standard", "cis")

        rules = self._get_rules(service, standard)
        hardened = self._generate_config(service, rules)
        changes, score = self._diff_config(current_config, rules, service)

        return {
            "hardened_config": hardened,
            "changes_needed": [c for c in changes if c["status"] != "compliant"],
            "compliance_score": score,
            "all_checks": changes,
            "service": service,
            "standard": standard,
            "total_rules": len(rules),
            "compliant_rules": sum(1 for c in changes if c["status"] == "compliant"),
        }
