"""Honeypot deployment configuration generator.

Generate honeypot configurations for common services including
fake banners, capture templates, and logging setup.
"""

import asyncio
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Default service banners that mimic real services
SERVICE_BANNERS = {
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
    "http": "Apache/2.4.54 (Ubuntu) OpenSSL/3.0.2",
    "ftp": "220 (vsFTPd 3.0.5)",
    "smtp": "220 mail.example.com ESMTP Postfix (Ubuntu)",
    "mysql": "5.7.42-0ubuntu0.18.04.1",
}

# Capture templates for each service type
CAPTURE_TEMPLATES = {
    "ssh": ["username", "password", "client_version", "auth_methods_tried"],
    "http": ["method", "path", "user_agent", "headers", "body", "cookies"],
    "ftp": ["username", "password", "commands_issued", "files_accessed"],
    "smtp": ["mail_from", "rcpt_to", "ehlo_domain", "auth_attempts"],
    "mysql": ["username", "password", "database", "queries"],
}

LOG_CONFIGS = {
    "basic": {
        "format": "%(asctime)s %(levelname)s %(message)s",
        "capture_fields": ["timestamp", "source_ip", "event_type"],
        "rotation": "daily",
    },
    "verbose": {
        "format": "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        "capture_fields": [
            "timestamp", "source_ip", "source_port", "event_type",
            "payload_hex", "session_id", "geolocation",
        ],
        "rotation": "hourly",
        "pcap_capture": True,
    },
}


class HoneypotDeployerModule(AtsModule):
    """Generate honeypot configurations for common services."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="honeypot_deployer",
            category=ModuleCategory.DECEPTION,
            description="Generate honeypot configurations for common services with fake banners, capture templates, and logging",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="service_type",
                    type=ParameterType.CHOICE,
                    description="Type of service to emulate",
                    required=True,
                    choices=["ssh", "http", "ftp", "smtp", "mysql"],
                ),
                Parameter(
                    name="port",
                    type=ParameterType.INTEGER,
                    description="Port number to listen on",
                    required=True,
                    min_value=1,
                    max_value=65535,
                ),
                Parameter(
                    name="log_level",
                    type=ParameterType.CHOICE,
                    description="Logging verbosity level",
                    required=False,
                    default="basic",
                    choices=["basic", "verbose"],
                ),
            ],
            outputs=[
                OutputField(name="honeypot_config", type="dict", description="Complete honeypot configuration"),
                OutputField(name="service_banner", type="string", description="Fake service banner text"),
                OutputField(name="monitoring_rules", type="list", description="Alert and monitoring rules"),
            ],
            tags=["deception", "honeypot", "defense", "detection"],
            author="ATS-Toolkit",
            requires_api_key=False,
            api_key_service=None,
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        service_type = config.get("service_type", "")
        if service_type not in SERVICE_BANNERS:
            return False, f"Invalid service_type: {service_type}"
        port = config.get("port")
        if port is None or not isinstance(port, int) or port < 1 or port > 65535:
            return False, "port must be an integer between 1 and 65535"
        return True, ""

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        service_type = config["service_type"]
        port = config["port"]
        log_level = config.get("log_level", "basic")

        self.logger.info("generating_honeypot_config", service=service_type, port=port)

        banner = SERVICE_BANNERS[service_type]
        capture_fields = CAPTURE_TEMPLATES[service_type]
        log_config = LOG_CONFIGS[log_level]

        honeypot_config = {
            "service": service_type,
            "listen_address": "0.0.0.0",
            "listen_port": port,
            "banner": banner,
            "capture_fields": capture_fields,
            "logging": log_config,
            "max_connections": 100,
            "connection_timeout_sec": 120,
            "rate_limit": {"max_per_ip": 20, "window_sec": 60},
        }

        monitoring_rules = [
            {
                "rule": "new_connection",
                "description": f"Alert on any new connection to honeypot {service_type}:{port}",
                "severity": "medium",
                "action": "log_and_alert",
            },
            {
                "rule": "brute_force",
                "description": "Alert when >5 auth attempts from single IP in 60s",
                "severity": "high",
                "threshold": 5,
                "window_sec": 60,
                "action": "log_alert_block",
            },
            {
                "rule": "exploitation_attempt",
                "description": "Alert on known exploit patterns in captured payloads",
                "severity": "critical",
                "action": "log_alert_capture",
            },
        ]

        self.logger.info("honeypot_config_generated", service=service_type, port=port)

        return {
            "honeypot_config": honeypot_config,
            "service_banner": banner,
            "monitoring_rules": monitoring_rules,
        }
