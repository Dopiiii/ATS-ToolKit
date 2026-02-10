"""Network decoy module.

Generate fake network service responses that simulate real services
to mislead attackers and gather intelligence on their techniques.
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

# Response profiles for different simulated environments
RESPONSE_PROFILES = {
    "windows_server": {
        "os_hint": "Windows Server 2019",
        "ttl": 128,
        "tcp_window": 65535,
    },
    "linux": {
        "os_hint": "Ubuntu 22.04 LTS",
        "ttl": 64,
        "tcp_window": 29200,
    },
    "router": {
        "os_hint": "Cisco IOS 15.7",
        "ttl": 255,
        "tcp_window": 4128,
    },
    "iot": {
        "os_hint": "Embedded Linux 4.14",
        "ttl": 64,
        "tcp_window": 5840,
    },
}

# Service-specific banners per profile
SERVICE_BANNERS = {
    "http": {
        "windows_server": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET",
        "linux": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)",
        "router": "HTTP/1.1 200 OK\r\nServer: cisco-IOS",
        "iot": "HTTP/1.1 200 OK\r\nServer: GoAhead-Webs/3.6.5",
    },
    "ssh": {
        "windows_server": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "linux": "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3",
        "router": "SSH-2.0-Cisco-1.25",
        "iot": "SSH-2.0-dropbear_2022.83",
    },
    "ftp": {
        "windows_server": "220 Microsoft FTP Service",
        "linux": "220 (vsFTPd 3.0.5)",
        "router": "220 FTP server ready",
        "iot": "220 BusyBox FTP server ready",
    },
    "telnet": {
        "windows_server": "Microsoft Telnet Service\r\nlogin: ",
        "linux": "Ubuntu 22.04 LTS\r\nlogin: ",
        "router": "User Access Verification\r\nUsername: ",
        "iot": "BusyBox v1.36.1 built-in shell\r\nlogin: ",
    },
    "rdp": {
        "windows_server": "RDP-Negotiation: TLS 1.2, CredSSP, NLA",
        "linux": "XRDP-Negotiation: TLS 1.2",
        "router": "Service not available",
        "iot": "Service not available",
    },
}

# Response templates for interactive sessions
RESPONSE_TEMPLATES = {
    "http": {
        "login_page": "<html><body><form action='/login' method='post'><input name='user'/><input name='pass' type='password'/></form></body></html>",
        "error_404": "<html><body><h1>404 Not Found</h1></body></html>",
        "robots_txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
    },
    "ssh": {
        "auth_fail": "Permission denied (publickey,password).",
        "motd": "Welcome to the server. Unauthorized access is prohibited.",
    },
    "ftp": {
        "auth_fail": "530 Login incorrect.",
        "dir_listing": "drwxr-xr-x  2 root root 4096 Jan 15 09:30 backup\n-rw-r--r--  1 root root  512 Jan 10 14:22 config.bak",
    },
    "telnet": {
        "auth_fail": "Login incorrect",
        "prompt": "$ ",
    },
    "rdp": {
        "negotiate": "RDP Negotiation Response: SSL required",
    },
}


class NetworkDecoyModule(AtsModule):
    """Generate fake network service responses for deception."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="network_decoy",
            category=ModuleCategory.DECEPTION,
            description="Generate fake network service responses simulating real services to mislead attackers",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="service",
                    type=ParameterType.CHOICE,
                    description="Network service to emulate",
                    required=True,
                    choices=["http", "ssh", "ftp", "telnet", "rdp"],
                ),
                Parameter(
                    name="response_profile",
                    type=ParameterType.CHOICE,
                    description="OS/device profile for response characteristics",
                    required=True,
                    choices=["windows_server", "linux", "router", "iot"],
                ),
                Parameter(
                    name="port",
                    type=ParameterType.INTEGER,
                    description="Port number for the decoy service",
                    required=True,
                    min_value=1,
                    max_value=65535,
                ),
            ],
            outputs=[
                OutputField(name="service_config", type="dict", description="Decoy service configuration"),
                OutputField(name="banner_text", type="string", description="Service banner for the decoy"),
                OutputField(name="response_templates", type="dict", description="Interactive response templates"),
            ],
            tags=["deception", "network", "decoy", "service", "emulation"],
            author="ATS-Toolkit",
            requires_api_key=False,
            api_key_service=None,
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        service = config.get("service", "")
        if service not in SERVICE_BANNERS:
            return False, f"Invalid service: {service}"
        profile = config.get("response_profile", "")
        if profile not in RESPONSE_PROFILES:
            return False, f"Invalid response_profile: {profile}"
        port = config.get("port")
        if port is None or not isinstance(port, int) or port < 1 or port > 65535:
            return False, "port must be an integer between 1 and 65535"
        return True, ""

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        service = config["service"]
        profile = config["response_profile"]
        port = config["port"]

        self.logger.info("generating_network_decoy", service=service, profile=profile, port=port)

        profile_data = RESPONSE_PROFILES[profile]
        banner = SERVICE_BANNERS[service][profile]
        templates = RESPONSE_TEMPLATES.get(service, {})

        service_config = {
            "service": service,
            "profile": profile,
            "port": port,
            "listen_address": "0.0.0.0",
            "os_hint": profile_data["os_hint"],
            "tcp_options": {
                "ttl": profile_data["ttl"],
                "window_size": profile_data["tcp_window"],
            },
            "banner": banner,
            "interaction_depth": "medium",
            "max_sessions": 50,
            "session_timeout_sec": 300,
        }

        self.logger.info("network_decoy_generated", service=service, profile=profile)

        return {
            "service_config": service_config,
            "banner_text": banner,
            "response_templates": templates,
        }
