"""ICS configuration auditor — checks ICS config files for security weaknesses."""

import re
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("root", "root"),
    ("root", ""), ("operator", "operator"), ("user", "user"), ("guest", "guest"),
    ("administrator", "administrator"), ("tech", "tech"), ("maint", "maint"),
    ("plc", "plc"), ("scada", "scada"), ("default", "default"),
]

INSECURE_PROTOCOL_PATTERNS = [
    (re.compile(r"\btelnet\b", re.IGNORECASE), "Telnet", "Use SSH instead of Telnet for remote access"),
    (re.compile(r"\bftp\b(?!s)", re.IGNORECASE), "FTP", "Use SFTP or SCP instead of unencrypted FTP"),
    (re.compile(r"\bhttp\b(?!s)", re.IGNORECASE), "HTTP", "Use HTTPS with valid certificates"),
    (re.compile(r"\bsnmp\s*v[12]\b", re.IGNORECASE), "SNMPv1/v2", "Upgrade to SNMPv3 with authentication"),
    (re.compile(r"\btftp\b", re.IGNORECASE), "TFTP", "Replace TFTP with secure file transfer"),
    (re.compile(r"\brsh\b", re.IGNORECASE), "RSH", "Use SSH instead of remote shell"),
    (re.compile(r"\brlogin\b", re.IGNORECASE), "rlogin", "Use SSH instead of rlogin"),
]

AUTH_WEAKNESS_PATTERNS = [
    (re.compile(r"auth(?:entication)?\s*[:=]\s*(?:none|off|disable|false|no|0)", re.IGNORECASE),
     "Authentication disabled", "critical"),
    (re.compile(r"(?:anonymous|guest)\s*[:=]\s*(?:true|yes|enable|on|1)", re.IGNORECASE),
     "Anonymous/guest access enabled", "high"),
    (re.compile(r"(?:require[_-]?password|password[_-]?required)\s*[:=]\s*(?:false|no|off|0)", re.IGNORECASE),
     "Password not required", "critical"),
    (re.compile(r"(?:encryption|encrypt)\s*[:=]\s*(?:none|off|disable|false|no|0)", re.IGNORECASE),
     "Encryption disabled", "high"),
    (re.compile(r"(?:ssl|tls)\s*[:=]\s*(?:false|no|off|disable|0)", re.IGNORECASE),
     "SSL/TLS disabled", "high"),
    (re.compile(r"debug\s*[:=]\s*(?:true|yes|on|enable|1)", re.IGNORECASE),
     "Debug mode enabled", "medium"),
    (re.compile(r"allow[_-]?remote[_-]?(?:access|programming)\s*[:=]\s*(?:true|yes|on|enable|1)", re.IGNORECASE),
     "Remote access/programming enabled", "high"),
    (re.compile(r"firewall\s*[:=]\s*(?:false|off|disable|no|0)", re.IGNORECASE),
     "Firewall disabled", "critical"),
]

DEVICE_SPECIFIC_CHECKS: dict[str, list[tuple[re.Pattern, str, str]]] = {
    "plc": [
        (re.compile(r"run[_-]?mode\s*[:=]\s*(?:remote|program)", re.IGNORECASE),
         "PLC in remote/program mode — susceptible to unauthorized changes", "high"),
        (re.compile(r"force[_-]?allow\s*[:=]\s*(?:true|yes|1)", re.IGNORECASE),
         "I/O forcing allowed — can override safety interlocks", "critical"),
    ],
    "hmi": [
        (re.compile(r"web[_-]?server\s*[:=]\s*(?:true|yes|on|enable|1)", re.IGNORECASE),
         "HMI web server enabled — potential attack surface", "medium"),
        (re.compile(r"vnc\s*[:=]\s*(?:true|yes|on|enable|1)", re.IGNORECASE),
         "VNC enabled on HMI — ensure strong authentication", "high"),
    ],
    "scada": [
        (re.compile(r"historian[_-]?port\s*[:=]\s*\d+", re.IGNORECASE),
         "Historian port exposed — validate access controls", "medium"),
        (re.compile(r"opc[_-]?(?:classic|da)\s*[:=]\s*(?:true|yes|enable)", re.IGNORECASE),
         "OPC Classic/DA enabled — lacks built-in security, prefer OPC-UA", "high"),
    ],
    "rtu": [
        (re.compile(r"serial[_-]?to[_-]?(?:ip|tcp|ethernet)", re.IGNORECASE),
         "Serial-to-IP bridge detected — may expose serial protocols to network", "high"),
        (re.compile(r"dnp3[_-]?(?:unsolicited|unsol)\s*[:=]\s*(?:true|yes|enable)", re.IGNORECASE),
         "DNP3 unsolicited responses enabled — monitor for spoofing", "medium"),
    ],
}


class IcsConfigAuditorModule(AtsModule):
    """Audit ICS device configuration data for security weaknesses and misconfigurations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_config_auditor",
            category=ModuleCategory.ADVANCED,
            description="Audit ICS configuration files for default credentials, insecure protocols, and misconfigurations",
            version="1.0.0",
            parameters=[
                Parameter(name="config_data", type=ParameterType.STRING,
                          description="Raw configuration text to audit"),
                Parameter(name="device_type", type=ParameterType.CHOICE,
                          description="Type of ICS device", choices=["plc", "hmi", "scada", "rtu"]),
                Parameter(name="strict_mode", type=ParameterType.BOOLEAN,
                          description="Enable strict checks (flag warnings as issues)", default=False),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Security findings with severity"),
                OutputField(name="risk_score", type="float", description="Overall risk score 0-100"),
                OutputField(name="summary", type="dict", description="Findings summary by severity"),
            ],
            tags=["advanced", "ics", "configuration", "audit", "compliance"],
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("config_data", "").strip():
            return False, "Configuration data is required"
        if not config.get("device_type", ""):
            return False, "Device type is required"
        return True, ""

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        config_data = config["config_data"]
        device_type = config["device_type"]
        strict = config.get("strict_mode", False)
        config_lower = config_data.lower()

        findings: list[dict[str, Any]] = []
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}

        # Check for default credentials
        for username, password in DEFAULT_CREDENTIALS:
            if username in config_lower and (not password or password in config_lower):
                findings.append({
                    "category": "default_credentials",
                    "severity": "critical",
                    "detail": f"Possible default credential found: {username}/{password or '(empty)'}",
                    "recommendation": "Change all default credentials immediately",
                })

        # Check for insecure protocols
        for pattern, proto_name, recommendation in INSECURE_PROTOCOL_PATTERNS:
            if pattern.search(config_data):
                findings.append({
                    "category": "insecure_protocol",
                    "severity": "high" if strict else "medium",
                    "detail": f"Insecure protocol detected: {proto_name}",
                    "recommendation": recommendation,
                })

        # Check authentication weaknesses
        for pattern, description, severity in AUTH_WEAKNESS_PATTERNS:
            if pattern.search(config_data):
                findings.append({
                    "category": "auth_weakness",
                    "severity": severity,
                    "detail": description,
                    "recommendation": "Enable and enforce strong authentication",
                })

        # Device-specific checks
        device_checks = DEVICE_SPECIFIC_CHECKS.get(device_type, [])
        for pattern, description, severity in device_checks:
            if pattern.search(config_data):
                findings.append({
                    "category": f"{device_type}_specific",
                    "severity": severity,
                    "detail": description,
                    "recommendation": "Review device-specific hardening guidelines",
                })

        # Calculate risk score
        total_weight = sum(severity_weights.get(f["severity"], 0) for f in findings)
        risk_score = min(100.0, total_weight)

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
        for f in findings:
            summary[f["severity"]] = summary.get(f["severity"], 0) + 1

        return {
            "findings": findings,
            "risk_score": risk_score,
            "summary": summary,
            "device_type": device_type,
            "config_length": len(config_data),
            "strict_mode": strict,
        }
