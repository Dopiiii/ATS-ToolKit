"""Cloud container security analyzer.

Analyzes Docker/container configurations for security issues including privilege escalation,
exposed ports, base image vulnerabilities, and secrets in environment variables.
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

KNOWN_VULNERABLE_IMAGES = {
    "alpine:3.12": "CVE-2021-36159 (libfetch)",
    "alpine:3.13": "Multiple musl libc issues",
    "node:14": "EOL - no security patches",
    "node:12": "EOL - critical vulnerabilities",
    "python:3.6": "EOL - no security patches",
    "python:3.7": "EOL - approaching end of life",
    "ubuntu:18.04": "Approaching EOL",
    "debian:stretch": "EOL",
    "nginx:1.16": "Multiple HTTP/2 vulnerabilities",
    "php:7.2": "EOL - no security patches",
}

SECRET_ENV_PATTERNS = [
    (r"(?:PASSWORD|PASSWD|PWD)\s*=\s*\S+", "Hardcoded password"),
    (r"(?:SECRET|TOKEN|API_KEY|APIKEY)\s*=\s*\S+", "Exposed secret/token"),
    (r"(?:AWS_ACCESS_KEY|AWS_SECRET)\s*=\s*\S+", "AWS credentials in env"),
    (r"(?:PRIVATE_KEY|RSA_KEY)\s*=\s*\S+", "Private key in env"),
    (r"(?:DATABASE_URL|DB_PASSWORD|MONGO_URI)\s*=\s*\S+", "Database credentials"),
    (r"(?:GITHUB_TOKEN|GH_TOKEN)\s*=\s*\S+", "GitHub token exposed"),
]


class CloudContainerScannerModule(AtsModule):
    """Analyze Docker/container configurations for security vulnerabilities."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_container_scanner",
            category=ModuleCategory.ADVANCED,
            description="Analyze container configurations for security issues and misconfigurations",
            version="1.0.0",
            parameters=[
                Parameter(name="image_name", type=ParameterType.STRING,
                          description="Docker image name or Dockerfile content", required=True),
                Parameter(name="check_level", type=ParameterType.CHOICE,
                          description="Depth of security checks",
                          choices=["basic", "deep"], default="basic"),
                Parameter(name="include_env_scan", type=ParameterType.BOOLEAN,
                          description="Scan environment variables for secrets", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Security findings"),
                OutputField(name="risk_score", type="float", description="Risk score 0-100"),
                OutputField(name="recommendations", type="list", description="Security recommendations"),
            ],
            tags=["advanced", "cloud", "container", "docker", "security"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        image_name = config.get("image_name", "").strip()
        if not image_name:
            return False, "Image name or Dockerfile content is required"
        return True, ""

    def _parse_dockerfile(self, content: str) -> dict[str, Any]:
        """Parse Dockerfile content into structured data."""
        parsed = {"from": [], "run": [], "env": [], "expose": [], "user": None,
                  "copy": [], "add": [], "cmd": None, "entrypoint": None,
                  "volumes": [], "labels": {}, "healthcheck": None}

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            upper = line.upper()
            if upper.startswith("FROM "):
                parsed["from"].append(line[5:].strip())
            elif upper.startswith("RUN "):
                parsed["run"].append(line[4:].strip())
            elif upper.startswith("ENV "):
                parsed["env"].append(line[4:].strip())
            elif upper.startswith("EXPOSE "):
                parsed["expose"].append(line[7:].strip())
            elif upper.startswith("USER "):
                parsed["user"] = line[5:].strip()
            elif upper.startswith("COPY "):
                parsed["copy"].append(line[5:].strip())
            elif upper.startswith("ADD "):
                parsed["add"].append(line[4:].strip())
            elif upper.startswith("CMD "):
                parsed["cmd"] = line[4:].strip()
            elif upper.startswith("ENTRYPOINT "):
                parsed["entrypoint"] = line[11:].strip()
            elif upper.startswith("VOLUME "):
                parsed["volumes"].append(line[7:].strip())
            elif upper.startswith("HEALTHCHECK "):
                parsed["healthcheck"] = line[12:].strip()

        return parsed

    def _check_base_image(self, image: str) -> list[dict]:
        """Check base image for known vulnerabilities."""
        findings = []
        image_lower = image.lower().split(" as ")[0].strip()

        for vuln_image, vuln_desc in KNOWN_VULNERABLE_IMAGES.items():
            if image_lower == vuln_image or image_lower.startswith(vuln_image.split(":")[0] + ":"):
                findings.append({"severity": "high", "category": "base_image",
                                 "issue": f"Vulnerable base image: {vuln_image} - {vuln_desc}"})

        if ":latest" in image_lower or ":" not in image_lower:
            findings.append({"severity": "medium", "category": "base_image",
                             "issue": "Using :latest or untagged image - unpredictable builds"})

        if image_lower.startswith("scratch"):
            findings.append({"severity": "info", "category": "base_image",
                             "issue": "Minimal scratch base image - good practice"})

        return findings

    def _check_security_practices(self, parsed: dict, deep: bool) -> list[dict]:
        """Analyze Dockerfile for security best practices."""
        findings = []

        if not parsed["user"] or parsed["user"] in ("root", "0"):
            findings.append({"severity": "high", "category": "privilege",
                             "issue": "Container runs as root - privilege escalation risk"})

        for run_cmd in parsed["run"]:
            if "chmod 777" in run_cmd:
                findings.append({"severity": "high", "category": "permissions",
                                 "issue": f"Overly permissive chmod 777 in RUN: {run_cmd[:80]}"})
            if "curl" in run_cmd and "| sh" in run_cmd or "| bash" in run_cmd:
                findings.append({"severity": "critical", "category": "supply_chain",
                                 "issue": "Piping curl to shell - supply chain risk"})
            if "--no-check-certificate" in run_cmd or "-k " in run_cmd:
                findings.append({"severity": "medium", "category": "tls",
                                 "issue": "TLS certificate verification disabled"})
            if deep and "apt-get install" in run_cmd and "-y" in run_cmd:
                if "apt-get clean" not in " ".join(parsed["run"]):
                    findings.append({"severity": "low", "category": "optimization",
                                     "issue": "Missing apt-get clean - bloated image"})

        for add_cmd in parsed["add"]:
            if add_cmd.startswith("http") or ".tar" in add_cmd:
                findings.append({"severity": "medium", "category": "supply_chain",
                                 "issue": f"ADD from remote URL or archive: {add_cmd[:80]} - use COPY instead"})

        sensitive_ports = {"22": "SSH", "23": "Telnet", "3389": "RDP", "5900": "VNC"}
        for port in parsed["expose"]:
            port_num = port.split("/")[0].strip()
            if port_num in sensitive_ports:
                findings.append({"severity": "medium", "category": "network",
                                 "issue": f"Exposed sensitive port {port_num} ({sensitive_ports[port_num]})"})

        if not parsed["healthcheck"]:
            if deep:
                findings.append({"severity": "low", "category": "reliability",
                                 "issue": "No HEALTHCHECK defined"})

        return findings

    def _scan_env_secrets(self, env_vars: list[str]) -> list[dict]:
        """Scan environment variables for hardcoded secrets."""
        findings = []
        for env_line in env_vars:
            for pattern, desc in SECRET_ENV_PATTERNS:
                if re.search(pattern, env_line, re.IGNORECASE):
                    findings.append({"severity": "critical", "category": "secrets",
                                     "issue": f"{desc} in ENV: {env_line[:60]}..."})
                    break
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        content = config["image_name"].strip()
        check_level = config.get("check_level", "basic")
        include_env = config.get("include_env_scan", True)
        deep = check_level == "deep"

        is_dockerfile = any(kw in content.upper() for kw in ["FROM ", "RUN ", "COPY ", "CMD "])
        findings = []
        recommendations = []

        if is_dockerfile:
            parsed = self._parse_dockerfile(content)
            for base_img in parsed["from"]:
                findings.extend(self._check_base_image(base_img))
            findings.extend(self._check_security_practices(parsed, deep))
            if include_env:
                findings.extend(self._scan_env_secrets(parsed["env"]))
        else:
            findings.extend(self._check_base_image(content))
            findings.append({"severity": "info", "category": "input",
                             "issue": "Only image name provided - provide Dockerfile for deeper analysis"})

        severity_map = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        risk_score = min(sum(severity_map.get(f["severity"], 0) for f in findings), 100.0)

        if any(f["severity"] == "critical" and f["category"] == "privilege" for f in findings):
            recommendations.append("Add USER directive with non-root user")
        if any(f["category"] == "secrets" for f in findings):
            recommendations.append("Use Docker secrets or build args instead of ENV for sensitive data")
        if any(f["category"] == "base_image" for f in findings):
            recommendations.append("Pin base images to specific digest and use minimal images")
        if any(f["category"] == "supply_chain" for f in findings):
            recommendations.append("Verify checksums for downloaded files and avoid piping to shell")

        return {
            "input_type": "dockerfile" if is_dockerfile else "image_name",
            "findings": findings,
            "finding_count": len(findings),
            "risk_score": round(risk_score, 1),
            "risk_level": "critical" if risk_score >= 60 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low",
            "recommendations": recommendations,
        }
