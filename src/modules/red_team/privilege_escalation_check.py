"""Privilege Escalation Check Module.

Check for common privilege escalation vectors including SUID binaries,
writable paths, sudo misconfigurations, and service permission issues.
"""

import asyncio
import re
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Known SUID binaries that can be exploited for privesc (GTFOBins)
DANGEROUS_SUID_BINARIES = {
    "bash", "sh", "dash", "zsh", "csh", "ksh",
    "python", "python2", "python3", "perl", "ruby", "lua",
    "vim", "vi", "nano", "less", "more", "man",
    "find", "nmap", "awk", "gawk", "env", "strace",
    "cp", "mv", "chmod", "chown", "dd",
    "wget", "curl", "nc", "ncat", "socat",
    "docker", "pkexec", "aria2c", "gdb",
    "php", "node", "tclsh", "wish",
}

# Common writable paths that can lead to hijacking
SENSITIVE_WRITABLE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
    "/etc/ld.so.conf", "/etc/ld.so.conf.d/",
    "/usr/local/bin", "/usr/local/sbin",
    "/tmp", "/var/tmp",
]

# Dangerous sudo configurations
DANGEROUS_SUDO_PATTERNS = [
    re.compile(r"ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL", re.IGNORECASE),
    re.compile(r"NOPASSWD:.*(/bin/bash|/bin/sh|/usr/bin/python|/usr/bin/perl)", re.IGNORECASE),
    re.compile(r"NOPASSWD:.*(/usr/bin/vim|/usr/bin/vi|/usr/bin/nano)", re.IGNORECASE),
    re.compile(r"NOPASSWD:.*(/usr/bin/find|/usr/bin/awk|/usr/bin/less)", re.IGNORECASE),
    re.compile(r"NOPASSWD:.*(env|strace|gdb|docker|pkexec)", re.IGNORECASE),
    re.compile(r"\(root\)\s*NOPASSWD:", re.IGNORECASE),
]

# Kernel exploit patterns (version -> known CVEs)
KNOWN_KERNEL_VULNS = {
    "3.13": ["CVE-2015-1328 (overlayfs)"],
    "4.4": ["CVE-2016-5195 (DirtyCow)"],
    "4.14": ["CVE-2018-18955 (user namespace)"],
    "5.8": ["CVE-2021-3490 (eBPF)", "CVE-2022-0847 (DirtyPipe)"],
    "5.10": ["CVE-2022-0847 (DirtyPipe)"],
    "5.15": ["CVE-2022-0847 (DirtyPipe)"],
    "5.16": ["CVE-2022-0847 (DirtyPipe)"],
}


class PrivilegeEscalationCheckModule(AtsModule):
    """Check for privilege escalation vectors on a target system."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="privilege_escalation_check",
            category=ModuleCategory.RED_TEAM,
            description="Check for privilege escalation vectors: SUID bits, writable paths, sudo misconfigs, and kernel exploits",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target hostname or IP to assess",
                    required=True,
                ),
                Parameter(
                    name="suid_binaries",
                    type=ParameterType.LIST,
                    description="List of SUID binary paths found on target (e.g. ['/usr/bin/find', '/usr/bin/python3'])",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="writable_paths",
                    type=ParameterType.LIST,
                    description="List of world-writable file/directory paths found on target",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="sudo_config",
                    type=ParameterType.STRING,
                    description="Contents of /etc/sudoers or sudo -l output",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="kernel_version",
                    type=ParameterType.STRING,
                    description="Kernel version string (e.g. 5.15.0-76-generic)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="services",
                    type=ParameterType.LIST,
                    description="List of running services with their user context (e.g. [{'name':'mysql','user':'root'}])",
                    required=False,
                    default=[],
                ),
            ],
            outputs=[
                OutputField(name="vulnerabilities", type="list", description="Identified privilege escalation vectors"),
                OutputField(name="summary", type="dict", description="Assessment summary with risk rating"),
            ],
            tags=["red_team", "privilege_escalation", "privesc", "linux", "audit"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target hostname or IP is required"
        return True, ""

    def _check_suid_binaries(self, suid_list: List[str]) -> List[Dict[str, Any]]:
        """Check provided SUID binaries against known exploitable list."""
        findings = []
        for binary_path in suid_list:
            binary_name = binary_path.strip().rstrip("/").split("/")[-1]
            if binary_name in DANGEROUS_SUID_BINARIES:
                findings.append({
                    "type": "dangerous_suid",
                    "severity": "critical",
                    "path": binary_path.strip(),
                    "binary": binary_name,
                    "description": f"SUID bit set on {binary_name} - exploitable via GTFOBins",
                    "reference": f"https://gtfobins.github.io/gtfobins/{binary_name}/#suid",
                })
        return findings

    def _check_writable_paths(self, writable_list: List[str]) -> List[Dict[str, Any]]:
        """Check writable paths for sensitive locations."""
        findings = []
        for path in writable_list:
            path = path.strip()
            for sensitive in SENSITIVE_WRITABLE_PATHS:
                if path == sensitive or path.startswith(sensitive):
                    findings.append({
                        "type": "writable_sensitive_path",
                        "severity": "high",
                        "path": path,
                        "description": f"Writable sensitive path: {path} may allow privilege escalation",
                    })
                    break
            # Check for writable PATH directories
            if path.startswith(("/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin")):
                findings.append({
                    "type": "writable_path_dir",
                    "severity": "critical",
                    "path": path,
                    "description": f"Writable system PATH directory: {path} allows binary hijacking",
                })
        return findings

    def _check_sudo_config(self, sudo_config: str) -> List[Dict[str, Any]]:
        """Analyze sudo configuration for dangerous rules."""
        if not sudo_config:
            return []
        findings = []
        for i, line in enumerate(sudo_config.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for pattern in DANGEROUS_SUDO_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "dangerous_sudo_rule",
                        "severity": "critical",
                        "line_number": i,
                        "rule": line,
                        "description": f"Dangerous sudo rule allows privilege escalation: {line[:100]}",
                    })
                    break
        return findings

    def _check_kernel_version(self, kernel_version: str) -> List[Dict[str, Any]]:
        """Match kernel version against known privilege escalation CVEs."""
        if not kernel_version:
            return []
        findings = []
        for ver_prefix, cves in KNOWN_KERNEL_VULNS.items():
            if kernel_version.startswith(ver_prefix):
                findings.append({
                    "type": "kernel_vulnerability",
                    "severity": "critical",
                    "kernel_version": kernel_version,
                    "potential_cves": cves,
                    "description": f"Kernel {kernel_version} may be vulnerable to: {', '.join(cves)}",
                })
        return findings

    def _check_services(self, services: List[Dict]) -> List[Dict[str, Any]]:
        """Check for services running as root that may be exploitable."""
        findings = []
        for svc in services:
            name = svc.get("name", "unknown")
            user = svc.get("user", "")
            if user == "root" and name not in ("init", "systemd", "kernel"):
                findings.append({
                    "type": "root_service",
                    "severity": "medium",
                    "service": name,
                    "user": user,
                    "description": f"Service '{name}' runs as root - may be exploitable if misconfigured",
                })
        return findings

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        suid_list = config.get("suid_binaries", []) or []
        writable_list = config.get("writable_paths", []) or []
        sudo_config = config.get("sudo_config", "") or ""
        kernel_version = config.get("kernel_version", "") or ""
        services = config.get("services", []) or []

        self.logger.info("privesc_check_start", target=target)

        loop = asyncio.get_event_loop()
        suid_findings = await loop.run_in_executor(None, self._check_suid_binaries, suid_list)
        writable_findings = await loop.run_in_executor(None, self._check_writable_paths, writable_list)
        sudo_findings = await loop.run_in_executor(None, self._check_sudo_config, sudo_config)
        kernel_findings = await loop.run_in_executor(None, self._check_kernel_version, kernel_version)
        service_findings = await loop.run_in_executor(None, self._check_services, services)

        all_vulns = suid_findings + writable_findings + sudo_findings + kernel_findings + service_findings

        critical = sum(1 for v in all_vulns if v["severity"] == "critical")
        high = sum(1 for v in all_vulns if v["severity"] == "high")
        medium = sum(1 for v in all_vulns if v["severity"] == "medium")
        risk_score = min(critical * 30 + high * 15 + medium * 5, 100)

        summary = {
            "target": target,
            "total_vectors_found": len(all_vulns),
            "critical": critical,
            "high": high,
            "medium": medium,
            "risk_score": risk_score,
            "checks_performed": {
                "suid_binaries": len(suid_list),
                "writable_paths": len(writable_list),
                "sudo_config": bool(sudo_config),
                "kernel_version": kernel_version or "not provided",
                "services": len(services),
            },
        }

        self.logger.info("privesc_check_complete", target=target, vectors=len(all_vulns), risk=risk_score)

        return {
            "vulnerabilities": all_vulns,
            "summary": summary,
        }
