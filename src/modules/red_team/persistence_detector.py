"""Persistence Detector Module.

Detect persistence mechanisms across Linux and Windows systems including
cron jobs, startup items, registry keys, scheduled tasks, and services.
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

# Suspicious cron patterns
SUSPICIOUS_CRON_PATTERNS = [
    re.compile(r"(curl|wget|nc|ncat|bash\s+-i|python\s+-c|perl\s+-e)", re.IGNORECASE),
    re.compile(r"(/dev/tcp/|/dev/udp/)", re.IGNORECASE),
    re.compile(r"(base64\s+-d|base64\s+--decode)", re.IGNORECASE),
    re.compile(r"(\|sh|\|bash|\|/bin/sh|\|/bin/bash)", re.IGNORECASE),
    re.compile(r"(mkfifo|backconnect|reverse)", re.IGNORECASE),
]

# Windows registry persistence locations
WINDOWS_PERSISTENCE_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
]

# Suspicious service/startup indicators
SUSPICIOUS_SERVICE_INDICATORS = [
    re.compile(r"(powershell|cmd\.exe|mshta|regsvr32|rundll32|wscript|cscript)", re.IGNORECASE),
    re.compile(r"(\.tmp|\.dat|%temp%|%appdata%|\\Temp\\)", re.IGNORECASE),
    re.compile(r"(base64|encodedcommand|-enc\s|-ec\s)", re.IGNORECASE),
]

# Known legitimate startup items to reduce false positives
KNOWN_LEGITIMATE = {
    "SecurityHealth", "WindowsDefender", "OneDrive", "Teams",
    "Edge", "Chrome", "Firefox", "Spotify", "Steam",
}


class PersistenceDetectorModule(AtsModule):
    """Detect persistence mechanisms on target systems."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="persistence_detector",
            category=ModuleCategory.RED_TEAM,
            description="Detect persistence mechanisms: cron jobs, startup items, registry keys, scheduled tasks, and services",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target hostname or IP being investigated",
                    required=True,
                ),
                Parameter(
                    name="cron_entries",
                    type=ParameterType.LIST,
                    description="List of cron entries (strings from crontab -l) for Linux targets",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="registry_entries",
                    type=ParameterType.LIST,
                    description="List of registry entry dicts with keys: path, name, value, type for Windows targets",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="scheduled_tasks",
                    type=ParameterType.LIST,
                    description="List of scheduled task dicts with keys: name, action, trigger, user",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="services",
                    type=ParameterType.LIST,
                    description="List of service dicts with keys: name, display_name, start_type, binary_path, user",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="startup_items",
                    type=ParameterType.LIST,
                    description="List of startup item dicts with keys: name, command, location",
                    required=False,
                    default=[],
                ),
            ],
            outputs=[
                OutputField(name="detections", type="list", description="Detected persistence mechanisms"),
                OutputField(name="summary", type="dict", description="Detection summary with risk assessment"),
            ],
            tags=["red_team", "persistence", "detection", "forensics", "malware"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target hostname or IP is required"
        has_data = any([
            config.get("cron_entries"),
            config.get("registry_entries"),
            config.get("scheduled_tasks"),
            config.get("services"),
            config.get("startup_items"),
        ])
        if not has_data:
            return False, "At least one data source (cron_entries, registry_entries, scheduled_tasks, services, or startup_items) must be provided"
        return True, ""

    def _analyze_cron_entries(self, entries: List[str]) -> List[Dict[str, Any]]:
        """Analyze cron entries for suspicious persistence."""
        findings = []
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            for pattern in SUSPICIOUS_CRON_PATTERNS:
                match = pattern.search(entry)
                if match:
                    findings.append({
                        "type": "suspicious_cron",
                        "severity": "high",
                        "entry": entry,
                        "matched_indicator": match.group(0),
                        "description": f"Suspicious cron job detected: contains '{match.group(0)}'",
                    })
                    break
        return findings

    def _analyze_registry_entries(self, entries: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze Windows registry entries for persistence mechanisms."""
        findings = []
        for entry in entries:
            reg_path = entry.get("path", "")
            name = entry.get("name", "")
            value = entry.get("value", "")

            # Check if this is a known persistence location
            is_persistence_key = any(reg_path.startswith(k) for k in WINDOWS_PERSISTENCE_KEYS)
            if not is_persistence_key:
                continue

            # Skip known legitimate entries
            if any(legit.lower() in name.lower() for legit in KNOWN_LEGITIMATE):
                continue

            severity = "medium"
            # Check value for suspicious patterns
            for pattern in SUSPICIOUS_SERVICE_INDICATORS:
                if pattern.search(str(value)):
                    severity = "critical"
                    break

            findings.append({
                "type": "registry_persistence",
                "severity": severity,
                "path": reg_path,
                "name": name,
                "value": str(value)[:500],
                "description": f"Persistence via registry: {name} at {reg_path}",
            })
        return findings

    def _analyze_scheduled_tasks(self, tasks: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze scheduled tasks for suspicious persistence."""
        findings = []
        for task in tasks:
            action = task.get("action", "")
            name = task.get("name", "")
            user = task.get("user", "")

            suspicious = False
            for pattern in SUSPICIOUS_SERVICE_INDICATORS:
                if pattern.search(action):
                    suspicious = True
                    break

            if suspicious or user.lower() == "system":
                findings.append({
                    "type": "suspicious_scheduled_task",
                    "severity": "high" if suspicious else "medium",
                    "task_name": name,
                    "action": action[:500],
                    "user": user,
                    "trigger": task.get("trigger", "unknown"),
                    "description": f"Suspicious scheduled task: {name} runs '{action[:80]}'",
                })
        return findings

    def _analyze_services(self, services: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze services for suspicious persistence."""
        findings = []
        for svc in services:
            binary_path = svc.get("binary_path", "")
            name = svc.get("name", "")
            start_type = svc.get("start_type", "")

            suspicious = False
            for pattern in SUSPICIOUS_SERVICE_INDICATORS:
                if pattern.search(binary_path):
                    suspicious = True
                    break

            if suspicious:
                findings.append({
                    "type": "suspicious_service",
                    "severity": "critical",
                    "service_name": name,
                    "display_name": svc.get("display_name", ""),
                    "binary_path": binary_path[:500],
                    "start_type": start_type,
                    "user": svc.get("user", ""),
                    "description": f"Suspicious service binary: {name} -> {binary_path[:80]}",
                })
        return findings

    def _analyze_startup_items(self, items: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze startup items for suspicious entries."""
        findings = []
        for item in items:
            command = item.get("command", "")
            name = item.get("name", "")

            if any(legit.lower() in name.lower() for legit in KNOWN_LEGITIMATE):
                continue

            suspicious = False
            for pattern in SUSPICIOUS_SERVICE_INDICATORS:
                if pattern.search(command):
                    suspicious = True
                    break

            if suspicious:
                findings.append({
                    "type": "suspicious_startup_item",
                    "severity": "high",
                    "name": name,
                    "command": command[:500],
                    "location": item.get("location", "unknown"),
                    "description": f"Suspicious startup item: {name} -> {command[:80]}",
                })
        return findings

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        cron_entries = config.get("cron_entries", []) or []
        registry_entries = config.get("registry_entries", []) or []
        scheduled_tasks = config.get("scheduled_tasks", []) or []
        services = config.get("services", []) or []
        startup_items = config.get("startup_items", []) or []

        self.logger.info("persistence_scan_start", target=target)

        loop = asyncio.get_event_loop()
        cron_findings = await loop.run_in_executor(None, self._analyze_cron_entries, cron_entries)
        reg_findings = await loop.run_in_executor(None, self._analyze_registry_entries, registry_entries)
        task_findings = await loop.run_in_executor(None, self._analyze_scheduled_tasks, scheduled_tasks)
        svc_findings = await loop.run_in_executor(None, self._analyze_services, services)
        startup_findings = await loop.run_in_executor(None, self._analyze_startup_items, startup_items)

        all_detections = cron_findings + reg_findings + task_findings + svc_findings + startup_findings

        critical = sum(1 for d in all_detections if d["severity"] == "critical")
        high = sum(1 for d in all_detections if d["severity"] == "high")
        medium = sum(1 for d in all_detections if d["severity"] == "medium")

        summary = {
            "target": target,
            "total_detections": len(all_detections),
            "by_type": {
                "cron_jobs": len(cron_findings),
                "registry_keys": len(reg_findings),
                "scheduled_tasks": len(task_findings),
                "services": len(svc_findings),
                "startup_items": len(startup_findings),
            },
            "severity_breakdown": {"critical": critical, "high": high, "medium": medium},
            "risk_score": min(critical * 30 + high * 15 + medium * 5, 100),
            "scanned_at": datetime.utcnow().isoformat(),
        }

        self.logger.info("persistence_scan_complete", target=target, detections=len(all_detections))

        return {
            "detections": all_detections,
            "summary": summary,
        }
