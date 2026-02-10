"""Lateral Movement Detector Module.

Detect lateral movement indicators by analyzing logs for pass-the-hash,
remote service creation, WMI execution, and PSExec-style activity patterns.
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

# Windows Event IDs associated with lateral movement
LATERAL_MOVEMENT_EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4697: "Service Installed",
    5140: "Network Share Accessed",
    5145: "Network Share Object Checked",
    7045: "New Service Installed",
}

# Logon types indicative of lateral movement
SUSPICIOUS_LOGON_TYPES = {
    3: "Network Logon (PtH / SMB)",
    10: "Remote Interactive (RDP)",
}

# Regex patterns for known lateral movement tool artefacts
TOOL_PATTERNS = {
    "psexec": re.compile(r"(?i)(psexe[cs]|PSEXESVC|\\\\.*\\ADMIN\$)", re.IGNORECASE),
    "wmi_exec": re.compile(r"(?i)(wmiprvse|wmic\s+/node|Win32_Process.*Create)", re.IGNORECASE),
    "smbexec": re.compile(r"(?i)(smbexec|\\\\.*\\C\$)", re.IGNORECASE),
    "dcom_exec": re.compile(r"(?i)(mmc\.exe.*-Embedding|ShellWindows|ShellBrowserWindow)", re.IGNORECASE),
    "winrm": re.compile(r"(?i)(wsmprovhost|Enter-PSSession|Invoke-Command)", re.IGNORECASE),
    "pass_the_hash": re.compile(r"(?i)(sekurlsa|mimikatz|NtlmHash|pth-)", re.IGNORECASE),
    "pass_the_ticket": re.compile(r"(?i)(kerberos::ptt|Rubeus|golden.*ticket)", re.IGNORECASE),
    "scheduled_task_lateral": re.compile(r"(?i)(schtasks\s+/create\s+/s\s+)", re.IGNORECASE),
}


class LateralMovementModule(AtsModule):
    """Detect lateral movement indicators in log data."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="lateral_movement_detector",
            category=ModuleCategory.RED_TEAM,
            description="Detect lateral movement indicators such as pass-the-hash, remote service creation, and WMI execution patterns",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target hostname or IP being investigated",
                    required=True,
                ),
                Parameter(
                    name="log_entries",
                    type=ParameterType.LIST,
                    description="List of log entry dicts with keys: event_id, message, timestamp, source_ip, dest_ip, logon_type (optional)",
                    required=True,
                ),
                Parameter(
                    name="time_window_minutes",
                    type=ParameterType.INTEGER,
                    description="Time window in minutes to correlate related events",
                    required=False,
                    default=60,
                    min_value=5,
                    max_value=1440,
                ),
                Parameter(
                    name="sensitivity",
                    type=ParameterType.CHOICE,
                    description="Detection sensitivity level",
                    required=False,
                    default="medium",
                    choices=["low", "medium", "high"],
                ),
            ],
            outputs=[
                OutputField(name="detections", type="list", description="Lateral movement detections with details"),
                OutputField(name="attack_timeline", type="list", description="Chronological timeline of suspicious events"),
                OutputField(name="summary", type="dict", description="Analysis summary with risk assessment"),
            ],
            tags=["red_team", "lateral_movement", "detection", "logs", "windows"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target hostname or IP is required"
        if not config.get("log_entries"):
            return False, "At least one log entry is required"
        return True, ""

    def _check_event_ids(self, log_entries: List[Dict]) -> List[Dict[str, Any]]:
        """Flag log entries whose event IDs match known lateral movement events."""
        findings = []
        for entry in log_entries:
            event_id = entry.get("event_id")
            if event_id in LATERAL_MOVEMENT_EVENT_IDS:
                finding = {
                    "type": "suspicious_event_id",
                    "event_id": event_id,
                    "description": LATERAL_MOVEMENT_EVENT_IDS[event_id],
                    "message": entry.get("message", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "source_ip": entry.get("source_ip", ""),
                    "dest_ip": entry.get("dest_ip", ""),
                }
                # Check for suspicious logon types
                logon_type = entry.get("logon_type")
                if logon_type in SUSPICIOUS_LOGON_TYPES:
                    finding["logon_type"] = logon_type
                    finding["logon_description"] = SUSPICIOUS_LOGON_TYPES[logon_type]
                    finding["severity"] = "high"
                else:
                    finding["severity"] = "medium"
                findings.append(finding)
        return findings

    def _check_tool_patterns(self, log_entries: List[Dict]) -> List[Dict[str, Any]]:
        """Scan log messages for known lateral movement tool artefacts."""
        findings = []
        for entry in log_entries:
            message = entry.get("message", "")
            for tool_name, pattern in TOOL_PATTERNS.items():
                if pattern.search(message):
                    findings.append({
                        "type": "tool_artifact",
                        "tool": tool_name,
                        "severity": "critical",
                        "matched_text": pattern.search(message).group(0),
                        "message": message[:300],
                        "timestamp": entry.get("timestamp", ""),
                        "source_ip": entry.get("source_ip", ""),
                        "dest_ip": entry.get("dest_ip", ""),
                    })
        return findings

    def _detect_ip_hopping(self, log_entries: List[Dict], sensitivity: str) -> List[Dict[str, Any]]:
        """Detect a single source account authenticating to multiple destinations (IP hopping)."""
        # Group events by source IP
        source_to_dests: Dict[str, set] = {}
        for entry in log_entries:
            src = entry.get("source_ip", "")
            dst = entry.get("dest_ip", "")
            if src and dst and src != dst:
                source_to_dests.setdefault(src, set()).add(dst)

        threshold = {"low": 5, "medium": 3, "high": 2}[sensitivity]
        findings = []
        for src, dests in source_to_dests.items():
            if len(dests) >= threshold:
                findings.append({
                    "type": "ip_hopping",
                    "severity": "high",
                    "source_ip": src,
                    "destination_count": len(dests),
                    "destinations": sorted(dests),
                    "description": f"Source {src} connected to {len(dests)} distinct destinations",
                })
        return findings

    def _build_timeline(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build a sorted chronological timeline from all detections."""
        timeline = []
        for det in detections:
            ts = det.get("timestamp", "")
            timeline.append({
                "timestamp": ts,
                "type": det.get("type", "unknown"),
                "severity": det.get("severity", "info"),
                "detail": det.get("description", det.get("matched_text", det.get("message", "")[:120])),
            })
        timeline.sort(key=lambda x: x["timestamp"] if x["timestamp"] else "")
        return timeline

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        log_entries = config["log_entries"]
        sensitivity = config.get("sensitivity", "medium")

        self.logger.info("lateral_movement_scan_start", target=target, entries=len(log_entries))

        loop = asyncio.get_event_loop()
        event_findings = await loop.run_in_executor(None, self._check_event_ids, log_entries)
        tool_findings = await loop.run_in_executor(None, self._check_tool_patterns, log_entries)
        hop_findings = await loop.run_in_executor(None, self._detect_ip_hopping, log_entries, sensitivity)

        all_detections = event_findings + tool_findings + hop_findings
        timeline = self._build_timeline(all_detections)

        # Compute risk score
        critical_count = sum(1 for d in all_detections if d.get("severity") == "critical")
        high_count = sum(1 for d in all_detections if d.get("severity") == "high")
        medium_count = sum(1 for d in all_detections if d.get("severity") == "medium")
        risk_score = min(critical_count * 30 + high_count * 15 + medium_count * 5, 100)

        summary = {
            "target": target,
            "total_logs_analyzed": len(log_entries),
            "total_detections": len(all_detections),
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "risk_score": risk_score,
            "sensitivity": sensitivity,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

        self.logger.info("lateral_movement_scan_complete", target=target, detections=len(all_detections), risk=risk_score)

        return {
            "detections": all_detections,
            "attack_timeline": timeline,
            "summary": summary,
        }
