"""Deception monitoring and analysis module.

Monitor and analyze interactions with deception assets by parsing
honeypot logs, detecting attack patterns, and building attacker profiles.
"""

import asyncio
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Patterns for identifying attack types in honeypot logs
ATTACK_PATTERNS = {
    "brute_force": [
        re.compile(r"Failed (password|login|auth).*from\s+([\d\.]+)", re.IGNORECASE),
        re.compile(r"authentication fail.*?([\d\.]+)", re.IGNORECASE),
        re.compile(r"invalid (user|password).*?([\d\.]+)", re.IGNORECASE),
    ],
    "scanning": [
        re.compile(r"connection from ([\d\.]+).*port\s+\d+", re.IGNORECASE),
        re.compile(r"SYN.*?([\d\.]+)", re.IGNORECASE),
        re.compile(r"probe.*?([\d\.]+)", re.IGNORECASE),
    ],
    "exploitation": [
        re.compile(r"(shell|exec|eval|system)\s*\(", re.IGNORECASE),
        re.compile(r"(\.\./|%2e%2e/){2,}", re.IGNORECASE),
        re.compile(r"(union\s+select|drop\s+table|<script>)", re.IGNORECASE),
        re.compile(r"(wget|curl)\s+https?://", re.IGNORECASE),
    ],
}

IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
TIMESTAMP_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)


class DeceptionMonitorModule(AtsModule):
    """Monitor and analyze interactions with deception assets."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="deception_monitor",
            category=ModuleCategory.DECEPTION,
            description="Monitor and analyze interactions with honeypots and deception assets to detect attack patterns and build attacker profiles",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="log_source",
                    type=ParameterType.STRING,
                    description="Path to honeypot or deception log file",
                    required=True,
                ),
                Parameter(
                    name="time_range",
                    type=ParameterType.INTEGER,
                    description="Analysis time range in hours (0 = all)",
                    required=False,
                    default=24,
                    min_value=0,
                    max_value=8760,
                ),
                Parameter(
                    name="alert_threshold",
                    type=ParameterType.INTEGER,
                    description="Minimum events from a single IP to trigger an alert",
                    required=False,
                    default=5,
                    min_value=1,
                    max_value=1000,
                ),
            ],
            outputs=[
                OutputField(name="interactions", type="list", description="Parsed interaction events"),
                OutputField(name="attacker_profiles", type="dict", description="Profiles of detected attackers by IP"),
                OutputField(name="attack_patterns", type="dict", description="Detected attack pattern summary"),
                OutputField(name="alerts", type="list", description="Generated alerts based on thresholds"),
            ],
            tags=["deception", "monitoring", "honeypot", "analysis", "detection"],
            author="ATS-Toolkit",
            requires_api_key=False,
            api_key_service=None,
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        log_source = config.get("log_source", "").strip()
        if not log_source:
            return False, "log_source is required"
        if not os.path.isfile(log_source):
            return False, f"Log file not found: {log_source}"
        return True, ""

    def _parse_timestamp(self, line: str) -> datetime | None:
        """Extract ISO-like timestamp from a log line."""
        match = TIMESTAMP_PATTERN.search(line)
        if match:
            ts_str = match.group(1).replace("T", " ")
            try:
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        return None

    def _extract_ips(self, line: str) -> List[str]:
        """Extract all IP addresses from a line."""
        return IP_PATTERN.findall(line)

    def _classify_attack(self, line: str) -> List[Dict[str, Any]]:
        """Classify a log line against known attack patterns."""
        results = []
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    results.append({
                        "type": attack_type,
                        "matched": match.group(0)[:200],
                    })
                    break
        return results

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        log_source = config["log_source"].strip()
        time_range = config.get("time_range", 24)
        alert_threshold = config.get("alert_threshold", 5)

        self.logger.info("deception_monitor_start", log=log_source, hours=time_range)

        cutoff = None
        if time_range > 0:
            cutoff = datetime.utcnow() - timedelta(hours=time_range)

        interactions: List[Dict[str, Any]] = []
        ip_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        pattern_counts: Dict[str, int] = Counter()

        loop = asyncio.get_event_loop()

        def _analyze():
            with open(log_source, "r", encoding="utf-8", errors="replace") as fh:
                for line_num, raw_line in enumerate(fh, 1):
                    line = raw_line.rstrip("\n\r")
                    if not line:
                        continue

                    ts = self._parse_timestamp(line)
                    if cutoff and ts and ts < cutoff:
                        continue

                    ips = self._extract_ips(line)
                    classifications = self._classify_attack(line)

                    event = {
                        "line_number": line_num,
                        "timestamp": ts.isoformat() if ts else None,
                        "source_ips": ips,
                        "classifications": classifications,
                        "raw": line[:300],
                    }
                    interactions.append(event)

                    for ip in ips:
                        ip_events[ip].append(event)

                    for cls in classifications:
                        pattern_counts[cls["type"]] += 1

        await loop.run_in_executor(None, _analyze)

        # Build attacker profiles
        attacker_profiles: Dict[str, Dict[str, Any]] = {}
        for ip, events in ip_events.items():
            attack_types = Counter()
            for ev in events:
                for cls in ev.get("classifications", []):
                    attack_types[cls["type"]] += 1

            attacker_profiles[ip] = {
                "total_events": len(events),
                "attack_types": dict(attack_types),
                "first_seen": events[0].get("timestamp"),
                "last_seen": events[-1].get("timestamp"),
            }

        # Generate alerts
        alerts: List[Dict[str, Any]] = []
        for ip, profile in attacker_profiles.items():
            if profile["total_events"] >= alert_threshold:
                severity = "critical" if profile["total_events"] >= alert_threshold * 5 else (
                    "high" if profile["total_events"] >= alert_threshold * 2 else "medium"
                )
                alerts.append({
                    "source_ip": ip,
                    "event_count": profile["total_events"],
                    "attack_types": profile["attack_types"],
                    "severity": severity,
                    "first_seen": profile["first_seen"],
                    "last_seen": profile["last_seen"],
                })

        alerts.sort(key=lambda a: a["event_count"], reverse=True)

        self.logger.info(
            "deception_monitor_complete",
            interactions=len(interactions),
            attackers=len(attacker_profiles),
            alerts=len(alerts),
        )

        return {
            "interactions": interactions[:500],
            "attacker_profiles": dict(sorted(
                attacker_profiles.items(),
                key=lambda x: x[1]["total_events"],
                reverse=True,
            )[:50]),
            "attack_patterns": dict(pattern_counts),
            "alerts": alerts[:100],
        }
