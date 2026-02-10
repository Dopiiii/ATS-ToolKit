"""Log file forensic analyzer module.

Analyze log files for suspicious patterns including failed logins,
privilege escalation attempts, unusual access times, and IP anomalies.
"""

import asyncio
import re
import os
from typing import Any, Dict, List, Tuple
from datetime import datetime, time as dt_time
from collections import Counter, defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Suspicious patterns for different log formats
SUSPICIOUS_PATTERNS = {
    "failed_login": [
        r"Failed password for .+ from ([\d\.]+)",
        r"authentication failure.*rhost=([\d\.]+)",
        r"FAILED LOGIN .+ FROM ([\d\.]+)",
        r"Invalid user \S+ from ([\d\.]+)",
        r"error: PAM: .+ for .+ from ([\d\.]+)",
    ],
    "privilege_escalation": [
        r"sudo:.+COMMAND=(.+)",
        r"su\[\d+\]: .+ session opened for user root",
        r"usermod.+(-G|--groups).+sudo",
        r"passwd.+password changed for root",
        r"COMMAND=/bin/(bash|sh|zsh)",
    ],
    "brute_force": [
        r"message repeated (\d+) times.*Failed",
        r"PAM \d+ more authentication failure",
        r"maximum authentication attempts exceeded",
    ],
    "suspicious_commands": [
        r"(wget|curl)\s+https?://\S+",
        r"(chmod|chown)\s+[0-7]{3,4}\s+",
        r"(nc|ncat|netcat)\s+.*-[elp]",
        r"/dev/(tcp|udp)/",
        r"(base64|eval|exec)\s+",
        r"rm\s+(-rf|--no-preserve-root)\s+/",
        r"(iptables|ufw)\s+.*(DROP|REJECT|delete)",
    ],
    "service_anomaly": [
        r"(sshd|httpd|apache|nginx)\[\d+\]:.*error",
        r"segfault at",
        r"Out of memory: Kill process",
        r"kernel:.*SYN flooding",
        r"UFW BLOCK",
    ],
}

# Syslog timestamp pattern
SYSLOG_TS_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
# ISO timestamp pattern
ISO_TS_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)
# Common log format timestamp
CLF_TS_PATTERN = re.compile(
    r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"
)

# IP address extraction
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class LogAnalyzerModule(AtsModule):
    """Analyze log files for suspicious forensic patterns."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="log_analyzer",
            category=ModuleCategory.FORENSICS,
            description="Analyze log files for suspicious patterns such as failed logins, privilege escalation, and IP anomalies",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="log_path",
                    type=ParameterType.FILE,
                    description="Path to the log file to analyze",
                    required=True,
                ),
                Parameter(
                    name="log_format",
                    type=ParameterType.CHOICE,
                    description="Log format type",
                    required=False,
                    default="auto",
                    choices=["auto", "syslog", "auth", "apache", "json"],
                ),
                Parameter(
                    name="time_window_start",
                    type=ParameterType.STRING,
                    description="Start of suspicious time window (HH:MM, e.g. 02:00 for off-hours analysis)",
                    required=False,
                    default="00:00",
                ),
                Parameter(
                    name="time_window_end",
                    type=ParameterType.STRING,
                    description="End of suspicious time window (HH:MM, e.g. 06:00 for off-hours analysis)",
                    required=False,
                    default="06:00",
                ),
                Parameter(
                    name="max_lines",
                    type=ParameterType.INTEGER,
                    description="Maximum number of lines to analyze (0 = unlimited)",
                    required=False,
                    default=100000,
                    min_value=0,
                    max_value=10000000,
                ),
            ],
            outputs=[
                OutputField(name="total_lines", type="integer", description="Total lines analyzed"),
                OutputField(name="suspicious_entries", type="list", description="List of suspicious log entries"),
                OutputField(name="failed_logins", type="dict", description="Failed login attempts by IP"),
                OutputField(name="privilege_events", type="list", description="Privilege escalation events"),
                OutputField(name="ip_summary", type="dict", description="IP address activity summary"),
                OutputField(name="off_hours_activity", type="list", description="Activity during suspicious hours"),
                OutputField(name="severity_score", type="float", description="Overall suspicion score 0-100"),
            ],
            tags=["forensics", "logs", "analysis", "incident-response", "syslog"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        log_path = config.get("log_path", "").strip()
        if not log_path:
            return False, "log_path is required"
        if not os.path.isfile(log_path):
            return False, f"Log file not found: {log_path}"

        for field in ("time_window_start", "time_window_end"):
            val = config.get(field, "")
            if val:
                if not re.match(r"^\d{2}:\d{2}$", val):
                    return False, f"{field} must be in HH:MM format"
        return True, ""

    def _parse_timestamp(self, line: str) -> datetime | None:
        """Extract timestamp from a log line."""
        match = ISO_TS_PATTERN.search(line)
        if match:
            ts_str = match.group(1).replace("T", " ")
            try:
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

        match = SYSLOG_TS_PATTERN.search(line)
        if match:
            ts_str = match.group(1)
            try:
                parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                return parsed.replace(year=datetime.now().year)
            except ValueError:
                pass

        match = CLF_TS_PATTERN.search(line)
        if match:
            ts_str = match.group(1)
            try:
                return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass

        return None

    def _is_off_hours(self, ts: datetime, start: dt_time, end: dt_time) -> bool:
        """Check if timestamp falls within suspicious time window."""
        t = ts.time()
        if start <= end:
            return start <= t <= end
        # Wraps midnight
        return t >= start or t <= end

    def _extract_ips(self, line: str) -> List[str]:
        """Extract all IP addresses from a line."""
        return IP_PATTERN.findall(line)

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        log_path = config["log_path"].strip()
        max_lines = config.get("max_lines", 100000)
        tw_start_str = config.get("time_window_start", "00:00")
        tw_end_str = config.get("time_window_end", "06:00")

        tw_start = dt_time(*map(int, tw_start_str.split(":")))
        tw_end = dt_time(*map(int, tw_end_str.split(":")))

        self.logger.info("analyzing_log_file", path=log_path)

        suspicious_entries: List[Dict[str, Any]] = []
        failed_logins: Dict[str, int] = Counter()
        privilege_events: List[Dict[str, Any]] = []
        ip_activity: Dict[str, List[str]] = defaultdict(list)
        off_hours_activity: List[Dict[str, Any]] = []
        pattern_hits: Dict[str, int] = Counter()
        total_lines = 0

        loop = asyncio.get_event_loop()

        def _analyze():
            nonlocal total_lines
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, 1):
                    if max_lines and line_num > max_lines:
                        break
                    total_lines = line_num
                    line = line.rstrip("\n\r")
                    if not line:
                        continue

                    ts = self._parse_timestamp(line)
                    ips = self._extract_ips(line)

                    for ip in ips:
                        ip_activity[ip].append(f"line:{line_num}")

                    # Check off-hours activity
                    if ts and self._is_off_hours(ts, tw_start, tw_end):
                        off_hours_activity.append({
                            "line_number": line_num,
                            "timestamp": ts.isoformat(),
                            "content": line[:300],
                        })

                    # Match against suspicious patterns
                    for category, patterns in SUSPICIOUS_PATTERNS.items():
                        for pattern in patterns:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                pattern_hits[category] += 1
                                entry = {
                                    "line_number": line_num,
                                    "category": category,
                                    "matched_pattern": pattern,
                                    "content": line[:300],
                                    "timestamp": ts.isoformat() if ts else None,
                                    "ips": ips,
                                }

                                if category == "failed_login" and match.groups():
                                    failed_logins[match.group(1)] += 1
                                    entry["source_ip"] = match.group(1)

                                if category == "privilege_escalation":
                                    privilege_events.append(entry)

                                suspicious_entries.append(entry)
                                break  # One match per category per line

        await loop.run_in_executor(None, _analyze)

        # Calculate severity score
        severity = 0.0
        if failed_logins:
            max_fails = max(failed_logins.values())
            if max_fails > 100:
                severity += 30
            elif max_fails > 20:
                severity += 20
            elif max_fails > 5:
                severity += 10

        if privilege_events:
            severity += min(len(privilege_events) * 5, 25)

        if pattern_hits.get("brute_force", 0) > 0:
            severity += 15

        if pattern_hits.get("suspicious_commands", 0) > 0:
            severity += min(pattern_hits["suspicious_commands"] * 3, 20)

        if len(off_hours_activity) > 10:
            severity += 10

        severity = min(severity, 100.0)

        # Build IP summary
        ip_summary = {}
        for ip, refs in sorted(ip_activity.items(), key=lambda x: len(x[1]), reverse=True)[:50]:
            ip_summary[ip] = {
                "occurrences": len(refs),
                "failed_logins": failed_logins.get(ip, 0),
            }

        self.logger.info(
            "log_analysis_complete",
            total_lines=total_lines,
            suspicious_count=len(suspicious_entries),
            severity_score=severity,
        )

        return {
            "log_path": log_path,
            "total_lines": total_lines,
            "suspicious_entries": suspicious_entries[:500],
            "failed_logins": dict(failed_logins.most_common(50)),
            "privilege_events": privilege_events[:100],
            "ip_summary": ip_summary,
            "off_hours_activity": off_hours_activity[:200],
            "pattern_summary": dict(pattern_hits),
            "severity_score": severity,
        }
