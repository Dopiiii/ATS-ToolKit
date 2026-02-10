"""Forensic timeline builder module.

Build a forensic timeline from multiple evidence sources including
file metadata, log entries, and registry timestamps. Sort and correlate events.
"""

import asyncio
import os
import re
import json
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
from pathlib import Path

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Timestamp patterns for various log formats
TIMESTAMP_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
    (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    (re.compile(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})"), "%m/%d/%Y %H:%M:%S"),
    (re.compile(r"(\d{10,13})"), "epoch"),
]


class TimelineBuilderModule(AtsModule):
    """Build forensic timelines from multiple evidence sources."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="timeline_builder",
            category=ModuleCategory.FORENSICS,
            description="Build a forensic timeline from multiple evidence sources including file metadata, log entries, and registry timestamps",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="evidence_paths",
                    type=ParameterType.LIST,
                    description="List of paths to evidence files (logs, directories for file metadata)",
                    required=True,
                ),
                Parameter(
                    name="output_format",
                    type=ParameterType.CHOICE,
                    description="Output format for the timeline",
                    required=False,
                    default="json",
                    choices=["json", "csv", "bodyfile"],
                ),
                Parameter(
                    name="date_filter_start",
                    type=ParameterType.STRING,
                    description="Filter events after this date (YYYY-MM-DD)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="date_filter_end",
                    type=ParameterType.STRING,
                    description="Filter events before this date (YYYY-MM-DD)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="include_file_metadata",
                    type=ParameterType.BOOLEAN,
                    description="Include filesystem metadata (creation, modification, access times)",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="timeline", type="list", description="Sorted list of timeline events"),
                OutputField(name="total_events", type="integer", description="Total events in timeline"),
                OutputField(name="sources_processed", type="integer", description="Number of evidence sources processed"),
                OutputField(name="date_range", type="dict", description="Earliest and latest event timestamps"),
                OutputField(name="event_types", type="dict", description="Count of events by type"),
            ],
            tags=["forensics", "timeline", "correlation", "incident-response", "evidence"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        evidence_paths = config.get("evidence_paths", [])
        if not evidence_paths:
            return False, "evidence_paths is required and must not be empty"

        for path in evidence_paths:
            if not os.path.exists(path):
                return False, f"Evidence path not found: {path}"

        for field in ("date_filter_start", "date_filter_end"):
            val = config.get(field, "")
            if val:
                try:
                    datetime.strptime(val, "%Y-%m-%d")
                except ValueError:
                    return False, f"{field} must be in YYYY-MM-DD format"

        return True, ""

    def _parse_timestamp_from_line(self, line: str) -> Optional[datetime]:
        """Extract and parse a timestamp from a log line."""
        for pattern, fmt in TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                ts_str = match.group(1).replace("T", " ")
                try:
                    if fmt == "epoch":
                        epoch_val = int(ts_str)
                        if epoch_val > 1e12:
                            epoch_val = epoch_val / 1000
                        return datetime.fromtimestamp(epoch_val)
                    parsed = datetime.strptime(ts_str, fmt)
                    if parsed.year == 1900:
                        parsed = parsed.replace(year=datetime.now().year)
                    return parsed
                except (ValueError, OSError, OverflowError):
                    continue
        return None

    def _collect_file_metadata(self, dir_path: str) -> List[Dict[str, Any]]:
        """Collect filesystem metadata events from a directory."""
        events = []
        try:
            for root, dirs, files in os.walk(dir_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        stat = os.stat(fpath)
                        # Modification time
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        events.append({
                            "timestamp": mtime.isoformat(),
                            "type": "file_modified",
                            "source": fpath,
                            "description": f"File modified: {fname}",
                            "metadata": {
                                "size": stat.st_size,
                                "path": fpath,
                            },
                        })
                        # Creation time (Windows) / ctime (Unix)
                        ctime = datetime.fromtimestamp(stat.st_ctime)
                        events.append({
                            "timestamp": ctime.isoformat(),
                            "type": "file_created",
                            "source": fpath,
                            "description": f"File created/changed: {fname}",
                            "metadata": {
                                "size": stat.st_size,
                                "path": fpath,
                            },
                        })
                        # Access time
                        atime = datetime.fromtimestamp(stat.st_atime)
                        events.append({
                            "timestamp": atime.isoformat(),
                            "type": "file_accessed",
                            "source": fpath,
                            "description": f"File accessed: {fname}",
                            "metadata": {
                                "size": stat.st_size,
                                "path": fpath,
                            },
                        })
                    except OSError:
                        continue
        except OSError:
            pass
        return events

    def _parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a log file into timeline events."""
        events = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    ts = self._parse_timestamp_from_line(line)
                    if ts:
                        events.append({
                            "timestamp": ts.isoformat(),
                            "type": "log_entry",
                            "source": f"{file_path}:{line_num}",
                            "description": line[:500],
                            "metadata": {
                                "file": file_path,
                                "line_number": line_num,
                            },
                        })
        except OSError:
            pass
        return events

    def _parse_json_events(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse a JSON file containing events."""
        events = []
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    # Look for timestamp fields
                    ts_str = None
                    for key in ("timestamp", "time", "date", "datetime", "@timestamp", "event_time"):
                        if key in item:
                            ts_str = str(item[key])
                            break
                    if ts_str:
                        ts = self._parse_timestamp_from_line(ts_str)
                        if ts:
                            events.append({
                                "timestamp": ts.isoformat(),
                                "type": item.get("type", item.get("event_type", "json_event")),
                                "source": file_path,
                                "description": json.dumps(item, default=str)[:500],
                                "metadata": item,
                            })
        except (OSError, json.JSONDecodeError):
            pass
        return events

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        evidence_paths = config["evidence_paths"]
        include_file_meta = config.get("include_file_metadata", True)
        date_start_str = config.get("date_filter_start", "")
        date_end_str = config.get("date_filter_end", "")

        date_start = datetime.strptime(date_start_str, "%Y-%m-%d") if date_start_str else None
        date_end = datetime.strptime(date_end_str, "%Y-%m-%d") if date_end_str else None

        self.logger.info("building_timeline", sources=len(evidence_paths))

        all_events: List[Dict[str, Any]] = []
        sources_processed = 0
        loop = asyncio.get_event_loop()

        def _process():
            nonlocal sources_processed
            for path in evidence_paths:
                path = path.strip()
                if os.path.isdir(path):
                    if include_file_meta:
                        all_events.extend(self._collect_file_metadata(path))
                    # Also scan for log files within directory
                    for fname in os.listdir(path):
                        fpath = os.path.join(path, fname)
                        if os.path.isfile(fpath):
                            if fname.endswith(".json"):
                                all_events.extend(self._parse_json_events(fpath))
                            elif not fname.endswith((".bin", ".dat", ".exe", ".dll", ".img")):
                                all_events.extend(self._parse_log_file(fpath))
                elif os.path.isfile(path):
                    if path.endswith(".json"):
                        all_events.extend(self._parse_json_events(path))
                    else:
                        all_events.extend(self._parse_log_file(path))
                sources_processed += 1

        await loop.run_in_executor(None, _process)

        # Apply date filters
        filtered = []
        for event in all_events:
            try:
                ts = datetime.fromisoformat(event["timestamp"])
                if date_start and ts < date_start:
                    continue
                if date_end and ts > date_end:
                    continue
                filtered.append(event)
            except (ValueError, KeyError):
                filtered.append(event)

        # Sort by timestamp
        filtered.sort(key=lambda e: e.get("timestamp", ""))

        # Compute summary
        event_types: Dict[str, int] = {}
        for event in filtered:
            etype = event.get("type", "unknown")
            event_types[etype] = event_types.get(etype, 0) + 1

        date_range = {}
        if filtered:
            date_range["earliest"] = filtered[0].get("timestamp", "")
            date_range["latest"] = filtered[-1].get("timestamp", "")

        self.logger.info(
            "timeline_complete",
            total_events=len(filtered),
            sources=sources_processed,
        )

        return {
            "timeline": filtered[:10000],
            "total_events": len(filtered),
            "sources_processed": sources_processed,
            "date_range": date_range,
            "event_types": event_types,
        }
