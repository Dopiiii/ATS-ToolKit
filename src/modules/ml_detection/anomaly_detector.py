"""Anomaly detection module using statistical methods.

Detect anomalies in log data by computing z-scores over event frequency
distributions within configurable time windows.
"""

import asyncio
import re
import math
from typing import Any
from collections import Counter
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Common timestamp patterns found in log files
TIMESTAMP_PATTERNS = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "%Y-%m-%dT%H:%M:%S"),
    (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "%Y-%m-%d %H:%M:%S"),
    (r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", None),  # syslog style
    (r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}", "%d/%b/%Y:%H:%M:%S"),
]

SENSITIVITY_THRESHOLDS = {"low": 3.0, "medium": 2.0, "high": 1.5}


class AnomalyDetectorModule(AtsModule):
    """Detect anomalies in log data using z-score statistical analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="anomaly_detector",
            category=ModuleCategory.ML_DETECTION,
            description="Detect anomalies in log data using statistical z-score analysis on event frequencies",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="log_file",
                    type=ParameterType.FILE,
                    description="Path to the log file to analyze",
                    required=True,
                ),
                Parameter(
                    name="sensitivity",
                    type=ParameterType.CHOICE,
                    description="Detection sensitivity level",
                    required=False,
                    default="medium",
                    choices=["low", "medium", "high"],
                ),
                Parameter(
                    name="baseline_window",
                    type=ParameterType.INTEGER,
                    description="Baseline window size in minutes for grouping events",
                    required=False,
                    default=5,
                    min_value=1,
                    max_value=1440,
                ),
            ],
            outputs=[
                OutputField(name="total_events", type="integer", description="Total log entries analyzed"),
                OutputField(name="time_windows", type="integer", description="Number of time windows evaluated"),
                OutputField(name="anomalies", type="list", description="List of anomalous windows with z-scores"),
                OutputField(name="statistics", type="dict", description="Mean, stddev, and threshold used"),
            ],
            tags=["ml", "detection", "anomaly", "log-analysis", "statistics"],
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        log_file = config.get("log_file", "").strip()
        if not log_file:
            return False, "log_file is required"
        sensitivity = config.get("sensitivity", "medium")
        if sensitivity not in SENSITIVITY_THRESHOLDS:
            return False, f"sensitivity must be one of: {list(SENSITIVITY_THRESHOLDS.keys())}"
        window = config.get("baseline_window", 5)
        if not isinstance(window, int) or window < 1:
            return False, "baseline_window must be a positive integer"
        return True, ""

    def _extract_timestamp(self, line: str) -> datetime | None:
        """Try to extract a timestamp from a log line."""
        for regex, fmt in TIMESTAMP_PATTERNS:
            match = re.search(regex, line)
            if match:
                raw = match.group(0).replace("T", " ")
                if fmt:
                    try:
                        return datetime.strptime(raw, fmt.replace("T", " "))
                    except ValueError:
                        continue
                else:
                    # Syslog format: assume current year
                    try:
                        raw_with_year = f"{datetime.now().year} {raw}"
                        return datetime.strptime(raw_with_year, "%Y %b %d %H:%M:%S")
                    except ValueError:
                        continue
        return None

    def _bucket_key(self, dt: datetime, window_minutes: int) -> str:
        """Convert a datetime to a time-bucket key."""
        total_minutes = dt.hour * 60 + dt.minute
        bucket = (total_minutes // window_minutes) * window_minutes
        bh, bm = divmod(bucket, 60)
        return f"{dt.strftime('%Y-%m-%d')} {bh:02d}:{bm:02d}"

    def _compute_zscore(self, value: float, mean: float, stddev: float) -> float:
        """Compute the z-score for a single value."""
        if stddev == 0:
            return 0.0 if value == mean else float("inf")
        return (value - mean) / stddev

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        log_file = config["log_file"].strip()
        sensitivity = config.get("sensitivity", "medium")
        window_minutes = config.get("baseline_window", 5)
        threshold = SENSITIVITY_THRESHOLDS[sensitivity]

        self.logger.info("starting_anomaly_detection", file=log_file, sensitivity=sensitivity)

        # Read and parse log file
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return {"error": f"File not found: {log_file}", "anomalies": [], "total_events": 0}
        except PermissionError:
            return {"error": f"Permission denied: {log_file}", "anomalies": [], "total_events": 0}

        # Bucket events by time window
        buckets: Counter = Counter()
        parsed_count = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            ts = self._extract_timestamp(line)
            if ts:
                key = self._bucket_key(ts, window_minutes)
                buckets[key] += 1
                parsed_count += 1

        if not buckets:
            return {
                "total_events": len(lines),
                "parsed_events": 0,
                "time_windows": 0,
                "anomalies": [],
                "statistics": {},
                "message": "No timestamps could be parsed from the log file",
            }

        # Compute statistics
        counts = list(buckets.values())
        n = len(counts)
        mean = sum(counts) / n
        variance = sum((c - mean) ** 2 for c in counts) / n if n > 1 else 0.0
        stddev = math.sqrt(variance)

        # Detect anomalies via z-score
        anomalies = []
        for window_key in sorted(buckets.keys()):
            count = buckets[window_key]
            zscore = self._compute_zscore(count, mean, stddev)
            if abs(zscore) >= threshold:
                anomalies.append({
                    "time_window": window_key,
                    "event_count": count,
                    "z_score": round(zscore, 4),
                    "deviation": round(abs(zscore) - threshold, 4),
                    "direction": "spike" if zscore > 0 else "drop",
                })

        anomalies.sort(key=lambda a: abs(a["z_score"]), reverse=True)

        self.logger.info(
            "anomaly_detection_complete",
            total_windows=n,
            anomalies_found=len(anomalies),
        )

        return {
            "total_events": len(lines),
            "parsed_events": parsed_count,
            "time_windows": n,
            "window_size_minutes": window_minutes,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "statistics": {
                "mean_events_per_window": round(mean, 4),
                "stddev": round(stddev, 4),
                "z_threshold": threshold,
                "sensitivity": sensitivity,
                "min_count": min(counts),
                "max_count": max(counts),
            },
        }
