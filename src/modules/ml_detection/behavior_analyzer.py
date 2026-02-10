"""Behavior analysis module for user/process/network entity profiling.

Build frequency profiles from event streams and detect deviations using
entropy and statistical methods to flag anomalous behavioral patterns.
"""

import asyncio
import re
import json
import math
from typing import Any
from collections import Counter, defaultdict
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class BehaviorAnalyzerModule(AtsModule):
    """Analyze entity behavior patterns and detect anomalies."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="behavior_analyzer",
            category=ModuleCategory.ML_DETECTION,
            description="Analyze user/process/network behavior patterns for anomalies using entropy and statistical deviation",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="events",
                    type=ParameterType.STRING,
                    description="JSON array of event objects with 'timestamp', 'action', 'source', and optional 'destination' fields",
                    required=True,
                ),
                Parameter(
                    name="entity_type",
                    type=ParameterType.CHOICE,
                    description="Type of entity being analyzed",
                    required=False,
                    default="user",
                    choices=["user", "process", "network"],
                ),
                Parameter(
                    name="time_window",
                    type=ParameterType.INTEGER,
                    description="Analysis time window in minutes",
                    required=False,
                    default=60,
                    min_value=1,
                    max_value=10080,
                ),
                Parameter(
                    name="anomaly_threshold",
                    type=ParameterType.FLOAT,
                    description="Standard-deviation multiplier for anomaly flagging (default 2.0)",
                    required=False,
                    default=2.0,
                    min_value=0.5,
                    max_value=5.0,
                ),
            ],
            outputs=[
                OutputField(name="behavioral_score", type="float", description="Overall anomaly score 0.0-1.0"),
                OutputField(name="anomalies", type="list", description="Detected behavioral anomalies"),
                OutputField(name="profile", type="dict", description="Computed behavioral profile"),
                OutputField(name="entity_summary", type="dict", description="Summary per observed entity"),
            ],
            tags=["ml", "detection", "behavior", "profiling", "anomaly"],
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("events", "").strip()
        if not raw:
            return False, "events is required"
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, list):
                return False, "events must be a JSON array"
            if len(parsed) == 0:
                return False, "events array must not be empty"
        except json.JSONDecodeError as exc:
            return False, f"events is not valid JSON: {exc}"
        entity_type = config.get("entity_type", "user")
        if entity_type not in ("user", "process", "network"):
            return False, "entity_type must be one of: user, process, network"
        return True, ""

    def _shannon_entropy(self, counts: list[int]) -> float:
        """Compute Shannon entropy from a list of frequency counts."""
        total = sum(counts)
        if total == 0:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)

    def _parse_timestamp(self, raw: str) -> datetime | None:
        """Try several common timestamp formats."""
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%s"):
            try:
                if fmt == "%s":
                    return datetime.fromtimestamp(float(raw))
                return datetime.strptime(raw, fmt)
            except (ValueError, TypeError, OSError):
                continue
        return None

    def _compute_stats(self, values: list[float]) -> dict[str, float]:
        """Compute mean and standard deviation for a list of values."""
        n = len(values)
        if n == 0:
            return {"mean": 0.0, "stddev": 0.0}
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return {"mean": mean, "stddev": math.sqrt(variance)}

    def _detect_unusual_hours(self, hours: list[int]) -> list[dict[str, Any]]:
        """Flag activity outside business hours (22:00-06:00)."""
        findings = []
        off_hours = [h for h in hours if h < 6 or h >= 22]
        if off_hours:
            ratio = len(off_hours) / len(hours) if hours else 0
            if ratio > 0.1:
                findings.append({
                    "type": "unusual_hours",
                    "description": f"{len(off_hours)} events outside business hours ({ratio:.0%} of total)",
                    "severity": "high" if ratio > 0.5 else "medium",
                    "off_hour_count": len(off_hours),
                })
        return findings

    def _detect_burst_activity(self, timestamps: list[datetime], threshold_mult: float) -> list[dict[str, Any]]:
        """Detect bursts where events cluster tightly together."""
        findings = []
        if len(timestamps) < 3:
            return findings
        sorted_ts = sorted(timestamps)
        gaps = [(sorted_ts[i + 1] - sorted_ts[i]).total_seconds() for i in range(len(sorted_ts) - 1)]
        stats = self._compute_stats(gaps)
        mean, stddev = stats["mean"], stats["stddev"]
        burst_count = 0
        for gap in gaps:
            if stddev > 0 and gap < max(mean - threshold_mult * stddev, 0.1):
                burst_count += 1
        if burst_count > len(gaps) * 0.3:
            findings.append({
                "type": "burst_activity",
                "description": f"{burst_count} rapid-fire gaps detected (mean gap {mean:.1f}s, stddev {stddev:.1f}s)",
                "severity": "high" if burst_count > len(gaps) * 0.6 else "medium",
                "burst_count": burst_count,
            })
        return findings

    def _detect_new_destinations(self, events: list[dict], entity_type: str) -> list[dict[str, Any]]:
        """Flag destinations that appear rarely (potential lateral movement or exfil)."""
        findings = []
        destinations = [e.get("destination", "") for e in events if e.get("destination")]
        if not destinations:
            return findings
        freq = Counter(destinations)
        total = len(destinations)
        rare = [d for d, c in freq.items() if c == 1]
        if len(rare) > total * 0.5 and total > 5:
            findings.append({
                "type": "many_unique_destinations",
                "description": f"{len(rare)} unique one-time destinations out of {total} total",
                "severity": "medium",
                "unique_destinations": rare[:20],
            })
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        events = json.loads(config["events"].strip())
        entity_type = config.get("entity_type", "user")
        time_window = config.get("time_window", 60)
        threshold = config.get("anomaly_threshold", 2.0)

        self.logger.info("starting_behavior_analysis", entity_type=entity_type, event_count=len(events))

        anomalies: list[dict[str, Any]] = []
        timestamps: list[datetime] = []
        hours: list[int] = []
        actions: Counter = Counter()
        sources: Counter = Counter()

        # Parse events and build counters
        for event in events:
            ts_raw = event.get("timestamp", "")
            ts = self._parse_timestamp(str(ts_raw)) if ts_raw else None
            if ts:
                timestamps.append(ts)
                hours.append(ts.hour)
            actions[event.get("action", "unknown")] += 1
            sources[event.get("source", "unknown")] += 1

        # Action entropy -- high entropy = diverse actions (suspicious for a single entity)
        action_entropy = self._shannon_entropy(list(actions.values()))
        max_entropy = math.log2(len(actions)) if len(actions) > 1 else 1.0
        normalized_action_entropy = action_entropy / max_entropy if max_entropy > 0 else 0.0

        # Detect specific anomaly types
        anomalies.extend(self._detect_unusual_hours(hours))
        anomalies.extend(self._detect_burst_activity(timestamps, threshold))
        anomalies.extend(self._detect_new_destinations(events, entity_type))

        # Action frequency deviation
        action_counts = list(actions.values())
        action_stats = self._compute_stats([float(c) for c in action_counts])
        for action, count in actions.items():
            if action_stats["stddev"] > 0:
                zscore = (count - action_stats["mean"]) / action_stats["stddev"]
                if abs(zscore) >= threshold:
                    anomalies.append({
                        "type": "action_frequency_outlier",
                        "description": f"Action '{action}' count {count} deviates (z={zscore:.2f})",
                        "severity": "high" if abs(zscore) > 3 else "medium",
                        "action": action,
                        "z_score": round(zscore, 4),
                    })

        # Compute overall behavioral score (0 = normal, 1 = highly anomalous)
        severity_weights = {"high": 0.35, "medium": 0.2, "low": 0.1}
        raw_score = sum(severity_weights.get(a.get("severity", "low"), 0.1) for a in anomalies)
        # Include entropy contribution
        raw_score += normalized_action_entropy * 0.15
        behavioral_score = min(raw_score, 1.0)

        # Build profile
        profile = {
            "total_events": len(events),
            "unique_actions": len(actions),
            "unique_sources": len(sources),
            "action_entropy": round(action_entropy, 4),
            "normalized_entropy": round(normalized_action_entropy, 4),
            "time_span_minutes": 0,
            "top_actions": actions.most_common(10),
            "top_sources": sources.most_common(10),
        }
        if len(timestamps) >= 2:
            sorted_ts = sorted(timestamps)
            span = (sorted_ts[-1] - sorted_ts[0]).total_seconds() / 60.0
            profile["time_span_minutes"] = round(span, 2)

        self.logger.info(
            "behavior_analysis_complete",
            score=behavioral_score,
            anomaly_count=len(anomalies),
        )

        return {
            "behavioral_score": round(behavioral_score, 4),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "profile": profile,
            "entity_type": entity_type,
            "time_window_minutes": time_window,
        }
