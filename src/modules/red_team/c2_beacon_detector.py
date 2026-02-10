"""C2 Beacon Detector Module.

Detect Command & Control beacon patterns in network traffic by analyzing
timing intervals, known beacon signatures, and JA3/JA3S hash matching.
"""

import asyncio
import statistics
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

# Known C2 framework beacon intervals (seconds)
KNOWN_BEACON_INTERVALS = {
    "cobalt_strike_default": 60.0,
    "cobalt_strike_fast": 5.0,
    "metasploit_default": 5.0,
    "empire_default": 5.0,
    "covenant_default": 10.0,
    "sliver_default": 30.0,
    "brute_ratel_default": 60.0,
    "havoc_default": 10.0,
}

# Known malicious JA3 hashes associated with C2 frameworks
KNOWN_C2_JA3_HASHES = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (4.x)",
    "51c64c77e60f3980eea90869b68c58a8": "Metasploit Meterpreter",
    "e7d705a3286e19ea42f587b344ee6865": "Empire",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Sliver",
    "6734f37431670b3ab4292b8f60f29984": "Brute Ratel C4",
    "b32309a26951912be7dba376398abc3b": "PoshC2",
    "8d63e53508e49dc8cf8281c3e8a35afb": "Havoc Framework",
    "c12f54a3f91dc7bafd92b1b4c8a7bb31": "Mythic",
}

JITTER_THRESHOLD = 0.15  # 15% jitter tolerance


class C2BeaconDetectorModule(AtsModule):
    """Detect C2 beacon patterns in network traffic data."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="c2_beacon_detector",
            category=ModuleCategory.RED_TEAM,
            description="Detect C2 beacon patterns by analyzing timing intervals, JA3 hashes, and known beacon signatures",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target IP or CIDR range to analyze traffic for",
                    required=True,
                ),
                Parameter(
                    name="timestamps",
                    type=ParameterType.LIST,
                    description="List of connection timestamps (ISO format or epoch floats) to analyze for periodicity",
                    required=True,
                ),
                Parameter(
                    name="ja3_hashes",
                    type=ParameterType.LIST,
                    description="List of JA3 fingerprint hashes observed in traffic",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="jitter_tolerance",
                    type=ParameterType.FLOAT,
                    description="Acceptable jitter tolerance as a fraction (0.0-1.0)",
                    required=False,
                    default=0.15,
                    min_value=0.0,
                    max_value=1.0,
                ),
            ],
            outputs=[
                OutputField(name="beacon_detected", type="bool", description="Whether beacon-like traffic was detected"),
                OutputField(name="detections", type="list", description="Detailed detection results"),
                OutputField(name="summary", type="dict", description="Analysis summary with risk score"),
            ],
            tags=["red_team", "c2", "beacon", "detection", "network"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target IP or CIDR range is required"
        timestamps = config.get("timestamps", [])
        if not timestamps or len(timestamps) < 3:
            return False, "At least 3 timestamps are required for interval analysis"
        return True, ""

    def _parse_timestamps(self, raw_timestamps: List[Any]) -> List[float]:
        """Convert mixed timestamp formats to epoch floats."""
        parsed = []
        for ts in raw_timestamps:
            if isinstance(ts, (int, float)):
                parsed.append(float(ts))
            elif isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    parsed.append(dt.timestamp())
                except ValueError:
                    parsed.append(float(ts))
        return sorted(parsed)

    def _compute_intervals(self, timestamps: List[float]) -> List[float]:
        """Compute inter-arrival intervals between consecutive timestamps."""
        return [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    def _detect_periodicity(self, intervals: List[float], jitter_tolerance: float) -> Dict[str, Any]:
        """Detect periodic beaconing behaviour in the interval data."""
        if len(intervals) < 2:
            return {"periodic": False, "reason": "Insufficient intervals"}

        mean_interval = statistics.mean(intervals)
        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

        is_periodic = cv <= jitter_tolerance

        return {
            "periodic": is_periodic,
            "mean_interval_sec": round(mean_interval, 3),
            "stdev_sec": round(stdev_interval, 3),
            "coefficient_of_variation": round(cv, 4),
            "sample_count": len(intervals),
            "jitter_tolerance": jitter_tolerance,
        }

    def _match_known_beacons(self, mean_interval: float, jitter_tolerance: float) -> List[Dict[str, Any]]:
        """Match observed interval against known C2 beacon intervals."""
        matches = []
        for framework, known_interval in KNOWN_BEACON_INTERVALS.items():
            deviation = abs(mean_interval - known_interval) / known_interval if known_interval > 0 else float("inf")
            if deviation <= jitter_tolerance:
                matches.append({
                    "framework": framework,
                    "known_interval_sec": known_interval,
                    "deviation_pct": round(deviation * 100, 2),
                })
        return matches

    def _check_ja3_hashes(self, ja3_hashes: List[str]) -> List[Dict[str, Any]]:
        """Check provided JA3 hashes against known C2 framework signatures."""
        hits = []
        for h in ja3_hashes:
            h_lower = h.strip().lower()
            if h_lower in KNOWN_C2_JA3_HASHES:
                hits.append({
                    "ja3_hash": h_lower,
                    "matched_framework": KNOWN_C2_JA3_HASHES[h_lower],
                    "confidence": "high",
                })
        return hits

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        raw_timestamps = config["timestamps"]
        ja3_hashes = config.get("ja3_hashes", []) or []
        jitter_tolerance = config.get("jitter_tolerance", JITTER_THRESHOLD)

        self.logger.info("c2_beacon_analysis_start", target=target, samples=len(raw_timestamps))

        timestamps = self._parse_timestamps(raw_timestamps)
        intervals = self._compute_intervals(timestamps)

        # Run analyses concurrently via asyncio tasks
        loop = asyncio.get_event_loop()
        periodicity_result = await loop.run_in_executor(None, self._detect_periodicity, intervals, jitter_tolerance)
        beacon_matches = await loop.run_in_executor(
            None, self._match_known_beacons, periodicity_result["mean_interval_sec"], jitter_tolerance
        )
        ja3_hits = await loop.run_in_executor(None, self._check_ja3_hashes, ja3_hashes)

        # Build detections list
        detections: List[Dict[str, Any]] = []
        risk_score = 0

        if periodicity_result["periodic"]:
            detections.append({
                "type": "periodic_beacon",
                "severity": "high",
                "detail": periodicity_result,
            })
            risk_score += 40

        if beacon_matches:
            detections.append({
                "type": "known_c2_interval_match",
                "severity": "critical",
                "matches": beacon_matches,
            })
            risk_score += 35

        if ja3_hits:
            detections.append({
                "type": "known_c2_ja3_match",
                "severity": "critical",
                "matches": ja3_hits,
            })
            risk_score += 25

        beacon_detected = len(detections) > 0

        summary = {
            "target": target,
            "beacon_detected": beacon_detected,
            "risk_score": min(risk_score, 100),
            "total_connections_analyzed": len(timestamps),
            "interval_stats": periodicity_result,
            "known_framework_matches": len(beacon_matches),
            "ja3_matches": len(ja3_hits),
        }

        self.logger.info("c2_beacon_analysis_complete", target=target, detected=beacon_detected, risk=risk_score)

        return {
            "beacon_detected": beacon_detected,
            "detections": detections,
            "summary": summary,
        }
