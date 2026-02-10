"""Wireless deauthentication attack detector.

Analyzes 802.11 frame capture data to detect deauthentication flood attacks,
identify attacking MAC addresses, and assess attack severity.
"""

import asyncio
import re
import json
import math
from typing import Any
from collections import defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

DEAUTH_REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous auth no longer valid",
    3: "Deauth: STA leaving BSS",
    4: "Inactivity timer expired",
    5: "AP unable to handle all STAs",
    6: "Class 2 frame from non-authenticated STA",
    7: "Class 3 frame from non-associated STA",
    8: "Disassoc: STA leaving BSS",
}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class WirelessDeauthDetectorModule(AtsModule):
    """Detect deauthentication attacks from captured 802.11 frame data."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="wireless_deauth_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect deauthentication flood attacks from 802.11 capture data",
            version="1.0.0",
            parameters=[
                Parameter(name="capture_data", type=ParameterType.STRING,
                          description="JSON array of frame objects with type, subtype, src, dst, reason, timestamp fields"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity level",
                          choices=["low", "medium", "high"], default="medium"),
                Parameter(name="time_window", type=ParameterType.INTEGER,
                          description="Time window in seconds for rate analysis", default=10,
                          min_value=1, max_value=300),
            ],
            outputs=[
                OutputField(name="attack_detected", type="boolean", description="Whether an attack was detected"),
                OutputField(name="deauth_frames", type="integer", description="Total deauth frames found"),
                OutputField(name="attacking_macs", type="list", description="Identified attacking MAC addresses"),
                OutputField(name="severity", type="string", description="Attack severity assessment"),
            ],
            tags=["advanced", "wireless", "deauth", "detection", "ids"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("capture_data", "").strip()
        if not raw:
            return False, "Capture data JSON array is required"
        try:
            data = json.loads(raw)
            if not isinstance(data, list):
                return False, "Capture data must be a JSON array of frame objects"
            if len(data) == 0:
                return False, "Capture data array is empty"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _normalize_mac(self, mac: str) -> str:
        return mac.lower().strip().replace("-", ":")

    def _extract_deauth_frames(self, frames: list[dict]) -> list[dict]:
        deauth_frames = []
        for frame in frames:
            frame_type = frame.get("type", "")
            subtype = frame.get("subtype", "")
            if (str(frame_type) in ("0", "management", "mgmt") and
                str(subtype) in ("12", "deauth", "deauthentication", "10", "disassoc", "disassociation")):
                deauth_frames.append({
                    "src": self._normalize_mac(frame.get("src", "00:00:00:00:00:00")),
                    "dst": self._normalize_mac(frame.get("dst", "ff:ff:ff:ff:ff:ff")),
                    "reason": frame.get("reason", 1),
                    "timestamp": frame.get("timestamp", 0),
                    "subtype": str(subtype),
                })
        return deauth_frames

    def _analyze_time_windows(self, deauth_frames: list[dict],
                               window_sec: int) -> list[dict[str, Any]]:
        if not deauth_frames:
            return []
        timestamps = sorted(f["timestamp"] for f in deauth_frames if f.get("timestamp"))
        if not timestamps:
            return [{"window_start": 0, "count": len(deauth_frames), "rate_per_sec": 0}]

        windows = []
        start = timestamps[0]
        end = timestamps[-1]
        current = start

        while current <= end:
            window_end = current + window_sec
            count = sum(1 for t in timestamps if current <= t < window_end)
            if count > 0:
                windows.append({
                    "window_start": current,
                    "window_end": window_end,
                    "count": count,
                    "rate_per_sec": round(count / window_sec, 2),
                })
            current += window_sec

        return windows

    def _identify_attackers(self, deauth_frames: list[dict],
                            threshold: int) -> list[dict[str, Any]]:
        src_counts: dict[str, int] = defaultdict(int)
        src_targets: dict[str, set] = defaultdict(set)
        src_reasons: dict[str, list] = defaultdict(list)

        for frame in deauth_frames:
            src = frame["src"]
            src_counts[src] += 1
            src_targets[src].add(frame["dst"])
            src_reasons[src].append(frame["reason"])

        attackers = []
        for mac, count in src_counts.items():
            if count >= threshold:
                targets = list(src_targets[mac])
                reason_set = set(src_reasons[mac])
                is_broadcast = BROADCAST_MAC in targets
                attacker_info = {
                    "mac": mac,
                    "deauth_count": count,
                    "unique_targets": len(targets),
                    "targets_broadcast": is_broadcast,
                    "reason_codes_used": sorted(reason_set),
                    "attack_pattern": "broadcast_flood" if is_broadcast else
                                      "targeted" if len(targets) <= 3 else "multi_target",
                }
                if len(reason_set) == 1:
                    code = list(reason_set)[0]
                    attacker_info["reason_text"] = DEAUTH_REASON_CODES.get(code, f"Unknown({code})")
                attackers.append(attacker_info)

        attackers.sort(key=lambda x: x["deauth_count"], reverse=True)
        return attackers

    def _assess_severity(self, total_deauth: int, attackers: list,
                         windows: list, sensitivity: str) -> dict[str, Any]:
        thresholds = {
            "low": {"warning": 50, "critical": 200},
            "medium": {"warning": 20, "critical": 100},
            "high": {"warning": 5, "critical": 30},
        }
        thresh = thresholds.get(sensitivity, thresholds["medium"])
        max_rate = max((w["rate_per_sec"] for w in windows), default=0)
        has_broadcast = any(a.get("targets_broadcast") for a in attackers)

        if total_deauth >= thresh["critical"] or max_rate > 20:
            severity = "critical"
        elif total_deauth >= thresh["warning"] or max_rate > 5:
            severity = "high"
        elif total_deauth >= thresh["warning"] // 2:
            severity = "medium"
        else:
            severity = "low"

        if has_broadcast and severity in ("medium", "low"):
            severity = "high"

        return {
            "severity": severity,
            "total_deauth_frames": total_deauth,
            "peak_rate_per_sec": max_rate,
            "broadcast_attack": has_broadcast,
            "num_attackers": len(attackers),
            "assessment": (f"{'Active' if severity in ('critical', 'high') else 'Possible'} "
                           f"deauthentication attack detected with {total_deauth} frames, "
                           f"peak rate {max_rate}/sec from {len(attackers)} source(s)"),
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        frames = json.loads(config["capture_data"].strip())
        sensitivity = config.get("sensitivity", "medium")
        time_window = config.get("time_window", 10)

        deauth_frames = self._extract_deauth_frames(frames)
        total_frames = len(frames)
        total_deauth = len(deauth_frames)

        attacker_thresholds = {"low": 10, "medium": 5, "high": 2}
        threshold = attacker_thresholds.get(sensitivity, 5)

        windows = self._analyze_time_windows(deauth_frames, time_window)
        attackers = self._identify_attackers(deauth_frames, threshold)
        severity_info = self._assess_severity(total_deauth, attackers, windows, sensitivity)

        attack_detected = severity_info["severity"] in ("critical", "high") or len(attackers) > 0

        return {
            "attack_detected": attack_detected,
            "total_frames_analyzed": total_frames,
            "deauth_frames": total_deauth,
            "deauth_ratio": round(total_deauth / max(total_frames, 1), 4),
            "attacking_macs": attackers,
            "time_windows": windows,
            "severity": severity_info["severity"],
            "severity_detail": severity_info,
        }
