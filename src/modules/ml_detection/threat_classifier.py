"""Threat classification module using rule-based scoring and entropy analysis.

Classify network or log entries into threat categories by matching against
pattern libraries and computing information-entropy indicators.
"""

import asyncio
import re
import math
from typing import Any
from collections import Counter

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Pattern libraries per threat category
THREAT_PATTERNS = {
    "brute_force": {
        "patterns": [
            r"(?i)failed\s+(password|login|auth)",
            r"(?i)invalid\s+(user|credentials|password)",
            r"(?i)authentication\s+fail",
            r"(?i)access\s+denied",
            r"(?i)too\s+many\s+(attempts|failures)",
            r"(?i)account\s+locked",
            r"(?i)unauthorized",
            r"(?i)login\s+attempt\s+from",
        ],
        "weight": 1.0,
    },
    "data_exfiltration": {
        "patterns": [
            r"(?i)large\s+(upload|transfer|outbound)",
            r"(?i)bytes[=: ]+(\d{7,})",  # 1M+ bytes
            r"(?i)(ftp|scp|sftp|rsync)\s+",
            r"(?i)dns\s+txt\s+.*[a-zA-Z0-9]{50,}",
            r"(?i)POST\s+.*\.(php|asp|jsp)\s+\d{6,}",
            r"(?i)encoded[_\s]*(payload|data|content)",
            r"(?i)outbound.*unusual",
        ],
        "weight": 1.2,
    },
    "c2_communication": {
        "patterns": [
            r"(?i)beacon\s*(interval|detected|traffic)",
            r"(?i)(callback|heartbeat|keepalive)\s+to\s+\d{1,3}\.\d{1,3}",
            r"(?i)(tor|onion|i2p|proxy)\s+(exit|relay|connection)",
            r"(?i)dns\s+query.*\.(tk|ml|ga|cf|pw)\b",
            r"(?i)connect.*port\s*(443|8443|4443|8080)\b",
            r"(?i)periodic\s+(connection|request)",
            r"(?i)(reverse|bind)\s+shell",
        ],
        "weight": 1.3,
    },
    "malware": {
        "patterns": [
            r"(?i)(trojan|worm|ransomware|rootkit|keylogger|backdoor)",
            r"(?i)(mimikatz|metasploit|cobalt\s*strike|empire)",
            r"(?i)powershell.*(-enc|-e |downloadstring|invoke-expression)",
            r"(?i)(cmd|bash).*(/c |exec|eval|system)\s",
            r"(?i)\.(exe|dll|scr|bat|ps1|vbs)\s+(created|dropped|written)",
            r"(?i)registry.*(run|runonce|services)",
            r"(?i)process\s+injection",
            r"(?i)privilege\s+escalation",
        ],
        "weight": 1.5,
    },
}

NETWORK_PATTERNS = {
    "port_scan": [r"SYN\s+to\s+\d+\s+ports", r"(?i)scan\s+detected", r"connection\s+refused.*(\d+\s+times)"],
    "dns_tunnel": [r"(?i)dns.*query.*length[>= ]+(\d{3,})", r"(?i)nxdomain.*rate", r"TXT\s+record.*[A-Za-z0-9+/=]{40,}"],
    "lateral_movement": [r"(?i)(smb|rdp|winrm|psexec|wmic)", r"(?i)admin\$", r"(?i)pass.the.(hash|ticket)"],
}


class ThreatClassifierModule(AtsModule):
    """Classify data entries into threat categories using pattern-based scoring."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="threat_classifier",
            category=ModuleCategory.ML_DETECTION,
            description="Classify network/log entries as threat types using rule-based scoring and entropy analysis",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="data",
                    type=ParameterType.STRING,
                    description="Log line, network data, or multi-line text to classify",
                    required=True,
                ),
                Parameter(
                    name="mode",
                    type=ParameterType.CHOICE,
                    description="Analysis mode tuned for data source type",
                    required=False,
                    default="log",
                    choices=["network", "log", "file"],
                ),
                Parameter(
                    name="min_confidence",
                    type=ParameterType.FLOAT,
                    description="Minimum confidence score (0.0-1.0) to include a classification",
                    required=False,
                    default=0.1,
                    min_value=0.0,
                    max_value=1.0,
                ),
            ],
            outputs=[
                OutputField(name="threat_type", type="string", description="Primary threat classification"),
                OutputField(name="confidence_score", type="float", description="Overall confidence 0.0-1.0"),
                OutputField(name="matched_indicators", type="list", description="Specific patterns that matched"),
                OutputField(name="classifications", type="list", description="All threat categories with scores"),
            ],
            tags=["ml", "detection", "threat", "classification", "scoring"],
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("data", "").strip()
        if not data:
            return False, "data is required"
        mode = config.get("mode", "log")
        if mode not in ("network", "log", "file"):
            return False, "mode must be one of: network, log, file"
        return True, ""

    def _shannon_entropy(self, text: str) -> float:
        """Compute Shannon entropy of the input string."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _score_category(self, data: str, category: str, patterns: list[str], weight: float) -> tuple[float, list[str]]:
        """Score data against a single threat category. Returns (score, matched_patterns)."""
        matched = []
        for pattern in patterns:
            matches = re.findall(pattern, data)
            if matches:
                matched.append(pattern)
        if not matched:
            return 0.0, []
        # Base score: ratio of matched patterns, weighted
        raw_score = (len(matched) / len(patterns)) * weight
        # Clamp to [0, 1]
        return min(raw_score, 1.0), matched

    def _apply_mode_bonus(self, scores: dict[str, float], mode: str) -> dict[str, float]:
        """Boost scores for categories especially relevant to the analysis mode."""
        bonuses = {
            "network": {"c2_communication": 0.1, "data_exfiltration": 0.1, "port_scan": 0.15},
            "log": {"brute_force": 0.1, "malware": 0.05},
            "file": {"malware": 0.15},
        }
        for cat, bonus in bonuses.get(mode, {}).items():
            if cat in scores and scores[cat] > 0:
                scores[cat] = min(scores[cat] + bonus, 1.0)
        return scores

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = config["data"].strip()
        mode = config.get("mode", "log")
        min_confidence = config.get("min_confidence", 0.1)

        self.logger.info("starting_threat_classification", mode=mode, data_length=len(data))

        all_indicators: list[dict[str, Any]] = []
        category_scores: dict[str, float] = {}

        # Score against each threat category
        for category, info in THREAT_PATTERNS.items():
            score, matched = self._score_category(data, category, info["patterns"], info["weight"])
            category_scores[category] = score
            for pat in matched:
                all_indicators.append({"category": category, "pattern": pat})

        # Score network-specific patterns when relevant
        if mode == "network":
            for category, patterns in NETWORK_PATTERNS.items():
                score, matched = self._score_category(data, category, patterns, 1.0)
                existing = category_scores.get(category, 0.0)
                category_scores[category] = min(existing + score, 1.0)
                for pat in matched:
                    all_indicators.append({"category": category, "pattern": pat})

        # Apply mode-specific bonuses
        category_scores = self._apply_mode_bonus(category_scores, mode)

        # Entropy analysis as an additional indicator
        entropy = self._shannon_entropy(data)
        entropy_flag = entropy > 5.5  # high entropy suggests encoded/encrypted content
        if entropy_flag:
            for cat in ("data_exfiltration", "c2_communication", "malware"):
                if cat in category_scores:
                    category_scores[cat] = min(category_scores[cat] + 0.1, 1.0)

        # Build classifications list, filtered by min_confidence
        classifications = []
        for cat, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
            if score >= min_confidence:
                classifications.append({"threat_type": cat, "confidence": round(score, 4)})

        # Determine primary threat
        if classifications:
            primary = classifications[0]
            threat_type = primary["threat_type"]
            confidence_score = primary["confidence"]
        else:
            threat_type = "benign"
            confidence_score = 0.0

        self.logger.info(
            "threat_classification_complete",
            threat_type=threat_type,
            confidence=confidence_score,
            indicators=len(all_indicators),
        )

        return {
            "threat_type": threat_type,
            "confidence_score": round(confidence_score, 4),
            "matched_indicators": all_indicators,
            "indicator_count": len(all_indicators),
            "classifications": classifications,
            "entropy": round(entropy, 4),
            "high_entropy": entropy_flag,
            "mode": mode,
        }
