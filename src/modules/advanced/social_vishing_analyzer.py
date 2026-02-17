"""Analyze call transcripts for vishing (voice phishing) indicators.

Detects urgency language, authority claims, information requests,
and manipulation techniques with weighted scoring.
"""

import asyncio
import re
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

URGENCY_PATTERNS = [
    (r'\b(?:immediately|urgent|right\s+now|asap|time[- ]?sensitive)\b', 3.0, "Direct urgency demand"),
    (r'\b(?:deadline|expir(?:e|ing|ation)|suspend(?:ed)?|terminat(?:e|ed|ion))\b', 2.5, "Consequence-based urgency"),
    (r'\b(?:hurry|quick(?:ly)?|fast|rush|don\'?t\s+delay)\b', 2.0, "Speed pressure language"),
    (r'\b(?:last\s+chance|final\s+notice|only\s+\d+\s+(?:hour|minute|day))\b', 3.0, "Scarcity/deadline pressure"),
    (r'\b(?:before\s+(?:it\'?s?\s+)?too\s+late|running\s+out\s+of\s+time)\b', 2.5, "Fear-of-missing-out language"),
]

AUTHORITY_PATTERNS = [
    (r'\b(?:this\s+is\s+(?:the\s+)?(?:IRS|FBI|police|government|bank|microsoft))\b', 4.0, "Government/brand authority claim"),
    (r'\b(?:I\'?m\s+(?:a|an|the|your)\s+(?:manager|supervisor|director|officer|agent|inspector))\b', 3.0, "Authority role claim"),
    (r'\b(?:legal\s+(?:action|proceedings|department)|law\s+enforcement|warrant)\b', 3.5, "Legal threat authority"),
    (r'\b(?:compliance|regulation|requirement|mandatory|policy\s+violation)\b', 2.0, "Policy/compliance authority"),
    (r'\b(?:badge\s+(?:number|id)|case\s+(?:number|id|file)|reference\s+(?:number|code))\b', 1.5, "Credential reference"),
]

INFO_REQUEST_PATTERNS = [
    (r'\b(?:social\s+security|SSN|tax\s+(?:id|number)|national\s+(?:id|insurance))\b', 5.0, "Government ID request"),
    (r'\b(?:credit\s+card|card\s+number|CVV|expir(?:y|ation)\s+date|bank\s+account)\b', 5.0, "Financial data request"),
    (r'\b(?:password|PIN|passcode|security\s+(?:code|question|answer)|OTP|verification\s+code)\b', 4.5, "Credential request"),
    (r'\b(?:date\s+of\s+birth|mother\'?s?\s+maiden|address|phone\s+number)\b', 2.5, "Personal data request"),
    (r'\b(?:employee\s+(?:id|number)|login|username|account\s+number)\b', 3.0, "Account identifier request"),
    (r'\b(?:remote\s+access|install\s+(?:this|the)|download|teamviewer|anydesk)\b', 4.0, "Remote access request"),
]

MANIPULATION_PATTERNS = [
    (r'\b(?:don\'?t\s+(?:tell|share|discuss|mention)\s+(?:this|anyone)|between\s+(?:us|you\s+and\s+me)|confidential)\b', 3.5, "Isolation/secrecy tactic"),
    (r'\b(?:trust\s+me|I\'?m\s+(?:trying\s+to\s+)?help(?:ing)?|for\s+your\s+(?:own\s+)?(?:safety|protection|good))\b', 2.0, "False rapport building"),
    (r'\b(?:you\s+(?:will|could|might)\s+(?:be\s+)?(?:arrested|prosecuted|fined|sued|charged))\b', 4.0, "Fear/threat of consequences"),
    (r'\b(?:special\s+(?:offer|deal|promotion)|only\s+for\s+you|limited\s+time|exclusive)\b', 2.0, "Incentive manipulation"),
    (r'\b(?:verify\s+(?:your\s+)?identity|confirm\s+(?:your\s+)?(?:details|information|account))\b', 2.5, "False verification pretext"),
    (r'\b(?:already\s+(?:been|have)\s+(?:compromised|hacked|breached|stolen))\b', 3.0, "Fear exploitation"),
]


class SocialVishingAnalyzerModule(AtsModule):
    """Analyze call transcripts for vishing attack indicators."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_vishing_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze call transcripts for vishing indicators, manipulation scoring, and threat assessment",
            version="1.0.0",
            parameters=[
                Parameter(name="call_transcript", type=ParameterType.STRING,
                          description="Call transcript text to analyze", required=True),
                Parameter(name="analysis_type", type=ParameterType.CHOICE,
                          description="Type of analysis to perform",
                          choices=["indicators", "scoring", "full"], default="full"),
                Parameter(name="context", type=ParameterType.STRING,
                          description="Additional context about the call (e.g., claimed organization)",
                          required=False, default=""),
            ],
            outputs=[
                OutputField(name="risk_score", type="float", description="Overall vishing risk score 0-100"),
                OutputField(name="indicators", type="list", description="Detected vishing indicators"),
                OutputField(name="verdict", type="string", description="Assessment verdict"),
            ],
            tags=["advanced", "social", "vishing", "voice-phishing", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        transcript = config.get("call_transcript", "").strip()
        if not transcript:
            return False, "Call transcript is required"
        if len(transcript) < 20:
            return False, "Transcript too short for meaningful analysis (minimum 20 characters)"
        return True, ""

    def _scan_patterns(self, text: str, patterns: list[tuple], category: str) -> list[dict[str, Any]]:
        """Scan text against a pattern set and return matches with metadata."""
        findings = []
        text_lower = text.lower()
        for pattern, weight, description in patterns:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            if matches:
                matched_texts = list({m.group() for m in matches})
                findings.append({
                    "category": category,
                    "description": description,
                    "weight": weight,
                    "occurrences": len(matches),
                    "matched_text": matched_texts[:5],
                    "effective_score": round(weight * min(len(matches), 3), 2),
                })
        return findings

    def _calculate_text_metrics(self, text: str) -> dict[str, Any]:
        """Calculate structural text metrics for additional signals."""
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        exclamation_count = text.count('!')
        question_count = text.count('?')
        caps_words = len(re.findall(r'\b[A-Z]{2,}\b', text))
        words = text.split()
        word_count = len(words)
        avg_sentence_len = word_count / max(len(sentences), 1)

        return {
            "word_count": word_count,
            "sentence_count": len(sentences),
            "avg_sentence_length": round(avg_sentence_len, 1),
            "exclamation_marks": exclamation_count,
            "question_marks": question_count,
            "capitalized_words": caps_words,
            "aggressive_punctuation": exclamation_count > 3 or caps_words > 5,
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        transcript = config["call_transcript"].strip()
        analysis_type = config.get("analysis_type", "full")
        context = config.get("context", "")

        all_indicators = []
        category_scores = {}

        pattern_sets = [
            ("urgency", URGENCY_PATTERNS),
            ("authority", AUTHORITY_PATTERNS),
            ("information_request", INFO_REQUEST_PATTERNS),
            ("manipulation", MANIPULATION_PATTERNS),
        ]

        for category, patterns in pattern_sets:
            findings = self._scan_patterns(transcript, patterns, category)
            all_indicators.extend(findings)
            cat_score = sum(f["effective_score"] for f in findings)
            category_scores[category] = round(cat_score, 2)

        text_metrics = self._calculate_text_metrics(transcript)
        if text_metrics["aggressive_punctuation"]:
            all_indicators.append({
                "category": "text_style",
                "description": "Aggressive punctuation or excessive capitalization",
                "weight": 1.0,
                "occurrences": 1,
                "matched_text": [],
                "effective_score": 1.0,
            })

        raw_score = sum(f["effective_score"] for f in all_indicators)
        categories_hit = sum(1 for v in category_scores.values() if v > 0)
        breadth_bonus = categories_hit * 5.0
        risk_score = min(100.0, raw_score * 2.5 + breadth_bonus)
        risk_score = round(risk_score, 1)

        if risk_score >= 80:
            verdict = "HIGHLY LIKELY VISHING - Multiple strong indicators detected"
        elif risk_score >= 60:
            verdict = "LIKELY VISHING - Significant manipulation indicators present"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS - Some vishing indicators detected, warrants investigation"
        elif risk_score >= 20:
            verdict = "LOW RISK - Minor indicators present, likely benign"
        else:
            verdict = "BENIGN - No significant vishing indicators detected"

        result: dict[str, Any] = {
            "risk_score": risk_score,
            "verdict": verdict,
            "categories_detected": categories_hit,
            "category_scores": category_scores,
        }

        if analysis_type in ("indicators", "full"):
            all_indicators.sort(key=lambda x: x["effective_score"], reverse=True)
            result["indicators"] = all_indicators
            result["total_indicators"] = len(all_indicators)

        if analysis_type in ("scoring", "full"):
            result["text_metrics"] = text_metrics
            result["scoring_breakdown"] = {
                "raw_indicator_score": round(raw_score, 2),
                "breadth_bonus": breadth_bonus,
                "final_score": risk_score,
            }

        if context:
            result["context_provided"] = context

        return result
