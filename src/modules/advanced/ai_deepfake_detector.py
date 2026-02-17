"""Deepfake indicator detection through metadata and structural analysis.

Analyzes media file metadata for deepfake indicators including software markers,
timestamp inconsistencies, EXIF tampering, and generation artifacts.
"""

import asyncio
import re
import math
import json
from typing import Any
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

DEEPFAKE_SOFTWARE_MARKERS = [
    "deepfacelab", "faceswap", "faceapp", "reface", "zao", "dall-e", "midjourney",
    "stable diffusion", "artbreeder", "thispersondoesnotexist", "gan", "deepfake",
    "wav2lip", "first order motion", "fsgan", "simswap", "roop", "facefusion",
    "synthesia", "d-id", "heygen", "runway", "pika", "sora",
]

SUSPICIOUS_EXIF_INDICATORS = {
    "missing_camera_model": "No camera model in EXIF - possibly AI-generated",
    "missing_lens_info": "No lens information - unlikely from real camera",
    "missing_gps": "No GPS data when other EXIF present - possible strip",
    "software_edit": "Edited with image manipulation software",
    "resolution_mismatch": "Resolution inconsistent with claimed camera",
    "missing_datetime_original": "Missing original capture datetime",
    "future_timestamp": "Timestamp is in the future",
    "thumbnail_mismatch": "Thumbnail dimensions inconsistent with main image",
}

VIDEO_DEEPFAKE_MARKERS = [
    "inconsistent_framerate", "variable_bitrate_spikes", "audio_video_desync",
    "missing_audio_metadata", "single_track_encoding", "unusual_codec_combination",
    "ffmpeg_synthetic_marker", "missing_creation_tool",
]

AUDIO_DEEPFAKE_MARKERS = [
    "flat_spectral_envelope", "missing_room_noise", "sample_rate_mismatch",
    "uniform_amplitude", "synthetic_vocoder_marker", "cloned_voice_pattern",
    "missing_encoder_info", "unusual_bitrate",
]


class AiDeepfakeDetectorModule(AtsModule):
    """Detect deepfake indicators in media metadata and structural properties."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ai_deepfake_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect deepfake indicators by analyzing media metadata and structural anomalies",
            version="1.0.0",
            parameters=[
                Parameter(name="metadata", type=ParameterType.STRING,
                          description="Media metadata as JSON string (EXIF, codec info, etc.)",
                          required=True),
                Parameter(name="analysis_type", type=ParameterType.CHOICE,
                          description="Type of media to analyze",
                          choices=["image", "video", "audio"], default="image"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity level",
                          choices=["low", "medium", "high"], default="medium"),
            ],
            outputs=[
                OutputField(name="deepfake_score", type="float",
                            description="Deepfake probability score 0.0-1.0"),
                OutputField(name="indicators", type="list",
                            description="Detected deepfake indicators"),
                OutputField(name="verdict", type="string",
                            description="Assessment verdict"),
            ],
            tags=["advanced", "ai", "deepfake", "detection", "forensics"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("metadata", "").strip()
        if not raw:
            return False, "Metadata JSON string is required"
        try:
            json.loads(raw)
        except json.JSONDecodeError:
            return False, "Metadata must be valid JSON"
        return True, ""

    def _check_software_markers(self, meta: dict[str, Any]) -> list[dict[str, Any]]:
        """Search metadata values for known deepfake software references."""
        indicators = []
        meta_str = json.dumps(meta).lower()
        for marker in DEEPFAKE_SOFTWARE_MARKERS:
            if marker in meta_str:
                indicators.append({
                    "type": "software_marker", "severity": "high",
                    "detail": f"Known deepfake/AI tool reference found: {marker}",
                })
        software = meta.get("Software", meta.get("software", "")).lower()
        editing_tools = ["photoshop", "gimp", "after effects", "premiere",
                         "davinci", "ffmpeg", "imagemagick"]
        for tool in editing_tools:
            if tool in software:
                indicators.append({
                    "type": "editing_software", "severity": "low",
                    "detail": f"Media edited with: {tool}",
                })
        return indicators

    def _check_exif_anomalies(self, meta: dict[str, Any]) -> list[dict[str, Any]]:
        """Check EXIF data for inconsistencies suggesting tampering."""
        indicators = []
        has_exif = any(k.lower().startswith("exif") or k in ("Make", "Model",
                       "FocalLength", "ExposureTime") for k in meta)

        if not meta.get("Make") and not meta.get("Model") and not meta.get("CameraModel"):
            indicators.append({"type": "missing_camera", "severity": "medium",
                               "detail": SUSPICIOUS_EXIF_INDICATORS["missing_camera_model"]})

        dt_original = meta.get("DateTimeOriginal", meta.get("datetime_original", ""))
        dt_modified = meta.get("ModifyDate", meta.get("modify_date", ""))
        if dt_original and dt_modified:
            try:
                fmt = "%Y:%m:%d %H:%M:%S"
                orig = datetime.strptime(str(dt_original), fmt)
                mod = datetime.strptime(str(dt_modified), fmt)
                if mod < orig:
                    indicators.append({"type": "timestamp_anomaly", "severity": "high",
                                       "detail": "Modify date precedes original capture date"})
                if orig > datetime.now():
                    indicators.append({"type": "future_timestamp", "severity": "medium",
                                       "detail": SUSPICIOUS_EXIF_INDICATORS["future_timestamp"]})
            except (ValueError, TypeError):
                pass
        elif has_exif and not dt_original:
            indicators.append({"type": "missing_datetime", "severity": "low",
                               "detail": SUSPICIOUS_EXIF_INDICATORS["missing_datetime_original"]})

        width = meta.get("ImageWidth", meta.get("width", 0))
        height = meta.get("ImageHeight", meta.get("height", 0))
        thumb_w = meta.get("ThumbnailWidth", meta.get("thumbnail_width", 0))
        thumb_h = meta.get("ThumbnailHeight", meta.get("thumbnail_height", 0))
        if width and height and thumb_w and thumb_h:
            aspect_main = round(int(width) / max(int(height), 1), 2)
            aspect_thumb = round(int(thumb_w) / max(int(thumb_h), 1), 2)
            if abs(aspect_main - aspect_thumb) > 0.1:
                indicators.append({"type": "thumbnail_mismatch", "severity": "high",
                                   "detail": SUSPICIOUS_EXIF_INDICATORS["thumbnail_mismatch"]})
        return indicators

    def _check_video_indicators(self, meta: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze video-specific metadata for deepfake markers."""
        indicators = []
        framerate = meta.get("framerate", meta.get("FrameRate", meta.get("fps", 0)))
        if framerate:
            fr = float(framerate)
            standard_rates = [23.976, 24, 25, 29.97, 30, 50, 59.94, 60]
            if not any(abs(fr - s) < 0.1 for s in standard_rates):
                indicators.append({"type": "unusual_framerate", "severity": "medium",
                                   "detail": f"Non-standard framerate: {fr} fps"})

        audio_codec = meta.get("audio_codec", meta.get("AudioCodec", ""))
        video_codec = meta.get("video_codec", meta.get("VideoCodec", ""))
        if video_codec and not audio_codec:
            indicators.append({"type": "missing_audio", "severity": "medium",
                               "detail": "Video has no audio track - common in synthetic media"})

        duration = float(meta.get("duration", meta.get("Duration", 0)) or 0)
        if duration and framerate:
            expected_frames = duration * float(framerate)
            actual_frames = int(meta.get("frame_count", meta.get("FrameCount", 0)) or 0)
            if actual_frames and abs(expected_frames - actual_frames) / max(expected_frames, 1) > 0.05:
                indicators.append({"type": "frame_count_mismatch", "severity": "high",
                                   "detail": "Frame count inconsistent with duration and framerate"})
        return indicators

    def _check_audio_indicators(self, meta: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze audio-specific metadata for synthesis markers."""
        indicators = []
        sample_rate = int(meta.get("sample_rate", meta.get("SampleRate", 0)) or 0)
        if sample_rate and sample_rate not in (8000, 11025, 16000, 22050, 44100, 48000, 96000):
            indicators.append({"type": "unusual_sample_rate", "severity": "medium",
                               "detail": f"Non-standard sample rate: {sample_rate} Hz"})

        channels = int(meta.get("channels", meta.get("Channels", 0)) or 0)
        if channels and channels > 2:
            indicators.append({"type": "unusual_channels", "severity": "low",
                               "detail": f"Unusual channel count: {channels}"})

        bitrate = int(meta.get("bitrate", meta.get("BitRate", 0)) or 0)
        if bitrate and bitrate < 32000:
            indicators.append({"type": "low_bitrate", "severity": "medium",
                               "detail": f"Very low bitrate ({bitrate} bps) - possible re-encoding"})

        encoder = meta.get("encoder", meta.get("Encoder", "")).lower()
        if encoder:
            synth_encoders = ["tts", "vocoder", "wavenet", "tacotron", "bark", "tortoise"]
            for se in synth_encoders:
                if se in encoder:
                    indicators.append({"type": "synthetic_encoder", "severity": "high",
                                       "detail": f"Known speech synthesis encoder: {se}"})
        return indicators

    def _compute_score(self, indicators: list[dict], sensitivity: str) -> float:
        """Compute deepfake probability score from indicators."""
        if not indicators:
            return 0.0
        weights = {"critical": 0.35, "high": 0.25, "medium": 0.15, "low": 0.05}
        sensitivity_mult = {"low": 0.7, "medium": 1.0, "high": 1.4}
        raw = sum(weights.get(i["severity"], 0.1) for i in indicators)
        scaled = raw * sensitivity_mult.get(sensitivity, 1.0)
        score = 1.0 - math.exp(-scaled)
        return round(min(1.0, score), 3)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        meta = json.loads(config["metadata"])
        analysis_type = config.get("analysis_type", "image")
        sensitivity = config.get("sensitivity", "medium")

        indicators: list[dict[str, Any]] = []

        indicators.extend(self._check_software_markers(meta))
        indicators.extend(self._check_exif_anomalies(meta))

        if analysis_type == "video":
            indicators.extend(self._check_video_indicators(meta))
        elif analysis_type == "audio":
            indicators.extend(self._check_audio_indicators(meta))

        score = self._compute_score(indicators, sensitivity)

        if score >= 0.75:
            verdict = "LIKELY_DEEPFAKE"
        elif score >= 0.45:
            verdict = "SUSPICIOUS"
        elif score >= 0.2:
            verdict = "INCONCLUSIVE"
        else:
            verdict = "LIKELY_AUTHENTIC"

        severity_counts = {}
        for ind in indicators:
            sev = ind["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "analysis_type": analysis_type,
            "sensitivity": sensitivity,
            "deepfake_score": score,
            "verdict": verdict,
            "indicators": indicators,
            "indicator_count": len(indicators),
            "severity_breakdown": severity_counts,
        }
