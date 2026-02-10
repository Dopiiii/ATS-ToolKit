"""RF signal characteristics analyzer.

Analyzes radio frequency signal data to identify protocols, detect anomalies,
and check for jamming indicators across common wireless frequencies.
"""

import asyncio
import re
import json
import math
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

KNOWN_FREQUENCIES = [
    {"range": (2400, 2484), "protocol": "WiFi 2.4GHz (802.11b/g/n)", "band": "ISM 2.4GHz"},
    {"range": (5150, 5850), "protocol": "WiFi 5GHz (802.11a/n/ac/ax)", "band": "U-NII"},
    {"range": (5925, 7125), "protocol": "WiFi 6E (802.11ax)", "band": "6GHz"},
    {"range": (2402, 2480), "protocol": "Bluetooth Classic/BLE", "band": "ISM 2.4GHz"},
    {"range": (2405, 2480), "protocol": "Zigbee (802.15.4)", "band": "ISM 2.4GHz"},
    {"range": (868, 868.6), "protocol": "Zigbee/Z-Wave (EU)", "band": "SRD 868MHz"},
    {"range": (902, 928), "protocol": "Zigbee/Z-Wave/LoRa (US)", "band": "ISM 902MHz"},
    {"range": (433.05, 434.79), "protocol": "ISM 433MHz (remotes, sensors)", "band": "ISM 433MHz"},
    {"range": (315, 315), "protocol": "Key fobs / garage doors (US)", "band": "315MHz"},
    {"range": (862, 875), "protocol": "LoRa (EU)", "band": "SRD 868MHz"},
    {"range": (1575.42, 1575.42), "protocol": "GPS L1", "band": "L-band"},
    {"range": (1227.6, 1227.6), "protocol": "GPS L2", "band": "L-band"},
    {"range": (1176.45, 1176.45), "protocol": "GPS L5", "band": "L-band"},
]

MODULATION_TYPES = {
    "ofdm": {"typical_for": ["WiFi", "LTE"], "complexity": "high"},
    "fhss": {"typical_for": ["Bluetooth"], "complexity": "medium"},
    "dsss": {"typical_for": ["Zigbee", "GPS", "802.11b"], "complexity": "medium"},
    "css": {"typical_for": ["LoRa"], "complexity": "low"},
    "ask": {"typical_for": ["key fobs", "remotes"], "complexity": "low"},
    "fsk": {"typical_for": ["Z-Wave", "sensors"], "complexity": "low"},
    "gfsk": {"typical_for": ["Bluetooth", "BLE", "Zigbee"], "complexity": "medium"},
    "qpsk": {"typical_for": ["satellite", "GPS"], "complexity": "medium"},
}


class RfSignalAnalyzerModule(AtsModule):
    """Analyze RF signal characteristics for protocol identification and anomaly detection."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="rf_signal_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze RF signal data for protocol identification, anomalies, and jamming indicators",
            version="1.0.0",
            parameters=[
                Parameter(name="signal_data", type=ParameterType.STRING,
                          description="JSON with frequency (MHz), power (dBm), modulation, bandwidth, and optional samples array"),
                Parameter(name="analysis_type", type=ParameterType.CHOICE,
                          description="Type of analysis to perform",
                          choices=["identification", "anomaly", "jamming"], default="identification"),
                Parameter(name="noise_floor", type=ParameterType.FLOAT,
                          description="Noise floor in dBm for SNR calculation", default=-90.0),
            ],
            outputs=[
                OutputField(name="identified_protocols", type="list", description="Matched protocols"),
                OutputField(name="anomalies", type="list", description="Detected signal anomalies"),
                OutputField(name="jamming_indicators", type="dict", description="Jamming detection results"),
            ],
            tags=["advanced", "wireless", "rf", "signal", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("signal_data", "").strip()
        if not raw:
            return False, "Signal data JSON is required"
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False, "Signal data must be a JSON object"
            if "frequency" not in data:
                return False, "Signal data must include 'frequency' field (in MHz)"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _identify_protocol(self, freq_mhz: float, modulation: str,
                           bandwidth: float) -> list[dict[str, Any]]:
        matches = []
        for entry in KNOWN_FREQUENCIES:
            lo, hi = entry["range"]
            tolerance = max(1.0, (hi - lo) * 0.05)
            if lo - tolerance <= freq_mhz <= hi + tolerance:
                confidence = 0.5
                if lo <= freq_mhz <= hi:
                    confidence = 0.7
                mod_info = MODULATION_TYPES.get(modulation.lower(), {})
                if any(p.lower() in entry["protocol"].lower() for p in mod_info.get("typical_for", [])):
                    confidence += 0.2
                if bandwidth > 0:
                    if "WiFi" in entry["protocol"] and 18 <= bandwidth <= 160:
                        confidence += 0.1
                    elif "Bluetooth" in entry["protocol"] and bandwidth <= 2:
                        confidence += 0.1
                    elif "Zigbee" in entry["protocol"] and bandwidth <= 5:
                        confidence += 0.1
                matches.append({
                    "protocol": entry["protocol"], "band": entry["band"],
                    "confidence": round(min(1.0, confidence), 2),
                    "frequency_match": lo <= freq_mhz <= hi,
                })
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches

    def _detect_anomalies(self, data: dict[str, Any], noise_floor: float) -> list[dict[str, Any]]:
        anomalies = []
        power = data.get("power", -50)
        freq = data.get("frequency", 0)
        snr = power - noise_floor

        if power > -10:
            anomalies.append({"type": "excessive_power", "severity": "high",
                              "detail": f"Signal power {power} dBm is unusually high, possible proximity or amplified source"})
        if snr > 60:
            anomalies.append({"type": "abnormal_snr", "severity": "medium",
                              "detail": f"SNR of {snr:.1f} dB is abnormally high"})
        if snr < 5:
            anomalies.append({"type": "weak_signal", "severity": "info",
                              "detail": f"SNR of {snr:.1f} dB is very low, signal may be unreliable"})

        samples = data.get("samples", [])
        if len(samples) >= 3:
            avg_power = sum(samples) / len(samples)
            variance = sum((s - avg_power) ** 2 for s in samples) / len(samples)
            std_dev = math.sqrt(variance)
            if std_dev > 15:
                anomalies.append({"type": "power_instability", "severity": "medium",
                                  "detail": f"Power variance is high (std_dev={std_dev:.1f} dB), signal is unstable"})
            if all(s > noise_floor + 30 for s in samples):
                anomalies.append({"type": "sustained_high_power", "severity": "high",
                                  "detail": "Sustained high power across all samples"})

        bandwidth = data.get("bandwidth", 0)
        if bandwidth > 200:
            anomalies.append({"type": "excessive_bandwidth", "severity": "high",
                              "detail": f"Bandwidth {bandwidth} MHz is unusually wide - possible wideband interference"})

        return anomalies

    def _check_jamming(self, data: dict[str, Any], noise_floor: float) -> dict[str, Any]:
        power = data.get("power", -50)
        bandwidth = data.get("bandwidth", 0)
        freq = data.get("frequency", 0)
        samples = data.get("samples", [])

        indicators = {"is_jamming_likely": False, "confidence": 0.0, "indicators": []}
        score = 0.0

        if power > -20:
            score += 0.25
            indicators["indicators"].append("Very high signal power")
        if bandwidth > 40:
            score += 0.2
            indicators["indicators"].append("Wide bandwidth signal")
        if samples:
            avg = sum(samples) / len(samples)
            variance = sum((s - avg) ** 2 for s in samples) / len(samples)
            if variance < 4:
                score += 0.2
                indicators["indicators"].append("Constant power level (low variance)")
            if all(s > noise_floor + 30 for s in samples):
                score += 0.15
                indicators["indicators"].append("All samples well above noise floor")
        modulation = data.get("modulation", "").lower()
        if modulation in ("noise", "broadband", "sweep", ""):
            score += 0.2
            indicators["indicators"].append(f"Suspicious modulation type: {modulation or 'none'}")

        indicators["confidence"] = round(min(1.0, score), 2)
        indicators["is_jamming_likely"] = score >= 0.5
        indicators["assessment"] = ("High probability of intentional jamming" if score >= 0.7
                                     else "Moderate jamming indicators present" if score >= 0.5
                                     else "Low jamming probability" if score >= 0.3
                                     else "No significant jamming indicators")
        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(config["signal_data"].strip())
        analysis_type = config.get("analysis_type", "identification")
        noise_floor = config.get("noise_floor", -90.0)

        freq = data.get("frequency", 0)
        modulation = data.get("modulation", "unknown")
        bandwidth = data.get("bandwidth", 0)
        power = data.get("power", -50)
        snr = power - noise_floor

        result: dict[str, Any] = {
            "frequency_mhz": freq,
            "power_dbm": power,
            "snr_db": round(snr, 1),
            "modulation": modulation,
            "bandwidth_mhz": bandwidth,
        }

        if analysis_type in ("identification", "jamming"):
            protocols = self._identify_protocol(freq, modulation, bandwidth)
            result["identified_protocols"] = protocols

        if analysis_type in ("anomaly", "jamming"):
            anomalies = self._detect_anomalies(data, noise_floor)
            result["anomalies"] = anomalies

        if analysis_type == "jamming":
            jamming = self._check_jamming(data, noise_floor)
            result["jamming_indicators"] = jamming

        return result
