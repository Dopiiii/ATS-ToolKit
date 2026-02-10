"""ICS traffic analyzer — detects anomalies in industrial control system network traffic."""

import json
import re
import statistics
from typing import Any

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField


MODBUS_WRITE_FCS = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}
MODBUS_DIAG_FCS = {0x07, 0x08, 0x0B, 0x0C, 0x11, 0x2B}
DNP3_WRITE_FCS = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0D}
DNP3_CONTROL_FCS = {0x03, 0x04, 0x05, 0x06}

KNOWN_FUNCTION_CODES: dict[str, dict[int, str]] = {
    "modbus": {
        1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
        4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
        15: "Write Multiple Coils", 16: "Write Multiple Registers",
        22: "Mask Write Register", 23: "Read/Write Multiple Registers",
        43: "Read Device Identification",
    },
    "dnp3": {
        0: "Confirm", 1: "Read", 2: "Write", 3: "Select",
        4: "Operate", 5: "Direct Operate", 6: "Direct Operate No Ack",
        7: "Immediate Freeze", 13: "Cold Restart", 14: "Warm Restart",
        20: "Enable Unsolicited", 21: "Disable Unsolicited",
    },
}


def _analyze_timing(connections: list[dict], field: str = "timestamp") -> dict[str, Any]:
    """Analyze timing patterns in connections to detect anomalies."""
    timestamps = []
    for c in connections:
        ts = c.get(field)
        if ts is not None:
            try:
                timestamps.append(float(ts))
            except (ValueError, TypeError):
                continue

    if len(timestamps) < 3:
        return {"intervals_analyzed": len(timestamps), "anomalies": []}

    timestamps.sort()
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    mean_interval = statistics.mean(intervals)
    stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    anomalies = []
    for i, interval in enumerate(intervals):
        if stdev_interval > 0 and abs(interval - mean_interval) > 3 * stdev_interval:
            anomalies.append({
                "index": i,
                "interval": round(interval, 4),
                "deviation_sigma": round(abs(interval - mean_interval) / stdev_interval, 2),
                "type": "timing_outlier",
            })

    return {
        "intervals_analyzed": len(intervals),
        "mean_interval": round(mean_interval, 4),
        "stdev_interval": round(stdev_interval, 4),
        "min_interval": round(min(intervals), 4),
        "max_interval": round(max(intervals), 4),
        "anomalies": anomalies,
    }


def _analyze_sources(connections: list[dict]) -> dict[str, Any]:
    """Analyze source IP addresses for new or unusual senders."""
    source_counts: dict[str, int] = {}
    source_first_seen: dict[str, int] = {}

    for idx, conn in enumerate(connections):
        src = conn.get("src_ip", conn.get("source", ""))
        if src:
            source_counts[src] = source_counts.get(src, 0) + 1
            if src not in source_first_seen:
                source_first_seen[src] = idx

    total = len(connections)
    rare_sources = []
    for src, count in source_counts.items():
        ratio = count / total if total else 0
        if ratio < 0.02 and count < 3:
            rare_sources.append({
                "source": src, "count": count, "ratio": round(ratio, 4),
                "first_seen_index": source_first_seen[src], "flag": "rare_source",
            })

    return {"unique_sources": len(source_counts), "total_connections": total, "rare_sources": rare_sources}


class IcsTrafficAnalyzerModule(AtsModule):
    """Analyze ICS network traffic patterns to detect anomalies and suspicious activity."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ics_traffic_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze ICS network traffic for anomalies: unusual function codes, writes, new sources, timing deviations",
            version="1.0.0",
            parameters=[
                Parameter(name="traffic_data", type=ParameterType.STRING,
                          description="JSON array of connection records [{src_ip, dst_ip, function_code, timestamp, ...}]"),
                Parameter(name="protocol", type=ParameterType.CHOICE,
                          description="ICS protocol to analyze",
                          default="modbus", choices=["modbus", "dnp3", "all"]),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Anomaly detection sensitivity",
                          default="medium", choices=["low", "medium", "high"]),
            ],
            outputs=[
                OutputField(name="anomalies", type="list", description="Detected anomalies"),
                OutputField(name="traffic_stats", type="dict", description="Traffic statistics"),
                OutputField(name="risk_indicators", type="list", description="Risk indicators found"),
            ],
            tags=["advanced", "ics", "traffic", "anomaly-detection", "monitoring"],
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("traffic_data", "").strip():
            return False, "Traffic data is required"
        try:
            data = json.loads(config["traffic_data"])
            if not isinstance(data, list):
                return False, "Traffic data must be a JSON array"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        connections = json.loads(config["traffic_data"])
        protocol = config.get("protocol", "modbus")
        sensitivity = config.get("sensitivity", "medium")

        sigma_thresholds = {"low": 4, "medium": 3, "high": 2}
        sigma = sigma_thresholds[sensitivity]

        anomalies: list[dict[str, Any]] = []
        risk_indicators: list[dict[str, Any]] = []

        # Function code analysis
        fc_counts: dict[int, int] = {}
        write_ops = 0
        unknown_fcs: list[dict[str, Any]] = []

        protocols_to_check = ["modbus", "dnp3"] if protocol == "all" else [protocol]

        for idx, conn in enumerate(connections):
            fc_raw = conn.get("function_code")
            if fc_raw is None:
                continue
            try:
                fc = int(fc_raw)
            except (ValueError, TypeError):
                continue
            fc_counts[fc] = fc_counts.get(fc, 0) + 1

            for proto in protocols_to_check:
                known = KNOWN_FUNCTION_CODES.get(proto, {})
                if fc not in known:
                    unknown_fcs.append({"index": idx, "function_code": fc, "protocol": proto})

                write_set = MODBUS_WRITE_FCS if proto == "modbus" else DNP3_WRITE_FCS
                if fc in write_set:
                    write_ops += 1

                diag_set = MODBUS_DIAG_FCS if proto == "modbus" else DNP3_CONTROL_FCS
                if fc in diag_set:
                    anomalies.append({
                        "type": "diagnostic_function_code",
                        "severity": "high",
                        "detail": f"Diagnostic/control function code {fc} at index {idx}",
                        "connection": conn,
                    })

        if unknown_fcs:
            anomalies.append({
                "type": "unknown_function_codes",
                "severity": "medium",
                "count": len(unknown_fcs),
                "items": unknown_fcs[:20],
            })

        if write_ops > len(connections) * 0.5 and len(connections) > 5:
            risk_indicators.append({
                "indicator": "high_write_ratio",
                "severity": "high",
                "detail": f"{write_ops}/{len(connections)} operations are writes ({write_ops/len(connections)*100:.0f}%)",
            })

        # Source analysis
        source_analysis = _analyze_sources(connections)
        for rare in source_analysis["rare_sources"]:
            anomalies.append({
                "type": "rare_source_ip",
                "severity": "medium",
                "detail": f"Rare source {rare['source']} seen only {rare['count']} times",
                "source": rare,
            })

        # Timing analysis
        timing_analysis = _analyze_timing(connections)
        for ta in timing_analysis.get("anomalies", []):
            if ta["deviation_sigma"] >= sigma:
                anomalies.append({
                    "type": "timing_anomaly",
                    "severity": "medium",
                    "detail": f"Timing outlier at index {ta['index']}: {ta['deviation_sigma']}σ deviation",
                    "timing": ta,
                })

        traffic_stats = {
            "total_connections": len(connections),
            "unique_function_codes": len(fc_counts),
            "function_code_distribution": fc_counts,
            "write_operations": write_ops,
            "source_analysis": source_analysis,
            "timing_analysis": timing_analysis,
        }

        return {
            "anomalies": anomalies,
            "traffic_stats": traffic_stats,
            "risk_indicators": risk_indicators,
            "protocol_analyzed": protocol,
            "sensitivity": sensitivity,
            "total_anomalies": len(anomalies),
        }
