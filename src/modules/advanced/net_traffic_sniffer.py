"""Network traffic analyzer for threat detection in captured packet data.

Performs statistical analysis on packet captures to identify top talkers,
protocol distribution, unusual port usage, large transfers, and encrypted ratios.
"""

import asyncio
import json
import re
from typing import Any
from collections import Counter, defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 1337, 31337, 8888, 9999, 12345, 54321,
    3127, 3128, 27374, 20034, 1524, 2745, 3410, 4899, 5800, 5900,
}
ENCRYPTED_PORTS = {443, 993, 995, 465, 8443, 990, 989, 636, 563, 853}
WELL_KNOWN_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}
LARGE_TRANSFER_THRESHOLD = 1_000_000  # 1 MB


class NetTrafficSnifferModule(AtsModule):
    """Analyze network traffic data for threats and anomalies."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_traffic_sniffer",
            category=ModuleCategory.ADVANCED,
            description="Analyze network traffic data for threat indicators and anomalies",
            version="1.0.0",
            parameters=[
                Parameter(name="traffic_data", type=ParameterType.STRING,
                          description="JSON array of packets with src, dst, port, proto, size, timestamp"),
                Parameter(name="filter_type", type=ParameterType.CHOICE,
                          description="Filter type for analysis",
                          choices=["all", "suspicious", "encrypted"], default="all"),
                Parameter(name="duration", type=ParameterType.INTEGER,
                          description="Analysis duration window in seconds", default=60),
            ],
            outputs=[
                OutputField(name="top_talkers", type="list", description="Top communicating hosts"),
                OutputField(name="protocol_distribution", type="dict", description="Protocol breakdown"),
                OutputField(name="suspicious_activity", type="list", description="Flagged suspicious items"),
                OutputField(name="statistics", type="dict", description="Traffic statistics summary"),
            ],
            tags=["advanced", "network", "traffic", "sniffer", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("traffic_data", "").strip()
        if not raw:
            return False, "Traffic data is required"
        try:
            packets = json.loads(raw)
            if not isinstance(packets, list):
                return False, "Traffic data must be a JSON array"
            if len(packets) == 0:
                return False, "Traffic data array is empty"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in traffic_data: {e}"
        return True, ""

    def _calculate_entropy(self, data: list[str]) -> float:
        """Calculate Shannon entropy of a list of strings."""
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counter.values():
            probability = count / total
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    def _detect_port_scan(self, packets: list[dict]) -> list[dict]:
        """Detect potential port scanning behavior."""
        src_to_ports: dict[str, set] = defaultdict(set)
        for pkt in packets:
            src = pkt.get("src", "")
            port = pkt.get("port", 0)
            if src and port:
                src_to_ports[src].add(port)
        scanners = []
        for src, ports in src_to_ports.items():
            if len(ports) > 15:
                scanners.append({
                    "source": src,
                    "unique_ports": len(ports),
                    "alert": "Possible port scan detected",
                    "severity": "high" if len(ports) > 50 else "medium",
                })
        return scanners

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        packets = json.loads(config["traffic_data"])
        filter_type = config.get("filter_type", "all")
        duration = config.get("duration", 60)

        # Apply filtering
        filtered = []
        for pkt in packets:
            port = int(pkt.get("port", 0))
            if filter_type == "suspicious" and port not in SUSPICIOUS_PORTS:
                continue
            if filter_type == "encrypted" and port not in ENCRYPTED_PORTS:
                continue
            filtered.append(pkt)

        # Top talkers analysis (by source IP)
        src_counts = Counter(pkt.get("src", "unknown") for pkt in filtered)
        dst_counts = Counter(pkt.get("dst", "unknown") for pkt in filtered)
        src_bytes: dict[str, int] = defaultdict(int)
        for pkt in filtered:
            src_bytes[pkt.get("src", "unknown")] += int(pkt.get("size", 0))
        top_talkers = [
            {"ip": ip, "packet_count": count, "bytes_sent": src_bytes.get(ip, 0)}
            for ip, count in src_counts.most_common(10)
        ]

        # Protocol distribution
        proto_counts = Counter(pkt.get("proto", "unknown").upper() for pkt in filtered)
        total_packets = len(filtered) or 1
        protocol_distribution = {
            proto: {"count": count, "percentage": round(count / total_packets * 100, 2)}
            for proto, count in proto_counts.most_common()
        }

        # Unusual port usage
        port_counts = Counter(int(pkt.get("port", 0)) for pkt in filtered)
        unusual_ports = []
        for port, count in port_counts.items():
            if port in SUSPICIOUS_PORTS:
                unusual_ports.append({
                    "port": port, "count": count, "risk": "suspicious",
                    "label": WELL_KNOWN_PORTS.get(port, "Unknown"),
                })
            elif port > 49151:
                unusual_ports.append({
                    "port": port, "count": count, "risk": "ephemeral_high_traffic",
                    "label": "Dynamic/Private",
                })

        # Large transfers
        large_transfers = []
        for pkt in filtered:
            size = int(pkt.get("size", 0))
            if size >= LARGE_TRANSFER_THRESHOLD:
                large_transfers.append({
                    "src": pkt.get("src", ""), "dst": pkt.get("dst", ""),
                    "port": pkt.get("port", 0), "size_bytes": size,
                    "size_mb": round(size / 1_000_000, 2),
                })

        # Encrypted traffic ratio
        encrypted_count = sum(
            1 for pkt in filtered if int(pkt.get("port", 0)) in ENCRYPTED_PORTS
        )
        encrypted_ratio = round(encrypted_count / total_packets * 100, 2)

        # Port scan detection
        scan_alerts = self._detect_port_scan(filtered)

        # Suspicious activity compilation
        suspicious_activity = []
        suspicious_activity.extend(scan_alerts)
        for item in unusual_ports:
            if item["risk"] == "suspicious":
                suspicious_activity.append({
                    "type": "suspicious_port", "port": item["port"],
                    "count": item["count"], "severity": "medium",
                })
        for xfer in large_transfers:
            suspicious_activity.append({
                "type": "large_transfer", "src": xfer["src"],
                "dst": xfer["dst"], "size_mb": xfer["size_mb"], "severity": "low",
            })

        # Compute destination entropy
        dst_entropy = self._calculate_entropy([pkt.get("dst", "") for pkt in filtered])

        total_bytes = sum(int(pkt.get("size", 0)) for pkt in filtered)
        statistics = {
            "total_packets": len(filtered),
            "total_bytes": total_bytes,
            "unique_sources": len(src_counts),
            "unique_destinations": len(dst_counts),
            "unique_ports": len(port_counts),
            "encrypted_ratio_pct": encrypted_ratio,
            "destination_entropy": dst_entropy,
            "analysis_duration_sec": duration,
            "avg_packet_size": round(total_bytes / total_packets, 2) if total_packets else 0,
        }

        risk_level = "low"
        if len(suspicious_activity) > 5:
            risk_level = "high"
        elif len(suspicious_activity) > 0:
            risk_level = "medium"

        return {
            "filter_applied": filter_type,
            "top_talkers": top_talkers,
            "protocol_distribution": protocol_distribution,
            "unusual_ports": unusual_ports,
            "large_transfers": large_transfers,
            "suspicious_activity": suspicious_activity,
            "statistics": statistics,
            "risk_level": risk_level,
        }
