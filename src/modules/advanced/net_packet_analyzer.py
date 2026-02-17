"""Deep packet analysis module for protocol distribution and anomaly detection.

Analyzes packet data for protocol distribution, header anomalies,
payload inspection, and suspicious traffic patterns.
"""

import asyncio
import json
import math
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
    4444: "Metasploit default",
    5555: "Common backdoor",
    6666: "IRC backdoor",
    6667: "IRC",
    31337: "Back Orifice",
    12345: "NetBus",
    27374: "SubSeven",
    1337: "Leet port",
    8080: "HTTP proxy",
    3128: "Squid proxy",
    9050: "Tor SOCKS",
    9001: "Tor relay",
}
PROTOCOL_NUMBERS = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}
PAYLOAD_SIGNATURES = [
    (r"\\x4d\\x5a", "PE executable header (MZ)"),
    (r"\\x7f\\x45\\x4c\\x46", "ELF binary header"),
    (r"PK\\x03\\x04", "ZIP archive"),
    (r"\\x89PNG", "PNG image"),
    (r"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/", "HTTP request"),
    (r"HTTP/\d\.\d\s+\d{3}", "HTTP response"),
    (r"SSH-\d\.\d", "SSH protocol"),
    (r"220[\s-].*(?:SMTP|smtp|mail)", "SMTP banner"),
    (r"USER\s+\S+\r?\nPASS\s+", "Cleartext credentials (FTP/POP3)"),
    (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+", "SQL statement"),
    (r"\\x00\\x00\\x00.*\\x00\\x00\\x00", "Potential C2 beacon pattern"),
]


class NetPacketAnalyzerModule(AtsModule):
    """Deep packet analysis for protocol distribution and anomaly detection."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_packet_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Deep packet analysis for protocol distribution, anomaly detection, and payload inspection",
            version="1.0.0",
            parameters=[
                Parameter(name="packet_data", type=ParameterType.STRING,
                          description="JSON array of packets with fields: src_ip, dst_ip, src_port, dst_port, protocol, size, flags, payload (optional), timestamp"),
                Parameter(name="analysis_type", type=ParameterType.CHOICE,
                          description="Type of analysis to perform",
                          choices=["protocol", "anomaly", "payload"], default="protocol"),
                Parameter(name="depth", type=ParameterType.CHOICE,
                          description="Analysis depth level",
                          choices=["headers", "full"], default="headers"),
            ],
            outputs=[
                OutputField(name="analysis_results", type="dict", description="Analysis results based on type"),
                OutputField(name="alerts", type="list", description="Security alerts from analysis"),
                OutputField(name="statistics", type="dict", description="Packet capture statistics"),
            ],
            tags=["advanced", "network", "packet", "protocol", "analysis"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("packet_data", "").strip()
        if not raw:
            return False, "Packet data is required"
        try:
            packets = json.loads(raw)
            if not isinstance(packets, list):
                return False, "Packet data must be a JSON array"
            if len(packets) == 0:
                return False, "Packet data array is empty"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in packet_data: {exc}"
        return True, ""

    def _analyze_protocol_distribution(self, packets: list[dict]) -> dict[str, Any]:
        """Analyze protocol distribution across packets."""
        proto_counts = Counter()
        port_counts = Counter()
        src_ip_counts = Counter()
        dst_ip_counts = Counter()
        total_bytes = 0
        conversation_map: dict[str, int] = defaultdict(int)

        for pkt in packets:
            proto = pkt.get("protocol", "unknown")
            if isinstance(proto, int):
                proto = PROTOCOL_NUMBERS.get(proto, f"proto_{proto}")
            proto_counts[str(proto).upper()] += 1

            src_port = pkt.get("src_port", 0)
            dst_port = pkt.get("dst_port", 0)
            if dst_port:
                port_counts[int(dst_port)] += 1
            if src_port:
                port_counts[int(src_port)] += 1

            src_ip = pkt.get("src_ip", "unknown")
            dst_ip = pkt.get("dst_ip", "unknown")
            src_ip_counts[src_ip] += 1
            dst_ip_counts[dst_ip] += 1

            size = pkt.get("size", 0)
            total_bytes += int(size)

            conv_key = f"{min(src_ip, dst_ip)}<->{max(src_ip, dst_ip)}"
            conversation_map[conv_key] += 1

        top_conversations = sorted(conversation_map.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "protocol_distribution": dict(proto_counts.most_common()),
            "top_destination_ports": [
                {"port": p, "count": c, "service": SUSPICIOUS_PORTS.get(p, "")}
                for p, c in port_counts.most_common(15)
            ],
            "top_source_ips": dict(src_ip_counts.most_common(10)),
            "top_destination_ips": dict(dst_ip_counts.most_common(10)),
            "top_conversations": [{"pair": k, "packet_count": v} for k, v in top_conversations],
            "total_bytes": total_bytes,
            "avg_packet_size": round(total_bytes / len(packets), 2) if packets else 0,
        }

    def _detect_anomalies(self, packets: list[dict]) -> tuple[dict, list[dict]]:
        """Detect packet-level anomalies."""
        alerts = []
        anomaly_stats = {
            "suspicious_port_connections": 0,
            "port_scan_indicators": 0,
            "large_packet_anomalies": 0,
            "flag_anomalies": 0,
            "fragmentation_anomalies": 0,
        }

        # Suspicious port detection
        for pkt in packets:
            dst_port = int(pkt.get("dst_port", 0))
            src_port = int(pkt.get("src_port", 0))
            for port in (dst_port, src_port):
                if port in SUSPICIOUS_PORTS:
                    anomaly_stats["suspicious_port_connections"] += 1
                    alerts.append({
                        "type": "suspicious_port",
                        "severity": "high",
                        "src_ip": pkt.get("src_ip", ""),
                        "dst_ip": pkt.get("dst_ip", ""),
                        "port": port,
                        "known_as": SUSPICIOUS_PORTS[port],
                        "detail": f"Traffic on suspicious port {port} ({SUSPICIOUS_PORTS[port]})",
                    })

        # Port scan detection: single source hitting many ports on same destination
        src_dst_ports: dict[str, set] = defaultdict(set)
        for pkt in packets:
            key = f"{pkt.get('src_ip', '')}>{pkt.get('dst_ip', '')}"
            dst_port = pkt.get("dst_port", 0)
            if dst_port:
                src_dst_ports[key].add(int(dst_port))

        for key, ports in src_dst_ports.items():
            if len(ports) > 20:
                src, dst = key.split(">", 1)
                anomaly_stats["port_scan_indicators"] += 1
                alerts.append({
                    "type": "port_scan",
                    "severity": "high",
                    "src_ip": src,
                    "dst_ip": dst,
                    "unique_ports": len(ports),
                    "sample_ports": sorted(list(ports))[:20],
                    "detail": f"Potential port scan: {src} probed {len(ports)} ports on {dst}",
                })

        # TCP flag anomalies
        for pkt in packets:
            flags = str(pkt.get("flags", "")).upper()
            if not flags:
                continue
            # Xmas tree scan: FIN+PSH+URG
            if all(f in flags for f in ["FIN", "PSH", "URG"]):
                anomaly_stats["flag_anomalies"] += 1
                alerts.append({
                    "type": "xmas_scan",
                    "severity": "high",
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "flags": flags,
                    "detail": "Xmas tree scan detected (FIN+PSH+URG flags)",
                })
            # Null scan: no flags
            elif flags in ("NONE", "NULL", "0", ""):
                anomaly_stats["flag_anomalies"] += 1
                alerts.append({
                    "type": "null_scan",
                    "severity": "medium",
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "detail": "Null scan detected (no TCP flags set)",
                })
            # SYN+FIN (invalid combination)
            if "SYN" in flags and "FIN" in flags:
                anomaly_stats["flag_anomalies"] += 1
                alerts.append({
                    "type": "invalid_flags",
                    "severity": "high",
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "flags": flags,
                    "detail": "Invalid TCP flag combination: SYN+FIN",
                })

        # Large/unusual packet sizes
        for pkt in packets:
            size = int(pkt.get("size", 0))
            if size > 65535:
                anomaly_stats["large_packet_anomalies"] += 1
                alerts.append({
                    "type": "oversized_packet",
                    "severity": "medium",
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "size": size,
                    "detail": f"Oversized packet detected: {size} bytes",
                })

        return anomaly_stats, alerts

    def _inspect_payloads(self, packets: list[dict]) -> tuple[dict, list[dict]]:
        """Inspect packet payloads for signatures and patterns."""
        alerts = []
        payload_stats = {
            "packets_with_payload": 0,
            "signatures_matched": 0,
            "cleartext_credentials": 0,
            "binary_content": 0,
        }

        for pkt in packets:
            payload = pkt.get("payload", "")
            if not payload:
                continue
            payload_stats["packets_with_payload"] += 1

            for pattern, description in PAYLOAD_SIGNATURES:
                if re.search(pattern, payload, re.IGNORECASE):
                    payload_stats["signatures_matched"] += 1
                    severity = "critical" if "credential" in description.lower() or "C2" in description else "medium"
                    alerts.append({
                        "type": "payload_signature",
                        "severity": severity,
                        "src_ip": pkt.get("src_ip", ""),
                        "dst_ip": pkt.get("dst_ip", ""),
                        "signature": description,
                        "pattern": pattern,
                        "detail": f"Payload signature matched: {description}",
                    })

            # Entropy analysis for potential encrypted/compressed data
            if len(payload) > 50:
                entropy = self._calculate_entropy(payload)
                if entropy > 4.5:
                    payload_stats["binary_content"] += 1
                    if entropy > 5.5:
                        alerts.append({
                            "type": "high_entropy_payload",
                            "severity": "low",
                            "src_ip": pkt.get("src_ip", ""),
                            "dst_ip": pkt.get("dst_ip", ""),
                            "entropy": round(entropy, 4),
                            "detail": f"High entropy payload ({round(entropy, 2)}) - possible encrypted/compressed data",
                        })

        return payload_stats, alerts

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        packets = json.loads(config["packet_data"])
        analysis_type = config.get("analysis_type", "protocol")
        depth = config.get("depth", "headers")

        analysis_results: dict[str, Any] = {}
        all_alerts: list[dict] = []

        # Protocol distribution (always computed for statistics)
        proto_results = self._analyze_protocol_distribution(packets)

        if analysis_type == "protocol":
            analysis_results = proto_results

        elif analysis_type == "anomaly":
            anomaly_stats, anomaly_alerts = self._detect_anomalies(packets)
            analysis_results = {
                "anomaly_statistics": anomaly_stats,
                "protocol_overview": proto_results["protocol_distribution"],
            }
            all_alerts.extend(anomaly_alerts)

        elif analysis_type == "payload":
            if depth == "full":
                payload_stats, payload_alerts = self._inspect_payloads(packets)
                analysis_results = {
                    "payload_statistics": payload_stats,
                    "protocol_overview": proto_results["protocol_distribution"],
                }
                all_alerts.extend(payload_alerts)
            else:
                analysis_results = {
                    "note": "Payload inspection requires depth=full",
                    "protocol_overview": proto_results["protocol_distribution"],
                }

        # Always check for anomalies if depth is full
        if depth == "full" and analysis_type != "anomaly":
            _, extra_alerts = self._detect_anomalies(packets)
            all_alerts.extend(extra_alerts)

        # Deduplicate alerts by creating a signature
        seen = set()
        unique_alerts = []
        for alert in all_alerts:
            sig = f"{alert['type']}:{alert.get('src_ip', '')}:{alert.get('dst_ip', '')}:{alert.get('port', '')}:{alert.get('signature', '')}"
            if sig not in seen:
                seen.add(sig)
                unique_alerts.append(alert)

        severity_counts = Counter(a["severity"] for a in unique_alerts)

        statistics = {
            "total_packets": len(packets),
            "analysis_type": analysis_type,
            "depth": depth,
            "alert_count": len(unique_alerts),
            "alert_severity_distribution": dict(severity_counts),
        }

        return {
            "analysis_results": analysis_results,
            "alerts": unique_alerts,
            "statistics": statistics,
        }
