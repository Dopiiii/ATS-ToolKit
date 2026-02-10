"""DNS tunneling detection module for analyzing DNS query logs.

Detects DNS tunneling by analyzing query length distribution, subdomain entropy,
query frequency, TXT record ratios, and unusual record types.
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

NORMAL_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "PTR"}
TUNNEL_RECORD_TYPES = {"TXT", "NULL", "PRIVATE", "CNAME", "MX"}
MAX_NORMAL_SUBDOMAIN_LENGTH = 30
MAX_NORMAL_QUERY_LENGTH = 80
ENTROPY_THRESHOLD_LOW = 3.0
ENTROPY_THRESHOLD_MED = 3.5
ENTROPY_THRESHOLD_HIGH = 4.0


class NetDnsTunnelDetectorModule(AtsModule):
    """Detect DNS tunneling in DNS query log data."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_dns_tunnel_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect DNS tunneling patterns in DNS query logs",
            version="1.0.0",
            parameters=[
                Parameter(name="dns_logs", type=ParameterType.STRING,
                          description="JSON array of DNS queries with fields: query, type, timestamp, client"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity level",
                          choices=["low", "medium", "high"], default="medium"),
                Parameter(name="max_queries", type=ParameterType.INTEGER,
                          description="Maximum queries to analyze", default=10000),
            ],
            outputs=[
                OutputField(name="tunnel_detected", type="boolean", description="Whether tunneling was detected"),
                OutputField(name="risk_score", type="float", description="Risk score 0-100"),
                OutputField(name="suspicious_domains", type="list", description="Domains flagged as suspicious"),
                OutputField(name="statistics", type="dict", description="Query analysis statistics"),
            ],
            tags=["advanced", "network", "dns", "tunnel", "exfiltration"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("dns_logs", "").strip()
        if not raw:
            return False, "DNS logs data is required"
        try:
            logs = json.loads(raw)
            if not isinstance(logs, list):
                return False, "DNS logs must be a JSON array"
            if len(logs) == 0:
                return False, "DNS logs array is empty"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in dns_logs: {e}"
        return True, ""

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _extract_subdomain(self, query: str) -> str:
        """Extract the subdomain portion from a DNS query."""
        parts = query.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return parts[0] if parts else ""

    def _extract_base_domain(self, query: str) -> str:
        """Extract the base domain from a DNS query."""
        parts = query.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return query

    def _analyze_query_lengths(self, queries: list[dict]) -> dict[str, Any]:
        """Analyze the distribution of query name lengths."""
        lengths = [len(q.get("query", "")) for q in queries]
        if not lengths:
            return {"mean": 0, "max": 0, "long_query_ratio": 0}
        avg_len = sum(lengths) / len(lengths)
        long_queries = sum(1 for l in lengths if l > MAX_NORMAL_QUERY_LENGTH)
        return {
            "mean_length": round(avg_len, 2),
            "max_length": max(lengths),
            "min_length": min(lengths),
            "long_query_count": long_queries,
            "long_query_ratio": round(long_queries / len(lengths) * 100, 2),
        }

    def _analyze_record_types(self, queries: list[dict]) -> dict[str, Any]:
        """Analyze distribution of DNS record types."""
        type_counts = Counter(q.get("type", "A").upper() for q in queries)
        total = len(queries) or 1
        txt_count = type_counts.get("TXT", 0)
        null_count = type_counts.get("NULL", 0)
        tunnel_type_count = sum(type_counts.get(t, 0) for t in TUNNEL_RECORD_TYPES)
        return {
            "type_distribution": dict(type_counts.most_common()),
            "txt_ratio_pct": round(txt_count / total * 100, 2),
            "null_record_count": null_count,
            "tunnel_type_ratio_pct": round(tunnel_type_count / total * 100, 2),
        }

    def _analyze_per_domain(self, queries: list[dict], sensitivity: str) -> list[dict]:
        """Group queries by base domain and analyze each for tunneling indicators."""
        domain_queries: dict[str, list] = defaultdict(list)
        for q in queries:
            base = self._extract_base_domain(q.get("query", ""))
            domain_queries[base].append(q)

        entropy_thresh = {
            "low": ENTROPY_THRESHOLD_HIGH,
            "medium": ENTROPY_THRESHOLD_MED,
            "high": ENTROPY_THRESHOLD_LOW,
        }.get(sensitivity, ENTROPY_THRESHOLD_MED)

        suspicious = []
        for domain, dqueries in domain_queries.items():
            subdomains = [self._extract_subdomain(q.get("query", "")) for q in dqueries]
            subdomains = [s for s in subdomains if s]
            if not subdomains:
                continue

            avg_entropy = sum(self._calculate_entropy(s) for s in subdomains) / len(subdomains)
            avg_length = sum(len(s) for s in subdomains) / len(subdomains)
            max_length = max(len(s) for s in subdomains)
            unique_ratio = len(set(subdomains)) / len(subdomains) if subdomains else 0
            type_counts = Counter(q.get("type", "A").upper() for q in dqueries)
            txt_ratio = type_counts.get("TXT", 0) / len(dqueries)

            score = 0
            reasons = []
            if avg_entropy >= entropy_thresh:
                score += 30
                reasons.append(f"High subdomain entropy: {round(avg_entropy, 2)}")
            if avg_length > MAX_NORMAL_SUBDOMAIN_LENGTH:
                score += 25
                reasons.append(f"Long avg subdomain length: {round(avg_length, 1)}")
            if unique_ratio > 0.9 and len(subdomains) > 10:
                score += 20
                reasons.append(f"High unique subdomain ratio: {round(unique_ratio, 2)}")
            if txt_ratio > 0.5:
                score += 15
                reasons.append(f"High TXT record ratio: {round(txt_ratio * 100, 1)}%")
            if len(dqueries) > 100 and unique_ratio > 0.8:
                score += 10
                reasons.append(f"High query volume with unique subdomains: {len(dqueries)}")

            if score >= 20:
                suspicious.append({
                    "domain": domain,
                    "query_count": len(dqueries),
                    "avg_subdomain_entropy": round(avg_entropy, 4),
                    "avg_subdomain_length": round(avg_length, 2),
                    "max_subdomain_length": max_length,
                    "unique_subdomain_ratio": round(unique_ratio, 4),
                    "txt_ratio_pct": round(txt_ratio * 100, 2),
                    "tunnel_score": min(score, 100),
                    "reasons": reasons,
                })

        suspicious.sort(key=lambda x: x["tunnel_score"], reverse=True)
        return suspicious

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        queries = json.loads(config["dns_logs"])
        sensitivity = config.get("sensitivity", "medium")
        max_queries = config.get("max_queries", 10000)

        # Limit query count
        queries = queries[:max_queries]

        # Length analysis
        length_stats = self._analyze_query_lengths(queries)

        # Record type analysis
        type_stats = self._analyze_record_types(queries)

        # Per-domain tunneling analysis
        suspicious_domains = self._analyze_per_domain(queries, sensitivity)

        # Client frequency analysis
        client_counts = Counter(q.get("client", "unknown") for q in queries)
        top_clients = [
            {"client": c, "query_count": cnt}
            for c, cnt in client_counts.most_common(10)
        ]

        # Overall risk score
        risk_score = 0.0
        if suspicious_domains:
            max_domain_score = max(d["tunnel_score"] for d in suspicious_domains)
            risk_score += max_domain_score * 0.5
        if type_stats["txt_ratio_pct"] > 30:
            risk_score += 15
        if length_stats["long_query_ratio"] > 20:
            risk_score += 15
        risk_score = min(round(risk_score, 1), 100.0)

        tunnel_detected = risk_score >= 40.0
        statistics = {
            "total_queries_analyzed": len(queries),
            "unique_domains": len(set(self._extract_base_domain(q.get("query", "")) for q in queries)),
            "query_length_stats": length_stats,
            "record_type_stats": type_stats,
            "top_clients": top_clients,
        }

        return {
            "tunnel_detected": tunnel_detected,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low",
            "suspicious_domains": suspicious_domains,
            "suspicious_domain_count": len(suspicious_domains),
            "statistics": statistics,
        }
