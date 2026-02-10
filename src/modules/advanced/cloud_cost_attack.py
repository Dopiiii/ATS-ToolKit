"""Cloud cost attack and crypto-mining indicator detector.

Analyzes compute usage patterns to detect crypto-mining, resource abuse,
cost spikes, unusual instance types, and unknown region activity.
"""

import asyncio
import re
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

CRYPTO_INSTANCE_TYPES = {
    "p3.16xlarge", "p3.8xlarge", "p3.2xlarge", "p2.16xlarge", "p2.8xlarge",
    "g4dn.xlarge", "g4dn.12xlarge", "g5.48xlarge", "g5.12xlarge",
    "Standard_NC6", "Standard_NC24", "Standard_NV12", "Standard_ND40rs_v2",
    "n1-standard-8-nvidia-tesla-v100", "a2-highgpu-8g",
}

MINING_POOL_INDICATORS = [
    "pool.minergate.com", "xmrpool.eu", "nanopool.org", "f2pool.com",
    "ethermine.org", "nicehash.com", "slushpool.com", "mining.bitcoin.cz",
    "stratum+tcp://", "stratum2+tcp://", "xmrig", "cpuminer", "cgminer",
]

UNUSUAL_REGIONS = {
    "aws": ["ap-east-1", "me-south-1", "af-south-1", "ap-southeast-3"],
    "azure": ["southafricanorth", "uaecentral", "brazilsoutheast"],
    "gcp": ["asia-south2", "australia-southeast2", "southamerica-west1"],
}

THRESHOLD_MULTIPLIERS = {"low": 1.5, "medium": 2.0, "high": 3.0}


class CloudCostAttackModule(AtsModule):
    """Detect crypto-mining and cost-attack indicators in cloud usage."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_cost_attack",
            category=ModuleCategory.ADVANCED,
            description="Detect crypto-mining and cost-attack indicators in cloud usage data",
            version="1.0.0",
            parameters=[
                Parameter(name="usage_data", type=ParameterType.STRING,
                          description="Cloud usage/billing data JSON", required=True),
                Parameter(name="threshold", type=ParameterType.CHOICE,
                          description="Detection sensitivity threshold",
                          choices=["low", "medium", "high"], default="medium"),
                Parameter(name="provider", type=ParameterType.CHOICE,
                          description="Cloud provider context",
                          choices=["aws", "azure", "gcp", "auto"], default="auto"),
            ],
            outputs=[
                OutputField(name="indicators", type="list", description="Detected attack indicators"),
                OutputField(name="risk_score", type="float", description="Overall risk score 0-100"),
                OutputField(name="anomalies", type="list", description="Usage anomalies detected"),
            ],
            tags=["advanced", "cloud", "cost", "cryptomining", "abuse"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("usage_data", "").strip()
        if not data:
            return False, "Usage data JSON is required"
        try:
            json.loads(data)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _detect_mining_instances(self, instances: list[dict]) -> list[dict]:
        """Detect instances commonly used for crypto mining."""
        findings = []
        for inst in instances:
            inst_type = inst.get("instanceType", inst.get("instance_type",
                         inst.get("vmSize", inst.get("machineType", ""))))
            state = inst.get("state", inst.get("status", "running")).lower()

            if inst_type in CRYPTO_INSTANCE_TYPES and state in ("running", "active"):
                findings.append({
                    "severity": "high",
                    "type": "crypto_instance",
                    "issue": f"GPU/compute-optimized instance running: {inst_type}",
                    "instance_id": inst.get("instanceId", inst.get("id", "unknown")),
                    "region": inst.get("region", inst.get("location", "unknown")),
                })

            cpu_util = inst.get("cpuUtilization", inst.get("cpu_percent"))
            if cpu_util is not None and isinstance(cpu_util, (int, float)):
                if cpu_util > 95:
                    findings.append({
                        "severity": "medium",
                        "type": "high_cpu",
                        "issue": f"Sustained high CPU ({cpu_util}%) on {inst.get('instanceId', 'unknown')}",
                        "instance_id": inst.get("instanceId", inst.get("id", "unknown")),
                    })

        return findings

    def _detect_cost_spikes(self, billing: dict, multiplier: float) -> list[dict]:
        """Detect unusual cost spikes in billing data."""
        findings = []
        costs = billing.get("costs", billing.get("line_items", []))

        if isinstance(costs, list):
            service_costs = {}
            for item in costs:
                service = item.get("service", item.get("product", "unknown"))
                cost = item.get("cost", item.get("amount", 0))
                if isinstance(cost, (int, float)):
                    if service not in service_costs:
                        service_costs[service] = []
                    service_costs[service].append(cost)

            for service, cost_list in service_costs.items():
                if len(cost_list) >= 2:
                    avg = sum(cost_list[:-1]) / len(cost_list[:-1])
                    latest = cost_list[-1]
                    if avg > 0 and latest > avg * multiplier:
                        findings.append({
                            "severity": "high",
                            "type": "cost_spike",
                            "issue": f"Cost spike on {service}: ${latest:.2f} vs avg ${avg:.2f} ({latest/avg:.1f}x)",
                            "service": service,
                            "current_cost": latest,
                            "average_cost": round(avg, 2),
                        })

        total_current = billing.get("totalCost", billing.get("total"))
        total_previous = billing.get("previousTotalCost", billing.get("previous_total"))
        if total_current and total_previous and isinstance(total_current, (int, float)):
            if isinstance(total_previous, (int, float)) and total_previous > 0:
                ratio = total_current / total_previous
                if ratio > multiplier:
                    findings.append({
                        "severity": "critical",
                        "type": "total_cost_spike",
                        "issue": f"Total cost spike: ${total_current:.2f} vs ${total_previous:.2f} ({ratio:.1f}x)",
                    })

        return findings

    def _detect_unusual_regions(self, resources: list[dict], provider: str) -> list[dict]:
        """Detect resources in unusual or unexpected regions."""
        findings = []
        unusual = UNUSUAL_REGIONS.get(provider, [])
        known_regions = set()

        for res in resources:
            region = res.get("region", res.get("location", ""))
            if region:
                known_regions.add(region)
                if region in unusual:
                    findings.append({
                        "severity": "medium",
                        "type": "unusual_region",
                        "issue": f"Resource in unusual region: {region}",
                        "resource": res.get("id", res.get("instanceId", "unknown")),
                        "region": region,
                    })

        if len(known_regions) > 5:
            findings.append({
                "severity": "low",
                "type": "region_spread",
                "issue": f"Resources spread across {len(known_regions)} regions - verify all are intended",
            })

        return findings

    def _check_network_indicators(self, network_data: list[dict]) -> list[dict]:
        """Check for mining pool connections in network data."""
        findings = []
        for conn in network_data:
            dest = str(conn.get("destination", conn.get("remote_addr", "")))
            for indicator in MINING_POOL_INDICATORS:
                if indicator.lower() in dest.lower():
                    findings.append({
                        "severity": "critical",
                        "type": "mining_pool_connection",
                        "issue": f"Connection to mining pool: {dest}",
                        "source": conn.get("source", conn.get("instance_id", "unknown")),
                    })
                    break
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(config["usage_data"])
        threshold = config.get("threshold", "medium")
        provider = config.get("provider", "auto")
        multiplier = THRESHOLD_MULTIPLIERS.get(threshold, 2.0)

        if provider == "auto":
            data_str = json.dumps(data).lower()
            if "arn:aws" in data_str or "ec2" in data_str:
                provider = "aws"
            elif "microsoft" in data_str or "azure" in data_str:
                provider = "azure"
            elif "gcp" in data_str or "gcloud" in data_str:
                provider = "gcp"
            else:
                provider = "aws"

        indicators = []
        anomalies = []

        instances = data.get("instances", data.get("vms", data.get("resources", [])))
        if instances:
            indicators.extend(self._detect_mining_instances(instances))
            anomalies.extend(self._detect_unusual_regions(instances, provider))

        billing = data.get("billing", data.get("costs", {}))
        if isinstance(billing, dict):
            indicators.extend(self._detect_cost_spikes(billing, multiplier))

        network = data.get("network_connections", data.get("flows", []))
        if network:
            indicators.extend(self._check_network_indicators(network))

        severity_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3}
        risk_score = min(sum(severity_weights.get(i["severity"], 0) for i in indicators + anomalies), 100.0)

        return {
            "provider": provider,
            "threshold": threshold,
            "indicators": indicators,
            "indicator_count": len(indicators),
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "risk_score": round(risk_score, 1),
            "risk_level": "critical" if risk_score >= 60 else "high" if risk_score >= 30 else "medium" if risk_score >= 10 else "low",
            "mining_detected": any(i["type"] in ("crypto_instance", "mining_pool_connection") for i in indicators),
        }
