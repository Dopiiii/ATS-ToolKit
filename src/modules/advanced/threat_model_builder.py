"""STRIDE/DREAD/PASTA threat model builder module.

Builds structured threat models from system descriptions, analyzing
components and data flows for threats with mitigations and priorities.
"""

import asyncio
import json
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

STRIDE_CATEGORIES = {
    "S": {"name": "Spoofing", "description": "Impersonating something or someone else",
          "question": "Can an attacker pretend to be this component or user?"},
    "T": {"name": "Tampering", "description": "Modifying data or code without authorization",
          "question": "Can data in transit or at rest be modified?"},
    "R": {"name": "Repudiation", "description": "Claiming to have not performed an action",
          "question": "Can actions be performed without proper audit trails?"},
    "I": {"name": "Information Disclosure", "description": "Exposing information to unauthorized parties",
          "question": "Can sensitive data be read by unauthorized actors?"},
    "D": {"name": "Denial of Service", "description": "Denying or degrading service to users",
          "question": "Can this component be overwhelmed or made unavailable?"},
    "E": {"name": "Elevation of Privilege", "description": "Gaining capabilities without proper authorization",
          "question": "Can an attacker gain higher privileges than intended?"},
}
COMPONENT_THREAT_PROFILES = {
    "web_server": {"S": 8, "T": 6, "R": 5, "I": 7, "D": 8, "E": 7},
    "database": {"S": 6, "T": 9, "R": 4, "I": 9, "D": 6, "E": 8},
    "api": {"S": 8, "T": 7, "R": 5, "I": 8, "D": 7, "E": 7},
    "auth_service": {"S": 10, "T": 6, "R": 7, "I": 7, "D": 6, "E": 9},
    "file_storage": {"S": 5, "T": 8, "R": 4, "I": 8, "D": 5, "E": 6},
    "message_queue": {"S": 6, "T": 7, "R": 5, "I": 6, "D": 7, "E": 5},
    "cache": {"S": 4, "T": 6, "R": 3, "I": 7, "D": 5, "E": 4},
    "default": {"S": 5, "T": 5, "R": 4, "I": 5, "D": 5, "E": 5},
}
STRIDE_MITIGATIONS = {
    "S": ["Implement strong authentication (MFA)", "Use mutual TLS for service-to-service", "Validate tokens and session integrity"],
    "T": ["Use integrity checks (HMAC, digital signatures)", "Implement input validation", "Use parameterized queries"],
    "R": ["Enable comprehensive audit logging", "Use tamper-evident logs", "Implement non-repudiation mechanisms"],
    "I": ["Encrypt data in transit (TLS 1.2+)", "Encrypt data at rest (AES-256)", "Apply principle of least privilege"],
    "D": ["Implement rate limiting", "Deploy DDoS protection", "Use circuit breakers and auto-scaling"],
    "E": ["Enforce RBAC/ABAC", "Run processes with minimum privileges", "Implement proper authorization checks"],
}


class ThreatModelBuilderModule(AtsModule):
    """Build STRIDE/DREAD/PASTA threat models from system descriptions."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="threat_model_builder",
            category=ModuleCategory.ADVANCED,
            description="Build STRIDE threat models with threat analysis, mitigations, and risk matrices",
            version="1.0.0",
            parameters=[
                Parameter(name="system_description", type=ParameterType.STRING,
                          description="JSON with: components [{name, type, description}], data_flows [{from, to, data, protocol}], trust_boundaries [{name, inside[], outside[]}]"),
                Parameter(name="methodology", type=ParameterType.CHOICE,
                          description="Threat modeling methodology",
                          choices=["stride", "dread", "pasta"], default="stride"),
            ],
            outputs=[
                OutputField(name="threats", type="list", description="Identified threats with scores"),
                OutputField(name="mitigations", type="list", description="Recommended mitigations"),
                OutputField(name="risk_matrix", type="dict", description="Threat risk matrix"),
                OutputField(name="priority_order", type="list", description="Threats ordered by priority"),
            ],
            tags=["advanced", "threat-modeling", "stride", "dread", "security-design"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("system_description", "").strip()
        if not raw:
            return False, "System description is required"
        try:
            desc = json.loads(raw)
            if not isinstance(desc, dict):
                return False, "System description must be a JSON object"
            if "components" not in desc or not desc["components"]:
                return False, "System description must include at least one component"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in system_description: {exc}"
        return True, ""

    def _analyze_component_stride(self, component: dict, boundaries: list[dict]) -> list[dict]:
        """Analyze a component for STRIDE threats."""
        comp_name = component.get("name", "Unknown")
        comp_type = component.get("type", "default").lower()
        profile = COMPONENT_THREAT_PROFILES.get(comp_type, COMPONENT_THREAT_PROFILES["default"])

        crosses_boundary = any(
            comp_name in b.get("inside", []) or comp_name in b.get("outside", [])
            for b in boundaries
        )
        threats = []
        for cat_key, base_score in profile.items():
            cat = STRIDE_CATEGORIES[cat_key]
            adjusted_score = min(base_score + (2 if crosses_boundary else 0), 10)
            if adjusted_score >= 4:
                threats.append({
                    "id": f"STRIDE-{cat_key}-{comp_name}",
                    "category": cat["name"],
                    "category_key": cat_key,
                    "component": comp_name,
                    "component_type": comp_type,
                    "description": f"{cat['name']} threat on {comp_name}: {cat['question']}",
                    "score": adjusted_score,
                    "severity": "critical" if adjusted_score >= 9 else "high" if adjusted_score >= 7 else "medium" if adjusted_score >= 4 else "low",
                    "crosses_trust_boundary": crosses_boundary,
                })
        return threats

    def _analyze_data_flows(self, flows: list[dict], boundaries: list[dict]) -> list[dict]:
        """Analyze data flows for tampering and information disclosure."""
        threats = []
        for flow in flows:
            src = flow.get("from", "unknown")
            dst = flow.get("to", "unknown")
            data = flow.get("data", "unspecified")
            protocol = flow.get("protocol", "unknown").lower()
            encrypted = protocol in ("https", "tls", "ssh", "grpc")

            if not encrypted:
                threats.append({
                    "id": f"FLOW-T-{src}-{dst}",
                    "category": "Tampering",
                    "category_key": "T",
                    "component": f"{src} -> {dst}",
                    "description": f"Data flow '{data}' from {src} to {dst} over {protocol} may be tampered",
                    "score": 8,
                    "severity": "high",
                })
                threats.append({
                    "id": f"FLOW-I-{src}-{dst}",
                    "category": "Information Disclosure",
                    "category_key": "I",
                    "component": f"{src} -> {dst}",
                    "description": f"Data flow '{data}' from {src} to {dst} over {protocol} may leak information",
                    "score": 8,
                    "severity": "high",
                })
        return threats

    def _generate_mitigations(self, threats: list[dict]) -> list[dict]:
        """Generate mitigations for identified threats."""
        seen_categories: dict[str, list] = {}
        for t in threats:
            key = t["category_key"]
            if key not in seen_categories:
                seen_categories[key] = []
            seen_categories[key].append(t["component"])

        mitigations = []
        for cat_key, components in seen_categories.items():
            cat = STRIDE_CATEGORIES[cat_key]
            for mitigation_text in STRIDE_MITIGATIONS.get(cat_key, []):
                mitigations.append({
                    "category": cat["name"],
                    "mitigation": mitigation_text,
                    "applies_to": list(set(components)),
                    "priority": "high" if cat_key in ("S", "E", "I") else "medium",
                })
        return mitigations

    def _build_risk_matrix(self, threats: list[dict]) -> dict[str, Any]:
        """Build a threat risk matrix grouped by category and severity."""
        matrix: dict[str, dict[str, list]] = {}
        for cat_key in STRIDE_CATEGORIES:
            cat_name = STRIDE_CATEGORIES[cat_key]["name"]
            matrix[cat_name] = {"critical": [], "high": [], "medium": [], "low": []}
        for t in threats:
            cat_name = t["category"]
            sev = t["severity"]
            if cat_name in matrix and sev in matrix[cat_name]:
                matrix[cat_name][sev].append(t["id"])
        summary = {cat: sum(len(v) for v in sevs.values()) for cat, sevs in matrix.items()}
        return {"matrix": matrix, "summary": summary, "total_threats": len(threats)}

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        desc = json.loads(config["system_description"])
        components = desc.get("components", [])
        data_flows = desc.get("data_flows", [])
        boundaries = desc.get("trust_boundaries", [])

        all_threats: list[dict] = []
        for comp in components:
            all_threats.extend(self._analyze_component_stride(comp, boundaries))
        all_threats.extend(self._analyze_data_flows(data_flows, boundaries))

        mitigations = self._generate_mitigations(all_threats)
        risk_matrix = self._build_risk_matrix(all_threats)
        priority_order = sorted(all_threats, key=lambda t: t["score"], reverse=True)

        return {
            "threats": all_threats,
            "mitigations": mitigations,
            "risk_matrix": risk_matrix,
            "priority_order": [{"id": t["id"], "category": t["category"],
                                "component": t["component"], "score": t["score"],
                                "severity": t["severity"]} for t in priority_order],
        }
