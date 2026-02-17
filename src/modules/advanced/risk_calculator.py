"""Risk calculation module using industry frameworks.

Calculates risk scores from threat data using NIST, ISO 27005, or FAIR
frameworks. Produces risk registers, matrices, and treatment recommendations.
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

FRAMEWORK_WEIGHTS = {
    "nist": {"likelihood": 1.0, "impact": 1.0, "category_multiplier": {
        "technical": 1.2, "operational": 1.0, "strategic": 1.1, "compliance": 1.3, "default": 1.0}},
    "iso27005": {"likelihood": 1.1, "impact": 0.9, "category_multiplier": {
        "technical": 1.0, "operational": 1.1, "strategic": 1.2, "compliance": 1.15, "default": 1.0}},
    "fair": {"likelihood": 0.9, "impact": 1.2, "category_multiplier": {
        "technical": 1.1, "operational": 1.0, "strategic": 1.3, "compliance": 1.0, "default": 1.0}},
}
APPETITE_THRESHOLDS = {
    "conservative": {"accept": 4, "mitigate": 10, "transfer": 16, "avoid": 25},
    "moderate": {"accept": 6, "mitigate": 14, "transfer": 20, "avoid": 25},
    "aggressive": {"accept": 9, "mitigate": 18, "transfer": 22, "avoid": 25},
}
LIKELIHOOD_LABELS = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost Certain"}
IMPACT_LABELS = {1: "Negligible", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Catastrophic"}


class RiskCalculatorModule(AtsModule):
    """Calculate risk scores using NIST, ISO 27005, or FAIR frameworks."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="risk_calculator",
            category=ModuleCategory.ADVANCED,
            description="Calculate risk scores using NIST, ISO 27005, or FAIR frameworks with risk matrices and treatment plans",
            version="1.0.0",
            parameters=[
                Parameter(name="threats", type=ParameterType.STRING,
                          description="JSON array of threats: [{name, likelihood(1-5), impact(1-5), category}]"),
                Parameter(name="framework", type=ParameterType.CHOICE,
                          description="Risk assessment framework",
                          choices=["nist", "iso27005", "fair"], default="nist"),
                Parameter(name="risk_appetite", type=ParameterType.CHOICE,
                          description="Organizational risk appetite",
                          choices=["conservative", "moderate", "aggressive"], default="moderate"),
            ],
            outputs=[
                OutputField(name="risk_register", type="list", description="Scored risk register entries"),
                OutputField(name="risk_matrix", type="dict", description="5x5 risk matrix with threat placement"),
                OutputField(name="top_risks", type="list", description="Top prioritized risks"),
                OutputField(name="recommendations", type="list", description="Risk treatment recommendations"),
            ],
            tags=["advanced", "risk", "assessment", "nist", "iso27005", "fair"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("threats", "").strip()
        if not raw:
            return False, "Threats JSON array is required"
        try:
            threats = json.loads(raw)
            if not isinstance(threats, list):
                return False, "Threats must be a JSON array"
            if len(threats) == 0:
                return False, "Threats array cannot be empty"
            for i, t in enumerate(threats):
                if not isinstance(t, dict):
                    return False, f"Threat at index {i} must be an object"
                if "name" not in t:
                    return False, f"Threat at index {i} missing 'name'"
                lk = t.get("likelihood", 0)
                imp = t.get("impact", 0)
                if not (1 <= int(lk) <= 5):
                    return False, f"Threat '{t['name']}' likelihood must be 1-5"
                if not (1 <= int(imp) <= 5):
                    return False, f"Threat '{t['name']}' impact must be 1-5"
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return False, f"Invalid threats data: {exc}"
        return True, ""

    def _calculate_risk_score(self, likelihood: int, impact: int, category: str, framework: str) -> float:
        """Calculate weighted risk score based on framework."""
        fw = FRAMEWORK_WEIGHTS[framework]
        cat_mult = fw["category_multiplier"].get(category.lower(), fw["category_multiplier"]["default"])
        inherent = likelihood * impact
        weighted = (likelihood * fw["likelihood"] + impact * fw["impact"]) / 2.0 * cat_mult
        return round(weighted * (inherent / 25.0) * 25.0, 2)

    def _classify_treatment(self, score: float, appetite: str) -> str:
        """Classify risk treatment strategy based on score and appetite."""
        thresholds = APPETITE_THRESHOLDS[appetite]
        if score <= thresholds["accept"]:
            return "accept"
        elif score <= thresholds["mitigate"]:
            return "mitigate"
        elif score <= thresholds["transfer"]:
            return "transfer"
        else:
            return "avoid"

    def _build_risk_matrix(self, register: list[dict]) -> dict[str, Any]:
        """Build a 5x5 risk matrix with threat placements."""
        matrix = {}
        for li in range(1, 6):
            for im in range(1, 6):
                cell_key = f"{li}x{im}"
                matrix[cell_key] = {
                    "likelihood": li,
                    "likelihood_label": LIKELIHOOD_LABELS[li],
                    "impact": im,
                    "impact_label": IMPACT_LABELS[im],
                    "inherent_risk": li * im,
                    "level": "low" if li * im <= 4 else "medium" if li * im <= 9 else "high" if li * im <= 16 else "critical",
                    "threats": [],
                }
        for entry in register:
            cell_key = f"{entry['likelihood']}x{entry['impact']}"
            matrix[cell_key]["threats"].append(entry["name"])

        visual_rows = []
        for li in range(5, 0, -1):
            row = []
            for im in range(1, 6):
                cell = matrix[f"{li}x{im}"]
                count = len(cell["threats"])
                row.append({"score": li * im, "count": count, "level": cell["level"]})
            visual_rows.append({"likelihood": li, "label": LIKELIHOOD_LABELS[li], "cells": row})

        return {"cells": matrix, "visual": visual_rows, "impact_headers": [IMPACT_LABELS[i] for i in range(1, 6)]}

    def _generate_recommendations(self, register: list[dict], framework: str) -> list[dict]:
        """Generate risk treatment recommendations."""
        recs = []
        treatment_actions = {
            "avoid": "Eliminate the risk source entirely. Discontinue the activity or implement alternative approaches.",
            "transfer": "Transfer risk through insurance, outsourcing, or contractual agreements with third parties.",
            "mitigate": "Implement controls to reduce likelihood or impact. Monitor effectiveness of controls.",
            "accept": "Accept the residual risk. Document acceptance rationale and monitor for changes.",
        }
        for entry in register:
            treatment = entry["treatment"]
            recs.append({
                "threat": entry["name"],
                "risk_score": entry["risk_score"],
                "treatment": treatment,
                "action": treatment_actions[treatment],
                "priority": "immediate" if treatment == "avoid" else "high" if treatment == "transfer" else "medium" if treatment == "mitigate" else "low",
                "framework_note": f"Assessed under {framework.upper()} framework guidelines",
            })
        return sorted(recs, key=lambda r: r["risk_score"], reverse=True)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        threats = json.loads(config["threats"])
        framework = config.get("framework", "nist")
        appetite = config.get("risk_appetite", "moderate")

        register = []
        for t in threats:
            lk = int(t["likelihood"])
            imp = int(t["impact"])
            cat = t.get("category", "default")
            score = self._calculate_risk_score(lk, imp, cat, framework)
            treatment = self._classify_treatment(score, appetite)
            register.append({
                "name": t["name"],
                "likelihood": lk,
                "likelihood_label": LIKELIHOOD_LABELS[lk],
                "impact": imp,
                "impact_label": IMPACT_LABELS[imp],
                "category": cat,
                "inherent_risk": lk * imp,
                "risk_score": score,
                "treatment": treatment,
            })

        register.sort(key=lambda r: r["risk_score"], reverse=True)
        matrix = self._build_risk_matrix(register)
        top_risks = register[:min(5, len(register))]
        recommendations = self._generate_recommendations(register, framework)

        return {
            "risk_register": register,
            "risk_matrix": matrix,
            "top_risks": top_risks,
            "recommendations": recommendations,
            "summary": {
                "framework": framework,
                "risk_appetite": appetite,
                "total_threats": len(register),
                "treatment_distribution": {
                    t: sum(1 for r in register if r["treatment"] == t)
                    for t in ["avoid", "transfer", "mitigate", "accept"]
                },
            },
        }
