"""Detect data poisoning attacks in machine learning training datasets.

Analyzes labeled training samples for statistical anomalies, label flips,
and outlier feature values that indicate potential data poisoning.
"""

import asyncio
import json
import math
import re
import hashlib
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class AiDataPoisoningDetectorModule(AtsModule):
    """Detect data poisoning in ML training datasets."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ai_data_poisoning_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect data poisoning attacks in training sets via statistical analysis, label checking, and outlier detection",
            version="1.0.0",
            parameters=[
                Parameter(name="data_samples", type=ParameterType.STRING,
                          description="JSON array of objects with 'label' and 'features' (list of numbers) keys",
                          required=True),
                Parameter(name="detection_method", type=ParameterType.CHOICE,
                          description="Detection method to use",
                          choices=["statistical", "label_check", "outlier"], default="statistical"),
                Parameter(name="sensitivity", type=ParameterType.CHOICE,
                          description="Detection sensitivity level",
                          choices=["low", "medium", "high"], default="medium"),
            ],
            outputs=[
                OutputField(name="poisoned_samples", type="list",
                            description="Indices and details of suspected poisoned samples"),
                OutputField(name="confidence_scores", type="list",
                            description="Confidence score per flagged sample"),
                OutputField(name="statistics", type="dict",
                            description="Dataset statistics and distribution summaries"),
            ],
            tags=["advanced", "ai", "data-poisoning", "ml-security"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("data_samples", "").strip()
        if not raw:
            return False, "data_samples JSON array is required"
        try:
            samples = json.loads(raw)
            if not isinstance(samples, list) or len(samples) < 3:
                return False, "data_samples must be a JSON array with at least 3 items"
            for i, s in enumerate(samples):
                if "label" not in s or "features" not in s:
                    return False, f"Sample {i} missing 'label' or 'features'"
                if not isinstance(s["features"], list) or not all(isinstance(v, (int, float)) for v in s["features"]):
                    return False, f"Sample {i} features must be a list of numbers"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON: {exc}"
        return True, ""

    def _compute_mean_std(self, values: list[float]) -> tuple[float, float]:
        """Return mean and standard deviation for a list of values."""
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / max(n - 1, 1)
        return mean, math.sqrt(variance)

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a)) or 1e-10
        mag_b = math.sqrt(sum(x * x for x in b)) or 1e-10
        return dot / (mag_a * mag_b)

    def _z_score_threshold(self, sensitivity: str) -> float:
        """Return z-score threshold based on sensitivity."""
        return {"low": 3.0, "medium": 2.0, "high": 1.5}.get(sensitivity, 2.0)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        samples = json.loads(config["data_samples"].strip())
        method = config.get("detection_method", "statistical")
        sensitivity = config.get("sensitivity", "medium")
        threshold = self._z_score_threshold(sensitivity)

        labels = sorted(set(s["label"] for s in samples))
        dim = len(samples[0]["features"])
        poisoned: list[dict[str, Any]] = []
        confidence_scores: list[float] = []

        # Group samples by label and compute per-label centroids
        label_groups: dict[str, list[int]] = {lb: [] for lb in labels}
        for idx, s in enumerate(samples):
            label_groups[s["label"]].append(idx)

        centroids: dict[str, list[float]] = {}
        for lb in labels:
            indices = label_groups[lb]
            centroid = [0.0] * dim
            for idx in indices:
                for d in range(dim):
                    centroid[d] += samples[idx]["features"][d]
            centroids[lb] = [c / max(len(indices), 1) for c in centroid]

        # Per-label feature stats
        label_stats: dict[str, list[tuple[float, float]]] = {}
        for lb in labels:
            stats = []
            for d in range(dim):
                vals = [samples[idx]["features"][d] for idx in label_groups[lb]]
                stats.append(self._compute_mean_std(vals))
            label_stats[lb] = stats

        if method == "statistical" or method == "label_check":
            # Detect label flips: samples closer to another class centroid
            for idx, s in enumerate(samples):
                own_sim = self._cosine_similarity(s["features"], centroids[s["label"]])
                max_other_sim = -1.0
                closest_label = s["label"]
                for lb in labels:
                    if lb == s["label"]:
                        continue
                    sim = self._cosine_similarity(s["features"], centroids[lb])
                    if sim > max_other_sim:
                        max_other_sim = sim
                        closest_label = lb
                if max_other_sim > own_sim + 0.05 / threshold:
                    conf = round(min(1.0, (max_other_sim - own_sim) * 2), 3)
                    poisoned.append({
                        "index": idx, "reason": "label_flip_suspect",
                        "current_label": s["label"], "suggested_label": closest_label,
                        "own_similarity": round(own_sim, 4),
                        "other_similarity": round(max_other_sim, 4),
                    })
                    confidence_scores.append(conf)

        if method == "statistical" or method == "outlier":
            # Z-score based outlier detection per feature per label
            for idx, s in enumerate(samples):
                lb = s["label"]
                z_flags = 0
                max_z = 0.0
                for d in range(dim):
                    mean, std = label_stats[lb][d]
                    if std < 1e-10:
                        continue
                    z = abs(s["features"][d] - mean) / std
                    if z > threshold:
                        z_flags += 1
                        max_z = max(max_z, z)
                if z_flags > 0:
                    already = any(p["index"] == idx for p in poisoned)
                    conf = round(min(1.0, max_z / (threshold * 2)), 3)
                    if already:
                        for i, p in enumerate(poisoned):
                            if p["index"] == idx:
                                confidence_scores[i] = max(confidence_scores[i], conf)
                                poisoned[i]["outlier_features"] = z_flags
                                poisoned[i]["max_z_score"] = round(max_z, 3)
                                break
                    else:
                        poisoned.append({
                            "index": idx, "reason": "feature_outlier",
                            "label": s["label"], "outlier_features": z_flags,
                            "max_z_score": round(max_z, 3),
                        })
                        confidence_scores.append(conf)

        # Build statistics summary
        global_means = []
        for d in range(dim):
            vals = [s["features"][d] for s in samples]
            m, sd = self._compute_mean_std(vals)
            global_means.append({"dimension": d, "mean": round(m, 4), "std": round(sd, 4)})

        statistics = {
            "total_samples": len(samples),
            "label_counts": {lb: len(label_groups[lb]) for lb in labels},
            "feature_dimensions": dim,
            "global_feature_stats": global_means,
            "detection_method": method,
            "sensitivity": sensitivity,
            "z_threshold": threshold,
        }

        return {
            "poisoned_samples": poisoned,
            "confidence_scores": confidence_scores,
            "statistics": statistics,
            "total_flagged": len(poisoned),
            "poison_ratio": round(len(poisoned) / max(len(samples), 1), 4),
        }
