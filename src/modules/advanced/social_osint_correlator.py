"""Correlate OSINT data from multiple sources.

Cross-references findings across identity, organization, and timeline
correlation types, building relationship graphs and confidence scores.
"""

import asyncio
import json
import re
import hashlib
from collections import defaultdict
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class SocialOsintCorrelatorModule(AtsModule):
    """Correlate OSINT findings from multiple data sources into unified intelligence."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_osint_correlator",
            category=ModuleCategory.ADVANCED,
            description="Cross-reference and correlate OSINT data from multiple sources with relationship mapping",
            version="1.0.0",
            parameters=[
                Parameter(name="data_sources", type=ParameterType.STRING,
                          description="JSON array of data source objects with 'source', 'type', and 'data' fields",
                          required=True),
                Parameter(name="correlation_type", type=ParameterType.CHOICE,
                          description="Type of correlation to perform",
                          choices=["identity", "organization", "timeline"], default="identity"),
                Parameter(name="min_confidence", type=ParameterType.FLOAT,
                          description="Minimum confidence threshold for correlations (0.0-1.0)",
                          default=0.5, min_value=0.0, max_value=1.0),
            ],
            outputs=[
                OutputField(name="correlations", type="list", description="Identified correlations between sources"),
                OutputField(name="entities", type="list", description="Unique entities discovered"),
                OutputField(name="relationship_graph", type="dict", description="Entity relationship graph"),
            ],
            tags=["advanced", "social", "osint", "correlation", "intelligence"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("data_sources", "").strip()
        if not raw:
            return False, "Data sources JSON array is required"
        try:
            sources = json.loads(raw)
            if not isinstance(sources, list) or len(sources) < 2:
                return False, "At least 2 data sources are required for correlation"
            for src in sources:
                if not isinstance(src, dict) or "source" not in src or "data" not in src:
                    return False, "Each source must have 'source' and 'data' fields"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _extract_identifiers(self, data: dict | list | str) -> dict[str, set]:
        """Extract identifiable attributes from data for correlation."""
        identifiers: dict[str, set] = defaultdict(set)
        text = json.dumps(data) if not isinstance(data, str) else data

        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        for email in emails:
            identifiers["email"].add(email.lower())

        phones = re.findall(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', text)
        for phone in phones:
            normalized = re.sub(r'[^\d+]', '', phone)
            identifiers["phone"].add(normalized)

        usernames = re.findall(r'@([a-zA-Z0-9_]{3,30})', text)
        for u in usernames:
            if '.' not in u:
                identifiers["username"].add(u.lower())

        domains = re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', text)
        for d in domains:
            identifiers["domain"].add(d.lower())

        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                identifiers["ip_address"].add(ip)

        names = re.findall(r'\b([A-Z][a-z]+\s+[A-Z][a-z]+)\b', text)
        for name in names:
            identifiers["person_name"].add(name)

        orgs = re.findall(r'\b([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Inc|LLC|Corp|Ltd|GmbH|Co)\b\.?)', text)
        for org in orgs:
            identifiers["organization"].add(org.strip())

        dates = re.findall(r'\b(\d{4}-\d{2}-\d{2})\b', text)
        for d in dates:
            identifiers["date"].add(d)

        return dict(identifiers)

    def _correlate_identity(self, sources_data: list[dict]) -> tuple[list, list, dict]:
        """Correlate data sources by identity markers."""
        source_identifiers = []
        for src in sources_data:
            ids = self._extract_identifiers(src["data"])
            source_identifiers.append({"source": src["source"], "identifiers": ids})

        correlations = []
        entities = {}
        relationship_edges = []

        for i in range(len(source_identifiers)):
            for j in range(i + 1, len(source_identifiers)):
                src_a = source_identifiers[i]
                src_b = source_identifiers[j]
                shared = {}
                for id_type in set(src_a["identifiers"].keys()) & set(src_b["identifiers"].keys()):
                    overlap = src_a["identifiers"][id_type] & src_b["identifiers"][id_type]
                    if overlap:
                        shared[id_type] = list(overlap)
                if shared:
                    match_types = len(shared)
                    match_values = sum(len(v) for v in shared.values())
                    confidence = min(1.0, 0.3 + match_types * 0.2 + match_values * 0.05)
                    correlations.append({
                        "source_a": src_a["source"],
                        "source_b": src_b["source"],
                        "shared_identifiers": shared,
                        "match_types": match_types,
                        "match_values": match_values,
                        "confidence": round(confidence, 3),
                    })
                    for id_type, values in shared.items():
                        for val in values:
                            entity_id = hashlib.md5(f"{id_type}:{val}".encode()).hexdigest()[:12]
                            if entity_id not in entities:
                                entities[entity_id] = {
                                    "id": entity_id, "type": id_type,
                                    "value": val, "sources": [],
                                }
                            entities[entity_id]["sources"].append(src_a["source"])
                            entities[entity_id]["sources"].append(src_b["source"])
                            relationship_edges.append({
                                "from": src_a["source"], "to": src_b["source"],
                                "via": f"{id_type}:{val}", "entity_id": entity_id,
                            })

        for eid in entities:
            entities[eid]["sources"] = list(set(entities[eid]["sources"]))
            entities[eid]["source_count"] = len(entities[eid]["sources"])

        entity_list = sorted(entities.values(), key=lambda x: x["source_count"], reverse=True)
        graph = {"nodes": [s["source"] for s in sources_data], "edges": relationship_edges,
                 "entity_count": len(entity_list)}
        return correlations, entity_list, graph

    def _correlate_organization(self, sources_data: list[dict]) -> tuple[list, list, dict]:
        """Correlate by organization-level attributes."""
        correlations, entities, graph = self._correlate_identity(sources_data)
        org_entities = [e for e in entities if e["type"] in ("domain", "organization", "email")]
        domain_groups: dict[str, list] = defaultdict(list)
        for entity in entities:
            if entity["type"] == "email":
                domain_part = entity["value"].split("@")[-1]
                domain_groups[domain_part].append(entity)
            elif entity["type"] == "domain":
                domain_groups[entity["value"]].append(entity)
        org_correlations = []
        for domain, related in domain_groups.items():
            if len(related) > 1:
                all_sources = set()
                for r in related:
                    all_sources.update(r["sources"])
                org_correlations.append({
                    "domain": domain,
                    "related_entities": len(related),
                    "sources": list(all_sources),
                    "confidence": round(min(1.0, 0.4 + len(related) * 0.15 + len(all_sources) * 0.1), 3),
                })
        correlations.extend(org_correlations)
        return correlations, org_entities + entities, graph

    def _correlate_timeline(self, sources_data: list[dict]) -> tuple[list, list, dict]:
        """Correlate events across a timeline."""
        correlations, entities, graph = self._correlate_identity(sources_data)
        date_entities = [e for e in entities if e["type"] == "date"]
        date_entities.sort(key=lambda x: x["value"])
        timeline_events = []
        for de in date_entities:
            timeline_events.append({
                "date": de["value"], "sources": de["sources"],
                "entity_id": de["id"],
            })
        if len(timeline_events) > 1:
            for i in range(1, len(timeline_events)):
                prev = timeline_events[i - 1]
                curr = timeline_events[i]
                shared_sources = set(prev["sources"]) & set(curr["sources"])
                if shared_sources:
                    correlations.append({
                        "type": "temporal_proximity",
                        "date_a": prev["date"],
                        "date_b": curr["date"],
                        "shared_sources": list(shared_sources),
                        "confidence": round(min(1.0, 0.5 + len(shared_sources) * 0.15), 3),
                    })
        graph["timeline"] = timeline_events
        return correlations, entities, graph

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        sources_data = json.loads(config["data_sources"].strip())
        correlation_type = config.get("correlation_type", "identity")
        min_confidence = config.get("min_confidence", 0.5)

        correlators = {
            "identity": self._correlate_identity,
            "organization": self._correlate_organization,
            "timeline": self._correlate_timeline,
        }

        correlator = correlators.get(correlation_type, self._correlate_identity)
        correlations, entities, graph = correlator(sources_data)

        filtered_correlations = [
            c for c in correlations
            if c.get("confidence", 1.0) >= min_confidence
        ]

        filtered_correlations.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        return {
            "correlation_type": correlation_type,
            "sources_analyzed": len(sources_data),
            "correlations": filtered_correlations,
            "total_correlations": len(filtered_correlations),
            "entities": entities,
            "total_entities": len(entities),
            "relationship_graph": graph,
            "min_confidence_used": min_confidence,
        }
