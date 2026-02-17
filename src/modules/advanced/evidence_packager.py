"""Forensic evidence packaging module for chain of custody documentation.

Packages forensic evidence items with integrity hashes, manifests,
chain of custody records, and tamper detection metadata.
"""

import asyncio
import hashlib
import json
import re
from typing import Any
from datetime import datetime, timezone

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

EVIDENCE_TYPES = {
    "file": {"required_fields": ["filename", "content_hash"], "icon": "FILE"},
    "log": {"required_fields": ["source", "entries"], "icon": "LOG"},
    "memory_dump": {"required_fields": ["process", "size"], "icon": "MEM"},
    "network_capture": {"required_fields": ["interface", "packet_count"], "icon": "NET"},
    "disk_image": {"required_fields": ["device", "size"], "icon": "DISK"},
    "screenshot": {"required_fields": ["filename"], "icon": "IMG"},
    "registry": {"required_fields": ["hive", "key_path"], "icon": "REG"},
    "artifact": {"required_fields": ["name", "description"], "icon": "ART"},
}


class EvidencePackagerModule(AtsModule):
    """Package forensic evidence with integrity verification and chain of custody."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="evidence_packager",
            category=ModuleCategory.ADVANCED,
            description="Package forensic evidence with integrity hashes, manifests, and chain of custody documentation",
            version="1.0.0",
            parameters=[
                Parameter(name="evidence_items", type=ParameterType.STRING,
                          description="JSON array of evidence items with fields: id, type, name, description, data, collected_by, collected_at"),
                Parameter(name="case_id", type=ParameterType.STRING,
                          description="Unique case identifier for this evidence package"),
                Parameter(name="examiner", type=ParameterType.STRING,
                          description="Name/ID of the forensic examiner packaging the evidence"),
                Parameter(name="classification", type=ParameterType.CHOICE,
                          description="Evidence classification level",
                          choices=["public", "internal", "confidential", "restricted"],
                          default="confidential", required=False),
            ],
            outputs=[
                OutputField(name="manifest", type="dict", description="Evidence manifest with all items"),
                OutputField(name="integrity_records", type="list", description="Hash records for each evidence item"),
                OutputField(name="chain_of_custody", type="dict", description="Chain of custody documentation"),
                OutputField(name="package_hash", type="string", description="Overall package integrity hash"),
            ],
            tags=["advanced", "forensics", "evidence", "chain-of-custody", "integrity"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("evidence_items", "").strip()
        if not raw:
            return False, "Evidence items are required"
        try:
            items = json.loads(raw)
            if not isinstance(items, list):
                return False, "Evidence items must be a JSON array"
            if len(items) == 0:
                return False, "Evidence items array is empty"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in evidence_items: {exc}"
        case_id = config.get("case_id", "").strip()
        if not case_id:
            return False, "Case ID is required"
        examiner = config.get("examiner", "").strip()
        if not examiner:
            return False, "Examiner name/ID is required"
        return True, ""

    def _compute_item_hash(self, item: dict) -> dict[str, str]:
        """Compute integrity hashes for an evidence item."""
        item_json = json.dumps(item, sort_keys=True, default=str)
        return {
            "md5": hashlib.md5(item_json.encode()).hexdigest(),
            "sha1": hashlib.sha1(item_json.encode()).hexdigest(),
            "sha256": hashlib.sha256(item_json.encode()).hexdigest(),
            "sha512": hashlib.sha512(item_json.encode()).hexdigest(),
        }

    def _validate_evidence_item(self, item: dict, index: int) -> dict[str, Any]:
        """Validate and normalize a single evidence item."""
        issues = []
        item_type = item.get("type", "artifact")
        item_id = item.get("id", f"EV-{index:04d}")
        name = item.get("name", f"Evidence Item {index}")

        if item_type in EVIDENCE_TYPES:
            required = EVIDENCE_TYPES[item_type]["required_fields"]
            data = item.get("data", {})
            if isinstance(data, dict):
                for field in required:
                    if field not in data and field not in item:
                        issues.append(f"Missing recommended field '{field}' for type '{item_type}'")
        else:
            issues.append(f"Unknown evidence type '{item_type}', treating as artifact")

        return {
            "item_id": item_id,
            "name": name,
            "type": item_type,
            "validation_issues": issues,
            "is_valid": len(issues) == 0,
        }

    def _build_manifest(self, items: list[dict], case_id: str, examiner: str,
                        classification: str) -> dict[str, Any]:
        """Build the evidence manifest document."""
        now = datetime.now(timezone.utc).isoformat()
        manifest_items = []
        for idx, item in enumerate(items):
            item_id = item.get("id", f"EV-{idx:04d}")
            manifest_items.append({
                "item_id": item_id,
                "name": item.get("name", f"Evidence Item {idx}"),
                "type": item.get("type", "artifact"),
                "description": item.get("description", ""),
                "collected_by": item.get("collected_by", examiner),
                "collected_at": item.get("collected_at", now),
                "index": idx,
            })

        return {
            "manifest_version": "1.0",
            "case_id": case_id,
            "examiner": examiner,
            "classification": classification,
            "created_at": now,
            "item_count": len(items),
            "items": manifest_items,
        }

    def _build_integrity_records(self, items: list[dict]) -> list[dict]:
        """Build integrity hash records for all evidence items."""
        records = []
        for idx, item in enumerate(items):
            item_id = item.get("id", f"EV-{idx:04d}")
            hashes = self._compute_item_hash(item)
            validation = self._validate_evidence_item(item, idx)

            records.append({
                "item_id": item_id,
                "name": item.get("name", f"Evidence Item {idx}"),
                "hashes": hashes,
                "hash_algorithm_primary": "sha256",
                "primary_hash": hashes["sha256"],
                "data_size_bytes": len(json.dumps(item, default=str).encode()),
                "validation": validation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        return records

    def _build_chain_of_custody(self, items: list[dict], case_id: str,
                                 examiner: str) -> dict[str, Any]:
        """Build chain of custody documentation."""
        now = datetime.now(timezone.utc).isoformat()
        custody_entries = []

        for idx, item in enumerate(items):
            item_id = item.get("id", f"EV-{idx:04d}")
            collected_by = item.get("collected_by", "Unknown")
            collected_at = item.get("collected_at", now)

            entries = [
                {
                    "action": "collected",
                    "performed_by": collected_by,
                    "timestamp": collected_at,
                    "location": item.get("location", "Not specified"),
                    "notes": item.get("collection_notes", ""),
                },
                {
                    "action": "packaged",
                    "performed_by": examiner,
                    "timestamp": now,
                    "location": "Evidence packaging system",
                    "notes": f"Packaged as part of case {case_id}",
                },
            ]

            # If there are transfer records in the item
            transfers = item.get("transfers", [])
            for transfer in transfers:
                entries.append({
                    "action": "transferred",
                    "performed_by": transfer.get("from", "Unknown"),
                    "received_by": transfer.get("to", "Unknown"),
                    "timestamp": transfer.get("timestamp", now),
                    "notes": transfer.get("notes", ""),
                })

            custody_entries.append({
                "item_id": item_id,
                "name": item.get("name", f"Evidence Item {idx}"),
                "custody_log": entries,
                "current_custodian": examiner,
            })

        return {
            "case_id": case_id,
            "chain_initiated": now,
            "lead_examiner": examiner,
            "total_items": len(items),
            "custody_records": custody_entries,
            "integrity_statement": (
                "All evidence items have been hashed using SHA-256, SHA-512, SHA-1, and MD5. "
                "Any modification to evidence items will be detectable through hash verification. "
                "Chain of custody has been maintained and documented for each item."
            ),
        }

    def _compute_package_hash(self, manifest: dict, integrity_records: list,
                               chain_of_custody: dict) -> str:
        """Compute overall package integrity hash."""
        package_content = json.dumps({
            "manifest": manifest,
            "integrity_records": integrity_records,
            "chain_of_custody": chain_of_custody,
        }, sort_keys=True, default=str)
        return hashlib.sha256(package_content.encode()).hexdigest()

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        items = json.loads(config["evidence_items"])
        case_id = config["case_id"].strip()
        examiner = config["examiner"].strip()
        classification = config.get("classification", "confidential")

        # Build manifest
        manifest = self._build_manifest(items, case_id, examiner, classification)

        # Build integrity records
        integrity_records = self._build_integrity_records(items)

        # Build chain of custody
        chain_of_custody = self._build_chain_of_custody(items, case_id, examiner)

        # Compute package hash
        package_hash = self._compute_package_hash(manifest, integrity_records, chain_of_custody)

        # Validation summary
        valid_items = sum(1 for r in integrity_records if r["validation"]["is_valid"])
        total_issues = sum(len(r["validation"]["validation_issues"]) for r in integrity_records)

        return {
            "manifest": manifest,
            "integrity_records": integrity_records,
            "chain_of_custody": chain_of_custody,
            "package_hash": package_hash,
            "package_hash_algorithm": "sha256",
            "validation_summary": {
                "total_items": len(items),
                "valid_items": valid_items,
                "items_with_issues": len(items) - valid_items,
                "total_issues": total_issues,
            },
        }
