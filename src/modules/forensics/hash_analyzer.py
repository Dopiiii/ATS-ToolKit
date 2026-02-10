"""Hash analyzer module for forensic file integrity verification.

Compute and verify file hashes (MD5, SHA1, SHA256, SHA512).
Compare against known-good/known-bad hash databases and detect file tampering.
"""

import asyncio
import hashlib
import os
import json
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
READ_CHUNK_SIZE = 65536


class HashAnalyzerModule(AtsModule):
    """Compute and verify file hashes for forensic analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="hash_analyzer",
            category=ModuleCategory.FORENSICS,
            description="Compute and verify file hashes (MD5, SHA1, SHA256, SHA512), compare against hash databases, and detect tampering",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target_path",
                    type=ParameterType.STRING,
                    description="Path to a file or directory to hash",
                    required=True,
                ),
                Parameter(
                    name="algorithms",
                    type=ParameterType.LIST,
                    description="Hash algorithms to compute (md5, sha1, sha256, sha512)",
                    required=False,
                    default=["md5", "sha256"],
                ),
                Parameter(
                    name="hash_database",
                    type=ParameterType.FILE,
                    description="Path to a JSON hash database file for comparison (known-good/known-bad)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="verify_hash",
                    type=ParameterType.STRING,
                    description="Expected hash value to verify against (single file only)",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="recursive",
                    type=ParameterType.BOOLEAN,
                    description="Recursively hash files in directories",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="file_hashes", type="list", description="Computed hashes for each file"),
                OutputField(name="total_files", type="integer", description="Total files hashed"),
                OutputField(name="total_bytes", type="integer", description="Total bytes processed"),
                OutputField(name="matches", type="list", description="Hash database matches"),
                OutputField(name="verification", type="dict", description="Verification result if verify_hash was provided"),
                OutputField(name="duplicates", type="list", description="Files with identical hashes"),
            ],
            tags=["forensics", "hashing", "integrity", "verification", "tamper-detection"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target_path = config.get("target_path", "").strip()
        if not target_path:
            return False, "target_path is required"
        if not os.path.exists(target_path):
            return False, f"Target path not found: {target_path}"

        algorithms = config.get("algorithms", ["md5", "sha256"])
        for alg in algorithms:
            if alg.lower() not in SUPPORTED_ALGORITHMS:
                return False, f"Unsupported algorithm: {alg}. Supported: {SUPPORTED_ALGORITHMS}"

        hash_db = config.get("hash_database", "")
        if hash_db and not os.path.isfile(hash_db):
            return False, f"Hash database file not found: {hash_db}"

        return True, ""

    def _compute_hashes(self, file_path: str, algorithms: List[str]) -> Dict[str, str]:
        """Compute multiple hashes for a single file."""
        hashers = {alg: hashlib.new(alg) for alg in algorithms}
        try:
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(READ_CHUNK_SIZE)
                    if not chunk:
                        break
                    for h in hashers.values():
                        h.update(chunk)
            return {alg: h.hexdigest() for alg, h in hashers.items()}
        except OSError as e:
            return {"error": str(e)}

    def _load_hash_database(self, db_path: str) -> Dict[str, Dict[str, str]]:
        """Load a hash database from JSON.

        Expected format:
        {
            "<hash_value>": {"status": "known-bad"|"known-good", "name": "...", "description": "..."},
            ...
        }
        """
        try:
            with open(db_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def _collect_files(self, target_path: str, recursive: bool) -> List[str]:
        """Collect file paths from a file or directory."""
        if os.path.isfile(target_path):
            return [target_path]

        files = []
        if recursive:
            for root, dirs, filenames in os.walk(target_path):
                for fname in filenames:
                    files.append(os.path.join(root, fname))
        else:
            for fname in os.listdir(target_path):
                fpath = os.path.join(target_path, fname)
                if os.path.isfile(fpath):
                    files.append(fpath)
        return files

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_path = config["target_path"].strip()
        algorithms = [a.lower() for a in config.get("algorithms", ["md5", "sha256"])]
        hash_db_path = config.get("hash_database", "")
        verify_hash = config.get("verify_hash", "").strip().lower()
        recursive = config.get("recursive", True)

        self.logger.info("starting_hash_analysis", target=target_path, algorithms=algorithms)

        # Load hash database if provided
        hash_db: Dict[str, Dict[str, str]] = {}
        if hash_db_path:
            hash_db = self._load_hash_database(hash_db_path)
            self.logger.info("hash_database_loaded", entries=len(hash_db))

        files = self._collect_files(target_path, recursive)
        self.logger.info("files_collected", count=len(files))

        file_hashes: List[Dict[str, Any]] = []
        matches: List[Dict[str, Any]] = []
        total_bytes = 0
        hash_to_files: Dict[str, List[str]] = {}

        loop = asyncio.get_event_loop()

        def _process():
            nonlocal total_bytes
            for fpath in files:
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    fsize = 0

                hashes = self._compute_hashes(fpath, algorithms)
                if "error" in hashes:
                    file_hashes.append({
                        "path": fpath,
                        "error": hashes["error"],
                    })
                    continue

                total_bytes += fsize

                entry = {
                    "path": fpath,
                    "size": fsize,
                    "hashes": hashes,
                    "modified": datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat() if os.path.exists(fpath) else None,
                }
                file_hashes.append(entry)

                # Track for duplicate detection (use first algorithm)
                primary_hash = hashes.get(algorithms[0], "")
                if primary_hash:
                    if primary_hash not in hash_to_files:
                        hash_to_files[primary_hash] = []
                    hash_to_files[primary_hash].append(fpath)

                # Check against hash database
                for alg, hash_val in hashes.items():
                    if hash_val in hash_db:
                        db_entry = hash_db[hash_val]
                        match_info = {
                            "file": fpath,
                            "algorithm": alg,
                            "hash": hash_val,
                            "status": db_entry.get("status", "unknown"),
                            "name": db_entry.get("name", ""),
                            "description": db_entry.get("description", ""),
                        }
                        matches.append(match_info)

        await loop.run_in_executor(None, _process)

        # Verification result
        verification = {}
        if verify_hash and len(files) == 1:
            file_entry = file_hashes[0] if file_hashes else {}
            hashes = file_entry.get("hashes", {})
            matched = False
            matched_alg = ""
            for alg, hash_val in hashes.items():
                if hash_val.lower() == verify_hash:
                    matched = True
                    matched_alg = alg
                    break
            verification = {
                "expected": verify_hash,
                "match": matched,
                "algorithm": matched_alg if matched else "none",
                "computed_hashes": hashes,
                "tampered": not matched,
            }

        # Find duplicates
        duplicates = []
        for hash_val, fpaths in hash_to_files.items():
            if len(fpaths) > 1:
                duplicates.append({
                    "hash": hash_val,
                    "algorithm": algorithms[0],
                    "files": fpaths,
                    "count": len(fpaths),
                })

        self.logger.info(
            "hash_analysis_complete",
            total_files=len(file_hashes),
            total_bytes=total_bytes,
            matches=len(matches),
            duplicates=len(duplicates),
        )

        return {
            "target_path": target_path,
            "file_hashes": file_hashes,
            "total_files": len(file_hashes),
            "total_bytes": total_bytes,
            "matches": matches,
            "verification": verification,
            "duplicates": duplicates,
        }
