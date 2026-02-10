"""File carver module for forensic recovery.

Recover files from raw data by detecting file signatures (magic bytes).
Supports PDF, JPEG, PNG, ZIP, DOCX, EXE and more.
"""

import asyncio
import os
import struct
from typing import Any, Dict, List, Tuple
from pathlib import Path

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# File signatures: (magic_bytes, offset, extension, description, footer/max_size)
FILE_SIGNATURES = [
    {
        "magic": b"\x89PNG\r\n\x1a\n",
        "offset": 0,
        "ext": "png",
        "desc": "PNG Image",
        "footer": b"IEND\xaeB`\x82",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "magic": b"\xff\xd8\xff",
        "offset": 0,
        "ext": "jpg",
        "desc": "JPEG Image",
        "footer": b"\xff\xd9",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "magic": b"%PDF-",
        "offset": 0,
        "ext": "pdf",
        "desc": "PDF Document",
        "footer": b"%%EOF",
        "max_size": 200 * 1024 * 1024,
    },
    {
        "magic": b"PK\x03\x04",
        "offset": 0,
        "ext": "zip",
        "desc": "ZIP Archive / DOCX / XLSX",
        "footer": b"PK\x05\x06",
        "max_size": 500 * 1024 * 1024,
    },
    {
        "magic": b"MZ",
        "offset": 0,
        "ext": "exe",
        "desc": "Windows Executable",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "magic": b"GIF87a",
        "offset": 0,
        "ext": "gif",
        "desc": "GIF Image (87a)",
        "footer": b"\x00\x3b",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "magic": b"GIF89a",
        "offset": 0,
        "ext": "gif",
        "desc": "GIF Image (89a)",
        "footer": b"\x00\x3b",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "magic": b"\x50\x4b\x03\x04\x14\x00\x06\x00",
        "offset": 0,
        "ext": "docx",
        "desc": "Office Open XML Document",
        "footer": b"PK\x05\x06",
        "max_size": 200 * 1024 * 1024,
    },
    {
        "magic": b"Rar!\x1a\x07",
        "offset": 0,
        "ext": "rar",
        "desc": "RAR Archive",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "magic": b"\x1f\x8b\x08",
        "offset": 0,
        "ext": "gz",
        "desc": "GZIP Archive",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "magic": b"\x42\x4d",
        "offset": 0,
        "ext": "bmp",
        "desc": "BMP Image",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "magic": b"\x7fELF",
        "offset": 0,
        "ext": "elf",
        "desc": "ELF Executable",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
]


class FileCarverModule(AtsModule):
    """Recover embedded files from raw data using magic byte signatures."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="file_carver",
            category=ModuleCategory.FORENSICS,
            description="Recover files from raw data by detecting file signatures (magic bytes) for PDF, JPEG, PNG, ZIP, DOCX, EXE and more",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="source_path",
                    type=ParameterType.FILE,
                    description="Path to the raw data file or disk image to carve",
                    required=True,
                ),
                Parameter(
                    name="output_dir",
                    type=ParameterType.STRING,
                    description="Directory to write recovered files to",
                    required=True,
                ),
                Parameter(
                    name="file_types",
                    type=ParameterType.LIST,
                    description="File types to search for (e.g. ['jpg','pdf','zip']). Empty means all types.",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="max_file_size",
                    type=ParameterType.INTEGER,
                    description="Maximum carved file size in bytes (default 100MB)",
                    required=False,
                    default=104857600,
                    min_value=1024,
                    max_value=1073741824,
                ),
                Parameter(
                    name="scan_chunk_size",
                    type=ParameterType.INTEGER,
                    description="Chunk size in bytes for reading source (default 4MB)",
                    required=False,
                    default=4194304,
                    min_value=65536,
                    max_value=67108864,
                ),
            ],
            outputs=[
                OutputField(name="carved_files", type="list", description="List of recovered file details"),
                OutputField(name="total_found", type="integer", description="Total files found"),
                OutputField(name="bytes_scanned", type="integer", description="Total bytes scanned"),
                OutputField(name="signature_hits", type="dict", description="Count of hits per file type"),
            ],
            tags=["forensics", "file-recovery", "carving", "disk-image", "data-recovery"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        source_path = config.get("source_path", "").strip()
        if not source_path:
            return False, "source_path is required"
        if not os.path.isfile(source_path):
            return False, f"Source file not found: {source_path}"

        output_dir = config.get("output_dir", "").strip()
        if not output_dir:
            return False, "output_dir is required"

        return True, ""

    def _get_active_signatures(self, file_types: List[str]) -> List[Dict]:
        """Filter signatures based on requested file types."""
        if not file_types:
            return FILE_SIGNATURES
        type_set = {ft.lower().strip(".") for ft in file_types}
        return [sig for sig in FILE_SIGNATURES if sig["ext"] in type_set]

    def _find_footer(self, data: bytes, start: int, footer: bytes, max_size: int) -> int:
        """Find the footer position within max_size from start."""
        search_end = min(start + max_size, len(data))
        pos = data.find(footer, start + 1, search_end)
        if pos != -1:
            return pos + len(footer)
        return -1

    def _estimate_exe_size(self, data: bytes, offset: int) -> int:
        """Estimate PE executable size from headers."""
        try:
            if len(data) < offset + 64:
                return -1
            pe_offset = struct.unpack_from("<I", data, offset + 0x3C)[0]
            if len(data) < offset + pe_offset + 0xF8:
                return -1
            # Read number of sections
            num_sections = struct.unpack_from("<H", data, offset + pe_offset + 6)[0]
            if num_sections == 0 or num_sections > 96:
                return -1
            # Calculate size from last section
            section_table_offset = offset + pe_offset + 0xF8
            max_end = 0
            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                if len(data) < sec_offset + 40:
                    break
                raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
                raw_ptr = struct.unpack_from("<I", data, sec_offset + 20)[0]
                sec_end = raw_ptr + raw_size
                if sec_end > max_end:
                    max_end = sec_end
            return max_end if max_end > 0 else -1
        except (struct.error, IndexError):
            return -1

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        source_path = config["source_path"].strip()
        output_dir = config["output_dir"].strip()
        file_types = config.get("file_types", [])
        max_file_size = config.get("max_file_size", 104857600)
        chunk_size = config.get("scan_chunk_size", 4194304)

        # Ensure output dir exists
        os.makedirs(output_dir, exist_ok=True)

        active_sigs = self._get_active_signatures(file_types)
        self.logger.info("starting_carve", source=source_path, signatures=len(active_sigs))

        carved_files: List[Dict[str, Any]] = []
        signature_hits: Dict[str, int] = {}
        file_counter = 0
        bytes_scanned = 0

        loop = asyncio.get_event_loop()

        def _carve():
            nonlocal file_counter, bytes_scanned
            source_size = os.path.getsize(source_path)
            overlap = max(len(sig["magic"]) for sig in active_sigs)

            with open(source_path, "rb") as fh:
                prev_tail = b""
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break

                    data = prev_tail + chunk
                    base_offset = bytes_scanned - len(prev_tail)

                    for sig in active_sigs:
                        magic = sig["magic"]
                        search_start = 0
                        while True:
                            pos = data.find(magic, search_start)
                            if pos == -1:
                                break
                            search_start = pos + 1
                            abs_offset = base_offset + pos

                            # Determine carved size
                            carved_size = -1
                            if sig["ext"] == "exe":
                                carved_size = self._estimate_exe_size(data, pos)
                            elif sig["footer"]:
                                carved_size = self._find_footer(data, pos, sig["footer"], min(max_file_size, sig["max_size"]))
                                if carved_size != -1:
                                    carved_size = carved_size - pos

                            if carved_size == -1:
                                carved_size = min(max_file_size, sig["max_size"])

                            carved_size = min(carved_size, max_file_size)
                            if carved_size < len(magic) + 4:
                                continue

                            # Extract file data
                            if pos + carved_size <= len(data):
                                file_data = data[pos:pos + carved_size]
                            else:
                                # Need to read more from source
                                current_pos = fh.tell()
                                fh.seek(abs_offset)
                                file_data = fh.read(carved_size)
                                fh.seek(current_pos)

                            if len(file_data) < len(magic) + 4:
                                continue

                            # Write carved file
                            file_counter += 1
                            filename = f"carved_{file_counter:04d}_0x{abs_offset:08X}.{sig['ext']}"
                            out_path = os.path.join(output_dir, filename)
                            with open(out_path, "wb") as out_fh:
                                out_fh.write(file_data)

                            carved_files.append({
                                "filename": filename,
                                "path": out_path,
                                "type": sig["desc"],
                                "extension": sig["ext"],
                                "offset": abs_offset,
                                "size": len(file_data),
                            })

                            signature_hits[sig["ext"]] = signature_hits.get(sig["ext"], 0) + 1

                    bytes_scanned += len(chunk)
                    prev_tail = data[-overlap:] if len(data) > overlap else data

        await loop.run_in_executor(None, _carve)

        self.logger.info(
            "carving_complete",
            files_found=file_counter,
            bytes_scanned=bytes_scanned,
        )

        return {
            "source_path": source_path,
            "output_dir": output_dir,
            "carved_files": carved_files,
            "total_found": file_counter,
            "bytes_scanned": bytes_scanned,
            "signature_hits": signature_hits,
        }
