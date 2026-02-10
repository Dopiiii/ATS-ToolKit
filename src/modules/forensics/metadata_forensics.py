"""Metadata forensics module.

Extract comprehensive file metadata including EXIF data, PDF properties,
Office document metadata, timestamps, author info, and GPS coordinates.
"""

import asyncio
import os
import re
import struct
import json
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
from pathlib import Path

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# EXIF tag IDs and names
EXIF_TAGS = {
    0x010F: "camera_make",
    0x0110: "camera_model",
    0x0112: "orientation",
    0x011A: "x_resolution",
    0x011B: "y_resolution",
    0x0131: "software",
    0x0132: "datetime",
    0x013B: "artist",
    0x8298: "copyright",
    0x8769: "exif_ifd",
    0x8825: "gps_ifd",
    0x9003: "datetime_original",
    0x9004: "datetime_digitized",
    0x920A: "focal_length",
    0xA002: "image_width",
    0xA003: "image_height",
    0xA420: "unique_id",
}

GPS_TAGS = {
    0x0001: "gps_latitude_ref",
    0x0002: "gps_latitude",
    0x0003: "gps_longitude_ref",
    0x0004: "gps_longitude",
    0x0005: "gps_altitude_ref",
    0x0006: "gps_altitude",
    0x0007: "gps_timestamp",
    0x001D: "gps_datestamp",
}


class MetadataForensicsModule(AtsModule):
    """Extract comprehensive file metadata for forensic analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="metadata_forensics",
            category=ModuleCategory.FORENSICS,
            description="Extract comprehensive file metadata including EXIF, PDF properties, Office document metadata, timestamps, author info, and GPS coordinates",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target_path",
                    type=ParameterType.STRING,
                    description="Path to a file or directory to analyze",
                    required=True,
                ),
                Parameter(
                    name="recursive",
                    type=ParameterType.BOOLEAN,
                    description="Recursively process directories",
                    required=False,
                    default=False,
                ),
                Parameter(
                    name="file_types",
                    type=ParameterType.LIST,
                    description="File extensions to process (e.g. ['jpg','pdf','docx']). Empty means all supported.",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="extract_gps",
                    type=ParameterType.BOOLEAN,
                    description="Attempt to extract GPS coordinates from EXIF data",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="files_analyzed", type="integer", description="Number of files analyzed"),
                OutputField(name="metadata_results", type="list", description="Metadata for each file"),
                OutputField(name="authors_found", type="list", description="Unique authors/creators found"),
                OutputField(name="software_found", type="list", description="Unique software/tools found"),
                OutputField(name="gps_locations", type="list", description="GPS coordinates found in files"),
            ],
            tags=["forensics", "metadata", "exif", "pdf", "gps", "document-analysis"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target_path = config.get("target_path", "").strip()
        if not target_path:
            return False, "target_path is required"
        if not os.path.exists(target_path):
            return False, f"Path not found: {target_path}"
        return True, ""

    def _get_filesystem_metadata(self, file_path: str) -> Dict[str, Any]:
        """Get basic filesystem metadata."""
        try:
            stat = os.stat(file_path)
            return {
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            }
        except OSError:
            return {}

    def _read_exif_value(self, data: bytes, offset: int, fmt: str, endian: str) -> Any:
        """Read a value from EXIF data at the given offset."""
        try:
            prefix = ">" if endian == "big" else "<"
            return struct.unpack_from(f"{prefix}{fmt}", data, offset)[0]
        except struct.error:
            return None

    def _parse_exif_rational(self, data: bytes, offset: int, endian: str) -> Optional[float]:
        """Parse an EXIF rational number (numerator/denominator)."""
        prefix = ">" if endian == "big" else "<"
        try:
            num = struct.unpack_from(f"{prefix}I", data, offset)[0]
            den = struct.unpack_from(f"{prefix}I", data, offset + 4)[0]
            return num / den if den != 0 else None
        except struct.error:
            return None

    def _extract_jpeg_exif(self, file_path: str, extract_gps: bool) -> Dict[str, Any]:
        """Extract EXIF metadata from a JPEG file."""
        metadata = {}
        gps_data = {}

        try:
            with open(file_path, "rb") as fh:
                header = fh.read(2)
                if header != b"\xff\xd8":
                    return metadata

                # Find APP1 EXIF marker
                while True:
                    marker = fh.read(2)
                    if len(marker) < 2:
                        break
                    if marker[0] != 0xFF:
                        break
                    length = struct.unpack(">H", fh.read(2))[0]
                    if marker[1] == 0xE1:  # APP1
                        exif_data = fh.read(length - 2)
                        if exif_data[:6] == b"Exif\x00\x00":
                            tiff_data = exif_data[6:]
                            endian = "big" if tiff_data[:2] == b"MM" else "little"
                            prefix = ">" if endian == "big" else "<"

                            ifd_offset = struct.unpack_from(f"{prefix}I", tiff_data, 4)[0]
                            if ifd_offset < len(tiff_data):
                                num_entries = struct.unpack_from(f"{prefix}H", tiff_data, ifd_offset)[0]

                                for i in range(num_entries):
                                    entry_offset = ifd_offset + 2 + (i * 12)
                                    if entry_offset + 12 > len(tiff_data):
                                        break

                                    tag_id = struct.unpack_from(f"{prefix}H", tiff_data, entry_offset)[0]
                                    data_type = struct.unpack_from(f"{prefix}H", tiff_data, entry_offset + 2)[0]
                                    count = struct.unpack_from(f"{prefix}I", tiff_data, entry_offset + 4)[0]
                                    value_offset = struct.unpack_from(f"{prefix}I", tiff_data, entry_offset + 8)[0]

                                    tag_name = EXIF_TAGS.get(tag_id)
                                    if tag_name:
                                        # ASCII string
                                        if data_type == 2 and value_offset < len(tiff_data):
                                            end = min(value_offset + count, len(tiff_data))
                                            val = tiff_data[value_offset:end].decode("ascii", errors="ignore").strip("\x00")
                                            if val:
                                                metadata[tag_name] = val
                                        # Short
                                        elif data_type == 3:
                                            val = struct.unpack_from(f"{prefix}H", tiff_data, entry_offset + 8)[0]
                                            metadata[tag_name] = val
                                        # Long
                                        elif data_type == 4:
                                            metadata[tag_name] = value_offset

                                    # GPS IFD pointer
                                    if extract_gps and tag_id == 0x8825:
                                        gps_ifd_offset = value_offset
                                        if gps_ifd_offset < len(tiff_data):
                                            gps_entries = struct.unpack_from(f"{prefix}H", tiff_data, gps_ifd_offset)[0]
                                            for j in range(min(gps_entries, 20)):
                                                gps_entry_off = gps_ifd_offset + 2 + (j * 12)
                                                if gps_entry_off + 12 > len(tiff_data):
                                                    break
                                                gps_tag = struct.unpack_from(f"{prefix}H", tiff_data, gps_entry_off)[0]
                                                gps_type = struct.unpack_from(f"{prefix}H", tiff_data, gps_entry_off + 2)[0]
                                                gps_val_off = struct.unpack_from(f"{prefix}I", tiff_data, gps_entry_off + 8)[0]
                                                gps_tag_name = GPS_TAGS.get(gps_tag)
                                                if gps_tag_name:
                                                    if gps_type == 2:  # ASCII
                                                        end = min(gps_val_off + 2, len(tiff_data))
                                                        gps_data[gps_tag_name] = tiff_data[gps_val_off:end].decode("ascii", errors="ignore").strip("\x00")
                                                    elif gps_type == 5 and gps_val_off + 24 <= len(tiff_data):  # Rational
                                                        vals = []
                                                        for k in range(3):
                                                            r = self._parse_exif_rational(tiff_data, gps_val_off + k * 8, endian)
                                                            if r is not None:
                                                                vals.append(r)
                                                        if vals:
                                                            gps_data[gps_tag_name] = vals
                        break
                    else:
                        fh.seek(length - 2, 1)

        except (OSError, struct.error):
            pass

        # Convert GPS coordinates to decimal degrees
        if gps_data.get("gps_latitude") and gps_data.get("gps_longitude"):
            try:
                lat_vals = gps_data["gps_latitude"]
                lon_vals = gps_data["gps_longitude"]
                if len(lat_vals) == 3 and len(lon_vals) == 3:
                    lat = lat_vals[0] + lat_vals[1] / 60 + lat_vals[2] / 3600
                    lon = lon_vals[0] + lon_vals[1] / 60 + lon_vals[2] / 3600
                    if gps_data.get("gps_latitude_ref") == "S":
                        lat = -lat
                    if gps_data.get("gps_longitude_ref") == "W":
                        lon = -lon
                    metadata["gps_decimal"] = {"latitude": round(lat, 6), "longitude": round(lon, 6)}
            except (TypeError, IndexError, ZeroDivisionError):
                pass

        if gps_data:
            metadata["gps_raw"] = {k: str(v) for k, v in gps_data.items()}

        return metadata

    def _extract_pdf_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from PDF files."""
        metadata = {}
        try:
            with open(file_path, "rb") as fh:
                content = fh.read(min(os.path.getsize(file_path), 1024 * 1024))
                text = content.decode("latin-1", errors="ignore")

                # PDF version
                version_match = re.search(r"%PDF-(\d+\.\d+)", text)
                if version_match:
                    metadata["pdf_version"] = version_match.group(1)

                # Info dictionary fields
                info_patterns = {
                    "title": r"/Title\s*\(([^)]*)\)",
                    "author": r"/Author\s*\(([^)]*)\)",
                    "subject": r"/Subject\s*\(([^)]*)\)",
                    "creator": r"/Creator\s*\(([^)]*)\)",
                    "producer": r"/Producer\s*\(([^)]*)\)",
                    "creation_date": r"/CreationDate\s*\(([^)]*)\)",
                    "mod_date": r"/ModDate\s*\(([^)]*)\)",
                    "keywords": r"/Keywords\s*\(([^)]*)\)",
                }

                for field, pattern in info_patterns.items():
                    match = re.search(pattern, text)
                    if match:
                        metadata[field] = match.group(1).strip()

                # Count pages
                page_count = len(re.findall(r"/Type\s*/Page(?!\w)", text))
                if page_count:
                    metadata["page_count"] = page_count

                # Check for encryption
                if "/Encrypt" in text:
                    metadata["encrypted"] = True

                # Check for JavaScript
                if "/JavaScript" in text or "/JS " in text:
                    metadata["contains_javascript"] = True

                # Check for embedded files
                if "/EmbeddedFile" in text:
                    metadata["has_embedded_files"] = True

        except OSError:
            pass
        return metadata

    def _extract_office_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from Office documents (DOCX/XLSX/PPTX via ZIP)."""
        metadata = {}
        try:
            import zipfile
            if not zipfile.is_zipfile(file_path):
                return metadata

            with zipfile.ZipFile(file_path, "r") as zf:
                # Check for core.xml (Office Open XML)
                core_files = [n for n in zf.namelist() if "core.xml" in n.lower()]
                for core_file in core_files:
                    content = zf.read(core_file).decode("utf-8", errors="ignore")
                    # Parse XML fields
                    xml_fields = {
                        "creator": r"<dc:creator>([^<]*)</dc:creator>",
                        "last_modified_by": r"<cp:lastModifiedBy>([^<]*)</cp:lastModifiedBy>",
                        "created": r"<dcterms:created[^>]*>([^<]*)</dcterms:created>",
                        "modified": r"<dcterms:modified[^>]*>([^<]*)</dcterms:modified>",
                        "title": r"<dc:title>([^<]*)</dc:title>",
                        "subject": r"<dc:subject>([^<]*)</dc:subject>",
                        "description": r"<dc:description>([^<]*)</dc:description>",
                        "revision": r"<cp:revision>([^<]*)</cp:revision>",
                    }
                    for field, pattern in xml_fields.items():
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match and match.group(1).strip():
                            metadata[field] = match.group(1).strip()

                # App.xml for application info
                app_files = [n for n in zf.namelist() if "app.xml" in n.lower()]
                for app_file in app_files:
                    content = zf.read(app_file).decode("utf-8", errors="ignore")
                    app_fields = {
                        "application": r"<Application>([^<]*)</Application>",
                        "app_version": r"<AppVersion>([^<]*)</AppVersion>",
                        "company": r"<Company>([^<]*)</Company>",
                        "total_time": r"<TotalTime>([^<]*)</TotalTime>",
                        "pages": r"<Pages>([^<]*)</Pages>",
                        "words": r"<Words>([^<]*)</Words>",
                    }
                    for field, pattern in app_fields.items():
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match and match.group(1).strip():
                            metadata[field] = match.group(1).strip()

        except (OSError, ImportError):
            pass
        return metadata

    def _collect_files(self, target_path: str, recursive: bool, file_types: List[str]) -> List[str]:
        """Collect files to analyze."""
        supported_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                                ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods"}
        if file_types:
            filter_ext = {"." + ft.lower().strip(".") for ft in file_types}
        else:
            filter_ext = supported_extensions

        if os.path.isfile(target_path):
            return [target_path]

        files = []
        if recursive:
            for root, dirs, filenames in os.walk(target_path):
                for fname in filenames:
                    if Path(fname).suffix.lower() in filter_ext:
                        files.append(os.path.join(root, fname))
        else:
            for fname in os.listdir(target_path):
                fpath = os.path.join(target_path, fname)
                if os.path.isfile(fpath) and Path(fname).suffix.lower() in filter_ext:
                    files.append(fpath)
        return files

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_path = config["target_path"].strip()
        recursive = config.get("recursive", False)
        file_types = config.get("file_types", [])
        extract_gps = config.get("extract_gps", True)

        self.logger.info("starting_metadata_extraction", target=target_path)

        files = self._collect_files(target_path, recursive, file_types)
        self.logger.info("files_to_analyze", count=len(files))

        results: List[Dict[str, Any]] = []
        authors_set: set = set()
        software_set: set = set()
        gps_locations: List[Dict[str, Any]] = []

        loop = asyncio.get_event_loop()

        def _process():
            for fpath in files:
                ext = Path(fpath).suffix.lower()
                entry: Dict[str, Any] = {
                    "path": fpath,
                    "filename": os.path.basename(fpath),
                    "extension": ext,
                    "filesystem": self._get_filesystem_metadata(fpath),
                }

                # JPEG/image EXIF
                if ext in (".jpg", ".jpeg", ".tiff"):
                    exif = self._extract_jpeg_exif(fpath, extract_gps)
                    if exif:
                        entry["exif"] = exif
                        if exif.get("artist"):
                            authors_set.add(exif["artist"])
                        if exif.get("software"):
                            software_set.add(exif["software"])
                        if exif.get("gps_decimal"):
                            gps_locations.append({
                                "file": fpath,
                                "coordinates": exif["gps_decimal"],
                            })

                # PDF
                elif ext == ".pdf":
                    pdf_meta = self._extract_pdf_metadata(fpath)
                    if pdf_meta:
                        entry["pdf"] = pdf_meta
                        for field in ("author", "creator"):
                            if pdf_meta.get(field):
                                authors_set.add(pdf_meta[field])
                        if pdf_meta.get("producer"):
                            software_set.add(pdf_meta["producer"])

                # Office documents
                elif ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods"):
                    office_meta = self._extract_office_metadata(fpath)
                    if office_meta:
                        entry["office"] = office_meta
                        if office_meta.get("creator"):
                            authors_set.add(office_meta["creator"])
                        if office_meta.get("last_modified_by"):
                            authors_set.add(office_meta["last_modified_by"])
                        if office_meta.get("application"):
                            software_set.add(office_meta["application"])

                results.append(entry)

        await loop.run_in_executor(None, _process)

        self.logger.info(
            "metadata_extraction_complete",
            files_analyzed=len(results),
            authors=len(authors_set),
            gps_locations=len(gps_locations),
        )

        return {
            "target_path": target_path,
            "files_analyzed": len(results),
            "metadata_results": results,
            "authors_found": sorted(authors_set),
            "software_found": sorted(software_set),
            "gps_locations": gps_locations,
        }
