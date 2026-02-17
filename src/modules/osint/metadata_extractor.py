"""File metadata extraction for OSINT investigations.

Extracts metadata from files accessible via URL including EXIF data from images,
author information from documents, GPS coordinates, creation dates, and software
details that can reveal valuable intelligence about file origins.
"""

import asyncio
import re
import struct
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# EXIF tag IDs and their human-readable names
EXIF_TAGS: dict[int, str] = {
    0x010F: "camera_make",
    0x0110: "camera_model",
    0x0112: "orientation",
    0x011A: "x_resolution",
    0x011B: "y_resolution",
    0x0131: "software",
    0x0132: "modify_date",
    0x013B: "artist",
    0x8298: "copyright",
    0x8769: "exif_ifd_pointer",
    0x8825: "gps_ifd_pointer",
    0x9003: "date_original",
    0x9004: "date_digitized",
    0x9207: "metering_mode",
    0x9209: "flash",
    0xA001: "color_space",
    0xA002: "pixel_x_dimension",
    0xA003: "pixel_y_dimension",
    0xA433: "lens_make",
    0xA434: "lens_model",
}

GPS_TAGS: dict[int, str] = {
    0x0001: "gps_latitude_ref",
    0x0002: "gps_latitude",
    0x0003: "gps_longitude_ref",
    0x0004: "gps_longitude",
    0x0005: "gps_altitude_ref",
    0x0006: "gps_altitude",
    0x0007: "gps_timestamp",
    0x001D: "gps_datestamp",
}

# PDF metadata keys
PDF_METADATA_KEYS = [
    "Title", "Author", "Subject", "Keywords", "Creator",
    "Producer", "CreationDate", "ModDate",
]

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit


class MetadataExtractorModule(AtsModule):
    """Extract metadata from files for OSINT analysis."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="metadata_extractor",
            category=ModuleCategory.OSINT,
            description="Extract metadata from files (images, PDFs, docs) including EXIF, author info, GPS coordinates",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="url", type=ParameterType.URL,
                    description="URL of the file to extract metadata from",
                    required=True,
                ),
                Parameter(
                    name="file_type", type=ParameterType.CHOICE,
                    description="Type of file to analyze (auto-detect if not specified)",
                    choices=["auto", "image", "pdf", "document"],
                    default="auto", required=False,
                ),
                Parameter(
                    name="extract_gps", type=ParameterType.BOOLEAN,
                    description="Attempt to extract GPS coordinates from EXIF data",
                    default=True, required=False,
                ),
                Parameter(
                    name="max_size_mb", type=ParameterType.INTEGER,
                    description="Maximum file size to download in MB",
                    default=20, min_value=1, max_value=50, required=False,
                ),
            ],
            outputs=[
                OutputField(name="file_info", type="dict", description="Basic file information (size, type, headers)"),
                OutputField(name="exif_data", type="dict", description="EXIF metadata from images"),
                OutputField(name="gps_coordinates", type="dict", description="GPS coordinates if available"),
                OutputField(name="document_metadata", type="dict", description="Document author/creator metadata"),
                OutputField(name="security_findings", type="list", description="Privacy/security relevant findings"),
            ],
            tags=["osint", "metadata", "exif", "gps", "forensics", "privacy"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        url = config.get("url", "").strip()
        if not url:
            return False, "URL is required"
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "URL must use HTTP or HTTPS scheme"
        if not parsed.netloc:
            return False, "URL must have a valid hostname"
        return True, ""

    def _detect_file_type(self, content_type: str, url: str) -> str:
        """Detect file type from Content-Type header and URL extension."""
        ct = content_type.lower()
        if any(t in ct for t in ("image/jpeg", "image/png", "image/tiff", "image/gif", "image/webp")):
            return "image"
        if "pdf" in ct:
            return "pdf"
        if any(t in ct for t in ("msword", "officedocument", "opendocument")):
            return "document"

        # Fallback to URL extension
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".tiff", ".gif", ".webp", ".bmp")):
            return "image"
        if path.endswith(".pdf"):
            return "pdf"
        if any(path.endswith(ext) for ext in (".doc", ".docx", ".odt", ".xls", ".xlsx", ".pptx")):
            return "document"

        return "unknown"

    def _parse_exif_from_jpeg(self, data: bytes) -> dict[str, Any]:
        """Parse EXIF data from JPEG binary content."""
        exif: dict[str, Any] = {}

        # Find EXIF marker (APP1 = 0xFFE1)
        marker_pos = data.find(b"\xff\xe1")
        if marker_pos == -1:
            return exif

        try:
            # Skip marker and length bytes
            offset = marker_pos + 4
            # Check for "Exif\x00\x00" header
            if data[offset:offset + 6] != b"Exif\x00\x00":
                return exif
            offset += 6
            tiff_start = offset

            # Determine byte order
            byte_order = data[offset:offset + 2]
            if byte_order == b"MM":
                endian = ">"
            elif byte_order == b"II":
                endian = "<"
            else:
                return exif

            # Verify TIFF magic number (42)
            magic = struct.unpack(f"{endian}H", data[offset + 2:offset + 4])[0]
            if magic != 42:
                return exif

            # Get offset to first IFD
            ifd_offset = struct.unpack(f"{endian}I", data[offset + 4:offset + 8])[0]

            # Parse IFD entries
            ifd_pos = tiff_start + ifd_offset
            num_entries = struct.unpack(f"{endian}H", data[ifd_pos:ifd_pos + 2])[0]

            gps_ifd_offset = None
            exif_ifd_offset = None

            for i in range(min(num_entries, 200)):  # Safety limit
                entry_pos = ifd_pos + 2 + (i * 12)
                if entry_pos + 12 > len(data):
                    break

                tag_id = struct.unpack(f"{endian}H", data[entry_pos:entry_pos + 2])[0]
                type_id = struct.unpack(f"{endian}H", data[entry_pos + 2:entry_pos + 4])[0]
                count = struct.unpack(f"{endian}I", data[entry_pos + 4:entry_pos + 8])[0]
                value_raw = data[entry_pos + 8:entry_pos + 12]

                # Check for sub-IFD pointers
                if tag_id == 0x8825:  # GPS IFD
                    gps_ifd_offset = struct.unpack(f"{endian}I", value_raw)[0]
                    continue
                if tag_id == 0x8769:  # EXIF IFD
                    exif_ifd_offset = struct.unpack(f"{endian}I", value_raw)[0]
                    continue

                if tag_id in EXIF_TAGS:
                    tag_name = EXIF_TAGS[tag_id]
                    value = self._read_exif_value(data, tiff_start, endian, type_id, count, value_raw)
                    if value is not None:
                        exif[tag_name] = value

            # Parse EXIF sub-IFD
            if exif_ifd_offset is not None:
                sub_exif = self._parse_ifd(data, tiff_start, tiff_start + exif_ifd_offset, endian, EXIF_TAGS)
                exif.update(sub_exif)

            # Parse GPS sub-IFD
            if gps_ifd_offset is not None:
                gps_data = self._parse_ifd(data, tiff_start, tiff_start + gps_ifd_offset, endian, GPS_TAGS)
                exif["gps_raw"] = gps_data

        except (struct.error, IndexError, ValueError):
            exif["parse_error"] = "Partial EXIF data extracted"

        return exif

    def _parse_ifd(
        self, data: bytes, tiff_start: int, ifd_pos: int,
        endian: str, tag_map: dict[int, str],
    ) -> dict[str, Any]:
        """Parse an IFD block and return tag values."""
        result: dict[str, Any] = {}
        try:
            if ifd_pos + 2 > len(data):
                return result
            num_entries = struct.unpack(f"{endian}H", data[ifd_pos:ifd_pos + 2])[0]
            for i in range(min(num_entries, 200)):
                entry_pos = ifd_pos + 2 + (i * 12)
                if entry_pos + 12 > len(data):
                    break
                tag_id = struct.unpack(f"{endian}H", data[entry_pos:entry_pos + 2])[0]
                type_id = struct.unpack(f"{endian}H", data[entry_pos + 2:entry_pos + 4])[0]
                count = struct.unpack(f"{endian}I", data[entry_pos + 4:entry_pos + 8])[0]
                value_raw = data[entry_pos + 8:entry_pos + 12]

                if tag_id in tag_map:
                    tag_name = tag_map[tag_id]
                    value = self._read_exif_value(data, tiff_start, endian, type_id, count, value_raw)
                    if value is not None:
                        result[tag_name] = value
        except (struct.error, IndexError):
            pass
        return result

    def _read_exif_value(
        self, data: bytes, tiff_start: int, endian: str,
        type_id: int, count: int, value_raw: bytes,
    ) -> Any:
        """Read an EXIF value based on its type."""
        try:
            # ASCII string (type 2)
            if type_id == 2:
                total = count
                if total <= 4:
                    return value_raw[:count].decode("ascii", errors="ignore").rstrip("\x00")
                offset = struct.unpack(f"{endian}I", value_raw)[0]
                pos = tiff_start + offset
                return data[pos:pos + count].decode("ascii", errors="ignore").rstrip("\x00")

            # Unsigned short (type 3)
            if type_id == 3 and count == 1:
                return struct.unpack(f"{endian}H", value_raw[:2])[0]

            # Unsigned long (type 4)
            if type_id == 4 and count == 1:
                return struct.unpack(f"{endian}I", value_raw)[0]

            # Unsigned rational (type 5) - numerator/denominator
            if type_id == 5:
                offset = struct.unpack(f"{endian}I", value_raw)[0]
                pos = tiff_start + offset
                values = []
                for j in range(min(count, 10)):
                    num = struct.unpack(f"{endian}I", data[pos + j * 8:pos + j * 8 + 4])[0]
                    den = struct.unpack(f"{endian}I", data[pos + j * 8 + 4:pos + j * 8 + 8])[0]
                    values.append(num / den if den != 0 else 0)
                return values if len(values) > 1 else values[0] if values else None

        except (struct.error, IndexError, UnicodeDecodeError):
            return None
        return None

    def _convert_gps_coordinates(self, gps_raw: dict[str, Any]) -> dict[str, Any] | None:
        """Convert raw GPS EXIF data to decimal degrees."""
        try:
            lat_values = gps_raw.get("gps_latitude")
            lon_values = gps_raw.get("gps_longitude")
            lat_ref = gps_raw.get("gps_latitude_ref", "N")
            lon_ref = gps_raw.get("gps_longitude_ref", "E")

            if not lat_values or not lon_values:
                return None

            if isinstance(lat_values, list) and len(lat_values) >= 3:
                lat = lat_values[0] + lat_values[1] / 60.0 + lat_values[2] / 3600.0
            else:
                return None

            if isinstance(lon_values, list) and len(lon_values) >= 3:
                lon = lon_values[0] + lon_values[1] / 60.0 + lon_values[2] / 3600.0
            else:
                return None

            if lat_ref == "S":
                lat = -lat
            if lon_ref == "W":
                lon = -lon

            return {
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "lat_ref": lat_ref,
                "lon_ref": lon_ref,
                "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                "altitude": gps_raw.get("gps_altitude"),
            }
        except (TypeError, ValueError, IndexError):
            return None

    def _extract_pdf_metadata(self, data: bytes) -> dict[str, Any]:
        """Extract metadata from PDF file content."""
        metadata: dict[str, Any] = {}
        text = data[:min(len(data), 65536)]  # Search first 64KB

        # Check PDF header for version
        if text[:5] == b"%PDF-":
            version_match = re.search(rb"%PDF-(\d+\.\d+)", text)
            if version_match:
                metadata["pdf_version"] = version_match.group(1).decode("ascii", errors="ignore")

        # Extract metadata from Info dictionary
        for key in PDF_METADATA_KEYS:
            # Match patterns like /Author (John Doe) or /Author <hex>
            pattern = rb"/" + key.encode() + rb"\s*\(([^)]*)\)"
            match = re.search(pattern, text)
            if match:
                value = match.group(1).decode("latin-1", errors="ignore")
                metadata[key.lower()] = value
                continue

            # Try hex-encoded string pattern
            pattern = rb"/" + key.encode() + rb"\s*<([0-9A-Fa-f]+)>"
            match = re.search(pattern, text)
            if match:
                try:
                    hex_str = match.group(1).decode("ascii")
                    value = bytes.fromhex(hex_str).decode("utf-16-be", errors="ignore")
                    metadata[key.lower()] = value.strip("\x00").strip("\xfe\xff")
                except (ValueError, UnicodeDecodeError):
                    pass

        # Check for XMP metadata block
        xmp_start = data.find(b"<x:xmpmeta")
        xmp_end = data.find(b"</x:xmpmeta>")
        if xmp_start != -1 and xmp_end != -1:
            xmp_block = data[xmp_start:xmp_end + 13].decode("utf-8", errors="ignore")
            metadata["has_xmp"] = True

            # Extract common XMP fields
            xmp_patterns = {
                "xmp_creator_tool": r"<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>",
                "xmp_create_date": r"<xmp:CreateDate>([^<]+)</xmp:CreateDate>",
                "xmp_modify_date": r"<xmp:ModifyDate>([^<]+)</xmp:ModifyDate>",
                "xmp_producer": r"<pdf:Producer>([^<]+)</pdf:Producer>",
            }
            for field_name, pattern in xmp_patterns.items():
                m = re.search(pattern, xmp_block)
                if m:
                    metadata[field_name] = m.group(1)

        # Count pages (rough estimate)
        page_count = len(re.findall(rb"/Type\s*/Page[^s]", data))
        if page_count > 0:
            metadata["estimated_pages"] = page_count

        return metadata

    def _extract_docx_metadata(self, data: bytes) -> dict[str, Any]:
        """Extract metadata from Office Open XML documents (basic detection)."""
        metadata: dict[str, Any] = {}

        # DOCX/XLSX/PPTX files are ZIP archives; check for PK signature
        if data[:2] == b"PK":
            metadata["format"] = "Office Open XML (ZIP-based)"

            # Search for core.xml properties within the ZIP data
            core_start = data.find(b"<cp:coreProperties")
            if core_start != -1:
                core_end = data.find(b"</cp:coreProperties>", core_start)
                if core_end != -1:
                    core_xml = data[core_start:core_end + 22].decode("utf-8", errors="ignore")

                    xml_fields = {
                        "creator": r"<dc:creator>([^<]+)</dc:creator>",
                        "last_modified_by": r"<cp:lastModifiedBy>([^<]+)</cp:lastModifiedBy>",
                        "created": r"<dcterms:created[^>]*>([^<]+)</dcterms:created>",
                        "modified": r"<dcterms:modified[^>]*>([^<]+)</dcterms:modified>",
                        "title": r"<dc:title>([^<]+)</dc:title>",
                        "subject": r"<dc:subject>([^<]+)</dc:subject>",
                        "description": r"<dc:description>([^<]+)</dc:description>",
                        "revision": r"<cp:revision>([^<]+)</cp:revision>",
                    }
                    for field_name, pattern in xml_fields.items():
                        m = re.search(pattern, core_xml)
                        if m:
                            metadata[field_name] = m.group(1)

            # Search for app.xml properties
            app_start = data.find(b"<Properties")
            if app_start != -1:
                app_end = data.find(b"</Properties>", app_start)
                if app_end != -1:
                    app_xml = data[app_start:app_end + 14].decode("utf-8", errors="ignore")

                    app_fields = {
                        "application": r"<Application>([^<]+)</Application>",
                        "app_version": r"<AppVersion>([^<]+)</AppVersion>",
                        "company": r"<Company>([^<]+)</Company>",
                        "total_time": r"<TotalTime>([^<]+)</TotalTime>",
                        "pages": r"<Pages>([^<]+)</Pages>",
                        "words": r"<Words>([^<]+)</Words>",
                    }
                    for field_name, pattern in app_fields.items():
                        m = re.search(pattern, app_xml)
                        if m:
                            metadata[field_name] = m.group(1)

        return metadata

    def _assess_security_findings(
        self, exif: dict[str, Any], gps: dict[str, Any] | None,
        doc_meta: dict[str, Any], file_type: str,
    ) -> list[dict[str, str]]:
        """Identify privacy and security relevant findings in metadata."""
        findings: list[dict[str, str]] = []

        if gps and gps.get("latitude") is not None:
            findings.append({
                "severity": "HIGH",
                "category": "privacy",
                "finding": f"GPS coordinates embedded: {gps['latitude']}, {gps['longitude']}",
                "recommendation": "Strip EXIF GPS data before publishing images",
            })

        if exif.get("artist") or exif.get("copyright"):
            name = exif.get("artist") or exif.get("copyright")
            findings.append({
                "severity": "MEDIUM",
                "category": "privacy",
                "finding": f"Author/artist information embedded: {name}",
                "recommendation": "Review if author identity should be public",
            })

        if exif.get("camera_make") or exif.get("camera_model"):
            device = f"{exif.get('camera_make', '')} {exif.get('camera_model', '')}".strip()
            findings.append({
                "severity": "LOW",
                "category": "device_fingerprint",
                "finding": f"Camera/device identified: {device}",
                "recommendation": "Device info can be used for tracking across images",
            })

        if exif.get("software"):
            findings.append({
                "severity": "LOW",
                "category": "software_fingerprint",
                "finding": f"Software identified: {exif['software']}",
                "recommendation": "Software version may reveal OS or editing tools used",
            })

        if doc_meta.get("creator"):
            findings.append({
                "severity": "MEDIUM",
                "category": "privacy",
                "finding": f"Document creator: {doc_meta['creator']}",
                "recommendation": "Author name may reveal employee identity",
            })

        if doc_meta.get("last_modified_by"):
            findings.append({
                "severity": "MEDIUM",
                "category": "privacy",
                "finding": f"Last modified by: {doc_meta['last_modified_by']}",
                "recommendation": "May reveal internal usernames or employee names",
            })

        if doc_meta.get("company"):
            findings.append({
                "severity": "LOW",
                "category": "organization",
                "finding": f"Company name in metadata: {doc_meta['company']}",
                "recommendation": "Confirms organizational affiliation",
            })

        if doc_meta.get("producer") or doc_meta.get("xmp_producer"):
            producer = doc_meta.get("producer") or doc_meta.get("xmp_producer")
            findings.append({
                "severity": "LOW",
                "category": "software_fingerprint",
                "finding": f"PDF producer: {producer}",
                "recommendation": "Producer reveals software used to generate the document",
            })

        return findings

    async def _download_file(
        self, session: aiohttp.ClientSession, url: str, max_size: int,
    ) -> tuple[bytes, dict[str, Any]]:
        """Download a file from URL with size limit, returning content and headers info."""
        headers_info: dict[str, Any] = {}
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30),
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0)"},
            ) as resp:
                headers_info["status"] = resp.status
                headers_info["content_type"] = resp.headers.get("Content-Type", "")
                headers_info["content_length"] = resp.headers.get("Content-Length", "")
                headers_info["server"] = resp.headers.get("Server", "")
                headers_info["last_modified"] = resp.headers.get("Last-Modified", "")
                headers_info["etag"] = resp.headers.get("ETag", "")

                if resp.status != 200:
                    return b"", headers_info

                # Check content length
                cl = resp.headers.get("Content-Length", "")
                if cl and int(cl) > max_size:
                    headers_info["error"] = f"File too large: {cl} bytes"
                    return b"", headers_info

                # Stream download with size limit
                chunks = []
                total = 0
                async for chunk in resp.content.iter_chunked(8192):
                    total += len(chunk)
                    if total > max_size:
                        headers_info["error"] = "File exceeded size limit during download"
                        break
                    chunks.append(chunk)

                return b"".join(chunks), headers_info

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            headers_info["error"] = str(exc)
            return b"", headers_info

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        url = config["url"].strip()
        file_type_hint = config.get("file_type", "auto")
        extract_gps = config.get("extract_gps", True)
        max_size_mb = config.get("max_size_mb", 20)
        max_size = max_size_mb * 1024 * 1024

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            data, headers_info = await self._download_file(session, url, max_size)

        if not data:
            return {
                "url": url,
                "file_info": headers_info,
                "error": headers_info.get("error", "Failed to download file"),
                "exif_data": {},
                "gps_coordinates": None,
                "document_metadata": {},
                "security_findings": [],
            }

        # Detect file type
        detected_type = file_type_hint
        if file_type_hint == "auto":
            detected_type = self._detect_file_type(
                headers_info.get("content_type", ""), url,
            )

        file_info = {
            **headers_info,
            "detected_type": detected_type,
            "downloaded_size": len(data),
            "url": url,
        }

        exif_data: dict[str, Any] = {}
        gps_coordinates: dict[str, Any] | None = None
        document_metadata: dict[str, Any] = {}

        if detected_type == "image":
            exif_data = self._parse_exif_from_jpeg(data)
            if extract_gps and "gps_raw" in exif_data:
                gps_coordinates = self._convert_gps_coordinates(exif_data.pop("gps_raw"))

        elif detected_type == "pdf":
            document_metadata = self._extract_pdf_metadata(data)

        elif detected_type == "document":
            document_metadata = self._extract_docx_metadata(data)

        # Assess security/privacy findings
        security_findings = self._assess_security_findings(
            exif_data, gps_coordinates, document_metadata, detected_type,
        )

        return {
            "url": url,
            "file_info": file_info,
            "exif_data": exif_data,
            "gps_coordinates": gps_coordinates,
            "document_metadata": document_metadata,
            "security_findings": security_findings,
            "total_findings": len(security_findings),
        }
