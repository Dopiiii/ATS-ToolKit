"""Windows registry forensic analyzer module.

Analyze Windows registry hive data for forensic artifacts including
MRU lists, USB device history, installed programs, user activity, and autorun entries.
"""

import asyncio
import os
import re
import struct
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timedelta

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Registry hive file signatures
REG_HIVE_SIGNATURE = b"regf"

# Known forensic registry paths
FORENSIC_KEYS = {
    "autorun": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ],
    "usb_history": [
        r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        r"SYSTEM\CurrentControlSet\Enum\USB",
        r"SYSTEM\MountedDevices",
    ],
    "installed_programs": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ],
    "user_activity": [
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    ],
    "network": [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures",
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    ],
    "services": [
        r"SYSTEM\CurrentControlSet\Services",
    ],
    "shellbags": [
        r"NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU",
        r"NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags",
    ],
}


class RegistryAnalyzerModule(AtsModule):
    """Analyze Windows registry hive data for forensic artifacts."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="registry_analyzer",
            category=ModuleCategory.FORENSICS,
            description="Analyze Windows registry hive data for forensic artifacts including MRU lists, USB history, installed programs, user activity, and autorun entries",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="hive_path",
                    type=ParameterType.FILE,
                    description="Path to the registry hive file (e.g. NTUSER.DAT, SOFTWARE, SYSTEM)",
                    required=True,
                ),
                Parameter(
                    name="artifact_types",
                    type=ParameterType.LIST,
                    description="Types of artifacts to search for (autorun, usb_history, installed_programs, user_activity, network, services, shellbags). Empty means all.",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="search_pattern",
                    type=ParameterType.STRING,
                    description="Regex pattern to search for in registry key names and values",
                    required=False,
                    default="",
                ),
                Parameter(
                    name="extract_timestamps",
                    type=ParameterType.BOOLEAN,
                    description="Attempt to extract and parse key last-write timestamps",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="hive_info", type="dict", description="Registry hive metadata"),
                OutputField(name="artifacts", type="dict", description="Discovered artifacts by category"),
                OutputField(name="autorun_entries", type="list", description="Autorun/persistence entries"),
                OutputField(name="usb_devices", type="list", description="USB device history"),
                OutputField(name="search_results", type="list", description="Custom pattern search results"),
                OutputField(name="total_artifacts", type="integer", description="Total artifacts found"),
            ],
            tags=["forensics", "registry", "windows", "persistence", "usb", "mru"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        hive_path = config.get("hive_path", "").strip()
        if not hive_path:
            return False, "hive_path is required"
        if not os.path.isfile(hive_path):
            return False, f"Hive file not found: {hive_path}"

        search_pattern = config.get("search_pattern", "")
        if search_pattern:
            try:
                re.compile(search_pattern)
            except re.error as e:
                return False, f"Invalid search pattern: {e}"

        artifact_types = config.get("artifact_types", [])
        valid_types = set(FORENSIC_KEYS.keys())
        for at in artifact_types:
            if at not in valid_types:
                return False, f"Unknown artifact type: {at}. Valid types: {sorted(valid_types)}"

        return True, ""

    def _parse_filetime(self, ft_bytes: bytes) -> Optional[datetime]:
        """Parse a Windows FILETIME (64-bit value) to datetime."""
        try:
            ft = struct.unpack("<Q", ft_bytes)[0]
            if ft == 0:
                return None
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            epoch_diff = 116444736000000000  # difference between 1601 and 1970 in 100ns
            if ft < epoch_diff:
                return None
            timestamp = (ft - epoch_diff) / 10000000
            return datetime.fromtimestamp(timestamp)
        except (struct.error, OSError, OverflowError, ValueError):
            return None

    def _parse_regf_header(self, data: bytes) -> Dict[str, Any]:
        """Parse the registry hive file header."""
        info = {}
        if len(data) < 4096:
            return info

        sig = data[0:4]
        if sig != REG_HIVE_SIGNATURE:
            info["valid_signature"] = False
            return info

        info["valid_signature"] = True

        try:
            # Sequence numbers
            seq1 = struct.unpack_from("<I", data, 4)[0]
            seq2 = struct.unpack_from("<I", data, 8)[0]
            info["sequence1"] = seq1
            info["sequence2"] = seq2
            info["clean_shutdown"] = seq1 == seq2

            # Last write timestamp
            ts_bytes = data[12:20]
            ts = self._parse_filetime(ts_bytes)
            if ts:
                info["last_write_time"] = ts.isoformat()

            # Major/minor version
            major = struct.unpack_from("<I", data, 20)[0]
            minor = struct.unpack_from("<I", data, 24)[0]
            info["version"] = f"{major}.{minor}"

            # Hive type
            hive_type = struct.unpack_from("<I", data, 28)[0]
            info["hive_type"] = hive_type

            # Root cell offset
            root_offset = struct.unpack_from("<I", data, 36)[0]
            info["root_cell_offset"] = root_offset

            # Hive bins data size
            data_size = struct.unpack_from("<I", data, 40)[0]
            info["data_size"] = data_size

            # Filename embedded in header (at offset 48, UTF-16LE, up to 64 bytes)
            try:
                name_bytes = data[48:112]
                name = name_bytes.decode("utf-16-le", errors="ignore").strip("\x00")
                if name:
                    info["embedded_filename"] = name
            except (UnicodeDecodeError, IndexError):
                pass

        except struct.error:
            pass

        return info

    def _extract_strings_from_cells(self, data: bytes, max_items: int = 5000) -> List[Dict[str, Any]]:
        """Walk through registry bin cells extracting key names and values."""
        items = []
        offset = 4096  # Skip header (first 4096 bytes)
        data_len = len(data)

        while offset < data_len - 32 and len(items) < max_items:
            try:
                # Read cell size (negative means allocated)
                cell_size = struct.unpack_from("<i", data, offset)[0]
                abs_size = abs(cell_size)

                if abs_size < 8 or abs_size > 1024 * 1024:
                    offset += 8
                    continue

                is_allocated = cell_size < 0

                if is_allocated and abs_size >= 24:
                    cell_data = data[offset + 4:offset + abs_size]

                    # Check for NK (named key) signature
                    if len(cell_data) >= 20 and cell_data[0:2] == b"nk":
                        flags = struct.unpack_from("<H", cell_data, 2)[0]
                        ts_bytes = cell_data[4:12]
                        ts = self._parse_filetime(ts_bytes)
                        name_length = struct.unpack_from("<H", cell_data, 72)[0] if len(cell_data) > 74 else 0
                        key_name = ""
                        if name_length > 0 and len(cell_data) > 76 + name_length:
                            try:
                                key_name = cell_data[76:76 + name_length].decode("ascii", errors="ignore")
                            except (UnicodeDecodeError, IndexError):
                                pass

                        if key_name:
                            items.append({
                                "type": "key",
                                "name": key_name,
                                "offset": offset,
                                "timestamp": ts.isoformat() if ts else None,
                                "flags": flags,
                            })

                    # Check for VK (value key) signature
                    elif len(cell_data) >= 20 and cell_data[0:2] == b"vk":
                        name_length = struct.unpack_from("<H", cell_data, 2)[0]
                        data_length = struct.unpack_from("<I", cell_data, 4)[0]
                        data_type = struct.unpack_from("<I", cell_data, 12)[0]
                        value_name = ""
                        if name_length > 0 and len(cell_data) > 20 + name_length:
                            try:
                                value_name = cell_data[20:20 + name_length].decode("ascii", errors="ignore")
                            except (UnicodeDecodeError, IndexError):
                                pass

                        # Read inline data for small values
                        value_data = ""
                        if data_length > 0 and data_length < 5:
                            raw = cell_data[8:12]
                            if data_type == 4:  # REG_DWORD
                                value_data = str(struct.unpack_from("<I", raw, 0)[0])
                            else:
                                value_data = raw[:data_length].decode("ascii", errors="ignore")
                        elif data_length > 0x80000000:
                            # Data is stored inline
                            real_len = data_length & 0x7FFFFFFF
                            if real_len <= 4:
                                raw = cell_data[8:12]
                                value_data = raw[:real_len].decode("ascii", errors="ignore")

                        items.append({
                            "type": "value",
                            "name": value_name or "(Default)",
                            "data_type": data_type,
                            "data_length": data_length & 0x7FFFFFFF,
                            "data_preview": value_data[:200] if value_data else "",
                            "offset": offset,
                        })

                offset += abs_size if abs_size >= 8 else 8

            except struct.error:
                offset += 8
                continue

        return items

    def _categorize_artifacts(self, items: List[Dict[str, Any]], artifact_types: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize extracted registry items into forensic artifact categories."""
        categories = {at: [] for at in (artifact_types if artifact_types else FORENSIC_KEYS.keys())}

        for item in items:
            name = item.get("name", "").lower()

            # Autorun detection
            if "autorun" in categories:
                if any(kw in name for kw in ("run", "runonce", "runservices", "startup")):
                    categories["autorun"].append(item)

            # USB history
            if "usb_history" in categories:
                if any(kw in name for kw in ("usbstor", "usb", "mounteddevices", "portable")):
                    categories["usb_history"].append(item)

            # Installed programs
            if "installed_programs" in categories:
                if any(kw in name for kw in ("uninstall", "displayname", "installdate", "publisher")):
                    categories["installed_programs"].append(item)

            # User activity
            if "user_activity" in categories:
                if any(kw in name for kw in ("recentdocs", "mru", "typedpaths", "wordwheel",
                                              "comdlg32", "opensave", "lastvisited")):
                    categories["user_activity"].append(item)

            # Network
            if "network" in categories:
                if any(kw in name for kw in ("networklist", "tcpip", "interfaces", "profilename")):
                    categories["network"].append(item)

            # Services
            if "services" in categories:
                if any(kw in name for kw in ("imagepath", "start", "type", "servicedll")):
                    categories["services"].append(item)

            # Shellbags
            if "shellbags" in categories:
                if any(kw in name for kw in ("bagmru", "bags", "shell")):
                    categories["shellbags"].append(item)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v}

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        hive_path = config["hive_path"].strip()
        artifact_types = config.get("artifact_types", [])
        search_pattern = config.get("search_pattern", "")
        extract_timestamps = config.get("extract_timestamps", True)

        self.logger.info("analyzing_registry_hive", path=hive_path)

        loop = asyncio.get_event_loop()

        def _analyze():
            with open(hive_path, "rb") as fh:
                data = fh.read()

            # Parse header
            hive_info = self._parse_regf_header(data)
            hive_info["file_size"] = len(data)
            hive_info["file_path"] = hive_path

            # Extract registry cells
            items = self._extract_strings_from_cells(data)

            # Categorize artifacts
            artifacts = self._categorize_artifacts(items, artifact_types)

            # Extract autorun entries specifically
            autorun_entries = []
            for item in artifacts.get("autorun", []):
                if item.get("type") == "value" and item.get("data_preview"):
                    autorun_entries.append({
                        "name": item["name"],
                        "value": item["data_preview"],
                        "offset": item["offset"],
                    })

            # Extract USB devices specifically
            usb_devices = []
            for item in artifacts.get("usb_history", []):
                if item.get("type") == "key":
                    usb_devices.append({
                        "name": item["name"],
                        "timestamp": item.get("timestamp"),
                        "offset": item["offset"],
                    })

            # Custom pattern search
            search_results = []
            if search_pattern:
                try:
                    pattern = re.compile(search_pattern, re.IGNORECASE)
                    for item in items:
                        name = item.get("name", "")
                        data_preview = item.get("data_preview", "")
                        if pattern.search(name) or pattern.search(data_preview):
                            search_results.append(item)
                except re.error:
                    pass

            # Timeline of key timestamps
            if extract_timestamps:
                timestamped = [
                    item for item in items
                    if item.get("timestamp") and item.get("type") == "key"
                ]
                timestamped.sort(key=lambda x: x.get("timestamp", ""))
                hive_info["key_timeline_count"] = len(timestamped)
                if timestamped:
                    hive_info["earliest_key"] = timestamped[0].get("timestamp")
                    hive_info["latest_key"] = timestamped[-1].get("timestamp")

            total = sum(len(v) for v in artifacts.values())

            return {
                "hive_info": hive_info,
                "artifacts": {k: v[:200] for k, v in artifacts.items()},
                "autorun_entries": autorun_entries[:100],
                "usb_devices": usb_devices[:100],
                "search_results": search_results[:200],
                "total_artifacts": total,
                "total_items_parsed": len(items),
            }

        result = await loop.run_in_executor(None, _analyze)

        self.logger.info(
            "registry_analysis_complete",
            total_artifacts=result["total_artifacts"],
            items_parsed=result["total_items_parsed"],
        )

        return result
