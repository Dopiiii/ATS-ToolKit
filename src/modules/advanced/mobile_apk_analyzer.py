"""Android APK metadata and security analyzer.

Analyzes APK files by parsing the ZIP structure to extract manifest data,
permissions, debug flags, and potential security issues.
"""

import asyncio
import re
import math
import json
import zipfile
import struct
from typing import Any
from pathlib import Path

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "Access contacts",
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.CALL_PHONE": "Make phone calls",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.CAMERA": "Access camera",
    "android.permission.RECORD_AUDIO": "Record audio",
    "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write external storage",
    "android.permission.READ_PHONE_STATE": "Read phone state/IMEI",
    "android.permission.INTERNET": "Full network access",
    "android.permission.ACCESS_WIFI_STATE": "View WiFi connections",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Run at startup",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over other apps",
    "android.permission.INSTALL_PACKAGES": "Install packages",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Request package install",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service binding",
    "android.permission.BIND_DEVICE_ADMIN": "Device admin binding",
}

SUSPICIOUS_PATTERNS = {
    "native_code": {"extensions": [".so"], "risk": "Native code libraries detected"},
    "dynamic_loading": {"patterns": ["DexClassLoader", "PathClassLoader", "loadClass"],
                        "risk": "Dynamic code loading capability"},
    "reflection": {"patterns": ["java.lang.reflect", "Method.invoke"],
                   "risk": "Java reflection usage detected"},
    "crypto": {"patterns": ["javax.crypto", "Cipher.getInstance"],
               "risk": "Cryptographic operations detected"},
    "root_detection": {"patterns": ["su ", "/system/xbin/su", "Superuser.apk"],
                       "risk": "Root detection mechanisms"},
}


class MobileApkAnalyzerModule(AtsModule):
    """Analyze Android APK files for security metadata and permission issues."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="mobile_apk_analyzer",
            category=ModuleCategory.ADVANCED,
            description="Analyze APK metadata, permissions, and security flags",
            version="1.0.0",
            parameters=[
                Parameter(name="file_path", type=ParameterType.FILE,
                          description="Path to the APK file", required=True),
                Parameter(name="analysis_depth", type=ParameterType.CHOICE,
                          description="Depth of analysis to perform",
                          choices=["manifest", "permissions", "all"], default="all"),
                Parameter(name="check_signatures", type=ParameterType.BOOLEAN,
                          description="Verify APK signing certificate info",
                          default=True),
            ],
            outputs=[
                OutputField(name="package_info", type="dict", description="Package name and version"),
                OutputField(name="permissions", type="list", description="Requested permissions"),
                OutputField(name="security_findings", type="list", description="Security issues found"),
            ],
            tags=["advanced", "mobile", "android", "apk", "security"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        file_path = config.get("file_path", "").strip()
        if not file_path:
            return False, "APK file path is required"
        path = Path(file_path)
        if not path.exists():
            return False, f"File not found: {file_path}"
        if not path.suffix.lower() == ".apk":
            return False, "File must have .apk extension"
        return True, ""

    def _parse_binary_xml_strings(self, data: bytes) -> list[str]:
        """Extract readable strings from Android binary XML."""
        strings = []
        text = data.decode("utf-8", errors="ignore")
        for match in re.finditer(r'[\x20-\x7e]{4,}', text):
            strings.append(match.group())
        for match in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', data):
            decoded = match.group().decode("utf-16-le", errors="ignore")
            if decoded and decoded not in strings:
                strings.append(decoded)
        return strings

    def _extract_permissions(self, strings: list[str]) -> list[dict[str, Any]]:
        """Identify Android permissions from extracted strings."""
        permissions = []
        seen = set()
        for s in strings:
            if "android.permission." in s:
                perm_match = re.search(r'(android\.permission\.[A-Z_]+)', s)
                if perm_match:
                    perm = perm_match.group(1)
                    if perm not in seen:
                        seen.add(perm)
                        is_dangerous = perm in DANGEROUS_PERMISSIONS
                        permissions.append({
                            "permission": perm,
                            "dangerous": is_dangerous,
                            "description": DANGEROUS_PERMISSIONS.get(perm, "Standard permission"),
                        })
        return permissions

    def _analyze_file_structure(self, zf: zipfile.ZipFile) -> dict[str, Any]:
        """Analyze the APK ZIP structure for security indicators."""
        structure = {"total_files": len(zf.namelist()), "dex_files": [], "native_libs": [],
                     "assets": [], "raw_resources": 0, "total_size": 0}
        for info in zf.infolist():
            structure["total_size"] += info.file_size
            name = info.filename
            if name.endswith(".dex"):
                structure["dex_files"].append(name)
            elif name.endswith(".so"):
                structure["native_libs"].append(name)
            elif name.startswith("assets/"):
                structure["assets"].append(name)
            elif name.startswith("res/"):
                structure["raw_resources"] += 1
        return structure

    def _check_debug_flags(self, strings: list[str]) -> list[dict[str, Any]]:
        """Check for debug flags and backup allowances."""
        findings = []
        combined = " ".join(strings).lower()
        if "debuggable" in combined and "true" in combined:
            findings.append({"type": "debug_enabled", "severity": "high",
                             "detail": "Application has debuggable flag enabled"})
        if "allowbackup" in combined and "true" in combined:
            findings.append({"type": "backup_enabled", "severity": "medium",
                             "detail": "Application allows backup - data can be extracted"})
        if "usescleartexttraffic" in combined or "usesCleartextTraffic" in " ".join(strings):
            findings.append({"type": "cleartext_traffic", "severity": "high",
                             "detail": "Application may allow cleartext HTTP traffic"})
        if "exported" in combined and "true" in combined:
            findings.append({"type": "exported_components", "severity": "medium",
                             "detail": "Exported components detected - potential attack surface"})
        return findings

    def _check_suspicious_content(self, zf: zipfile.ZipFile) -> list[dict[str, Any]]:
        """Scan file contents for suspicious patterns."""
        findings = []
        for name in zf.namelist():
            if name.endswith(".dex"):
                try:
                    data = zf.read(name)
                    text = data.decode("utf-8", errors="ignore")
                    for category, info in SUSPICIOUS_PATTERNS.items():
                        patterns = info.get("patterns", [])
                        for pattern in patterns:
                            if pattern in text:
                                findings.append({
                                    "type": category, "severity": "medium",
                                    "detail": info["risk"],
                                    "location": name,
                                })
                                break
                except Exception:
                    continue
        return findings

    def _extract_package_info(self, strings: list[str]) -> dict[str, Any]:
        """Extract package name and version from manifest strings."""
        info = {"package_name": None, "version_name": None, "min_sdk": None, "target_sdk": None}
        for s in strings:
            if re.match(r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2,}$', s) and not info["package_name"]:
                info["package_name"] = s
            if re.match(r'^\d+\.\d+(\.\d+)*$', s) and not info["version_name"]:
                info["version_name"] = s
        return info

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        file_path = config["file_path"].strip()
        analysis_depth = config.get("analysis_depth", "all")
        check_sigs = config.get("check_signatures", True)

        findings: list[dict[str, Any]] = []
        permissions: list[dict[str, Any]] = []
        package_info: dict[str, Any] = {}
        structure: dict[str, Any] = {}

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                structure = self._analyze_file_structure(zf)

                manifest_strings: list[str] = []
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_data = zf.read("AndroidManifest.xml")
                    manifest_strings = self._parse_binary_xml_strings(manifest_data)
                    package_info = self._extract_package_info(manifest_strings)
                else:
                    findings.append({"type": "missing_manifest", "severity": "critical",
                                     "detail": "AndroidManifest.xml not found in APK"})

                if analysis_depth in ("permissions", "all"):
                    permissions = self._extract_permissions(manifest_strings)
                    dangerous_count = sum(1 for p in permissions if p["dangerous"])
                    if dangerous_count >= 5:
                        findings.append({"type": "excessive_permissions", "severity": "high",
                                         "detail": f"{dangerous_count} dangerous permissions requested"})

                if analysis_depth == "all":
                    findings.extend(self._check_debug_flags(manifest_strings))
                    findings.extend(self._check_suspicious_content(zf))

                if check_sigs:
                    cert_files = [n for n in zf.namelist()
                                  if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
                    if not cert_files:
                        findings.append({"type": "unsigned", "severity": "critical",
                                         "detail": "No signing certificate found in APK"})
                    else:
                        package_info["signing_files"] = cert_files

                if len(structure.get("dex_files", [])) > 1:
                    findings.append({"type": "multidex", "severity": "low",
                                     "detail": f"Multi-DEX app with {len(structure['dex_files'])} DEX files"})

        except zipfile.BadZipFile:
            return {"error": "Invalid or corrupted APK file", "security_findings": [],
                    "permissions": [], "package_info": {}}

        risk_score = sum({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
            f["severity"], 1) for f in findings)

        return {
            "file_path": file_path,
            "package_info": package_info,
            "permissions": permissions,
            "dangerous_permission_count": sum(1 for p in permissions if p["dangerous"]),
            "file_structure": structure,
            "security_findings": findings,
            "finding_count": len(findings),
            "risk_score": min(10, round(risk_score / max(len(findings), 1), 1)),
        }
