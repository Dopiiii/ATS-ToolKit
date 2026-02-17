"""Mobile application privacy compliance auditor.

Audits mobile app metadata for privacy compliance against GDPR, CCPA, and other
frameworks by analyzing permissions, trackers, and data collection practices.
"""

import asyncio
import re
import math
import json
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

KNOWN_TRACKERS = {
    "com.google.firebase.analytics": {"name": "Firebase Analytics", "category": "analytics"},
    "com.google.android.gms.analytics": {"name": "Google Analytics", "category": "analytics"},
    "com.facebook.appevents": {"name": "Facebook Events", "category": "advertising"},
    "com.facebook.ads": {"name": "Facebook Ads", "category": "advertising"},
    "com.appsflyer": {"name": "AppsFlyer", "category": "attribution"},
    "com.adjust.sdk": {"name": "Adjust", "category": "attribution"},
    "com.mixpanel": {"name": "Mixpanel", "category": "analytics"},
    "com.amplitude": {"name": "Amplitude", "category": "analytics"},
    "com.crashlytics": {"name": "Crashlytics", "category": "crash_reporting"},
    "io.sentry": {"name": "Sentry", "category": "crash_reporting"},
    "com.braze": {"name": "Braze", "category": "marketing"},
    "com.onesignal": {"name": "OneSignal", "category": "push"},
    "com.segment": {"name": "Segment", "category": "analytics"},
    "com.mopub": {"name": "MoPub", "category": "advertising"},
    "com.unity3d.ads": {"name": "Unity Ads", "category": "advertising"},
    "com.google.ads": {"name": "Google Ads", "category": "advertising"},
    "com.applovin": {"name": "AppLovin", "category": "advertising"},
    "com.chartboost": {"name": "Chartboost", "category": "advertising"},
}

PERMISSION_DATA_MAP = {
    "android.permission.ACCESS_FINE_LOCATION": "precise_location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate_location",
    "android.permission.CAMERA": "camera_images",
    "android.permission.RECORD_AUDIO": "audio_recordings",
    "android.permission.READ_CONTACTS": "contact_list",
    "android.permission.READ_SMS": "sms_messages",
    "android.permission.READ_CALL_LOG": "call_history",
    "android.permission.READ_CALENDAR": "calendar_events",
    "android.permission.READ_EXTERNAL_STORAGE": "device_files",
    "android.permission.READ_PHONE_STATE": "device_identifiers",
    "android.permission.BODY_SENSORS": "health_data",
    "android.permission.ACTIVITY_RECOGNITION": "physical_activity",
    "android.permission.ACCESS_WIFI_STATE": "wifi_information",
    "android.permission.BLUETOOTH": "bluetooth_data",
}

GDPR_REQUIREMENTS = [
    {"id": "consent", "name": "User Consent", "description": "Explicit opt-in consent before data collection"},
    {"id": "purpose", "name": "Purpose Limitation", "description": "Data collected only for stated purposes"},
    {"id": "minimization", "name": "Data Minimization", "description": "Only necessary data collected"},
    {"id": "retention", "name": "Retention Policy", "description": "Clear data retention periods"},
    {"id": "portability", "name": "Data Portability", "description": "User can export their data"},
    {"id": "deletion", "name": "Right to Erasure", "description": "User can request data deletion"},
    {"id": "transparency", "name": "Transparency", "description": "Clear privacy policy available"},
    {"id": "dpo", "name": "Data Protection Officer", "description": "DPO contact available"},
]

CCPA_REQUIREMENTS = [
    {"id": "disclosure", "name": "Data Disclosure", "description": "Disclose what data is collected"},
    {"id": "opt_out", "name": "Opt-Out of Sale", "description": "Option to opt out of data sale"},
    {"id": "non_discrimination", "name": "Non-Discrimination", "description": "Equal service regardless of opt-out"},
    {"id": "access", "name": "Right to Know", "description": "User can request collected data"},
    {"id": "deletion", "name": "Right to Delete", "description": "User can request data deletion"},
    {"id": "notice", "name": "Notice at Collection", "description": "Privacy notice at data collection point"},
]


class MobilePrivacyAuditModule(AtsModule):
    """Audit mobile app metadata for privacy compliance."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="mobile_privacy_audit",
            category=ModuleCategory.ADVANCED,
            description="Audit mobile app privacy practices against GDPR and CCPA frameworks",
            version="1.0.0",
            parameters=[
                Parameter(name="app_metadata", type=ParameterType.STRING,
                          description="App metadata as JSON (permissions, packages, privacy policy URL)",
                          required=True),
                Parameter(name="privacy_framework", type=ParameterType.CHOICE,
                          description="Compliance framework to audit against",
                          choices=["gdpr", "ccpa", "all"], default="all"),
                Parameter(name="strict_mode", type=ParameterType.BOOLEAN,
                          description="Apply strict interpretation of regulations",
                          default=False),
            ],
            outputs=[
                OutputField(name="compliance_score", type="float",
                            description="Overall compliance score 0-100"),
                OutputField(name="trackers_found", type="list",
                            description="Identified third-party trackers"),
                OutputField(name="findings", type="list",
                            description="Privacy compliance findings"),
            ],
            tags=["advanced", "mobile", "privacy", "gdpr", "ccpa", "compliance"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("app_metadata", "").strip()
        if not raw:
            return False, "App metadata JSON is required"
        try:
            json.loads(raw)
        except json.JSONDecodeError:
            return False, "App metadata must be valid JSON"
        return True, ""

    def _detect_trackers(self, meta: dict[str, Any]) -> list[dict[str, Any]]:
        """Identify known trackers from app package/library metadata."""
        trackers_found = []
        packages = meta.get("packages", []) + meta.get("libraries", []) + meta.get("sdks", [])
        meta_str = json.dumps(meta).lower()

        seen = set()
        for tracker_id, info in KNOWN_TRACKERS.items():
            if tracker_id.lower() in meta_str or any(tracker_id.lower() in p.lower() for p in packages):
                if tracker_id not in seen:
                    seen.add(tracker_id)
                    trackers_found.append({
                        "tracker_id": tracker_id,
                        "name": info["name"],
                        "category": info["category"],
                    })
        return trackers_found

    def _analyze_permissions(self, meta: dict[str, Any]) -> dict[str, Any]:
        """Analyze permissions to determine data collection scope."""
        permissions = meta.get("permissions", [])
        data_collected: list[str] = []
        excessive: list[dict[str, str]] = []

        app_category = meta.get("category", "").lower()
        for perm in permissions:
            data_type = PERMISSION_DATA_MAP.get(perm)
            if data_type:
                data_collected.append(data_type)

        if "precise_location" in data_collected and app_category not in (
                "navigation", "maps", "weather", "fitness", "travel"):
            excessive.append({"permission": "ACCESS_FINE_LOCATION",
                              "reason": "Precise location unnecessary for app category"})
        if "contact_list" in data_collected and app_category not in (
                "social", "messaging", "communication"):
            excessive.append({"permission": "READ_CONTACTS",
                              "reason": "Contact access unnecessary for app category"})
        if "sms_messages" in data_collected and app_category not in ("messaging", "security"):
            excessive.append({"permission": "READ_SMS",
                              "reason": "SMS access rarely justified"})
        if "audio_recordings" in data_collected and app_category not in (
                "communication", "music", "voice"):
            excessive.append({"permission": "RECORD_AUDIO",
                              "reason": "Audio recording unnecessary for app category"})

        return {"data_collected": data_collected, "excessive_permissions": excessive,
                "total_permissions": len(permissions),
                "sensitive_permissions": len(data_collected)}

    def _audit_gdpr(self, meta: dict[str, Any], trackers: list, perm_analysis: dict,
                    strict: bool) -> list[dict[str, Any]]:
        """Audit against GDPR requirements."""
        findings = []
        has_privacy_policy = bool(meta.get("privacy_policy_url") or meta.get("privacy_policy"))
        has_consent_mechanism = meta.get("has_consent_dialog", False)
        has_data_export = meta.get("has_data_export", False)
        has_account_deletion = meta.get("has_account_deletion", False)

        if not has_consent_mechanism:
            findings.append({"requirement": "consent", "status": "fail", "severity": "critical",
                             "detail": "No consent mechanism detected for data collection"})
        else:
            findings.append({"requirement": "consent", "status": "pass", "severity": "info",
                             "detail": "Consent mechanism present"})

        if perm_analysis["excessive_permissions"]:
            details = "; ".join(e["reason"] for e in perm_analysis["excessive_permissions"])
            findings.append({"requirement": "minimization", "status": "fail", "severity": "high",
                             "detail": f"Data minimization concerns: {details}"})
        else:
            findings.append({"requirement": "minimization", "status": "pass", "severity": "info",
                             "detail": "Permissions appear proportional to app function"})

        if not has_privacy_policy:
            findings.append({"requirement": "transparency", "status": "fail", "severity": "critical",
                             "detail": "No privacy policy URL found"})
        else:
            findings.append({"requirement": "transparency", "status": "pass", "severity": "info",
                             "detail": "Privacy policy available"})

        if not has_data_export:
            sev = "high" if strict else "medium"
            findings.append({"requirement": "portability", "status": "fail", "severity": sev,
                             "detail": "No data export functionality detected"})

        if not has_account_deletion:
            findings.append({"requirement": "deletion", "status": "fail", "severity": "high",
                             "detail": "No account deletion option detected"})

        ad_trackers = [t for t in trackers if t["category"] == "advertising"]
        if ad_trackers and not has_consent_mechanism:
            findings.append({"requirement": "consent", "status": "fail", "severity": "critical",
                             "detail": f"{len(ad_trackers)} ad trackers without consent mechanism"})
        return findings

    def _audit_ccpa(self, meta: dict[str, Any], trackers: list, perm_analysis: dict,
                    strict: bool) -> list[dict[str, Any]]:
        """Audit against CCPA requirements."""
        findings = []
        has_privacy_policy = bool(meta.get("privacy_policy_url") or meta.get("privacy_policy"))
        has_opt_out = meta.get("has_opt_out", False)
        has_data_request = meta.get("has_data_request", False)

        if not has_privacy_policy:
            findings.append({"requirement": "notice", "status": "fail", "severity": "critical",
                             "detail": "No privacy notice at collection"})

        ad_trackers = [t for t in trackers if t["category"] == "advertising"]
        if ad_trackers and not has_opt_out:
            findings.append({"requirement": "opt_out", "status": "fail", "severity": "critical",
                             "detail": f"{len(ad_trackers)} ad trackers but no opt-out of data sale"})
        elif has_opt_out:
            findings.append({"requirement": "opt_out", "status": "pass", "severity": "info",
                             "detail": "Opt-out mechanism available"})

        if not has_data_request:
            sev = "high" if strict else "medium"
            findings.append({"requirement": "access", "status": "fail", "severity": sev,
                             "detail": "No mechanism to request collected data"})

        if perm_analysis["sensitive_permissions"] > 5:
            findings.append({"requirement": "disclosure", "status": "warning", "severity": "medium",
                             "detail": f"{perm_analysis['sensitive_permissions']} sensitive data types "
                                       f"collected - ensure all are disclosed"})
        return findings

    def _compute_score(self, findings: list[dict]) -> float:
        """Compute compliance score from findings."""
        if not findings:
            return 100.0
        total = len(findings)
        pass_count = sum(1 for f in findings if f["status"] == "pass")
        penalty_map = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
        penalty = sum(penalty_map.get(f["severity"], 0) for f in findings if f["status"] != "pass")
        base = (pass_count / max(total, 1)) * 100
        return round(max(0, min(100, base - penalty)), 1)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        meta = json.loads(config["app_metadata"])
        framework = config.get("privacy_framework", "all")
        strict = config.get("strict_mode", False)

        trackers = self._detect_trackers(meta)
        perm_analysis = self._analyze_permissions(meta)

        findings: list[dict[str, Any]] = []
        if framework in ("gdpr", "all"):
            findings.extend(self._audit_gdpr(meta, trackers, perm_analysis, strict))
        if framework in ("ccpa", "all"):
            findings.extend(self._audit_ccpa(meta, trackers, perm_analysis, strict))

        score = self._compute_score(findings)

        tracker_summary = {}
        for t in trackers:
            cat = t["category"]
            tracker_summary[cat] = tracker_summary.get(cat, 0) + 1

        return {
            "framework": framework,
            "compliance_score": score,
            "trackers_found": trackers,
            "tracker_count": len(trackers),
            "tracker_categories": tracker_summary,
            "permission_analysis": perm_analysis,
            "findings": findings,
            "pass_count": sum(1 for f in findings if f["status"] == "pass"),
            "fail_count": sum(1 for f in findings if f["status"] == "fail"),
            "verdict": "COMPLIANT" if score >= 80 else "PARTIAL" if score >= 50 else "NON_COMPLIANT",
        }
