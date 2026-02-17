"""Incident response procedure generator module.

Generates phase-by-phase incident response plans with action items,
evidence checklists, communication templates, and escalation matrices.
"""

import asyncio
import json
import re
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

IR_PHASES = ["Preparation", "Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"]
INCIDENT_ACTIONS: dict[str, dict[str, list[str]]] = {
    "malware": {
        "Preparation": ["Ensure AV/EDR agents are deployed and updated", "Verify backup integrity and isolation", "Confirm network segmentation controls"],
        "Identification": ["Analyze alerts from EDR/AV for IOCs", "Identify patient zero and infection vector", "Determine malware family and capabilities", "Check for lateral movement indicators"],
        "Containment": ["Isolate infected hosts from network", "Block C2 domains/IPs at firewall", "Disable compromised accounts", "Preserve forensic images before cleanup"],
        "Eradication": ["Remove malware artifacts from all affected systems", "Patch exploited vulnerabilities", "Reset credentials for compromised accounts", "Scan all endpoints for remaining IOCs"],
        "Recovery": ["Restore systems from verified clean backups", "Re-enable network access incrementally", "Monitor for reinfection indicators", "Validate system integrity post-restore"],
        "Lessons Learned": ["Document initial infection vector", "Review detection time and response efficacy", "Update AV/EDR signatures and rules", "Conduct tabletop exercise based on incident"],
    },
    "phishing": {
        "Preparation": ["Deploy email security gateway with anti-phishing", "Conduct security awareness training", "Establish phishing report mechanism"],
        "Identification": ["Analyze reported email headers and links", "Identify all recipients of phishing email", "Determine if credentials were submitted", "Check for payload downloads"],
        "Containment": ["Block sender domain and URLs", "Quarantine phishing emails from all mailboxes", "Force password reset for compromised users", "Revoke active sessions for affected accounts"],
        "Eradication": ["Remove all phishing emails from environment", "Scan for downloaded payloads on endpoints", "Revoke any OAuth tokens granted via phishing"],
        "Recovery": ["Restore compromised accounts with new credentials", "Re-enable MFA for affected accounts", "Monitor for unauthorized access using stolen credentials"],
        "Lessons Learned": ["Analyze phishing campaign characteristics", "Update email filtering rules", "Schedule targeted awareness training", "Review MFA coverage gaps"],
    },
    "data_breach": {
        "Preparation": ["Classify and inventory sensitive data stores", "Implement DLP controls and monitoring", "Establish legal and PR contacts for breach response"],
        "Identification": ["Determine scope of data accessed/exfiltrated", "Identify affected data subjects and types", "Determine attack vector and timeline", "Assess if data was encrypted at rest"],
        "Containment": ["Revoke access for threat actor", "Block exfiltration channels", "Preserve evidence of data access", "Engage legal counsel immediately"],
        "Eradication": ["Close the access vector used for breach", "Audit all access controls on affected systems", "Rotate all keys and credentials for affected services"],
        "Recovery": ["Implement enhanced monitoring on affected data", "Deploy additional DLP controls", "Notify affected parties per regulatory requirements", "Engage credit monitoring if PII involved"],
        "Lessons Learned": ["Document full breach timeline", "Calculate breach impact and cost", "Review data classification and access controls", "Update incident response plan with findings"],
    },
    "ddos": {
        "Preparation": ["Deploy DDoS mitigation service", "Document baseline traffic patterns", "Establish ISP emergency contacts"],
        "Identification": ["Analyze traffic patterns for attack type (volumetric/protocol/application)", "Identify source IPs and attack vectors", "Determine targeted services and impact"],
        "Containment": ["Activate DDoS mitigation/scrubbing", "Implement rate limiting at edge", "Enable geo-blocking if applicable", "Scale infrastructure if possible"],
        "Eradication": ["Fine-tune filtering rules for attack traffic", "Block confirmed attack source ranges", "Validate mitigation effectiveness"],
        "Recovery": ["Gradually remove emergency filters", "Restore normal traffic routing", "Monitor for renewed attack attempts", "Verify all services are fully operational"],
        "Lessons Learned": ["Analyze attack characteristics and duration", "Review mitigation response time", "Update DDoS runbooks", "Consider CDN or additional mitigation capacity"],
    },
    "insider": {
        "Preparation": ["Implement privileged access management", "Deploy user behavior analytics (UBA)", "Establish HR and legal coordination procedures"],
        "Identification": ["Review UBA/SIEM alerts for anomalous activity", "Correlate access logs with HR reports", "Determine scope of unauthorized actions", "Identify data accessed or modified"],
        "Containment": ["Disable insider's accounts immediately", "Revoke all access badges and VPN", "Preserve insider's workstation forensically", "Restrict access to systems the insider touched"],
        "Eradication": ["Audit all changes made by insider", "Revert unauthorized modifications", "Rotate secrets the insider had access to", "Review and revoke any backdoor accounts"],
        "Recovery": ["Redistribute insider's legitimate responsibilities", "Implement enhanced monitoring on affected systems", "Review and tighten access controls"],
        "Lessons Learned": ["Review hiring and offboarding processes", "Enhance separation of duties", "Update insider threat detection rules", "Conduct insider threat awareness training"],
    },
}
EVIDENCE_CHECKLISTS: dict[str, list[str]] = {
    "malware": ["Memory dumps from infected hosts", "Malware samples (quarantined)", "Network traffic captures (PCAP)", "EDR/AV logs and alerts", "System event logs", "File system timeline", "Registry changes (Windows)"],
    "phishing": ["Original phishing email (with headers)", "Screenshots of phishing page", "Email gateway logs", "Web proxy logs for URL access", "Authentication logs for compromised accounts", "Email delivery reports"],
    "data_breach": ["Access logs for breached systems", "Data flow logs and DLP alerts", "Firewall and proxy logs", "Database query logs", "File access audit logs", "Network traffic captures"],
    "ddos": ["Network flow data (NetFlow/sFlow)", "Firewall logs", "Load balancer logs", "CDN/DDoS mitigation logs", "Application performance metrics", "ISP communication records"],
    "insider": ["User access logs", "VPN and badge access records", "Email and messaging logs", "File access and copy logs", "USB/removable media logs", "Workstation forensic image", "CCTV footage if applicable"],
}


class IncidentResponderModule(AtsModule):
    """Generate incident response procedures and action plans."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="incident_responder",
            category=ModuleCategory.ADVANCED,
            description="Generate phase-by-phase incident response plans with checklists, communications, and escalation matrices",
            version="1.0.0",
            parameters=[
                Parameter(name="incident_type", type=ParameterType.CHOICE,
                          description="Type of security incident",
                          choices=["malware", "phishing", "data_breach", "ddos", "insider"]),
                Parameter(name="severity", type=ParameterType.CHOICE,
                          description="Incident severity level",
                          choices=["low", "medium", "high", "critical"], default="medium"),
                Parameter(name="org_type", type=ParameterType.CHOICE,
                          description="Organization type for tailored response",
                          choices=["small", "enterprise"], default="enterprise"),
            ],
            outputs=[
                OutputField(name="ir_plan", type="dict", description="Phase-by-phase incident response plan"),
                OutputField(name="checklist", type="list", description="Evidence collection checklist"),
                OutputField(name="communications", type="dict", description="Communication templates"),
                OutputField(name="timeline", type="dict", description="Expected response timeline"),
            ],
            tags=["advanced", "incident-response", "ir", "security-operations"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        inc_type = config.get("incident_type", "")
        if inc_type not in INCIDENT_ACTIONS:
            return False, f"Unsupported incident type '{inc_type}'"
        return True, ""

    def _build_ir_plan(self, inc_type: str, severity: str, org_type: str) -> dict[str, Any]:
        """Build full IR plan with phases and actions."""
        actions = INCIDENT_ACTIONS[inc_type]
        phases = []
        for phase in IR_PHASES:
            phase_actions = actions.get(phase, [])
            if org_type == "small" and len(phase_actions) > 3:
                phase_actions = phase_actions[:3]
            phases.append({
                "phase": phase,
                "actions": phase_actions,
                "owner": self._get_phase_owner(phase, org_type),
                "priority": "critical" if phase in ("Containment", "Identification") and severity in ("critical", "high") else "high" if phase in ("Eradication", "Recovery") else "standard",
            })
        return {"incident_type": inc_type, "severity": severity, "org_type": org_type, "phases": phases}

    @staticmethod
    def _get_phase_owner(phase: str, org_type: str) -> str:
        """Determine phase owner based on org type."""
        owners_enterprise = {
            "Preparation": "Security Operations Center (SOC)",
            "Identification": "SOC / Incident Response Team",
            "Containment": "Incident Response Team",
            "Eradication": "Incident Response Team / IT Operations",
            "Recovery": "IT Operations / System Owners",
            "Lessons Learned": "CISO / IR Team Lead",
        }
        owners_small = {
            "Preparation": "IT Manager",
            "Identification": "IT Team",
            "Containment": "IT Team",
            "Eradication": "IT Team / External Support",
            "Recovery": "IT Team",
            "Lessons Learned": "Management / IT Manager",
        }
        owners = owners_enterprise if org_type == "enterprise" else owners_small
        return owners.get(phase, "IT Team")

    def _build_communications(self, inc_type: str, severity: str, org_type: str) -> dict[str, Any]:
        """Generate communication templates for internal, external, and legal notifications."""
        inc_label = inc_type.replace("_", " ").title()
        internal = {
            "subject": f"[{severity.upper()}] Security Incident - {inc_label}",
            "body": (f"A {severity} severity {inc_label} incident has been identified. "
                     f"The incident response team has been activated. "
                     f"Please follow established protocols and direct all inquiries to the IR team lead. "
                     f"Do not discuss incident details outside authorized channels."),
            "recipients": ["IR Team", "IT Management", "CISO"] if org_type == "enterprise" else ["IT Team", "Management"],
        }
        external = {
            "subject": f"Security Notification - {inc_label}",
            "body": (f"We are writing to inform you of a security incident involving {inc_label.lower()}. "
                     f"Our security team is actively investigating and containing the situation. "
                     f"We are taking all necessary steps to protect affected systems and data. "
                     f"We will provide updates as our investigation progresses."),
            "use_when": "Required for data breaches affecting customers or regulatory notification",
        }
        legal = {
            "subject": f"Legal Notice - Security Incident #{inc_type[:4].upper()}",
            "body": (f"This communication is privileged and confidential. A {severity} severity "
                     f"{inc_label.lower()} incident has been detected. Legal review is requested for "
                     f"regulatory notification obligations and potential liability assessment."),
            "notify_within": "72 hours for GDPR, varies by jurisdiction",
        }
        escalation = self._build_escalation_matrix(severity, org_type)
        return {"internal": internal, "external": external, "legal": legal, "escalation_matrix": escalation}

    @staticmethod
    def _build_escalation_matrix(severity: str, org_type: str) -> list[dict]:
        """Build escalation matrix based on severity."""
        matrix = [
            {"level": 1, "role": "SOC Analyst" if org_type == "enterprise" else "IT Staff",
             "notify_within": "15 min", "applies_to": ["low", "medium", "high", "critical"]},
            {"level": 2, "role": "IR Team Lead" if org_type == "enterprise" else "IT Manager",
             "notify_within": "30 min", "applies_to": ["medium", "high", "critical"]},
            {"level": 3, "role": "CISO" if org_type == "enterprise" else "CEO/Owner",
             "notify_within": "1 hour", "applies_to": ["high", "critical"]},
            {"level": 4, "role": "Executive Leadership / Board",
             "notify_within": "4 hours", "applies_to": ["critical"]},
        ]
        return [e for e in matrix if severity in e["applies_to"]]

    @staticmethod
    def _build_timeline(severity: str) -> dict[str, Any]:
        """Build expected response timeline based on severity."""
        timelines = {
            "critical": {"detection_to_triage": "15 minutes", "triage_to_containment": "1 hour",
                         "containment_to_eradication": "4-8 hours", "eradication_to_recovery": "24-48 hours",
                         "lessons_learned": "Within 5 business days"},
            "high": {"detection_to_triage": "30 minutes", "triage_to_containment": "2 hours",
                     "containment_to_eradication": "8-24 hours", "eradication_to_recovery": "48-72 hours",
                     "lessons_learned": "Within 10 business days"},
            "medium": {"detection_to_triage": "1 hour", "triage_to_containment": "4 hours",
                       "containment_to_eradication": "24-48 hours", "eradication_to_recovery": "3-5 days",
                       "lessons_learned": "Within 15 business days"},
            "low": {"detection_to_triage": "4 hours", "triage_to_containment": "8 hours",
                    "containment_to_eradication": "3-5 days", "eradication_to_recovery": "5-10 days",
                    "lessons_learned": "Within 20 business days"},
        }
        return {"severity": severity, "milestones": timelines.get(severity, timelines["medium"])}

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        inc_type = config["incident_type"]
        severity = config.get("severity", "medium")
        org_type = config.get("org_type", "enterprise")

        ir_plan = self._build_ir_plan(inc_type, severity, org_type)
        checklist = EVIDENCE_CHECKLISTS.get(inc_type, [])
        communications = self._build_communications(inc_type, severity, org_type)
        timeline = self._build_timeline(severity)

        return {
            "ir_plan": ir_plan,
            "checklist": checklist,
            "communications": communications,
            "timeline": timeline,
        }
