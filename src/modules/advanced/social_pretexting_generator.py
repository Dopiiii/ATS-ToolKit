"""Generate social engineering pretexts for authorized penetration testing.

Creates realistic pretext scripts, phone scripts, and email templates
for helpdesk, vendor, executive, and new employee scenarios.
"""

import asyncio
import random
import re
from datetime import datetime
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

SCENARIO_TEMPLATES = {
    "helpdesk": {
        "role": "IT Helpdesk Technician",
        "basic": {
            "phone_opener": "Hi, this is {name} from IT Support. We're seeing some unusual activity on your account and need to verify a few things.",
            "email_subject": "Action Required: Account Security Verification",
            "email_body": "Dear {target_name},\n\nOur security monitoring system has flagged unusual activity on your {org} account. As part of our standard security protocol, we need to verify your identity.\n\nPlease click the link below to complete the verification process within 24 hours.\n\n[LINK]\n\nBest regards,\nIT Support Team\n{org}",
            "pretext_notes": ["Establish urgency via security alert", "Reference internal systems by name", "Use organization-specific terminology"],
        },
        "detailed": {
            "phone_opener": "Good {time_of_day}, this is {name} from {org}'s IT Security Operations Center. Badge number {badge}. We've been alerted to a potential compromise affecting accounts in your department. I need to walk you through our incident response procedure.",
            "phone_script": [
                "Introduce yourself with badge number and department",
                "Reference a recent real security incident in the news",
                "Explain that their department was flagged by the SIEM",
                "Request they verify their identity by confirming their employee ID",
                "Walk them through 'resetting' their credentials via a provided link",
                "Offer a callback number (controlled line) for verification",
            ],
            "email_subject": "URGENT: Security Incident Response - Immediate Action Required",
            "email_body": "Dear {target_name},\n\nThis message is from the {org} Security Operations Center (SOC).\n\nIncident ID: INC-{incident_id}\nSeverity: High\nDate Detected: {date}\n\nOur intrusion detection systems have identified potentially compromised credentials within your business unit. In accordance with {org}'s Incident Response Policy (IRP-{policy_num}), all affected users must re-authenticate through our secure portal.\n\nImmediate Actions Required:\n1. Navigate to the secure verification portal: [LINK]\n2. Authenticate using your current credentials\n3. Follow the guided password reset process\n4. Enable the new MFA token provided\n\nFailure to complete these steps within 4 hours may result in temporary account suspension per policy IRP-{policy_num} Section 4.2.\n\nIf you have questions, contact the SOC directly at ext. {extension}.\n\nRegards,\n{name}\nSenior Security Analyst\n{org} Security Operations Center",
            "pretext_notes": [
                "Reference specific internal policy numbers",
                "Include an incident ID for credibility",
                "Provide a controlled callback number",
                "Use time pressure with policy-backed consequences",
                "Mirror real incident response communications",
            ],
        },
    },
    "vendor": {
        "role": "Third-Party Vendor Representative",
        "basic": {
            "phone_opener": "Hello, this is {name} from {vendor_company}, your {service_type} provider. I'm calling about a scheduled maintenance that requires your coordination.",
            "email_subject": "Service Maintenance Notification - Credential Update Required",
            "email_body": "Dear {target_name},\n\nAs part of our scheduled system migration for {org}'s {service_type} service, we need to update the authentication tokens for your integration.\n\nPlease provide your current API credentials so we can ensure a seamless transition.\n\nTimeline: {date}\n\nContact: {name}\n{vendor_company}",
            "pretext_notes": ["Impersonate a known vendor", "Reference existing service agreements", "Create urgency via maintenance window"],
        },
        "detailed": {
            "phone_opener": "Hi, this is {name}, Senior Account Manager at {vendor_company}. I'm calling regarding contract {contract_id} for your {service_type} service. We have a critical platform migration happening {date} and I need to coordinate with your IT team.",
            "phone_script": [
                "Reference the specific vendor contract by number",
                "Mention recent legitimate communications from the vendor",
                "Explain a platform migration requiring credential rotation",
                "Request a technical contact who handles integrations",
                "Ask for current integration endpoints and credentials",
                "Offer to send 'updated documentation' (payload delivery)",
            ],
            "email_subject": "Contract {contract_id}: Urgent Platform Migration - Action Required by {date}",
            "email_body": "Dear {target_name},\n\nRe: Service Agreement {contract_id}\n\nI hope this email finds you well. As communicated in our Q{quarter} roadmap briefing, {vendor_company} is migrating our {service_type} platform to our next-generation infrastructure.\n\nKey Migration Details:\n- Migration Window: {date}\n- Estimated Downtime: 2-4 hours\n- Action Required: Credential rotation for API integrations\n\nTo ensure zero downtime for {org}'s operations, we need:\n1. Current API endpoint configurations\n2. Service account credentials for re-provisioning\n3. Designated technical contact for go-live verification\n\nPlease complete the attached migration readiness form and return by EOD {deadline}.\n\nI've also attached the updated SDK documentation for your development team.\n\nBest regards,\n{name}\nSenior Account Manager\n{vendor_company}\nDirect: {phone}",
            "pretext_notes": [
                "Research actual vendors the target organization uses",
                "Reference real contract numbers if available via OSINT",
                "Attach benign-looking payload as 'SDK documentation'",
                "Use business language matching the vendor's communication style",
                "Target procurement or IT integration teams",
            ],
        },
    },
    "executive": {
        "role": "C-Level Executive",
        "basic": {
            "phone_opener": "This is {exec_name}, {exec_title}. I need you to handle something for me urgently before my next meeting.",
            "email_subject": "Urgent - Need This Handled ASAP",
            "email_body": "Hi {target_name},\n\nI'm between meetings and need you to take care of something immediately. Please process the attached wire transfer authorization for our new vendor engagement.\n\nI'll explain more later but this is time-sensitive. Please confirm once done.\n\nThanks,\n{exec_name}\n{exec_title}\n\nSent from my iPhone",
            "pretext_notes": ["Leverage authority and urgency", "Keep communication brief like a busy executive", "Target finance or admin staff"],
        },
        "detailed": {
            "phone_opener": "Hi {target_name}, this is {exec_name}. I know this is unusual but I'm dealing with a confidential matter. {exec_title_short} asked me to handle this discreetly and I need your help.",
            "phone_script": [
                "Identify as a senior executive (name from OSINT)",
                "Mention being in transit or between meetings",
                "Reference a confidential acquisition or deal",
                "Request urgent wire transfer or credential access",
                "Emphasize discretion - 'don't discuss with others yet'",
                "Promise to follow up with formal authorization 'after the board meeting'",
            ],
            "email_subject": "Confidential: Time-Sensitive Request",
            "email_body": "Hi {target_name},\n\nI'm reaching out directly because of the sensitive nature of this request. We're finalizing a confidential {deal_type} that the board approved in yesterday's closed session.\n\nI need you to:\n1. Prepare a wire transfer of ${amount} to the account details in the attached memo\n2. Process this under project code '{project_code}'\n3. Keep this between us until the public announcement on {announce_date}\n\nI'll be in meetings until {time} but you can reach me at {phone} if needed. Please confirm receipt and expected processing time.\n\nThis is extremely time-sensitive.\n\nRegards,\n{exec_name}\n{exec_title}\n{org}",
            "pretext_notes": [
                "Research real executives via LinkedIn and annual reports",
                "Reference actual upcoming events (earnings, conferences)",
                "Use display name spoofing on the email From header",
                "Target accounts payable, executive assistants",
                "Include 'Sent from iPhone' for casual tone explanation",
                "Create isolation - 'keep this confidential'",
            ],
        },
    },
    "new_employee": {
        "role": "Recently Hired Employee",
        "basic": {
            "phone_opener": "Hi, I'm {name}, I just started in {department} last week. I'm having trouble accessing {system} and my manager {manager_name} suggested I call you directly.",
            "email_subject": "New Employee - Access Request Help",
            "email_body": "Hello,\n\nMy name is {name} and I recently joined {org}'s {department} team. I've been having difficulty setting up my access to {system}.\n\nMy manager {manager_name} said you might be able to help me get set up. Could you provide me with the login portal URL and help reset my temporary credentials?\n\nThank you for your patience with the new person!\n\nBest,\n{name}\n{department}\n{org}",
            "pretext_notes": ["Leverage helpfulness toward new hires", "Reference real managers from OSINT", "Request system access or credentials"],
        },
        "detailed": {
            "phone_opener": "Hi, sorry to bother you! I'm {name}, brand new in {department} - today's actually my {day_number} day. {manager_name} is out of office and I'm completely stuck. I can't get into {system} and I have a deliverable due to {exec_name} by end of day.",
            "phone_script": [
                "Present as nervous and apologetic new hire",
                "Reference specific department and manager names from OSINT",
                "Mention that your manager is unavailable (traveling, PTO)",
                "Express anxiety about missing a deadline for an executive",
                "Ask for temporary credentials or a password reset",
                "Request access to shared drives or internal portals",
                "Thank profusely - establish rapport for future contacts",
            ],
            "email_subject": "Urgent: Access Issues - New Hire in {department} (Starting {start_date})",
            "email_body": "Hi {target_name},\n\nI hope you can help me - I'm feeling a bit overwhelmed! I'm {name}, a new {job_title} in {department} (employee ID pending from HR).\n\nI've been trying to set up my workstation but I'm running into issues:\n- Cannot access {system} (getting 'account not provisioned' errors)\n- VPN client won't accept my temporary credentials\n- Unable to reach the internal wiki at {wiki_url}\n\nMy manager {manager_name} is at the {conference_name} conference this week and not very responsive. I have a project kickoff with {exec_name} tomorrow and need access to the {project_name} shared drive.\n\nCould you either:\n1. Reset my credentials for {system}\n2. Grant me temporary access to the shared resources\n3. Point me to someone who can help urgently\n\nI really don't want to make a bad first impression by missing my first deadline!\n\nThanks so much,\n{name}\n{job_title} (New Hire)\n{department}, {org}",
            "pretext_notes": [
                "Research recent job postings to identify realistic roles",
                "Find manager names and org structure via LinkedIn",
                "Reference real internal systems from job postings or leaks",
                "Exploit onboarding process gaps",
                "Create empathy through new-hire anxiety narrative",
                "Target IT helpdesk and department administrators",
            ],
        },
    },
}


class SocialPretextingGeneratorModule(AtsModule):
    """Generate social engineering pretexts for authorized security testing."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_pretexting_generator",
            category=ModuleCategory.ADVANCED,
            description="Generate realistic SE pretext scripts for authorized penetration testing engagements",
            version="1.0.0",
            parameters=[
                Parameter(name="target_org", type=ParameterType.STRING,
                          description="Target organization name for the pretext", required=True),
                Parameter(name="scenario", type=ParameterType.CHOICE,
                          description="Social engineering scenario type",
                          choices=["helpdesk", "vendor", "executive", "new_employee"],
                          default="helpdesk"),
                Parameter(name="detail_level", type=ParameterType.CHOICE,
                          description="Level of detail in generated pretext",
                          choices=["basic", "detailed"], default="basic"),
            ],
            outputs=[
                OutputField(name="pretext", type="dict", description="Generated pretext with scripts"),
                OutputField(name="phone_script", type="string", description="Phone call script"),
                OutputField(name="email_template", type="string", description="Email template"),
            ],
            tags=["advanced", "social", "pretexting", "social-engineering"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        if not config.get("target_org", "").strip():
            return False, "Target organization name is required"
        return True, ""

    def _fill_template(self, text: str, variables: dict[str, str]) -> str:
        """Replace template placeholders with generated values."""
        result = text
        for key, value in variables.items():
            result = result.replace("{" + key + "}", value)
        return result

    def _generate_variables(self, org: str, scenario: str) -> dict[str, str]:
        """Generate realistic placeholder values."""
        first_names = ["Michael", "Sarah", "James", "Jennifer", "Robert", "Emily", "David", "Amanda"]
        last_names = ["Thompson", "Mitchell", "Anderson", "Roberts", "Campbell", "Parker", "Wright", "Collins"]
        departments = ["Engineering", "Marketing", "Finance", "Human Resources", "Operations", "Sales"]
        systems = ["Workday", "ServiceNow", "Okta", "Salesforce", "Jira", "Confluence", "SharePoint"]
        vendor_companies = ["Accenture", "Deloitte Digital", "CloudFlare Solutions", "DataSync Pro", "NetSecure Inc."]
        exec_titles = ["Chief Financial Officer", "VP of Operations", "Chief Technology Officer", "SVP of Engineering"]
        service_types = ["cloud infrastructure", "identity management", "endpoint protection", "data analytics"]

        now = datetime.now()
        name = f"{random.choice(first_names)} {random.choice(last_names)}"
        return {
            "name": name,
            "org": org,
            "target_name": "[TARGET_NAME]",
            "department": random.choice(departments),
            "system": random.choice(systems),
            "manager_name": f"{random.choice(first_names)} {random.choice(last_names)}",
            "exec_name": f"{random.choice(first_names)} {random.choice(last_names)}",
            "exec_title": random.choice(exec_titles),
            "exec_title_short": "The CEO",
            "vendor_company": random.choice(vendor_companies),
            "service_type": random.choice(service_types),
            "badge": f"IT-{random.randint(10000, 99999)}",
            "incident_id": f"{random.randint(100000, 999999)}",
            "contract_id": f"SA-{now.year}-{random.randint(1000, 9999)}",
            "policy_num": f"{random.randint(100, 999)}",
            "extension": f"x{random.randint(4000, 4999)}",
            "date": now.strftime("%B %d, %Y"),
            "deadline": (now.strftime("%B %d, %Y")),
            "time_of_day": "morning" if now.hour < 12 else "afternoon",
            "phone": f"+1 (555) {random.randint(100, 999)}-{random.randint(1000, 9999)}",
            "amount": f"{random.randint(15, 85) * 1000:,}",
            "deal_type": random.choice(["acquisition", "strategic partnership", "vendor consolidation"]),
            "project_code": f"PRJ-{random.choice(['ALPHA', 'PHOENIX', 'HORIZON', 'NEXUS'])}-{random.randint(10, 99)}",
            "announce_date": "next Monday",
            "time": f"{random.randint(2, 5)}:00 PM",
            "quarter": str((now.month - 1) // 3 + 1),
            "day_number": str(random.randint(2, 5)),
            "start_date": now.strftime("%B %d"),
            "job_title": random.choice(["Business Analyst", "Software Engineer", "Project Manager", "Data Analyst"]),
            "wiki_url": f"wiki.{org.lower().replace(' ', '')}.internal",
            "conference_name": random.choice(["AWS re:Invent", "RSA Conference", "Gartner Summit", "CES"]),
            "project_name": random.choice(["Q4 Migration", "Platform Modernization", "Security Uplift"]),
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        org = config["target_org"].strip()
        scenario = config.get("scenario", "helpdesk")
        detail_level = config.get("detail_level", "basic")

        template_set = SCENARIO_TEMPLATES.get(scenario, SCENARIO_TEMPLATES["helpdesk"])
        detail = template_set.get(detail_level, template_set["basic"])
        variables = self._generate_variables(org, scenario)

        phone_opener = self._fill_template(detail["phone_opener"], variables)
        email_subject = self._fill_template(detail["email_subject"], variables)
        email_body = self._fill_template(detail["email_body"], variables)

        phone_script_steps = []
        if "phone_script" in detail:
            phone_script_steps = detail["phone_script"]

        pretext = {
            "scenario": scenario,
            "role": template_set["role"],
            "detail_level": detail_level,
            "target_organization": org,
            "generated_identity": variables["name"],
            "phone_opener": phone_opener,
            "phone_script_steps": phone_script_steps,
            "email_subject": email_subject,
            "email_body": email_body,
            "pretext_notes": detail.get("pretext_notes", []),
            "legal_notice": "FOR AUTHORIZED PENETRATION TESTING ONLY. Ensure written authorization exists before use.",
        }

        full_phone_script = f"OPENER: {phone_opener}"
        if phone_script_steps:
            full_phone_script += "\n\nSCRIPT STEPS:\n" + "\n".join(
                f"  {i+1}. {step}" for i, step in enumerate(phone_script_steps)
            )

        full_email = f"Subject: {email_subject}\n\n{email_body}"

        return {
            "pretext": pretext,
            "phone_script": full_phone_script,
            "email_template": full_email,
            "scenario": scenario,
            "detail_level": detail_level,
            "disclaimer": "This content is generated for authorized security testing only.",
        }
