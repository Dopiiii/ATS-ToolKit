"""Decoy file creator module.

Create decoy/canary files that alert on access, with embedded markers
for tracking and configurable alert methods.
"""

import asyncio
import hashlib
import uuid
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Content templates for each decoy file type
FILE_TEMPLATES = {
    "pdf": {
        "extension": ".pdf",
        "mime_type": "application/pdf",
        "description": "Decoy PDF document with embedded tracking pixel reference",
        "content_hint": "Employee salary report, merger details, or credentials list",
    },
    "docx": {
        "extension": ".docx",
        "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "description": "Decoy Word document with macro-less tracking",
        "content_hint": "Board meeting minutes or internal policy draft",
    },
    "xlsx": {
        "extension": ".xlsx",
        "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "description": "Decoy spreadsheet with embedded external reference",
        "content_hint": "Financial projections or customer database extract",
    },
    "config": {
        "extension": ".conf",
        "mime_type": "text/plain",
        "description": "Decoy configuration file with fake credentials",
        "content_hint": "Database connection strings or API keys",
    },
    "database": {
        "extension": ".sql",
        "mime_type": "application/sql",
        "description": "Decoy SQL dump with fake user data",
        "content_hint": "User table dump with passwords or PII",
    },
}

ALERT_METHODS = {
    "log": {
        "description": "Write access events to a local log file",
        "setup": "Configure auditd or inotifywait to monitor file access",
    },
    "webhook": {
        "description": "Send HTTP POST to a webhook URL on file access",
        "setup": "Use incron or fanotify to trigger curl on file events",
    },
    "file_monitor": {
        "description": "Monitor file metadata changes (atime, open count)",
        "setup": "Use OS-level file auditing (auditd on Linux, SACL on Windows)",
    },
}


class DecoyFileCreatorModule(AtsModule):
    """Create decoy/canary files that alert on access."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="decoy_file_creator",
            category=ModuleCategory.DECEPTION,
            description="Create decoy canary files with embedded markers that alert when accessed",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="file_type",
                    type=ParameterType.CHOICE,
                    description="Type of decoy file to create",
                    required=True,
                    choices=["pdf", "docx", "xlsx", "config", "database"],
                ),
                Parameter(
                    name="decoy_name",
                    type=ParameterType.STRING,
                    description="Filename for the decoy (without extension)",
                    required=True,
                ),
                Parameter(
                    name="alert_method",
                    type=ParameterType.CHOICE,
                    description="Method used to detect file access",
                    required=False,
                    default="log",
                    choices=["log", "webhook", "file_monitor"],
                ),
            ],
            outputs=[
                OutputField(name="decoy_spec", type="dict", description="Full decoy file specification"),
                OutputField(name="monitoring_instructions", type="dict", description="Setup instructions for monitoring"),
            ],
            tags=["deception", "canary", "decoy", "file", "detection"],
            author="ATS-Toolkit",
            requires_api_key=False,
            api_key_service=None,
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        file_type = config.get("file_type", "")
        if file_type not in FILE_TEMPLATES:
            return False, f"Invalid file_type: {file_type}"
        decoy_name = config.get("decoy_name", "").strip()
        if not decoy_name:
            return False, "decoy_name is required"
        return True, ""

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        file_type = config["file_type"]
        decoy_name = config["decoy_name"].strip()
        alert_method = config.get("alert_method", "log")

        self.logger.info("creating_decoy_file", type=file_type, name=decoy_name)

        template = FILE_TEMPLATES[file_type]
        canary_id = str(uuid.uuid4())
        marker = hashlib.sha256(f"canary:{canary_id}:{decoy_name}".encode()).hexdigest()[:16]
        filename = f"{decoy_name}{template['extension']}"

        decoy_spec = {
            "filename": filename,
            "file_type": file_type,
            "mime_type": template["mime_type"],
            "canary_id": canary_id,
            "embedded_marker": marker,
            "content_hint": template["content_hint"],
            "description": template["description"],
        }

        alert_info = ALERT_METHODS[alert_method]
        monitoring_instructions = {
            "alert_method": alert_method,
            "description": alert_info["description"],
            "setup": alert_info["setup"],
            "target_file": filename,
            "canary_id": canary_id,
            "marker_to_watch": marker,
        }

        self.logger.info("decoy_file_created", filename=filename, canary_id=canary_id)

        return {
            "decoy_spec": decoy_spec,
            "monitoring_instructions": monitoring_instructions,
        }
