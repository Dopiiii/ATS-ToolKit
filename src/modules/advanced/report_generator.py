"""Security assessment report generator module.

Generates structured security assessment reports in Markdown format
with executive summaries, technical details, and remediation roadmaps.
"""

import asyncio
import json
import re
from typing import Any
from datetime import datetime, timezone

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICONS = {"critical": "!!!", "high": "!!", "medium": "!", "low": "-", "info": "i"}
PRIORITY_MAP = {"critical": "P0 - Immediate", "high": "P1 - Urgent", "medium": "P2 - Short-term", "low": "P3 - Planned", "info": "P4 - Informational"}


class ReportGeneratorModule(AtsModule):
    """Generate security assessment reports in Markdown format."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="report_generator",
            category=ModuleCategory.ADVANCED,
            description="Generate security assessment reports in Markdown with executive summary, technical details, and remediation roadmap",
            version="1.0.0",
            parameters=[
                Parameter(name="findings", type=ParameterType.STRING,
                          description="JSON array of findings, each with: title, severity (critical/high/medium/low/info), description, remediation"),
                Parameter(name="report_format", type=ParameterType.CHOICE,
                          description="Report format type",
                          choices=["executive", "technical", "full"], default="full"),
                Parameter(name="title", type=ParameterType.STRING,
                          description="Report title"),
            ],
            outputs=[
                OutputField(name="markdown_report", type="string", description="Complete report in Markdown format"),
                OutputField(name="statistics", type="dict", description="Report statistics and metadata"),
                OutputField(name="severity_breakdown", type="dict", description="Finding counts by severity level"),
            ],
            tags=["advanced", "reporting", "assessment", "documentation"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("findings", "").strip()
        if not raw:
            return False, "Findings JSON array is required"
        try:
            findings = json.loads(raw)
            if not isinstance(findings, list):
                return False, "Findings must be a JSON array"
            if len(findings) == 0:
                return False, "Findings array cannot be empty"
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    return False, f"Finding at index {i} must be an object"
                if "title" not in f:
                    return False, f"Finding at index {i} missing 'title'"
                sev = f.get("severity", "info").lower()
                if sev not in SEVERITY_ORDER:
                    return False, f"Finding at index {i} has invalid severity '{sev}'"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in findings: {exc}"
        if not config.get("title", "").strip():
            return False, "Report title is required"
        return True, ""

    def _sort_findings(self, findings: list[dict]) -> list[dict]:
        """Sort findings by severity: critical > high > medium > low > info."""
        for f in findings:
            f["severity"] = f.get("severity", "info").lower()
        return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    def _compute_stats(self, findings: list[dict]) -> tuple[dict, dict]:
        """Compute severity breakdown and statistics."""
        breakdown = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            breakdown[f["severity"]] = breakdown.get(f["severity"], 0) + 1
        stats = {
            "total_findings": len(findings),
            "critical_count": breakdown["critical"],
            "high_count": breakdown["high"],
            "actionable_findings": breakdown["critical"] + breakdown["high"] + breakdown["medium"],
            "risk_rating": "Critical" if breakdown["critical"] > 0 else "High" if breakdown["high"] > 0 else "Medium" if breakdown["medium"] > 0 else "Low",
        }
        return stats, breakdown

    def _generate_executive_section(self, findings: list[dict], stats: dict, breakdown: dict, title: str) -> str:
        """Generate the executive summary section."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = [
            f"# {title}",
            f"\n**Date:** {now}  ",
            f"**Overall Risk Rating:** {stats['risk_rating']}  ",
            f"**Total Findings:** {stats['total_findings']}",
            "\n## Executive Summary\n",
            f"This assessment identified **{stats['total_findings']}** findings across the evaluated scope. "
            f"Of these, **{stats['critical_count']}** are critical, **{stats['high_count']}** are high severity, "
            f"and **{stats['actionable_findings']}** require actionable remediation.\n",
            "### Severity Distribution\n",
            "| Severity | Count | Percentage |",
            "|----------|-------|------------|",
        ]
        for sev in SEVERITY_ORDER:
            count = breakdown[sev]
            pct = round(count / len(findings) * 100, 1) if findings else 0
            lines.append(f"| {sev.capitalize()} | {count} | {pct}% |")
        lines.append("")
        return "\n".join(lines)

    def _generate_technical_section(self, findings: list[dict]) -> str:
        """Generate detailed technical findings section."""
        lines = ["\n## Technical Findings\n"]
        for idx, f in enumerate(findings, 1):
            sev = f["severity"].upper()
            icon = SEVERITY_ICONS.get(f["severity"], "?")
            lines.append(f"### [{sev}] Finding {idx}: {f['title']}\n")
            lines.append(f"**Severity:** {sev} ({icon})  ")
            lines.append(f"**Description:**\n\n{f.get('description', 'No description provided.')}\n")
            remediation = f.get("remediation", "")
            if remediation:
                lines.append(f"**Remediation:**\n\n{remediation}\n")
            lines.append("---\n")
        return "\n".join(lines)

    def _generate_roadmap_section(self, findings: list[dict]) -> str:
        """Generate remediation roadmap sorted by priority."""
        lines = ["\n## Remediation Roadmap\n"]
        for priority_sev in ["critical", "high", "medium", "low"]:
            group = [f for f in findings if f["severity"] == priority_sev and f.get("remediation")]
            if not group:
                continue
            label = PRIORITY_MAP[priority_sev]
            lines.append(f"### {label}\n")
            for f in group:
                lines.append(f"- **{f['title']}**: {f['remediation']}")
            lines.append("")
        return "\n".join(lines)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        findings = json.loads(config["findings"])
        report_format = config.get("report_format", "full")
        title = config["title"].strip()

        sorted_findings = self._sort_findings(findings)
        stats, breakdown = self._compute_stats(sorted_findings)

        sections = []
        if report_format in ("executive", "full"):
            sections.append(self._generate_executive_section(sorted_findings, stats, breakdown, title))
        if report_format in ("technical", "full"):
            if report_format == "technical":
                sections.append(f"# {title}\n")
            sections.append(self._generate_technical_section(sorted_findings))
        if report_format == "full":
            sections.append(self._generate_roadmap_section(sorted_findings))

        markdown_report = "\n".join(sections)

        return {
            "markdown_report": markdown_report,
            "statistics": stats,
            "severity_breakdown": breakdown,
        }
