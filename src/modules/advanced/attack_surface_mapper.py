"""Attack surface mapping module for organizational exposure assessment.

Maps and categorizes attack surface entry points from organizational data,
scores exposure levels, and identifies high-risk attack vectors.
"""

import asyncio
import json
import re
from typing import Any
from collections import Counter, defaultdict

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

HIGH_RISK_PORTS = {
    21: ("FTP", 9), 22: ("SSH", 6), 23: ("Telnet", 10), 25: ("SMTP", 7),
    53: ("DNS", 5), 80: ("HTTP", 4), 110: ("POP3", 8), 135: ("RPC", 9),
    139: ("NetBIOS", 9), 143: ("IMAP", 7), 443: ("HTTPS", 3), 445: ("SMB", 10),
    1433: ("MSSQL", 9), 1521: ("Oracle", 9), 3306: ("MySQL", 8),
    3389: ("RDP", 10), 5432: ("PostgreSQL", 8), 5900: ("VNC", 9),
    6379: ("Redis", 9), 8080: ("HTTP-Alt", 5), 8443: ("HTTPS-Alt", 4),
    9200: ("Elasticsearch", 8), 27017: ("MongoDB", 9),
}
ENTRY_POINT_CATEGORIES = [
    "network_service", "web_application", "api_endpoint", "email_gateway",
    "vpn_access", "remote_desktop", "database", "file_share", "dns",
    "cloud_service", "iot_device", "wireless_access",
]


class AttackSurfaceMapperModule(AtsModule):
    """Map organizational attack surface and score exposure levels."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="attack_surface_mapper",
            category=ModuleCategory.ADVANCED,
            description="Map attack surface entry points, categorize by type, and score exposure levels",
            version="1.0.0",
            parameters=[
                Parameter(name="org_data", type=ParameterType.STRING,
                          description="JSON object with fields: domains (list), ips (list of {ip, ports, services}), services (list of {name, type, version, exposed})"),
                Parameter(name="depth", type=ParameterType.CHOICE,
                          description="Analysis depth",
                          choices=["basic", "comprehensive"], default="basic"),
                Parameter(name="include_recommendations", type=ParameterType.BOOLEAN,
                          description="Include remediation recommendations",
                          default=True, required=False),
            ],
            outputs=[
                OutputField(name="entry_points", type="list", description="Identified attack surface entry points"),
                OutputField(name="exposure_score", type="float", description="Overall exposure score 0-100"),
                OutputField(name="category_breakdown", type="dict", description="Entry points by category"),
                OutputField(name="high_risk_items", type="list", description="Highest risk entry points"),
            ],
            tags=["advanced", "recon", "attack-surface", "exposure", "assessment"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        raw = config.get("org_data", "").strip()
        if not raw:
            return False, "Organization data is required"
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False, "Organization data must be a JSON object"
            if not any(k in data for k in ("domains", "ips", "services")):
                return False, "Organization data must contain at least one of: domains, ips, services"
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON in org_data: {exc}"
        return True, ""

    def _analyze_domains(self, domains: list) -> list[dict]:
        """Analyze domain-based entry points."""
        entry_points = []
        for domain in domains:
            if isinstance(domain, str):
                domain_data = {"name": domain}
            else:
                domain_data = domain

            domain_name = domain_data.get("name", str(domain))
            subdomains = domain_data.get("subdomains", [])

            # Main domain entry point
            entry_points.append({
                "id": f"dom-{domain_name}",
                "type": "web_application",
                "target": domain_name,
                "category": "web_application",
                "risk_score": 5,
                "description": f"Web presence at {domain_name}",
                "details": {"domain": domain_name, "has_subdomains": len(subdomains) > 0},
            })

            # Subdomain entry points increase attack surface
            for sub in subdomains:
                sub_name = sub if isinstance(sub, str) else sub.get("name", "")
                risk = 7 if any(kw in sub_name.lower() for kw in ["admin", "dev", "test", "staging", "api", "vpn", "mail"]) else 4
                entry_points.append({
                    "id": f"sub-{sub_name}",
                    "type": "web_application",
                    "target": sub_name,
                    "category": self._categorize_subdomain(sub_name),
                    "risk_score": risk,
                    "description": f"Subdomain: {sub_name}",
                    "details": {"parent_domain": domain_name, "subdomain": sub_name},
                })

        return entry_points

    def _categorize_subdomain(self, subdomain: str) -> str:
        """Categorize a subdomain based on naming patterns."""
        lower = subdomain.lower()
        if any(kw in lower for kw in ["api", "rest", "graphql", "ws"]):
            return "api_endpoint"
        if any(kw in lower for kw in ["mail", "smtp", "imap", "pop", "mx"]):
            return "email_gateway"
        if any(kw in lower for kw in ["vpn", "remote", "gateway"]):
            return "vpn_access"
        if any(kw in lower for kw in ["rdp", "rds", "terminal"]):
            return "remote_desktop"
        if any(kw in lower for kw in ["db", "sql", "mongo", "redis", "elastic"]):
            return "database"
        if any(kw in lower for kw in ["ftp", "sftp", "file", "share", "nas"]):
            return "file_share"
        if any(kw in lower for kw in ["dns", "ns1", "ns2"]):
            return "dns"
        return "web_application"

    def _analyze_ips(self, ips: list) -> list[dict]:
        """Analyze IP-based entry points with port exposure."""
        entry_points = []
        for ip_entry in ips:
            if isinstance(ip_entry, str):
                ip_entry = {"ip": ip_entry, "ports": [], "services": []}
            ip_addr = ip_entry.get("ip", "")
            ports = ip_entry.get("ports", [])
            services = ip_entry.get("services", [])

            for port in ports:
                port_num = int(port) if not isinstance(port, dict) else int(port.get("number", 0))
                port_info = HIGH_RISK_PORTS.get(port_num, (f"port-{port_num}", 3))
                service_name, base_risk = port_info

                entry_points.append({
                    "id": f"ip-{ip_addr}:{port_num}",
                    "type": "network_service",
                    "target": f"{ip_addr}:{port_num}",
                    "category": "network_service",
                    "risk_score": base_risk,
                    "description": f"{service_name} service on {ip_addr}:{port_num}",
                    "details": {
                        "ip": ip_addr,
                        "port": port_num,
                        "service": service_name,
                        "known_risky": port_num in HIGH_RISK_PORTS,
                    },
                })

            # If no ports specified, add IP as generic entry point
            if not ports:
                entry_points.append({
                    "id": f"ip-{ip_addr}",
                    "type": "network_service",
                    "target": ip_addr,
                    "category": "network_service",
                    "risk_score": 3,
                    "description": f"Host at {ip_addr}",
                    "details": {"ip": ip_addr, "ports_unknown": True},
                })

        return entry_points

    def _analyze_services(self, services: list) -> list[dict]:
        """Analyze service-based entry points."""
        entry_points = []
        for svc in services:
            if isinstance(svc, str):
                svc = {"name": svc, "type": "unknown", "exposed": True}

            name = svc.get("name", "Unknown Service")
            svc_type = svc.get("type", "unknown")
            version = svc.get("version", "unknown")
            exposed = svc.get("exposed", True)

            risk = 3
            if exposed:
                risk += 3
            if version.lower() in ("unknown", "unpatched", "outdated"):
                risk += 2
            if svc_type in ("database", "remote_desktop", "file_share"):
                risk += 2

            entry_points.append({
                "id": f"svc-{name}-{svc_type}",
                "type": svc_type,
                "target": name,
                "category": svc_type if svc_type in ENTRY_POINT_CATEGORIES else "network_service",
                "risk_score": min(risk, 10),
                "description": f"Service: {name} ({svc_type}) v{version}",
                "details": {
                    "service_name": name,
                    "service_type": svc_type,
                    "version": version,
                    "externally_exposed": exposed,
                },
            })

        return entry_points

    def _generate_recommendations(self, high_risk_items: list[dict]) -> list[dict]:
        """Generate remediation recommendations for high-risk items."""
        recommendations = []
        seen_types = set()
        for item in high_risk_items:
            item_type = item.get("category", "")
            if item_type in seen_types:
                continue
            seen_types.add(item_type)

            rec_map = {
                "network_service": "Review and restrict exposed network services. Apply firewall rules to limit access to necessary sources only.",
                "web_application": "Perform web application security assessment. Implement WAF and ensure secure coding practices.",
                "api_endpoint": "Implement API gateway with rate limiting, authentication, and input validation.",
                "email_gateway": "Deploy email security gateway with SPF, DKIM, DMARC, and anti-phishing controls.",
                "vpn_access": "Enforce MFA on VPN access. Review and restrict VPN split tunneling configurations.",
                "remote_desktop": "Disable direct RDP exposure. Use VPN or jump box with MFA for remote access.",
                "database": "Remove direct database exposure from internet. Use application-layer access with parameterized queries.",
                "file_share": "Restrict file share access. Implement DLP controls and monitor for unusual access patterns.",
            }
            if item_type in rec_map:
                recommendations.append({
                    "category": item_type,
                    "recommendation": rec_map[item_type],
                    "priority": "high" if item.get("risk_score", 0) >= 8 else "medium",
                })

        return recommendations

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        org_data = json.loads(config["org_data"])
        depth = config.get("depth", "basic")
        include_recs = config.get("include_recommendations", True)

        all_entry_points: list[dict] = []

        # Analyze domains
        domains = org_data.get("domains", [])
        if domains:
            all_entry_points.extend(self._analyze_domains(domains))

        # Analyze IPs
        ips = org_data.get("ips", [])
        if ips:
            all_entry_points.extend(self._analyze_ips(ips))

        # Analyze services
        services = org_data.get("services", [])
        if services:
            all_entry_points.extend(self._analyze_services(services))

        # Category breakdown
        category_counts: dict[str, list] = defaultdict(list)
        for ep in all_entry_points:
            category_counts[ep["category"]].append(ep["id"])

        category_breakdown = {
            cat: {"count": len(items), "items": items}
            for cat, items in category_counts.items()
        }

        # High-risk items (risk_score >= 7)
        high_risk_items = sorted(
            [ep for ep in all_entry_points if ep.get("risk_score", 0) >= 7],
            key=lambda x: x["risk_score"], reverse=True,
        )

        # Exposure score
        if all_entry_points:
            avg_risk = sum(ep.get("risk_score", 0) for ep in all_entry_points) / len(all_entry_points)
            high_risk_ratio = len(high_risk_items) / len(all_entry_points)
            exposure_score = min(round(avg_risk * 8 + high_risk_ratio * 40 + len(all_entry_points) * 0.3, 1), 100.0)
        else:
            exposure_score = 0.0

        result: dict[str, Any] = {
            "entry_points": all_entry_points,
            "entry_point_count": len(all_entry_points),
            "exposure_score": exposure_score,
            "exposure_level": "critical" if exposure_score >= 75 else "high" if exposure_score >= 50 else "medium" if exposure_score >= 25 else "low",
            "category_breakdown": category_breakdown,
            "high_risk_items": high_risk_items,
            "high_risk_count": len(high_risk_items),
        }

        if include_recs and high_risk_items:
            result["recommendations"] = self._generate_recommendations(high_risk_items)

        return result
