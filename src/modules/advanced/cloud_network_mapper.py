"""Cloud network topology mapper.

Parses VPC, subnet, and security group configurations to identify exposed services
and missing network segmentation.
"""

import asyncio
import re
import json
from typing import Any
from ipaddress import ip_network, ip_address

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

WELL_KNOWN_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

SENSITIVE_PORTS = {22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


class CloudNetworkMapperModule(AtsModule):
    """Map cloud network topology and identify security issues."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_network_mapper",
            category=ModuleCategory.ADVANCED,
            description="Map cloud network topology and identify exposed services and segmentation issues",
            version="1.0.0",
            parameters=[
                Parameter(name="config_data", type=ParameterType.STRING,
                          description="VPC/network configuration JSON", required=True),
                Parameter(name="detail_level", type=ParameterType.CHOICE,
                          description="Analysis detail level",
                          choices=["basic", "detailed"], default="basic"),
                Parameter(name="check_segmentation", type=ParameterType.BOOLEAN,
                          description="Analyze network segmentation", default=True),
            ],
            outputs=[
                OutputField(name="topology", type="dict", description="Network topology map"),
                OutputField(name="findings", type="list", description="Security findings"),
                OutputField(name="exposed_services", type="list", description="Publicly exposed services"),
            ],
            tags=["advanced", "cloud", "network", "vpc", "topology"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("config_data", "").strip()
        if not data:
            return False, "Network configuration JSON is required"
        try:
            json.loads(data)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _parse_security_groups(self, config: dict) -> list[dict]:
        """Extract and parse security group rules."""
        sgs = config.get("SecurityGroups", config.get("securityGroups",
                config.get("security_groups", [])))
        parsed = []
        for sg in sgs:
            sg_id = sg.get("GroupId", sg.get("id", sg.get("name", "unknown")))
            sg_name = sg.get("GroupName", sg.get("name", sg_id))
            ingress = sg.get("IpPermissions", sg.get("inboundRules",
                        sg.get("ingress", [])))
            egress = sg.get("IpPermissionsEgress", sg.get("outboundRules",
                       sg.get("egress", [])))
            parsed.append({"id": sg_id, "name": sg_name,
                          "ingress": ingress, "egress": egress})
        return parsed

    def _analyze_sg_rules(self, rules: list, direction: str) -> list[dict]:
        """Analyze security group rules for misconfigurations."""
        findings = []
        for rule in rules:
            from_port = rule.get("FromPort", rule.get("fromPort", rule.get("port_range_min")))
            to_port = rule.get("ToPort", rule.get("toPort", rule.get("port_range_max")))
            protocol = rule.get("IpProtocol", rule.get("protocol", "tcp"))

            ip_ranges = rule.get("IpRanges", rule.get("cidrBlocks", []))
            if isinstance(ip_ranges, list):
                cidrs = [r.get("CidrIp", r) if isinstance(r, dict) else r for r in ip_ranges]
            else:
                cidrs = [str(ip_ranges)]

            for cidr in cidrs:
                cidr_str = str(cidr)
                if cidr_str in ("0.0.0.0/0", "::/0"):
                    if protocol == "-1" or protocol == "all":
                        findings.append({
                            "severity": "critical", "category": "security_group",
                            "issue": f"All traffic allowed from anywhere ({direction})",
                            "cidr": cidr_str, "protocol": protocol,
                        })
                    elif from_port is not None and to_port is not None:
                        port_range = range(int(from_port), int(to_port) + 1)
                        exposed_sensitive = [p for p in port_range if p in SENSITIVE_PORTS]
                        if exposed_sensitive:
                            for port in exposed_sensitive:
                                svc = WELL_KNOWN_PORTS.get(port, "Unknown")
                                findings.append({
                                    "severity": "high", "category": "exposed_service",
                                    "issue": f"Sensitive port {port} ({svc}) exposed to internet",
                                    "cidr": cidr_str, "port": port, "direction": direction,
                                })
                        if to_port - from_port > 100:
                            findings.append({
                                "severity": "medium", "category": "security_group",
                                "issue": f"Wide port range {from_port}-{to_port} open to internet",
                                "cidr": cidr_str, "direction": direction,
                            })
        return findings

    def _parse_subnets(self, config: dict) -> list[dict]:
        """Extract subnet information."""
        subnets = config.get("Subnets", config.get("subnets", []))
        parsed = []
        for subnet in subnets:
            subnet_id = subnet.get("SubnetId", subnet.get("id", "unknown"))
            cidr = subnet.get("CidrBlock", subnet.get("cidr", subnet.get("addressPrefix", "")))
            az = subnet.get("AvailabilityZone", subnet.get("zone", ""))
            public = subnet.get("MapPublicIpOnLaunch", subnet.get("public", False))
            parsed.append({"id": subnet_id, "cidr": cidr, "az": az, "public": public})
        return parsed

    def _check_segmentation(self, subnets: list[dict], sgs: list[dict]) -> list[dict]:
        """Analyze network segmentation."""
        findings = []
        public_subnets = [s for s in subnets if s.get("public")]
        private_subnets = [s for s in subnets if not s.get("public")]

        if not private_subnets and subnets:
            findings.append({"severity": "high", "category": "segmentation",
                             "issue": "No private subnets - all subnets are public"})

        if len(subnets) == 1:
            findings.append({"severity": "medium", "category": "segmentation",
                             "issue": "Single subnet - no network segmentation"})

        azs = set(s.get("az", "") for s in subnets if s.get("az"))
        if len(azs) == 1 and len(subnets) > 1:
            findings.append({"severity": "medium", "category": "availability",
                             "issue": "All subnets in single availability zone - no HA"})

        for subnet in subnets:
            cidr = subnet.get("cidr", "")
            if cidr:
                try:
                    net = ip_network(cidr, strict=False)
                    if net.prefixlen < 20:
                        findings.append({"severity": "low", "category": "sizing",
                                         "issue": f"Large subnet {cidr} (/{net.prefixlen}) - consider splitting"})
                except ValueError:
                    pass

        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(config["config_data"])
        detail_level = config.get("detail_level", "basic")
        check_seg = config.get("check_segmentation", True)

        security_groups = self._parse_security_groups(data)
        subnets = self._parse_subnets(data)
        findings = []
        exposed_services = []

        for sg in security_groups:
            ingress_findings = self._analyze_sg_rules(sg["ingress"], "ingress")
            egress_findings = self._analyze_sg_rules(sg["egress"], "egress")
            for f in ingress_findings + egress_findings:
                f["security_group"] = sg["name"]
            findings.extend(ingress_findings)
            if detail_level == "detailed":
                findings.extend(egress_findings)
            for f in ingress_findings:
                if f.get("category") == "exposed_service":
                    exposed_services.append({
                        "port": f["port"], "service": WELL_KNOWN_PORTS.get(f["port"], "Unknown"),
                        "security_group": sg["name"], "cidr": f["cidr"],
                    })

        if check_seg:
            findings.extend(self._check_segmentation(subnets, security_groups))

        vpc_info = {"vpc_id": data.get("VpcId", data.get("id", "unknown")),
                    "cidr": data.get("CidrBlock", data.get("cidr", "")),
                    "region": data.get("region", "")}
        topology = {"vpc": vpc_info, "subnet_count": len(subnets),
                    "security_group_count": len(security_groups),
                    "subnets": subnets, "public_subnets": sum(1 for s in subnets if s.get("public")),
                    "private_subnets": sum(1 for s in subnets if not s.get("public"))}

        return {
            "topology": topology,
            "findings": findings,
            "finding_count": len(findings),
            "exposed_services": exposed_services,
            "risk_level": "critical" if any(f["severity"] == "critical" for f in findings) else
                         "high" if any(f["severity"] == "high" for f in findings) else "medium",
        }
