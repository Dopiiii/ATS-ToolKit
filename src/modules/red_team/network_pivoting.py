"""Network Pivoting Module.

Analyze network topology to identify pivot points, segmentation gaps,
and reachable subnets for lateral movement planning.
"""

import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Default ports to probe for reachability
PIVOT_PROBE_PORTS = [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080]

# Common internal network ranges
INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


class NetworkPivotingModule(AtsModule):
    """Network pivoting analysis to identify pivot points and segmentation gaps."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="network_pivoting",
            category=ModuleCategory.RED_TEAM,
            description="Network pivoting analysis: identify pivot points, segmentation gaps, and reachable subnets",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Compromised host IP address (the pivot origin)",
                    required=True,
                ),
                Parameter(
                    name="known_subnets",
                    type=ParameterType.LIST,
                    description="List of known internal subnets in CIDR notation (e.g. ['10.0.1.0/24','10.0.2.0/24'])",
                    required=True,
                ),
                Parameter(
                    name="interfaces",
                    type=ParameterType.LIST,
                    description="List of network interface dicts from pivot host with keys: name, ip, netmask, gateway",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="routes",
                    type=ParameterType.LIST,
                    description="List of routing table entries with keys: destination, gateway, interface, metric",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="probe_ports",
                    type=ParameterType.LIST,
                    description="Ports to probe for reachability testing",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="scan_timeout",
                    type=ParameterType.INTEGER,
                    description="Timeout in seconds per connection probe",
                    required=False,
                    default=2,
                    min_value=1,
                    max_value=10,
                ),
            ],
            outputs=[
                OutputField(name="pivot_points", type="list", description="Identified pivot points with reachable networks"),
                OutputField(name="segmentation_gaps", type="list", description="Detected network segmentation failures"),
                OutputField(name="reachability_map", type="dict", description="Subnet reachability from the pivot host"),
                OutputField(name="summary", type="dict", description="Pivoting analysis summary"),
            ],
            tags=["red_team", "pivoting", "network", "lateral_movement", "segmentation"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target pivot host IP is required"
        if not config.get("known_subnets"):
            return False, "At least one known subnet is required"
        for subnet in config["known_subnets"]:
            try:
                ipaddress.ip_network(subnet.strip(), strict=False)
            except ValueError:
                return False, f"Invalid CIDR notation: {subnet}"
        return True, ""

    def _identify_directly_connected(self, interfaces: List[Dict]) -> List[Dict[str, Any]]:
        """Identify subnets directly connected via the pivot host's interfaces."""
        connected = []
        for iface in interfaces:
            ip_str = iface.get("ip", "")
            mask = iface.get("netmask", "")
            if not ip_str or not mask:
                continue
            try:
                interface = ipaddress.ip_interface(f"{ip_str}/{mask}")
                connected.append({
                    "interface": iface.get("name", "unknown"),
                    "ip": ip_str,
                    "network": str(interface.network),
                    "gateway": iface.get("gateway", ""),
                })
            except ValueError:
                continue
        return connected

    def _analyze_routes(self, routes: List[Dict], known_subnets: List[str]) -> List[Dict[str, Any]]:
        """Analyze routing table to determine reachable subnets."""
        reachable = []
        known_nets = [ipaddress.ip_network(s.strip(), strict=False) for s in known_subnets]

        for route in routes:
            dest = route.get("destination", "")
            gw = route.get("gateway", "")
            if not dest:
                continue
            try:
                route_net = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                continue

            # Check overlap with known internal subnets
            overlapping = [str(kn) for kn in known_nets if route_net.overlaps(kn)]
            if overlapping:
                reachable.append({
                    "route_destination": str(route_net),
                    "gateway": gw,
                    "interface": route.get("interface", ""),
                    "metric": route.get("metric", ""),
                    "overlapping_known_subnets": overlapping,
                })
        return reachable

    async def _probe_host(self, ip: str, port: int, timeout: int) -> Dict[str, Any]:
        """Probe a single host:port for reachability."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return {"ip": ip, "port": port, "reachable": True}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {"ip": ip, "port": port, "reachable": False}

    async def _probe_subnet_sample(self, subnet_str: str, ports: List[int], timeout: int) -> Dict[str, Any]:
        """Probe a sample of hosts in a subnet to test reachability."""
        network = ipaddress.ip_network(subnet_str, strict=False)
        # Sample up to 5 hosts from the subnet (gateway + first few hosts)
        hosts = list(network.hosts())
        sample = hosts[:5] if len(hosts) > 5 else hosts

        probe_results = []
        for host in sample:
            for port in ports[:3]:  # Limit ports per host to keep scans fast
                result = await self._probe_host(str(host), port, timeout)
                if result["reachable"]:
                    probe_results.append(result)

        return {
            "subnet": subnet_str,
            "hosts_sampled": len(sample),
            "reachable_services": probe_results,
            "any_reachable": len(probe_results) > 0,
        }

    def _detect_segmentation_gaps(self, pivot_ip: str, connected: List[Dict],
                                   reachability: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify segmentation gaps where the pivot host can reach multiple network zones."""
        gaps = []
        connected_nets = [c["network"] for c in connected]

        # If pivot host has multiple interfaces in different subnets, that is a pivot opportunity
        if len(connected_nets) > 1:
            gaps.append({
                "type": "multi_homed_host",
                "severity": "high",
                "pivot_ip": pivot_ip,
                "connected_networks": connected_nets,
                "description": f"Pivot host {pivot_ip} is multi-homed across {len(connected_nets)} networks",
                "recommendation": "Enforce host-based firewall rules to restrict cross-network traffic",
            })

        # Check reachable subnets that are NOT directly connected
        for subnet, data in reachability.items():
            if data.get("any_reachable") and subnet not in connected_nets:
                gaps.append({
                    "type": "unexpected_reachability",
                    "severity": "medium",
                    "from_pivot": pivot_ip,
                    "reachable_subnet": subnet,
                    "description": f"Pivot host can reach non-local subnet {subnet}",
                    "recommendation": "Review ACLs and network segmentation for this path",
                })

        return gaps

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        known_subnets = [s.strip() for s in config["known_subnets"]]
        interfaces = config.get("interfaces", []) or []
        routes = config.get("routes", []) or []
        probe_ports = config.get("probe_ports", []) or PIVOT_PROBE_PORTS
        probe_ports = [int(p) for p in probe_ports]
        scan_timeout = config.get("scan_timeout", 2)

        self.logger.info("pivoting_analysis_start", pivot=target, subnets=len(known_subnets))

        # Step 1: Identify directly connected networks
        connected = self._identify_directly_connected(interfaces)

        # Step 2: Analyze routing table
        routed = self._analyze_routes(routes, known_subnets)

        # Step 3: Probe subnet samples for reachability
        reachability_map: Dict[str, Any] = {}
        probe_tasks = [
            self._probe_subnet_sample(subnet, probe_ports, scan_timeout)
            for subnet in known_subnets
        ]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        for result in probe_results:
            if isinstance(result, dict):
                reachability_map[result["subnet"]] = result

        # Step 4: Identify pivot points
        pivot_points = []
        for conn in connected:
            reachable_from_here = []
            for subnet, reach_data in reachability_map.items():
                if reach_data.get("any_reachable"):
                    reachable_from_here.append(subnet)
            pivot_points.append({
                "interface": conn["interface"],
                "ip": conn["ip"],
                "network": conn["network"],
                "gateway": conn["gateway"],
                "reachable_subnets": reachable_from_here,
            })

        # If no interfaces were provided, create a basic pivot point from target
        if not pivot_points:
            reachable_all = [s for s, d in reachability_map.items() if d.get("any_reachable")]
            pivot_points.append({
                "interface": "unknown",
                "ip": target,
                "network": "unknown",
                "gateway": "unknown",
                "reachable_subnets": reachable_all,
            })

        # Step 5: Detect segmentation gaps
        segmentation_gaps = self._detect_segmentation_gaps(target, connected, reachability_map)

        summary = {
            "pivot_host": target,
            "known_subnets": len(known_subnets),
            "directly_connected_networks": len(connected),
            "routed_paths": len(routed),
            "reachable_subnets": sum(1 for d in reachability_map.values() if d.get("any_reachable")),
            "segmentation_gaps": len(segmentation_gaps),
            "pivot_points_identified": len(pivot_points),
        }

        self.logger.info("pivoting_analysis_complete", pivot=target, gaps=len(segmentation_gaps))

        return {
            "pivot_points": pivot_points,
            "segmentation_gaps": segmentation_gaps,
            "reachability_map": reachability_map,
            "summary": summary,
        }
