"""DNS records lookup module.

Comprehensive DNS record enumeration for a domain.
"""

import asyncio
import dns.resolver
import dns.reversename
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class DnsRecordsModule(AtsModule):
    """Enumerate all DNS records for a domain."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="dns_records",
            category=ModuleCategory.OSINT,
            description="Comprehensive DNS record enumeration",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain",
                    type=ParameterType.DOMAIN,
                    description="Target domain",
                    required=True,
                ),
                Parameter(
                    name="record_types",
                    type=ParameterType.CHOICE,
                    description="Record types to query",
                    required=False,
                    default="common",
                    choices=["basic", "common", "all"],
                ),
                Parameter(
                    name="nameserver",
                    type=ParameterType.STRING,
                    description="Custom DNS server (optional)",
                    required=False,
                ),
            ],
            outputs=[
                OutputField(name="records", type="dict", description="DNS records by type"),
                OutputField(name="summary", type="dict", description="Record count summary"),
            ],
            tags=["dns", "records", "enumeration", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        if not domain or "." not in domain:
            return False, "Invalid domain format"
        return True, ""

    def _get_record_types(self, selection: str) -> List[str]:
        """Get record types based on selection."""
        basic = ["A", "AAAA", "MX", "NS"]
        common = basic + ["TXT", "CNAME", "SOA"]
        all_types = common + ["CAA", "SRV", "PTR", "DNSKEY", "DS", "NAPTR", "TLSA"]

        if selection == "basic":
            return basic
        elif selection == "common":
            return common
        else:
            return all_types

    async def _resolve_record(
        self,
        resolver: dns.resolver.Resolver,
        domain: str,
        record_type: str
    ) -> List[Dict[str, Any]]:
        """Resolve a specific DNS record type."""
        records = []

        try:
            answers = resolver.resolve(domain, record_type)

            for rdata in answers:
                record = {
                    "type": record_type,
                    "ttl": answers.rrset.ttl,
                    "value": str(rdata),
                }

                # Add specific fields based on record type
                if record_type == "MX":
                    record["priority"] = rdata.preference
                    record["exchange"] = str(rdata.exchange).rstrip('.')
                elif record_type == "SOA":
                    record["mname"] = str(rdata.mname).rstrip('.')
                    record["rname"] = str(rdata.rname).rstrip('.')
                    record["serial"] = rdata.serial
                    record["refresh"] = rdata.refresh
                    record["retry"] = rdata.retry
                    record["expire"] = rdata.expire
                    record["minimum"] = rdata.minimum
                elif record_type == "SRV":
                    record["priority"] = rdata.priority
                    record["weight"] = rdata.weight
                    record["port"] = rdata.port
                    record["target"] = str(rdata.target).rstrip('.')
                elif record_type == "CAA":
                    record["flags"] = rdata.flags
                    record["tag"] = rdata.tag.decode()
                    record["value"] = rdata.value.decode()

                records.append(record)

        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except Exception as e:
            self.logger.debug(f"DNS {record_type} query failed: {e}")

        return records

    async def _check_dnssec(
        self,
        resolver: dns.resolver.Resolver,
        domain: str
    ) -> Dict[str, Any]:
        """Check DNSSEC configuration."""
        result = {
            "enabled": False,
            "dnskey": False,
            "ds": False,
        }

        try:
            # Check for DNSKEY
            answers = resolver.resolve(domain, 'DNSKEY')
            if answers:
                result["dnskey"] = True
                result["enabled"] = True
        except:
            pass

        try:
            # Check for DS record at parent
            answers = resolver.resolve(domain, 'DS')
            if answers:
                result["ds"] = True
        except:
            pass

        return result

    async def _analyze_spf(self, txt_records: List[Dict]) -> Dict[str, Any]:
        """Analyze SPF record."""
        analysis = {
            "found": False,
            "record": None,
            "mechanisms": [],
            "includes": [],
            "all_mechanism": None,
        }

        for record in txt_records:
            value = record.get("value", "")
            if value.startswith('"v=spf1') or value.startswith('v=spf1'):
                analysis["found"] = True
                analysis["record"] = value.strip('"')

                # Parse mechanisms
                parts = value.replace('"', '').split()
                for part in parts[1:]:  # Skip v=spf1
                    if part.startswith("include:"):
                        analysis["includes"].append(part[8:])
                    elif part.startswith("+") or part.startswith("-") or part.startswith("~") or part.startswith("?"):
                        if part[1:] == "all":
                            analysis["all_mechanism"] = part
                        else:
                            analysis["mechanisms"].append(part)
                    elif part == "all" or part.endswith("all"):
                        analysis["all_mechanism"] = part
                    else:
                        analysis["mechanisms"].append(part)
                break

        return analysis

    async def _analyze_dmarc(
        self,
        resolver: dns.resolver.Resolver,
        domain: str
    ) -> Dict[str, Any]:
        """Analyze DMARC record."""
        analysis = {
            "found": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": 100,
            "rua": [],
            "ruf": [],
        }

        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, 'TXT')

            for rdata in answers:
                value = str(rdata).strip('"')
                if value.startswith("v=DMARC1"):
                    analysis["found"] = True
                    analysis["record"] = value

                    # Parse DMARC tags
                    tags = value.split(";")
                    for tag in tags:
                        tag = tag.strip()
                        if tag.startswith("p="):
                            analysis["policy"] = tag[2:]
                        elif tag.startswith("sp="):
                            analysis["subdomain_policy"] = tag[3:]
                        elif tag.startswith("pct="):
                            analysis["pct"] = int(tag[4:])
                        elif tag.startswith("rua="):
                            analysis["rua"] = tag[4:].split(",")
                        elif tag.startswith("ruf="):
                            analysis["ruf"] = tag[4:].split(",")
                    break

        except:
            pass

        return analysis

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower().strip()
        record_types_selection = config.get("record_types", "common")
        custom_ns = config.get("nameserver")

        self.logger.info("starting_dns_enumeration", domain=domain)

        # Configure resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        if custom_ns:
            resolver.nameservers = [custom_ns]

        record_types = self._get_record_types(record_types_selection)

        # Resolve all record types
        all_records = {}
        for rtype in record_types:
            records = await self._resolve_record(resolver, domain, rtype)
            if records:
                all_records[rtype] = records

        # Additional analysis
        dnssec = await self._check_dnssec(resolver, domain)
        spf_analysis = await self._analyze_spf(all_records.get("TXT", []))
        dmarc_analysis = await self._analyze_dmarc(resolver, domain)

        # Build summary
        summary = {
            "total_records": sum(len(r) for r in all_records.values()),
            "record_types_found": list(all_records.keys()),
            "has_ipv6": "AAAA" in all_records,
            "has_mail": "MX" in all_records,
            "dnssec_enabled": dnssec["enabled"],
        }

        self.logger.info(
            "dns_enumeration_complete",
            domain=domain,
            total_records=summary["total_records"]
        )

        return {
            "domain": domain,
            "records": all_records,
            "summary": summary,
            "dnssec": dnssec,
            "spf_analysis": spf_analysis,
            "dmarc_analysis": dmarc_analysis,
            "email_security": {
                "spf": spf_analysis["found"],
                "dmarc": dmarc_analysis["found"],
                "dmarc_policy": dmarc_analysis.get("policy"),
            }
        }
