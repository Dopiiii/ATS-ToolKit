"""Subdomain enumeration via bruteforce and Certificate Transparency logs.

Discovers subdomains using concurrent DNS resolution of common subdomain names
and queries the crt.sh Certificate Transparency database.
"""

import asyncio
import re
from typing import Any

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

WORDLIST_SMALL = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "dns", "mx", "api", "dev", "staging", "test", "admin", "portal", "vpn",
    "remote", "cdn", "cloud", "app", "blog", "shop", "store", "m", "mobile",
]

WORDLIST_MEDIUM = WORDLIST_SMALL + [
    "secure", "login", "auth", "sso", "gateway", "proxy", "lb", "internal",
    "docs", "wiki", "git", "gitlab", "jenkins", "ci", "cd", "monitor",
    "grafana", "kibana", "elastic", "db", "mysql", "postgres", "redis",
    "cache", "queue", "mq", "rabbitmq", "kafka", "s3", "storage", "backup",
    "dr", "beta", "alpha", "sandbox", "demo", "uat", "qa", "preprod",
    "web", "web1", "web2", "app1", "app2", "server", "host", "node",
    "media", "static", "assets", "img", "images", "video", "download",
]

WORDLIST_LARGE = WORDLIST_MEDIUM + [
    "intranet", "extranet", "partners", "clients", "crm", "erp", "hr",
    "finance", "accounts", "billing", "payment", "checkout", "cart",
    "search", "solr", "ldap", "ad", "exchange", "owa", "autodiscover",
    "relay", "spam", "waf", "firewall", "ids", "ips", "siem", "log",
    "syslog", "ntp", "time", "pki", "ca", "cert", "ssl", "tls",
    "vpn2", "ipsec", "wireguard", "openvpn", "ssh", "sftp", "ftps",
    "nas", "san", "nfs", "share", "print", "scan", "fax", "voip",
    "sip", "pbx", "phone", "meet", "zoom", "teams", "slack", "chat",
    "status", "health", "ping", "nagios", "zabbix", "prometheus",
    "vault", "consul", "terraform", "ansible", "puppet", "chef",
    "docker", "k8s", "kubernetes", "registry", "harbor", "nexus",
    "maven", "npm", "pypi", "nuget", "composer", "cargo",
]

WORDLISTS = {
    "small": WORDLIST_SMALL,
    "medium": WORDLIST_MEDIUM,
    "large": WORDLIST_LARGE,
}


class SubdomainEnumModule(AtsModule):
    """Enumerate subdomains via bruteforce and Certificate Transparency logs."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="subdomain_enum",
            category=ModuleCategory.OSINT,
            description="Subdomain enumeration via bruteforce DNS and crt.sh CT log queries",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain for subdomain discovery", required=True,
                ),
                Parameter(
                    name="method", type=ParameterType.CHOICE,
                    description="Enumeration method",
                    choices=["bruteforce", "crtsh", "both"], default="both",
                ),
                Parameter(
                    name="wordlist_size", type=ParameterType.CHOICE,
                    description="Wordlist size for bruteforce enumeration",
                    choices=["small", "medium", "large"], default="medium",
                ),
            ],
            outputs=[
                OutputField(name="subdomains", type="list", description="Discovered subdomains"),
                OutputField(name="total_found", type="integer", description="Total subdomains found"),
                OutputField(name="methods_used", type="list", description="Methods used for discovery"),
                OutputField(name="resolved", type="list", description="Subdomains with resolved IPs"),
            ],
            tags=["osint", "subdomain", "enumeration", "dns", "crt.sh"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        domain = config.get("domain", "").strip()
        if not domain:
            return False, "Domain is required"
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', domain):
            return False, "Invalid domain format"
        return True, ""

    async def _resolve_subdomain(
        self, session: aiohttp.ClientSession, subdomain: str,
    ) -> dict[str, Any] | None:
        """Resolve a subdomain via DNS-over-HTTPS."""
        try:
            url = f"https://dns.google/resolve?name={subdomain}&type=A"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get("Answer", [])
                    if answers:
                        ips = [a.get("data", "") for a in answers if a.get("type") == 1]
                        if ips:
                            return {"subdomain": subdomain, "ips": ips, "source": "bruteforce"}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None

    async def _bruteforce_subdomains(
        self, session: aiohttp.ClientSession, domain: str, wordlist: list[str],
    ) -> list[dict[str, Any]]:
        """Bruteforce subdomains using a wordlist."""
        found: list[dict[str, Any]] = []
        # Process in batches to avoid overwhelming DNS
        batch_size = 20
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = [
                self._resolve_subdomain(session, f"{word}.{domain}")
                for word in batch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict) and res is not None:
                    found.append(res)
            # Brief delay between batches
            await asyncio.sleep(0.1)
        return found

    async def _query_crtsh(
        self, session: aiohttp.ClientSession, domain: str,
    ) -> list[dict[str, Any]]:
        """Query crt.sh Certificate Transparency logs."""
        found: list[dict[str, Any]] = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    seen: set[str] = set()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{domain}") and name not in seen:
                                if "*" not in name:
                                    seen.add(name)
                                    found.append({
                                        "subdomain": name,
                                        "source": "crt.sh",
                                        "issuer": entry.get("issuer_name", ""),
                                        "not_before": entry.get("not_before", ""),
                                    })
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return found

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        method = config.get("method", "both")
        wordlist_size = config.get("wordlist_size", "medium")

        wordlist = WORDLISTS.get(wordlist_size, WORDLIST_MEDIUM)
        methods_used: list[str] = []
        all_subdomains: dict[str, dict[str, Any]] = {}

        connector = aiohttp.TCPConnector(limit=15, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            if method in ("bruteforce", "both"):
                methods_used.append("bruteforce")
                bf_results = await self._bruteforce_subdomains(session, domain, wordlist)
                for entry in bf_results:
                    sub = entry["subdomain"]
                    if sub not in all_subdomains:
                        all_subdomains[sub] = entry

            if method in ("crtsh", "both"):
                methods_used.append("crt.sh")
                ct_results = await self._query_crtsh(session, domain)
                for entry in ct_results:
                    sub = entry["subdomain"]
                    if sub not in all_subdomains:
                        all_subdomains[sub] = entry

        subdomains = sorted(all_subdomains.values(), key=lambda x: x["subdomain"])
        resolved = [s for s in subdomains if s.get("ips")]

        return {
            "domain": domain,
            "subdomains": subdomains,
            "total_found": len(subdomains),
            "methods_used": methods_used,
            "resolved": resolved,
            "wordlist_size": wordlist_size,
        }
