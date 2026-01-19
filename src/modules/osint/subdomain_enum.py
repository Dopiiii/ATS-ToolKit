"""Subdomain enumeration module.

Discover subdomains using multiple techniques: DNS brute-force, certificate transparency, etc.
"""

import asyncio
import dns.resolver
import aiohttp
from typing import Any, Dict, List, Tuple, Set

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "www2", "admin",
    "portal", "api", "test", "staging", "prod", "production", "app", "apps",
    "web", "server", "host", "support", "email", "cloud", "cdn", "static",
    "assets", "img", "images", "media", "video", "files", "download", "uploads",
    "git", "gitlab", "github", "svn", "cvs", "repo", "jenkins", "ci", "build",
    "vpn", "remote", "secure", "ssl", "ww1", "ww2", "old", "new", "beta",
    "alpha", "demo", "sandbox", "uat", "qa", "dev1", "dev2", "stage", "stg",
    "db", "database", "mysql", "postgres", "sql", "oracle", "mongo", "redis",
    "cache", "memcache", "elastic", "kibana", "grafana", "prometheus", "logs",
    "monitor", "monitoring", "status", "health", "metrics", "analytics",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing", "invoice",
    "crm", "erp", "hr", "intranet", "internal", "corp", "corporate", "office",
    "docs", "doc", "wiki", "help", "faq", "kb", "knowledge", "learn", "training",
    "m", "mobile", "ios", "android", "api-v1", "api-v2", "v1", "v2", "rest",
    "graphql", "ws", "websocket", "socket", "chat", "msg", "message", "notify",
]


class SubdomainEnumModule(AtsModule):
    """Enumerate subdomains for a target domain."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="subdomain_enum",
            category=ModuleCategory.OSINT,
            description="Discover subdomains via DNS brute-force and CT logs",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain",
                    type=ParameterType.DOMAIN,
                    description="Target domain",
                    required=True,
                ),
                Parameter(
                    name="method",
                    type=ParameterType.CHOICE,
                    description="Enumeration method",
                    required=False,
                    default="hybrid",
                    choices=["bruteforce", "passive", "hybrid"],
                ),
                Parameter(
                    name="wordlist",
                    type=ParameterType.CHOICE,
                    description="Wordlist size for bruteforce",
                    required=False,
                    default="common",
                    choices=["small", "common", "large"],
                ),
                Parameter(
                    name="threads",
                    type=ParameterType.INTEGER,
                    description="Concurrent threads",
                    required=False,
                    default=50,
                    min_value=1,
                    max_value=200,
                ),
            ],
            outputs=[
                OutputField(name="subdomains", type="list", description="Discovered subdomains"),
                OutputField(name="count", type="integer", description="Number of subdomains found"),
            ],
            tags=["subdomain", "dns", "enumeration", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        if "." not in domain:
            return False, "Invalid domain format"
        return True, ""

    def _get_wordlist(self, size: str) -> List[str]:
        """Get subdomain wordlist based on size."""
        if size == "small":
            return COMMON_SUBDOMAINS[:30]
        elif size == "common":
            return COMMON_SUBDOMAINS
        else:  # large
            # In production, would load from file
            return COMMON_SUBDOMAINS + [f"sub{i}" for i in range(1, 100)]

    async def _resolve_subdomain(
        self,
        subdomain: str,
        resolver: dns.resolver.Resolver
    ) -> Dict[str, Any] | None:
        """Try to resolve a subdomain."""
        try:
            answers = resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            return {
                "subdomain": subdomain,
                "ips": ips,
                "source": "dns_bruteforce"
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except Exception:
            return None

    async def _bruteforce_subdomains(
        self,
        domain: str,
        wordlist: List[str],
        threads: int
    ) -> List[Dict[str, Any]]:
        """Bruteforce subdomains using DNS resolution."""
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(threads)

        async def check_subdomain(word: str):
            async with semaphore:
                subdomain = f"{word}.{domain}"
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._resolve_subdomain_sync(subdomain, resolver)
                )
                if result:
                    found.append(result)
                    self.logger.debug("subdomain_found", subdomain=subdomain)

        tasks = [check_subdomain(word) for word in wordlist]
        await asyncio.gather(*tasks)

        return found

    def _resolve_subdomain_sync(
        self,
        subdomain: str,
        resolver: dns.resolver.Resolver
    ) -> Dict[str, Any] | None:
        """Synchronous subdomain resolution."""
        try:
            answers = resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            return {
                "subdomain": subdomain,
                "ips": ips,
                "source": "dns_bruteforce"
            }
        except:
            return None

    async def _query_crtsh(
        self,
        session: aiohttp.ClientSession,
        domain: str
    ) -> List[Dict[str, Any]]:
        """Query crt.sh certificate transparency logs."""
        found = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    seen = set()

                    for entry in data:
                        name = entry.get("name_value", "")
                        # Handle wildcard and multi-line entries
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lstrip("*.")
                            if subdomain.endswith(domain) and subdomain not in seen:
                                seen.add(subdomain)
                                found.append({
                                    "subdomain": subdomain,
                                    "source": "crt.sh",
                                    "issuer": entry.get("issuer_name", "")[:50]
                                })

        except Exception as e:
            self.logger.warning("crtsh_query_failed", error=str(e))

        return found

    async def _query_hackertarget(
        self,
        session: aiohttp.ClientSession,
        domain: str
    ) -> List[Dict[str, Any]]:
        """Query HackerTarget API for subdomains."""
        found = []
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    text = await response.text()
                    if "error" not in text.lower():
                        for line in text.strip().split("\n"):
                            if "," in line:
                                subdomain, ip = line.split(",", 1)
                                found.append({
                                    "subdomain": subdomain.strip(),
                                    "ips": [ip.strip()],
                                    "source": "hackertarget"
                                })

        except Exception as e:
            self.logger.warning("hackertarget_query_failed", error=str(e))

        return found

    async def _passive_enumeration(
        self,
        domain: str
    ) -> List[Dict[str, Any]]:
        """Perform passive subdomain enumeration."""
        found = []

        async with aiohttp.ClientSession() as session:
            # Query multiple sources concurrently
            tasks = [
                self._query_crtsh(session, domain),
                self._query_hackertarget(session, domain),
            ]

            results = await asyncio.gather(*tasks)

            for result_list in results:
                found.extend(result_list)

        return found

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower().strip()
        method = config.get("method", "hybrid")
        wordlist_size = config.get("wordlist", "common")
        threads = config.get("threads", 50)

        self.logger.info(
            "starting_subdomain_enum",
            domain=domain,
            method=method
        )

        all_subdomains: Dict[str, Dict] = {}

        # Passive enumeration
        if method in ["passive", "hybrid"]:
            passive_results = await self._passive_enumeration(domain)
            for result in passive_results:
                subdomain = result["subdomain"]
                if subdomain not in all_subdomains:
                    all_subdomains[subdomain] = result

        # Active bruteforce
        if method in ["bruteforce", "hybrid"]:
            wordlist = self._get_wordlist(wordlist_size)
            bruteforce_results = await self._bruteforce_subdomains(domain, wordlist, threads)
            for result in bruteforce_results:
                subdomain = result["subdomain"]
                if subdomain not in all_subdomains:
                    all_subdomains[subdomain] = result

        # Sort results
        subdomains = sorted(all_subdomains.values(), key=lambda x: x["subdomain"])

        self.logger.info(
            "subdomain_enum_complete",
            domain=domain,
            found=len(subdomains)
        )

        return {
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "method": method,
            "sources": list(set(s.get("source", "unknown") for s in subdomains))
        }
