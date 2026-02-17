"""Dark web monitoring for OSINT investigations.

Monitors dark web sources for mentions of domains, email addresses, and keywords
using publicly accessible dark web search APIs and Tor-based intelligence feeds.
Provides alerts on leaked credentials, data dumps, and threat actor discussions.
"""

import asyncio
import hashlib
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# IntelX API (Intelligence X provides dark web indexing)
INTELX_API_BASE = "https://2.intelx.io"

# Ahmia.fi - Tor search engine with a clearnet API
AHMIA_SEARCH_BASE = "https://ahmia.fi"

# Onion search services (clearnet proxies)
ONION_SEARCH_ENGINES: list[dict[str, str]] = [
    {"name": "Ahmia", "url": "https://ahmia.fi/search/?q={query}"},
    {"name": "IntelX", "url": "https://intelx.io/?s={query}"},
]

# Categories of dark web threats
THREAT_CATEGORIES: dict[str, list[str]] = {
    "credential_leak": [
        "password", "credential", "login", "account", "combo", "combolist",
        "dump", "leak", "breach", "cracked",
    ],
    "data_sale": [
        "sell", "sale", "buy", "market", "shop", "database", "dump",
        "fullz", "ssn", "credit card", "cc",
    ],
    "threat_actor": [
        "hack", "exploit", "vulnerability", "zero-day", "0day", "backdoor",
        "ransomware", "malware", "rat", "botnet",
    ],
    "corporate_espionage": [
        "internal", "confidential", "proprietary", "source code", "api key",
        "secret", "private", "employee",
    ],
    "brand_abuse": [
        "phishing", "fake", "clone", "impersonate", "scam", "fraud",
        "counterfeit", "lookalike",
    ],
}


class DarkWebMonitorModule(AtsModule):
    """Monitor dark web for mentions of domains, emails, and keywords."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="dark_web_monitor",
            category=ModuleCategory.OSINT,
            description="Monitor dark web for mentions of domains, emails, and keywords via search APIs and intel feeds",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="query", type=ParameterType.STRING,
                    description="Search query: domain, email address, or keyword to monitor",
                    required=True,
                ),
                Parameter(
                    name="query_type", type=ParameterType.CHOICE,
                    description="Type of query to perform",
                    choices=["domain", "email", "keyword", "auto"],
                    default="auto", required=False,
                ),
                Parameter(
                    name="max_results", type=ParameterType.INTEGER,
                    description="Maximum number of results to return",
                    default=50, min_value=10, max_value=200, required=False,
                ),
                Parameter(
                    name="sources", type=ParameterType.CHOICE,
                    description="Which dark web intelligence sources to query",
                    choices=["all", "ahmia", "intelx"],
                    default="all", required=False,
                ),
                Parameter(
                    name="date_from", type=ParameterType.STRING,
                    description="Only return results after this date (YYYY-MM-DD)",
                    required=False, default="",
                ),
            ],
            outputs=[
                OutputField(name="results", type="list", description="Dark web mentions and findings"),
                OutputField(name="threat_summary", type="dict", description="Threat categorization summary"),
                OutputField(name="risk_indicators", type="list", description="Risk indicators found"),
                OutputField(name="sources_queried", type="list", description="Intelligence sources that were queried"),
                OutputField(name="total_results", type="integer", description="Total results found"),
            ],
            requires_api_key=False,
            api_key_service=None,
            tags=["osint", "darkweb", "tor", "monitoring", "threat-intel", "leaked-data"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        query = config.get("query", "").strip()
        if not query:
            return False, "Search query is required"
        if len(query) < 3:
            return False, "Query must be at least 3 characters"
        if len(query) > 200:
            return False, "Query must be under 200 characters"

        date_from = config.get("date_from", "").strip()
        if date_from:
            try:
                datetime.strptime(date_from, "%Y-%m-%d")
            except ValueError:
                return False, "date_from must be in YYYY-MM-DD format"

        return True, ""

    def _detect_query_type(self, query: str) -> str:
        """Auto-detect the type of query."""
        if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', query):
            return "email"
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', query):
            return "domain"
        return "keyword"

    async def _search_ahmia(
        self, session: aiohttp.ClientSession, query: str, max_results: int,
    ) -> list[dict[str, Any]]:
        """Search Ahmia.fi dark web search engine."""
        results: list[dict[str, Any]] = []
        encoded_query = quote(query)
        url = f"{AHMIA_SEARCH_BASE}/search/?q={encoded_query}"

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=20),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
                    "Accept": "text/html,application/xhtml+xml",
                },
            ) as resp:
                if resp.status == 200:
                    html = await resp.text(errors="ignore")
                    results = self._parse_ahmia_html(html, max_results)
                elif resp.status == 429:
                    results.append({"error": "Ahmia rate limit exceeded"})
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            results.append({"error": f"Ahmia search failed: {str(exc)}"})

        return results

    def _parse_ahmia_html(self, html: str, max_results: int) -> list[dict[str, Any]]:
        """Parse Ahmia search results from HTML response."""
        results: list[dict[str, Any]] = []

        # Extract search result blocks
        # Ahmia results are in <li class="result"> blocks
        result_pattern = re.compile(
            r'<li[^>]*class="result"[^>]*>.*?'
            r'<a[^>]*href="([^"]*)"[^>]*>([^<]*)</a>'
            r'.*?<p[^>]*>([^<]*)</p>',
            re.DOTALL | re.IGNORECASE,
        )

        # Also try alternate pattern for Ahmia's current layout
        alt_pattern = re.compile(
            r'<h4>\s*<a\s+href="(/search/redirect\?[^"]*)"[^>]*>([^<]*)</a>\s*</h4>'
            r'\s*<p[^>]*class="[^"]*"[^>]*>([^<]*)</p>',
            re.DOTALL | re.IGNORECASE,
        )

        # Try both patterns
        matches = result_pattern.findall(html)
        if not matches:
            matches = alt_pattern.findall(html)

        # Fallback: extract all links and surrounding text
        if not matches:
            link_pattern = re.compile(
                r'<a[^>]*href="([^"]*onion[^"]*)"[^>]*>([^<]*)</a>',
                re.IGNORECASE,
            )
            for href, title in link_pattern.findall(html)[:max_results]:
                results.append({
                    "title": title.strip(),
                    "url": href.strip(),
                    "snippet": "",
                    "source": "ahmia",
                    "timestamp": datetime.utcnow().isoformat(),
                })
            return results

        for match in matches[:max_results]:
            url_val, title, snippet = match
            results.append({
                "title": title.strip(),
                "url": url_val.strip(),
                "snippet": snippet.strip(),
                "source": "ahmia",
                "timestamp": datetime.utcnow().isoformat(),
            })

        return results

    async def _search_intelx(
        self, session: aiohttp.ClientSession, query: str,
        api_key: str, max_results: int, query_type: str,
    ) -> list[dict[str, Any]]:
        """Search Intelligence X for dark web mentions."""
        results: list[dict[str, Any]] = []

        if not api_key:
            # Use the free public API tier with limited results
            api_key = "9df61df0-84f7-4dc7-b34c-8ccfb8646571"  # Public demo key

        # Determine media type for IntelX
        media_type_map = {
            "email": 1,    # Email
            "domain": 2,   # Domain
            "keyword": 0,  # General
        }
        media_type = media_type_map.get(query_type, 0)

        # Start search
        search_url = f"{INTELX_API_BASE}/intelligent/search"
        search_body = {
            "term": query,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": max_results,
            "timeout": 10,
            "datefrom": "",
            "dateto": "",
            "sort": 2,  # Sort by date descending
            "media": media_type,
            "terminate": [],
        }

        headers = {
            "x-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "ATS-Toolkit/1.0",
        }

        try:
            # Submit search
            async with session.post(
                search_url,
                json=search_body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    search_id = data.get("id", "")
                    if not search_id:
                        return results
                elif resp.status == 402:
                    return [{"error": "IntelX API quota exceeded"}]
                else:
                    return [{"error": f"IntelX search returned HTTP {resp.status}"}]

            # Wait for results
            await asyncio.sleep(3)

            # Fetch results
            result_url = f"{INTELX_API_BASE}/intelligent/search/result"
            params = {"id": search_id, "limit": max_results, "offset": 0}

            async with session.get(
                result_url,
                params=params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    records = data.get("records", [])
                    for record in records:
                        result_entry = {
                            "title": record.get("name", ""),
                            "url": record.get("systemid", ""),
                            "snippet": record.get("name", ""),
                            "source": "intelx",
                            "media_type": record.get("media", 0),
                            "bucket": record.get("bucket", ""),
                            "timestamp": record.get("date", ""),
                            "size": record.get("size", 0),
                            "storage_id": record.get("storageid", ""),
                        }
                        results.append(result_entry)

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            results.append({"error": f"IntelX search failed: {str(exc)}"})

        return results

    def _categorize_threats(
        self, results: list[dict[str, Any]], query: str,
    ) -> dict[str, Any]:
        """Categorize dark web findings by threat type."""
        categories: dict[str, list[int]] = {cat: [] for cat in THREAT_CATEGORIES}

        for i, result in enumerate(results):
            if "error" in result:
                continue

            # Combine title and snippet for analysis
            text = f"{result.get('title', '')} {result.get('snippet', '')}".lower()

            for category, keywords in THREAT_CATEGORIES.items():
                for keyword in keywords:
                    if keyword in text:
                        if i not in categories[category]:
                            categories[category].append(i)
                        break

        # Build summary
        summary: dict[str, Any] = {}
        for category, indices in categories.items():
            if indices:
                summary[category] = {
                    "count": len(indices),
                    "result_indices": indices[:10],  # Limit to first 10 references
                }

        summary["total_categorized"] = sum(len(v) for v in categories.values())
        summary["uncategorized"] = len([
            r for i, r in enumerate(results)
            if "error" not in r and not any(i in indices for indices in categories.values())
        ])

        return summary

    def _assess_risk_indicators(
        self, results: list[dict[str, Any]], query: str, query_type: str,
    ) -> list[dict[str, str]]:
        """Identify specific risk indicators from results."""
        indicators: list[dict[str, str]] = []

        if not results:
            indicators.append({
                "level": "INFO",
                "indicator": f"No dark web mentions found for '{query}'",
                "recommendation": "Continue monitoring periodically",
            })
            return indicators

        valid_results = [r for r in results if "error" not in r]
        total = len(valid_results)

        if total == 0:
            return indicators

        # Volume-based risk
        if total >= 50:
            indicators.append({
                "level": "HIGH",
                "indicator": f"High volume of mentions ({total} results) on dark web",
                "recommendation": "Conduct thorough investigation of each mention",
            })
        elif total >= 10:
            indicators.append({
                "level": "MEDIUM",
                "indicator": f"Moderate mentions ({total} results) on dark web",
                "recommendation": "Review results for credential leaks and threats",
            })
        else:
            indicators.append({
                "level": "LOW",
                "indicator": f"Low volume of mentions ({total} results) on dark web",
                "recommendation": "Monitor for new appearances",
            })

        # Check for credential-related content
        cred_keywords = ["password", "credential", "login", "combo", "dump"]
        cred_count = 0
        for result in valid_results:
            text = f"{result.get('title', '')} {result.get('snippet', '')}".lower()
            if any(kw in text for kw in cred_keywords):
                cred_count += 1

        if cred_count > 0:
            indicators.append({
                "level": "CRITICAL",
                "indicator": f"{cred_count} result(s) potentially contain credential leaks",
                "recommendation": "Immediately verify if credentials are valid and force password resets",
            })

        # Check for active sales/marketplace listings
        sale_keywords = ["sell", "sale", "buy", "market", "shop", "price", "$"]
        sale_count = 0
        for result in valid_results:
            text = f"{result.get('title', '')} {result.get('snippet', '')}".lower()
            if any(kw in text for kw in sale_keywords):
                sale_count += 1

        if sale_count > 0:
            indicators.append({
                "level": "HIGH",
                "indicator": f"{sale_count} result(s) suggest data may be for sale",
                "recommendation": "Engage incident response team to assess scope of data exposure",
            })

        # Check for recent mentions
        recent_count = 0
        now = datetime.utcnow()
        for result in valid_results:
            ts = result.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "").split("+")[0])
                    if (now - dt).days < 30:
                        recent_count += 1
                except (ValueError, TypeError):
                    pass

        if recent_count > 0:
            indicators.append({
                "level": "HIGH",
                "indicator": f"{recent_count} mention(s) from the last 30 days",
                "recommendation": "Recent activity suggests ongoing or fresh exposure",
            })

        # Query-type specific indicators
        if query_type == "email":
            indicators.append({
                "level": "MEDIUM",
                "indicator": "Email address found on dark web sources",
                "recommendation": "Change associated passwords and enable MFA on all accounts",
            })
        elif query_type == "domain":
            indicators.append({
                "level": "MEDIUM",
                "indicator": "Organization domain found on dark web sources",
                "recommendation": "Audit all employee accounts and review access controls",
            })

        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        query = config["query"].strip()
        query_type = config.get("query_type", "auto")
        max_results = config.get("max_results", 50)
        sources = config.get("sources", "all")
        date_from = config.get("date_from", "").strip()
        intelx_api_key = config.get("api_key", "")

        # Auto-detect query type
        if query_type == "auto":
            query_type = self._detect_query_type(query)

        all_results: list[dict[str, Any]] = []
        sources_queried: list[str] = []
        errors: list[str] = []

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks: list[Any] = []

            if sources in ("all", "ahmia"):
                tasks.append(("ahmia", self._search_ahmia(session, query, max_results)))
                sources_queried.append("ahmia")

            if sources in ("all", "intelx"):
                tasks.append(("intelx", self._search_intelx(
                    session, query, intelx_api_key, max_results, query_type,
                )))
                sources_queried.append("intelx")

            # Execute all searches concurrently
            coros = [t[1] for t in tasks]
            task_names = [t[0] for t in tasks]
            results = await asyncio.gather(*coros, return_exceptions=True)

            for name, res in zip(task_names, results):
                if isinstance(res, Exception):
                    errors.append(f"{name} error: {str(res)}")
                else:
                    # Separate errors from results
                    for entry in res:
                        if "error" in entry:
                            errors.append(entry["error"])
                        else:
                            all_results.append(entry)

        # Filter by date if specified
        if date_from:
            cutoff = datetime.strptime(date_from, "%Y-%m-%d")
            filtered: list[dict[str, Any]] = []
            for result in all_results:
                ts = result.get("timestamp", "")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "").split("+")[0])
                        if dt >= cutoff:
                            filtered.append(result)
                    except (ValueError, TypeError):
                        filtered.append(result)  # Include if date unparseable
                else:
                    filtered.append(result)
            all_results = filtered

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique_results: list[dict[str, Any]] = []
        for result in all_results:
            url_key = result.get("url", "")
            title_key = result.get("title", "")
            dedup_key = f"{url_key}|{title_key}"
            if dedup_key not in seen_urls:
                seen_urls.add(dedup_key)
                unique_results.append(result)

        # Limit results
        unique_results = unique_results[:max_results]

        # Categorize threats
        threat_summary = self._categorize_threats(unique_results, query)

        # Assess risk
        risk_indicators = self._assess_risk_indicators(unique_results, query, query_type)

        output: dict[str, Any] = {
            "query": query,
            "query_type": query_type,
            "results": unique_results,
            "threat_summary": threat_summary,
            "risk_indicators": risk_indicators,
            "sources_queried": sources_queried,
            "total_results": len(unique_results),
        }

        if errors:
            output["warnings"] = errors

        return output
