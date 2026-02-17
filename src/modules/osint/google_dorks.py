"""Google dork query generator for targeted information gathering.

Generates site-specific Google dork queries organized by category to discover
exposed files, directories, sensitive information, and potential vulnerabilities.
"""

import asyncio
import re
from urllib.parse import quote_plus
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

DORK_CATEGORIES = {
    "files": [
        ('Exposed PDF files', 'site:{domain} filetype:pdf'),
        ('Excel spreadsheets', 'site:{domain} filetype:xlsx OR filetype:xls'),
        ('Word documents', 'site:{domain} filetype:docx OR filetype:doc'),
        ('Configuration files', 'site:{domain} filetype:xml OR filetype:conf OR filetype:cfg'),
        ('Log files', 'site:{domain} filetype:log'),
        ('SQL database dumps', 'site:{domain} filetype:sql'),
        ('Backup files', 'site:{domain} filetype:bak OR filetype:backup OR filetype:old'),
        ('Environment files', 'site:{domain} filetype:env'),
        ('CSV data exports', 'site:{domain} filetype:csv'),
        ('Source code files', 'site:{domain} filetype:py OR filetype:php OR filetype:js'),
    ],
    "directories": [
        ('Open directory listings', 'site:{domain} intitle:"Index of /"'),
        ('Parent directory access', 'site:{domain} intitle:"Parent Directory"'),
        ('Backup directories', 'site:{domain} inurl:backup OR inurl:bak'),
        ('Admin panels', 'site:{domain} inurl:admin OR inurl:administrator'),
        ('Upload directories', 'site:{domain} inurl:upload OR inurl:uploads'),
        ('Temporary directories', 'site:{domain} inurl:tmp OR inurl:temp'),
        ('Hidden directories', 'site:{domain} inurl:.git OR inurl:.svn'),
        ('API endpoints', 'site:{domain} inurl:api OR inurl:/v1/ OR inurl:/v2/'),
        ('Config directories', 'site:{domain} inurl:config OR inurl:conf'),
        ('Include directories', 'site:{domain} inurl:includes OR inurl:inc'),
    ],
    "sensitive": [
        ('Exposed passwords', 'site:{domain} intext:"password" filetype:txt OR filetype:log'),
        ('Private keys', 'site:{domain} filetype:pem OR filetype:key'),
        ('Database credentials', 'site:{domain} intext:"db_password" OR intext:"database_password"'),
        ('API keys exposed', 'site:{domain} intext:"api_key" OR intext:"apikey" OR intext:"api_secret"'),
        ('Email addresses', 'site:{domain} intext:"@{domain}" filetype:txt OR filetype:csv'),
        ('phpinfo pages', 'site:{domain} inurl:phpinfo.php'),
        ('Error messages', 'site:{domain} intext:"Warning:" OR intext:"Fatal error:"'),
        ('Login pages', 'site:{domain} inurl:login OR inurl:signin'),
        ('AWS keys', 'site:{domain} intext:"AKIA" OR intext:"aws_secret"'),
        ('SSH keys', 'site:{domain} intext:"BEGIN RSA PRIVATE KEY" OR intext:"BEGIN OPENSSH"'),
    ],
    "vulnerabilities": [
        ('SQL injection vectors', 'site:{domain} inurl:"id=" OR inurl:"page=" OR inurl:"cat="'),
        ('PHP file inclusion', 'site:{domain} inurl:"file=" OR inurl:"path=" OR inurl:"include="'),
        ('Open redirect params', 'site:{domain} inurl:"redirect=" OR inurl:"url=" OR inurl:"next="'),
        ('Debug/test pages', 'site:{domain} inurl:debug OR inurl:test OR inurl:trace'),
        ('WordPress exposure', 'site:{domain} inurl:wp-content OR inurl:wp-admin'),
        ('Server status pages', 'site:{domain} inurl:server-status OR inurl:server-info'),
        ('CGI-bin scripts', 'site:{domain} inurl:cgi-bin'),
        ('XMLRPC endpoints', 'site:{domain} inurl:xmlrpc.php'),
        ('Exposed .htaccess', 'site:{domain} filetype:htaccess'),
        ('Robots.txt secrets', 'site:{domain} inurl:robots.txt "Disallow:"'),
    ],
}


class GoogleDorksModule(AtsModule):
    """Generate Google dork queries for targeted information discovery."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="google_dorks",
            category=ModuleCategory.OSINT,
            description="Generate Google dork queries to discover exposed files, dirs, and vulnerabilities",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain", type=ParameterType.DOMAIN,
                    description="Target domain for Google dork queries", required=True,
                ),
                Parameter(
                    name="categories", type=ParameterType.CHOICE,
                    description="Dork categories to generate",
                    choices=["all", "files", "directories", "sensitive", "vulnerabilities"],
                    default="all",
                ),
                Parameter(
                    name="include_urls", type=ParameterType.BOOLEAN,
                    description="Include direct Google search URLs for each dork",
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="dorks", type="list", description="Generated dork queries"),
                OutputField(name="total_dorks", type="integer", description="Total dork queries generated"),
                OutputField(name="categories", type="list", description="Categories covered"),
                OutputField(name="search_urls", type="list", description="Google search URLs"),
            ],
            tags=["osint", "google", "dorks", "information-gathering"],
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

    def _generate_dorks(
        self, domain: str, categories: list[str], include_urls: bool,
    ) -> list[dict[str, Any]]:
        """Generate dork queries for the specified categories."""
        dorks: list[dict[str, Any]] = []

        for category in categories:
            cat_dorks = DORK_CATEGORIES.get(category, [])
            for description, template in cat_dorks:
                query = template.format(domain=domain)
                entry: dict[str, Any] = {
                    "description": description,
                    "query": query,
                    "category": category,
                }
                if include_urls:
                    entry["search_url"] = f"https://www.google.com/search?q={quote_plus(query)}"
                dorks.append(entry)

        return dorks

    def _generate_custom_dorks(self, domain: str) -> list[dict[str, Any]]:
        """Generate additional domain-specific custom dorks."""
        custom: list[dict[str, Any]] = []

        # Subdomain discovery via Google
        custom.append({
            "description": "Subdomain discovery",
            "query": f"site:*.{domain} -www",
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(f'site:*.{domain} -www')}",
        })

        # Third-party references
        custom.append({
            "description": "Third-party references to domain",
            "query": f'"{domain}" -site:{domain}',
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(f'{domain} -site:{domain}')}",
        })

        # Cached/archived versions
        custom.append({
            "description": "Cached pages",
            "query": f"cache:{domain}",
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(f'cache:{domain}')}",
        })

        # LinkedIn employee search
        linkedin_query = f'site:linkedin.com/in "{domain}"'
        custom.append({
            "description": "LinkedIn employee profiles",
            "query": linkedin_query,
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(linkedin_query)}",
        })

        # Pastebin/GitHub leaks
        pastebin_query = f'site:pastebin.com "{domain}"'
        custom.append({
            "description": "Pastebin mentions",
            "query": pastebin_query,
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(pastebin_query)}",
        })

        github_query = f'site:github.com "{domain}"'
        custom.append({
            "description": "GitHub code mentions",
            "query": github_query,
            "category": "custom",
            "search_url": f"https://www.google.com/search?q={quote_plus(github_query)}",
        })

        return custom

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["domain"].strip().lower()
        category_choice = config.get("categories", "all")
        include_urls = config.get("include_urls", True)

        if category_choice == "all":
            categories = list(DORK_CATEGORIES.keys())
        else:
            categories = [category_choice]

        dorks = self._generate_dorks(domain, categories, include_urls)
        custom_dorks = self._generate_custom_dorks(domain)
        all_dorks = dorks + custom_dorks

        # Organize by category for summary
        category_summary: dict[str, int] = {}
        for dork in all_dorks:
            cat = dork["category"]
            category_summary[cat] = category_summary.get(cat, 0) + 1

        # Extract just the search URLs
        search_urls = [d["search_url"] for d in all_dorks if "search_url" in d]

        return {
            "domain": domain,
            "dorks": all_dorks,
            "total_dorks": len(all_dorks),
            "categories": categories + ["custom"],
            "category_summary": category_summary,
            "search_urls": search_urls if include_urls else [],
        }
