"""Google Dorks module.

Generate and organize Google dork queries for reconnaissance.
"""

from typing import Any, Dict, List, Tuple
import urllib.parse

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Predefined dork templates by category
DORK_TEMPLATES = {
    "files": [
        ('Exposed PDFs', 'site:{domain} filetype:pdf'),
        ('Exposed DOCs', 'site:{domain} filetype:doc OR filetype:docx'),
        ('Exposed XLS', 'site:{domain} filetype:xls OR filetype:xlsx'),
        ('Config Files', 'site:{domain} filetype:conf OR filetype:cfg'),
        ('Log Files', 'site:{domain} filetype:log'),
        ('SQL Files', 'site:{domain} filetype:sql'),
        ('Backup Files', 'site:{domain} filetype:bak OR filetype:backup'),
        ('Database Files', 'site:{domain} filetype:db OR filetype:sqlite'),
        ('Environment Files', 'site:{domain} filetype:env'),
    ],
    "directories": [
        ('Directory Listings', 'site:{domain} intitle:"Index of"'),
        ('Admin Panels', 'site:{domain} inurl:admin'),
        ('Login Pages', 'site:{domain} inurl:login OR inurl:signin'),
        ('Backup Directories', 'site:{domain} inurl:backup'),
        ('Upload Directories', 'site:{domain} inurl:upload'),
        ('Config Directories', 'site:{domain} inurl:config'),
        ('Include Directories', 'site:{domain} inurl:include'),
    ],
    "sensitive": [
        ('Exposed Passwords', 'site:{domain} intext:password filetype:txt'),
        ('Private Keys', 'site:{domain} filetype:key OR filetype:pem'),
        ('Git Exposed', 'site:{domain} inurl:.git'),
        ('SVN Exposed', 'site:{domain} inurl:.svn'),
        ('Htaccess Files', 'site:{domain} filetype:htaccess'),
        ('SSH Keys', 'site:{domain} filetype:ppk OR filetype:pem'),
        ('Config with Passwords', 'site:{domain} intext:"password" filetype:xml'),
    ],
    "vulnerabilities": [
        ('SQL Errors', 'site:{domain} intext:"sql syntax" OR intext:"mysql_fetch"'),
        ('PHP Errors', 'site:{domain} intext:"Warning: " filetype:php'),
        ('Debug Pages', 'site:{domain} intext:"debug" OR inurl:debug'),
        ('phpinfo', 'site:{domain} inurl:phpinfo.php'),
        ('Server Status', 'site:{domain} inurl:server-status'),
        ('Test Pages', 'site:{domain} inurl:test OR intitle:test'),
    ],
    "api": [
        ('API Documentation', 'site:{domain} inurl:api AND (inurl:doc OR inurl:docs)'),
        ('Swagger UI', 'site:{domain} inurl:swagger'),
        ('GraphQL', 'site:{domain} inurl:graphql'),
        ('API Keys Exposed', 'site:{domain} intext:"api_key" OR intext:"apikey"'),
        ('REST Endpoints', 'site:{domain} inurl:/api/v'),
    ],
    "infrastructure": [
        ('Jenkins', 'site:{domain} intitle:"Dashboard [Jenkins]"'),
        ('GitLab', 'site:{domain} inurl:gitlab'),
        ('Jira', 'site:{domain} inurl:jira'),
        ('Confluence', 'site:{domain} inurl:confluence'),
        ('Kibana', 'site:{domain} inurl:kibana'),
        ('Grafana', 'site:{domain} inurl:grafana'),
        ('WordPress', 'site:{domain} inurl:wp-admin OR inurl:wp-content'),
        ('Drupal', 'site:{domain} inurl:sites/default'),
    ],
    "subdomains": [
        ('All Indexed Pages', 'site:{domain}'),
        ('Subdomains', 'site:*.{domain}'),
        ('Excluding WWW', 'site:*.{domain} -site:www.{domain}'),
        ('Dev/Test Subdomains', 'site:*.{domain} (dev OR test OR staging OR uat)'),
    ],
}


class GoogleDorksModule(AtsModule):
    """Generate Google dork queries for reconnaissance."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="google_dorks",
            category=ModuleCategory.OSINT,
            description="Generate Google dork queries for reconnaissance",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="domain",
                    type=ParameterType.DOMAIN,
                    description="Target domain",
                    required=True,
                ),
                Parameter(
                    name="categories",
                    type=ParameterType.CHOICE,
                    description="Dork categories to generate",
                    required=False,
                    default="all",
                    choices=["all", "files", "directories", "sensitive", "vulnerabilities", "api", "infrastructure", "subdomains"],
                ),
                Parameter(
                    name="custom_term",
                    type=ParameterType.STRING,
                    description="Additional search term to include",
                    required=False,
                ),
            ],
            outputs=[
                OutputField(name="dorks", type="list", description="Generated dork queries"),
                OutputField(name="urls", type="list", description="Google search URLs"),
            ],
            tags=["google", "dorks", "osint", "recon"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        domain = config.get("domain", "")
        if not domain or "." not in domain:
            return False, "Invalid domain format"
        return True, ""

    def _generate_dork(self, template: str, domain: str, custom_term: str = "") -> str:
        """Generate a dork query from template."""
        dork = template.format(domain=domain)
        if custom_term:
            dork = f"{dork} {custom_term}"
        return dork

    def _create_google_url(self, query: str) -> str:
        """Create a Google search URL for a query."""
        encoded = urllib.parse.quote_plus(query)
        return f"https://www.google.com/search?q={encoded}"

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = config["domain"].lower().strip()
        categories_selection = config.get("categories", "all")
        custom_term = config.get("custom_term", "")

        self.logger.info("generating_dorks", domain=domain, categories=categories_selection)

        results = {
            "domain": domain,
            "dorks": [],
            "urls": [],
            "by_category": {},
        }

        # Determine which categories to use
        if categories_selection == "all":
            categories = list(DORK_TEMPLATES.keys())
        else:
            categories = [categories_selection]

        # Generate dorks for each category
        for category in categories:
            templates = DORK_TEMPLATES.get(category, [])
            category_dorks = []

            for name, template in templates:
                dork = self._generate_dork(template, domain, custom_term)
                google_url = self._create_google_url(dork)

                dork_entry = {
                    "name": name,
                    "query": dork,
                    "url": google_url,
                    "category": category,
                }

                category_dorks.append(dork_entry)
                results["dorks"].append(dork_entry)
                results["urls"].append(google_url)

            results["by_category"][category] = category_dorks

        # Add custom dorks
        custom_dorks = self._generate_custom_dorks(domain)
        results["custom_dorks"] = custom_dorks
        results["dorks"].extend(custom_dorks)

        self.logger.info(
            "dorks_generated",
            domain=domain,
            total=len(results["dorks"])
        )

        return results

    def _generate_custom_dorks(self, domain: str) -> List[Dict[str, Any]]:
        """Generate additional custom dorks."""
        custom = []

        # Year-based searches
        import datetime
        current_year = datetime.datetime.now().year

        custom.append({
            "name": f"Recent content ({current_year})",
            "query": f'site:{domain} "{current_year}"',
            "url": self._create_google_url(f'site:{domain} "{current_year}"'),
            "category": "custom",
        })

        # Common sensitive terms
        sensitive_terms = ["confidential", "internal", "private", "secret"]
        for term in sensitive_terms:
            custom.append({
                "name": f"Pages with '{term}'",
                "query": f'site:{domain} intext:"{term}"',
                "url": self._create_google_url(f'site:{domain} intext:"{term}"'),
                "category": "custom",
            })

        return custom
