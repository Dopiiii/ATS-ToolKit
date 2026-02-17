"""Website technology stack detection for OSINT investigations.

Analyzes HTTP response headers, HTML content, JavaScript references, and
meta tags to identify CMS platforms, web frameworks, JavaScript libraries,
server software, analytics tools, and CDN providers.
"""

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Technology signature database
HEADER_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "server": [
        {"pattern": r"nginx", "tech": "Nginx", "category": "web_server"},
        {"pattern": r"apache", "tech": "Apache", "category": "web_server"},
        {"pattern": r"microsoft-iis", "tech": "Microsoft IIS", "category": "web_server"},
        {"pattern": r"litespeed", "tech": "LiteSpeed", "category": "web_server"},
        {"pattern": r"cloudflare", "tech": "Cloudflare", "category": "cdn"},
        {"pattern": r"openresty", "tech": "OpenResty", "category": "web_server"},
        {"pattern": r"caddy", "tech": "Caddy", "category": "web_server"},
        {"pattern": r"gunicorn", "tech": "Gunicorn", "category": "web_server"},
    ],
    "x-powered-by": [
        {"pattern": r"php/?(\d[\d.]*)?", "tech": "PHP", "category": "language"},
        {"pattern": r"asp\.?net", "tech": "ASP.NET", "category": "framework"},
        {"pattern": r"express", "tech": "Express.js", "category": "framework"},
        {"pattern": r"next\.?js", "tech": "Next.js", "category": "framework"},
        {"pattern": r"django", "tech": "Django", "category": "framework"},
        {"pattern": r"flask", "tech": "Flask", "category": "framework"},
        {"pattern": r"ruby", "tech": "Ruby", "category": "language"},
    ],
    "x-generator": [
        {"pattern": r"wordpress", "tech": "WordPress", "category": "cms"},
        {"pattern": r"drupal", "tech": "Drupal", "category": "cms"},
        {"pattern": r"joomla", "tech": "Joomla", "category": "cms"},
        {"pattern": r"hugo", "tech": "Hugo", "category": "static_site_generator"},
        {"pattern": r"gatsby", "tech": "Gatsby", "category": "static_site_generator"},
    ],
}

HTML_SIGNATURES: list[dict[str, str]] = [
    # CMS signatures
    {"pattern": r'content=["\']WordPress', "tech": "WordPress", "category": "cms"},
    {"pattern": r"/wp-content/", "tech": "WordPress", "category": "cms"},
    {"pattern": r"/wp-includes/", "tech": "WordPress", "category": "cms"},
    {"pattern": r'Drupal\.settings', "tech": "Drupal", "category": "cms"},
    {"pattern": r"/sites/default/files", "tech": "Drupal", "category": "cms"},
    {"pattern": r'content=["\']Joomla', "tech": "Joomla", "category": "cms"},
    {"pattern": r"/media/jui/", "tech": "Joomla", "category": "cms"},
    {"pattern": r"Shopify\.theme", "tech": "Shopify", "category": "ecommerce"},
    {"pattern": r"cdn\.shopify\.com", "tech": "Shopify", "category": "ecommerce"},
    {"pattern": r"Magento", "tech": "Magento", "category": "ecommerce"},
    {"pattern": r"/skin/frontend/", "tech": "Magento", "category": "ecommerce"},
    {"pattern": r"WooCommerce", "tech": "WooCommerce", "category": "ecommerce"},
    {"pattern": r"wix\.com", "tech": "Wix", "category": "website_builder"},
    {"pattern": r"squarespace\.com", "tech": "Squarespace", "category": "website_builder"},
    {"pattern": r"ghost\.org", "tech": "Ghost", "category": "cms"},

    # JavaScript frameworks
    {"pattern": r"__next", "tech": "Next.js", "category": "framework"},
    {"pattern": r"__nuxt", "tech": "Nuxt.js", "category": "framework"},
    {"pattern": r"__NUXT__", "tech": "Nuxt.js", "category": "framework"},
    {"pattern": r'ng-version="', "tech": "Angular", "category": "framework"},
    {"pattern": r"ng-app=", "tech": "AngularJS", "category": "framework"},
    {"pattern": r'data-reactroot', "tech": "React", "category": "framework"},
    {"pattern": r"__REACT_DEVTOOLS", "tech": "React", "category": "framework"},
    {"pattern": r"_react", "tech": "React", "category": "framework"},
    {"pattern": r"vue\.js", "tech": "Vue.js", "category": "framework"},
    {"pattern": r'data-v-[a-f0-9]', "tech": "Vue.js", "category": "framework"},
    {"pattern": r"svelte", "tech": "Svelte", "category": "framework"},
    {"pattern": r"ember", "tech": "Ember.js", "category": "framework"},
    {"pattern": r"gatsby", "tech": "Gatsby", "category": "static_site_generator"},

    # JavaScript libraries
    {"pattern": r"jquery[.\-/](\d[\d.]*)?\.(?:min\.)?js", "tech": "jQuery", "category": "js_library"},
    {"pattern": r"bootstrap[.\-/](\d[\d.]*)?", "tech": "Bootstrap", "category": "css_framework"},
    {"pattern": r"tailwindcss", "tech": "Tailwind CSS", "category": "css_framework"},
    {"pattern": r"font-awesome", "tech": "Font Awesome", "category": "icon_library"},
    {"pattern": r"lodash", "tech": "Lodash", "category": "js_library"},
    {"pattern": r"moment\.js", "tech": "Moment.js", "category": "js_library"},
    {"pattern": r"axios", "tech": "Axios", "category": "js_library"},
    {"pattern": r"gsap", "tech": "GSAP", "category": "js_library"},
    {"pattern": r"three\.js", "tech": "Three.js", "category": "js_library"},
    {"pattern": r"socket\.io", "tech": "Socket.IO", "category": "js_library"},

    # Analytics and tracking
    {"pattern": r"google-analytics\.com|gtag|GoogleAnalyticsObject", "tech": "Google Analytics", "category": "analytics"},
    {"pattern": r"googletagmanager\.com", "tech": "Google Tag Manager", "category": "analytics"},
    {"pattern": r"hotjar\.com", "tech": "Hotjar", "category": "analytics"},
    {"pattern": r"segment\.com|analytics\.js", "tech": "Segment", "category": "analytics"},
    {"pattern": r"mixpanel", "tech": "Mixpanel", "category": "analytics"},
    {"pattern": r"facebook\.net/.*fbevents|fbq\(", "tech": "Facebook Pixel", "category": "analytics"},
    {"pattern": r"clarity\.ms", "tech": "Microsoft Clarity", "category": "analytics"},
    {"pattern": r"plausible\.io", "tech": "Plausible", "category": "analytics"},
    {"pattern": r"matomo", "tech": "Matomo", "category": "analytics"},

    # CDN / Infrastructure
    {"pattern": r"cloudflare", "tech": "Cloudflare", "category": "cdn"},
    {"pattern": r"akamai", "tech": "Akamai", "category": "cdn"},
    {"pattern": r"fastly", "tech": "Fastly", "category": "cdn"},
    {"pattern": r"amazonaws\.com", "tech": "Amazon S3/CloudFront", "category": "cdn"},
    {"pattern": r"vercel", "tech": "Vercel", "category": "hosting"},
    {"pattern": r"netlify", "tech": "Netlify", "category": "hosting"},
    {"pattern": r"herokuapp\.com", "tech": "Heroku", "category": "hosting"},
    {"pattern": r"firebase", "tech": "Firebase", "category": "backend"},
]

COOKIE_SIGNATURES: list[dict[str, str]] = [
    {"pattern": r"__cf_bm|cf_clearance", "tech": "Cloudflare", "category": "cdn"},
    {"pattern": r"PHPSESSID", "tech": "PHP", "category": "language"},
    {"pattern": r"ASP\.NET_SessionId", "tech": "ASP.NET", "category": "framework"},
    {"pattern": r"JSESSIONID", "tech": "Java", "category": "language"},
    {"pattern": r"laravel_session", "tech": "Laravel", "category": "framework"},
    {"pattern": r"_rails_session", "tech": "Ruby on Rails", "category": "framework"},
    {"pattern": r"django", "tech": "Django", "category": "framework"},
    {"pattern": r"connect\.sid", "tech": "Express.js", "category": "framework"},
    {"pattern": r"wp-settings", "tech": "WordPress", "category": "cms"},
]


class TechDetectorModule(AtsModule):
    """Detect technology stack of websites."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="tech_detector",
            category=ModuleCategory.OSINT,
            description="Detect website technology stack including CMS, frameworks, JS libraries, servers, and analytics",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="url", type=ParameterType.URL,
                    description="Target website URL to analyze",
                    required=True,
                ),
                Parameter(
                    name="follow_redirects", type=ParameterType.BOOLEAN,
                    description="Follow HTTP redirects",
                    default=True, required=False,
                ),
                Parameter(
                    name="check_robots", type=ParameterType.BOOLEAN,
                    description="Also check robots.txt for technology hints",
                    default=True, required=False,
                ),
                Parameter(
                    name="check_common_paths", type=ParameterType.BOOLEAN,
                    description="Probe common technology-specific paths",
                    default=True, required=False,
                ),
            ],
            outputs=[
                OutputField(name="technologies", type="list", description="Detected technologies with details"),
                OutputField(name="categories", type="dict", description="Technologies grouped by category"),
                OutputField(name="headers_analysis", type="dict", description="Security-relevant header analysis"),
                OutputField(name="total_detected", type="integer", description="Total technologies detected"),
            ],
            tags=["osint", "technology", "fingerprint", "cms", "framework", "recon"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        url = config.get("url", "").strip()
        if not url:
            return False, "URL is required"
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "URL must use HTTP or HTTPS scheme"
        if not parsed.netloc:
            return False, "URL must have a valid hostname"
        return True, ""

    async def _fetch_page(
        self, session: aiohttp.ClientSession, url: str, follow_redirects: bool,
    ) -> tuple[str, dict[str, str], list[str], int]:
        """Fetch page HTML and return (body, headers, cookies, status)."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        try:
            async with session.get(
                url,
                headers=headers,
                allow_redirects=follow_redirects,
                timeout=aiohttp.ClientTimeout(total=20),
                max_redirects=5,
            ) as resp:
                body = await resp.text(errors="ignore")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = [f"{k}={v.value}" for k, v in resp.cookies.items()]
                return body, resp_headers, cookies, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return "", {}, [], 0

    async def _check_path(
        self, session: aiohttp.ClientSession, base_url: str, path: str,
    ) -> tuple[str, int]:
        """Check if a specific path exists and return (path, status_code)."""
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.head(
                url,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0)"},
            ) as resp:
                return path, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return path, 0

    def _analyze_headers(
        self, headers: dict[str, str],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Analyze response headers for technology and security info."""
        detected: list[dict[str, Any]] = []
        security_headers: dict[str, Any] = {}

        # Technology detection from headers
        for header_name, signatures in HEADER_SIGNATURES.items():
            value = headers.get(header_name, "")
            if not value:
                continue
            for sig in signatures:
                match = re.search(sig["pattern"], value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                    detected.append({
                        "technology": sig["tech"],
                        "category": sig["category"],
                        "version": version,
                        "source": f"header:{header_name}",
                        "confidence": "high",
                    })

        # Security header analysis
        security_checks = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
            "cross-origin-opener-policy": "COOP",
            "cross-origin-resource-policy": "CORP",
        }
        for header, label in security_checks.items():
            value = headers.get(header, "")
            security_headers[label] = {
                "present": bool(value),
                "value": value if value else None,
            }

        return detected, security_headers

    def _analyze_html(self, html: str) -> list[dict[str, Any]]:
        """Analyze HTML content for technology signatures."""
        detected: list[dict[str, Any]] = []
        seen: set[str] = set()

        for sig in HTML_SIGNATURES:
            if sig["tech"] in seen:
                continue
            match = re.search(sig["pattern"], html, re.IGNORECASE)
            if match:
                version = None
                if match.lastindex and match.lastindex >= 1:
                    v = match.group(1)
                    if v and re.match(r"^\d", v):
                        version = v
                detected.append({
                    "technology": sig["tech"],
                    "category": sig["category"],
                    "version": version,
                    "source": "html_content",
                    "confidence": "medium",
                })
                seen.add(sig["tech"])

        # Extract meta generator tag
        gen_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', html, re.IGNORECASE,
        )
        if gen_match:
            gen_value = gen_match.group(1).strip()
            detected.append({
                "technology": gen_value,
                "category": "cms_or_generator",
                "version": None,
                "source": "meta_generator",
                "confidence": "high",
            })

        return detected

    def _analyze_cookies(self, cookies: list[str]) -> list[dict[str, Any]]:
        """Analyze cookies for technology signatures."""
        detected: list[dict[str, Any]] = []
        cookie_str = " ".join(cookies)

        seen: set[str] = set()
        for sig in COOKIE_SIGNATURES:
            if sig["tech"] in seen:
                continue
            if re.search(sig["pattern"], cookie_str, re.IGNORECASE):
                detected.append({
                    "technology": sig["tech"],
                    "category": sig["category"],
                    "version": None,
                    "source": "cookie",
                    "confidence": "medium",
                })
                seen.add(sig["tech"])

        return detected

    def _analyze_robots_txt(self, content: str) -> list[dict[str, Any]]:
        """Analyze robots.txt for technology hints."""
        detected: list[dict[str, Any]] = []
        sigs = [
            (r"/wp-admin", "WordPress", "cms"),
            (r"/wp-content", "WordPress", "cms"),
            (r"/administrator", "Joomla", "cms"),
            (r"/sites/default", "Drupal", "cms"),
            (r"/magento", "Magento", "ecommerce"),
            (r"/cart", "E-commerce platform", "ecommerce"),
            (r"/ghost", "Ghost", "cms"),
            (r"/umbraco", "Umbraco", "cms"),
        ]
        for pattern, tech, category in sigs:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append({
                    "technology": tech,
                    "category": category,
                    "version": None,
                    "source": "robots_txt",
                    "confidence": "medium",
                })
        return detected

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        url = config["url"].strip()
        follow_redirects = config.get("follow_redirects", True)
        check_robots = config.get("check_robots", True)
        check_common = config.get("check_common_paths", True)

        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        all_detected: list[dict[str, Any]] = []

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Fetch main page
            html, headers, cookies, status = await self._fetch_page(
                session, url, follow_redirects,
            )

            if status == 0:
                return {
                    "url": url,
                    "error": "Failed to connect to target",
                    "technologies": [],
                    "categories": {},
                    "headers_analysis": {},
                    "total_detected": 0,
                }

            # Analyze headers
            header_techs, security_headers = self._analyze_headers(headers)
            all_detected.extend(header_techs)

            # Analyze HTML
            if html:
                html_techs = self._analyze_html(html)
                all_detected.extend(html_techs)

            # Analyze cookies
            if cookies:
                cookie_techs = self._analyze_cookies(cookies)
                all_detected.extend(cookie_techs)

            # Check robots.txt
            robots_content = ""
            if check_robots:
                try:
                    robots_url = f"{base_url}/robots.txt"
                    async with session.get(
                        robots_url,
                        timeout=aiohttp.ClientTimeout(total=8),
                        headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0)"},
                    ) as resp:
                        if resp.status == 200:
                            robots_content = await resp.text(errors="ignore")
                            robot_techs = self._analyze_robots_txt(robots_content)
                            all_detected.extend(robot_techs)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

            # Probe common technology paths
            path_results: list[dict[str, Any]] = []
            if check_common:
                tech_paths = [
                    ("wp-login.php", "WordPress", "cms"),
                    ("wp-json/wp/v2/posts", "WordPress REST API", "cms"),
                    ("administrator/index.php", "Joomla", "cms"),
                    ("user/login", "Drupal", "cms"),
                    ("graphql", "GraphQL API", "api"),
                    (".well-known/security.txt", "security.txt", "security"),
                    ("sitemap.xml", "XML Sitemap", "seo"),
                    ("ads.txt", "ads.txt", "advertising"),
                    ("humans.txt", "humans.txt", "misc"),
                ]

                tasks = [
                    self._check_path(session, base_url, path)
                    for path, _, _ in tech_paths
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        continue
                    path, code = result
                    if code == 200:
                        _, tech_name, category = tech_paths[i]
                        all_detected.append({
                            "technology": tech_name,
                            "category": category,
                            "version": None,
                            "source": f"path_probe:{path}",
                            "confidence": "medium",
                        })
                        path_results.append({"path": path, "status": code, "technology": tech_name})

        # Deduplicate technologies (keep highest confidence)
        seen: dict[str, dict[str, Any]] = {}
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        for tech in all_detected:
            key = tech["technology"]
            existing = seen.get(key)
            if existing is None:
                seen[key] = tech
            else:
                # Keep higher confidence
                if confidence_order.get(tech.get("confidence", "low"), 0) > \
                        confidence_order.get(existing.get("confidence", "low"), 0):
                    seen[key] = tech
                # Merge version info
                if tech.get("version") and not existing.get("version"):
                    seen[key]["version"] = tech["version"]

        unique_techs = list(seen.values())

        # Group by category
        categories: dict[str, list[str]] = {}
        for tech in unique_techs:
            cat = tech.get("category", "other")
            if cat not in categories:
                categories[cat] = []
            label = tech["technology"]
            if tech.get("version"):
                label += f" {tech['version']}"
            categories[cat].append(label)

        return {
            "url": url,
            "status_code": status,
            "technologies": unique_techs,
            "categories": categories,
            "headers_analysis": security_headers,
            "path_probes": path_results if check_common else [],
            "total_detected": len(unique_techs),
        }
