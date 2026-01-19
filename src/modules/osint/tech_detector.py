"""Technology detector module.

Detect technologies, frameworks, and services used by a website.
"""

import asyncio
import re
import aiohttp
from typing import Any, Dict, List, Tuple, Optional

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


# Technology signatures
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "headers": [],
        "cookies": ["wordpress_", "wp-"],
        "html": [r'wp-content', r'wp-includes', r'/wp-json/', r'WordPress'],
        "scripts": [r'wp-emoji'],
        "meta": [r'generator.*WordPress'],
    },
    "Drupal": {
        "headers": [r'X-Drupal-'],
        "cookies": ["Drupal."],
        "html": [r'Drupal', r'sites/default/files', r'/modules/'],
        "scripts": [r'drupal.js'],
        "meta": [r'generator.*Drupal'],
    },
    "Joomla": {
        "headers": [],
        "cookies": [],
        "html": [r'/components/com_', r'joomla', r'/templates/'],
        "scripts": [],
        "meta": [r'generator.*Joomla'],
    },
    "Shopify": {
        "headers": [r'X-ShopId'],
        "cookies": ["_shopify"],
        "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "scripts": [],
        "meta": [],
    },
    "Magento": {
        "headers": [],
        "cookies": ["frontend"],
        "html": [r'Mage\.', r'/skin/frontend/', r'magento'],
        "scripts": [r'mage/'],
        "meta": [],
    },

    # JavaScript Frameworks
    "React": {
        "headers": [],
        "cookies": [],
        "html": [r'_reactRootContainer', r'data-reactroot', r'__NEXT_DATA__'],
        "scripts": [r'react\.', r'react-dom'],
        "meta": [],
    },
    "Vue.js": {
        "headers": [],
        "cookies": [],
        "html": [r'__vue__', r'v-cloak', r'data-v-'],
        "scripts": [r'vue\.', r'vue@'],
        "meta": [],
    },
    "Angular": {
        "headers": [],
        "cookies": [],
        "html": [r'ng-version', r'ng-app', r'angular'],
        "scripts": [r'angular\.', r'@angular/'],
        "meta": [],
    },
    "Next.js": {
        "headers": [r'x-nextjs-'],
        "cookies": [],
        "html": [r'__NEXT_DATA__', r'_next/static'],
        "scripts": [r'_next/'],
        "meta": [],
    },
    "Nuxt.js": {
        "headers": [],
        "cookies": [],
        "html": [r'__NUXT__', r'_nuxt/'],
        "scripts": [r'_nuxt/'],
        "meta": [],
    },

    # JavaScript Libraries
    "jQuery": {
        "headers": [],
        "cookies": [],
        "html": [],
        "scripts": [r'jquery', r'jquery-'],
        "meta": [],
    },
    "Bootstrap": {
        "headers": [],
        "cookies": [],
        "html": [r'class="[^"]*\b(container|row|col-|btn-|navbar)', r'bootstrap'],
        "scripts": [r'bootstrap'],
        "meta": [],
    },
    "Tailwind CSS": {
        "headers": [],
        "cookies": [],
        "html": [r'class="[^"]*\b(flex|grid|p-\d|m-\d|text-|bg-|w-|h-)'],
        "scripts": [],
        "meta": [],
    },

    # Web Servers
    "nginx": {
        "headers": [r'Server:.*nginx'],
        "cookies": [],
        "html": [],
        "scripts": [],
        "meta": [],
    },
    "Apache": {
        "headers": [r'Server:.*Apache'],
        "cookies": [],
        "html": [],
        "scripts": [],
        "meta": [],
    },
    "Microsoft-IIS": {
        "headers": [r'Server:.*IIS', r'X-Powered-By:.*ASP\.NET'],
        "cookies": [],
        "html": [],
        "scripts": [],
        "meta": [],
    },

    # CDN
    "Cloudflare": {
        "headers": [r'cf-ray', r'Server:.*cloudflare'],
        "cookies": ["__cf"],
        "html": [],
        "scripts": [],
        "meta": [],
    },
    "Fastly": {
        "headers": [r'X-Served-By:.*cache', r'Fastly'],
        "cookies": [],
        "html": [],
        "scripts": [],
        "meta": [],
    },
    "Akamai": {
        "headers": [r'X-Akamai'],
        "cookies": [],
        "html": [],
        "scripts": [],
        "meta": [],
    },

    # Analytics
    "Google Analytics": {
        "headers": [],
        "cookies": ["_ga", "_gid"],
        "html": [r'google-analytics\.com', r'gtag\(', r'GoogleAnalyticsObject'],
        "scripts": [r'google-analytics', r'gtag'],
        "meta": [],
    },
    "Google Tag Manager": {
        "headers": [],
        "cookies": [],
        "html": [r'googletagmanager\.com', r'GTM-'],
        "scripts": [],
        "meta": [],
    },
    "Facebook Pixel": {
        "headers": [],
        "cookies": [],
        "html": [r'connect\.facebook\.net', r'fbq\('],
        "scripts": [],
        "meta": [],
    },

    # Security
    "reCAPTCHA": {
        "headers": [],
        "cookies": [],
        "html": [r'google\.com/recaptcha', r'g-recaptcha'],
        "scripts": [r'recaptcha'],
        "meta": [],
    },
    "Cloudflare WAF": {
        "headers": [r'cf-ray'],
        "cookies": ["__cfduid"],
        "html": [],
        "scripts": [],
        "meta": [],
    },
}


class TechDetectorModule(AtsModule):
    """Detect technologies used by a website."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="tech_detector",
            category=ModuleCategory.OSINT,
            description="Detect web technologies, frameworks, and services",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="url",
                    type=ParameterType.URL,
                    description="URL to analyze",
                    required=True,
                ),
                Parameter(
                    name="follow_redirects",
                    type=ParameterType.BOOLEAN,
                    description="Follow HTTP redirects",
                    required=False,
                    default=True,
                ),
            ],
            outputs=[
                OutputField(name="technologies", type="list", description="Detected technologies"),
                OutputField(name="categories", type="dict", description="Technologies by category"),
            ],
            tags=["technology", "fingerprint", "osint", "detection"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        url = config.get("url", "").strip()
        if not url:
            return False, "URL is required"
        if not url.startswith(("http://", "https://")):
            return False, "URL must start with http:// or https://"
        return True, ""

    def _check_patterns(
        self,
        patterns: List[str],
        text: str
    ) -> bool:
        """Check if any pattern matches."""
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _detect_tech(
        self,
        tech_name: str,
        signatures: Dict,
        headers: str,
        cookies: str,
        html: str,
        scripts: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Detect a specific technology."""
        confidence = 0
        evidence = []

        # Check headers
        if signatures.get("headers"):
            if self._check_patterns(signatures["headers"], headers):
                confidence += 30
                evidence.append("headers")

        # Check cookies
        if signatures.get("cookies"):
            for cookie_pattern in signatures["cookies"]:
                if cookie_pattern.lower() in cookies.lower():
                    confidence += 20
                    evidence.append("cookies")
                    break

        # Check HTML
        if signatures.get("html"):
            if self._check_patterns(signatures["html"], html):
                confidence += 25
                evidence.append("html")

        # Check scripts
        if signatures.get("scripts"):
            scripts_text = " ".join(scripts)
            if self._check_patterns(signatures["scripts"], scripts_text):
                confidence += 25
                evidence.append("scripts")

        # Check meta tags
        if signatures.get("meta"):
            if self._check_patterns(signatures["meta"], html):
                confidence += 20
                evidence.append("meta")

        if confidence > 0:
            return {
                "name": tech_name,
                "confidence": min(confidence, 100),
                "evidence": evidence,
            }

        return None

    def _categorize_tech(self, tech_name: str) -> str:
        """Categorize a technology."""
        categories = {
            "CMS": ["WordPress", "Drupal", "Joomla", "Shopify", "Magento"],
            "JavaScript Framework": ["React", "Vue.js", "Angular", "Next.js", "Nuxt.js"],
            "JavaScript Library": ["jQuery", "Bootstrap", "Tailwind CSS"],
            "Web Server": ["nginx", "Apache", "Microsoft-IIS"],
            "CDN": ["Cloudflare", "Fastly", "Akamai"],
            "Analytics": ["Google Analytics", "Google Tag Manager", "Facebook Pixel"],
            "Security": ["reCAPTCHA", "Cloudflare WAF"],
        }

        for category, techs in categories.items():
            if tech_name in techs:
                return category

        return "Other"

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        url = config["url"].strip()
        follow_redirects = config.get("follow_redirects", True)

        self.logger.info("starting_tech_detection", url=url)

        results = {
            "url": url,
            "technologies": [],
            "categories": {},
            "raw_data": {},
        }

        headers_dict = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        try:
            async with aiohttp.ClientSession(headers=headers_dict) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    allow_redirects=follow_redirects
                ) as response:
                    results["final_url"] = str(response.url)
                    results["status"] = response.status

                    # Collect data for analysis
                    headers_str = str(dict(response.headers))
                    cookies_str = str(response.cookies)
                    html = await response.text()

                    # Extract script sources
                    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)

                    results["raw_data"] = {
                        "headers": dict(response.headers),
                        "scripts_count": len(scripts),
                    }

                    # Detect technologies
                    for tech_name, signatures in TECH_SIGNATURES.items():
                        detection = self._detect_tech(
                            tech_name,
                            signatures,
                            headers_str,
                            cookies_str,
                            html,
                            scripts
                        )

                        if detection:
                            detection["category"] = self._categorize_tech(tech_name)
                            results["technologies"].append(detection)

                            # Add to categories
                            cat = detection["category"]
                            if cat not in results["categories"]:
                                results["categories"][cat] = []
                            results["categories"][cat].append(detection["name"])

            # Sort by confidence
            results["technologies"].sort(key=lambda x: x["confidence"], reverse=True)

        except Exception as e:
            results["error"] = str(e)
            self.logger.error("tech_detection_failed", error=str(e))

        self.logger.info(
            "tech_detection_complete",
            url=url,
            technologies=len(results["technologies"])
        )

        return results
