"""Metadata extractor module.

Extract metadata from files and URLs.
"""

import asyncio
import aiohttp
import re
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class MetadataExtractorModule(AtsModule):
    """Extract metadata from files and web pages."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="metadata_extractor",
            category=ModuleCategory.OSINT,
            description="Extract metadata from files and URLs",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="URL or file path to analyze",
                    required=True,
                ),
                Parameter(
                    name="extract_type",
                    type=ParameterType.CHOICE,
                    description="Type of extraction",
                    required=False,
                    default="auto",
                    choices=["auto", "web", "document"],
                ),
            ],
            outputs=[
                OutputField(name="metadata", type="dict", description="Extracted metadata"),
                OutputField(name="technologies", type="list", description="Detected technologies"),
            ],
            tags=["metadata", "exif", "osint", "analysis"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target is required"
        return True, ""

    async def _extract_web_metadata(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Dict[str, Any]:
        """Extract metadata from a web page."""
        metadata = {
            "url": url,
            "title": None,
            "description": None,
            "keywords": [],
            "author": None,
            "generator": None,
            "og_tags": {},
            "twitter_tags": {},
            "links": {
                "internal": [],
                "external": [],
            },
            "headers": {},
            "technologies": [],
        }

        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30),
                allow_redirects=True
            ) as response:
                metadata["final_url"] = str(response.url)
                metadata["status"] = response.status
                metadata["headers"] = dict(response.headers)

                # Detect technologies from headers
                if "Server" in response.headers:
                    metadata["technologies"].append({
                        "name": response.headers["Server"],
                        "type": "server"
                    })

                if "X-Powered-By" in response.headers:
                    metadata["technologies"].append({
                        "name": response.headers["X-Powered-By"],
                        "type": "framework"
                    })

                # Parse HTML
                html = await response.text()

                # Title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
                if title_match:
                    metadata["title"] = title_match.group(1).strip()

                # Meta tags
                meta_tags = re.findall(
                    r'<meta\s+([^>]+)>',
                    html,
                    re.IGNORECASE
                )

                for tag in meta_tags:
                    # Description
                    desc_match = re.search(r'name=["\']description["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if not desc_match:
                        desc_match = re.search(r'content=["\'](.*?)["\']\s+name=["\']description["\']', tag, re.IGNORECASE)
                    if desc_match:
                        metadata["description"] = desc_match.group(1)

                    # Keywords
                    keywords_match = re.search(r'name=["\']keywords["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if keywords_match:
                        metadata["keywords"] = [k.strip() for k in keywords_match.group(1).split(",")]

                    # Author
                    author_match = re.search(r'name=["\']author["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if author_match:
                        metadata["author"] = author_match.group(1)

                    # Generator
                    gen_match = re.search(r'name=["\']generator["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if gen_match:
                        metadata["generator"] = gen_match.group(1)
                        metadata["technologies"].append({
                            "name": gen_match.group(1),
                            "type": "cms"
                        })

                    # Open Graph
                    og_match = re.search(r'property=["\']og:(\w+)["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if og_match:
                        metadata["og_tags"][og_match.group(1)] = og_match.group(2)

                    # Twitter
                    tw_match = re.search(r'name=["\']twitter:(\w+)["\']\s+content=["\'](.*?)["\']', tag, re.IGNORECASE)
                    if tw_match:
                        metadata["twitter_tags"][tw_match.group(1)] = tw_match.group(2)

                # Detect technologies from HTML
                metadata["technologies"].extend(self._detect_technologies(html, response.headers))

                # Extract links
                parsed_url = urlparse(url)
                base_domain = parsed_url.netloc

                links = re.findall(r'href=["\']([^"\']+)["\']', html)
                for link in links[:100]:  # Limit
                    if link.startswith("http"):
                        link_domain = urlparse(link).netloc
                        if link_domain == base_domain:
                            if link not in metadata["links"]["internal"]:
                                metadata["links"]["internal"].append(link)
                        else:
                            if link not in metadata["links"]["external"]:
                                metadata["links"]["external"].append(link)

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _detect_technologies(self, html: str, headers: dict) -> List[Dict[str, str]]:
        """Detect technologies from HTML content."""
        technologies = []

        # CMS Detection
        cms_patterns = {
            "WordPress": [r'wp-content', r'wp-includes', r'/wp-json/'],
            "Drupal": [r'drupal', r'sites/default/files'],
            "Joomla": [r'/components/com_', r'joomla'],
            "Shopify": [r'cdn.shopify.com', r'shopify'],
            "Wix": [r'wix.com', r'wixstatic'],
            "Squarespace": [r'squarespace'],
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    technologies.append({"name": cms, "type": "cms"})
                    break

        # JS Frameworks
        js_patterns = {
            "React": [r'react', r'_reactRootContainer'],
            "Vue.js": [r'vue', r'__vue__'],
            "Angular": [r'ng-version', r'angular'],
            "jQuery": [r'jquery'],
            "Bootstrap": [r'bootstrap'],
        }

        for framework, patterns in js_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    technologies.append({"name": framework, "type": "framework"})
                    break

        # Analytics
        if 'google-analytics' in html or 'gtag' in html:
            technologies.append({"name": "Google Analytics", "type": "analytics"})
        if 'googletagmanager' in html:
            technologies.append({"name": "Google Tag Manager", "type": "analytics"})

        return technologies

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        extract_type = config.get("extract_type", "auto")

        self.logger.info("starting_metadata_extraction", target=target)

        # Determine if URL or file
        is_url = target.startswith("http://") or target.startswith("https://")

        if extract_type == "auto":
            extract_type = "web" if is_url else "document"

        results = {
            "target": target,
            "type": extract_type,
            "metadata": {},
            "technologies": [],
        }

        if extract_type == "web" and is_url:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            async with aiohttp.ClientSession(headers=headers) as session:
                web_metadata = await self._extract_web_metadata(session, target)
                results["metadata"] = web_metadata
                results["technologies"] = web_metadata.get("technologies", [])

        elif extract_type == "document":
            # Document metadata extraction would require additional libraries
            # like PyPDF2, python-docx, pillow for EXIF
            results["metadata"] = {
                "note": "Document metadata extraction requires file access",
                "supported_formats": ["PDF", "DOCX", "XLSX", "Images (EXIF)"],
            }

        self.logger.info(
            "metadata_extraction_complete",
            target=target,
            technologies=len(results["technologies"])
        )

        return results
