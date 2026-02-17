"""Social media profile analysis and enumeration.

Checks for the existence of social media profiles across multiple platforms,
extracts publicly available metadata, and analyzes profile consistency.
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

SOCIAL_PLATFORMS = {
    "twitter": {
        "name": "Twitter/X",
        "url": "https://x.com/{}",
        "api_check": "https://x.com/{}",
        "meta_patterns": {
            "display_name": r'"name":"([^"]+)"',
            "followers": r'"followers_count":(\d+)',
            "description": r'"description":"([^"]+)"',
        },
    },
    "instagram": {
        "name": "Instagram",
        "url": "https://www.instagram.com/{}/",
        "api_check": "https://www.instagram.com/{}/?__a=1&__d=dis",
        "meta_patterns": {
            "display_name": r'"full_name":"([^"]+)"',
            "followers": r'"edge_followed_by":\{"count":(\d+)\}',
            "bio": r'"biography":"([^"]+)"',
        },
    },
    "linkedin": {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{}/",
        "api_check": "https://www.linkedin.com/in/{}/",
        "meta_patterns": {
            "title": r"<title>([^<]+)</title>",
        },
    },
    "github": {
        "name": "GitHub",
        "url": "https://github.com/{}",
        "api_url": "https://api.github.com/users/{}",
        "meta_patterns": {},
    },
    "reddit": {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{}/",
        "api_url": "https://www.reddit.com/user/{}/about.json",
        "meta_patterns": {},
    },
    "tiktok": {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{}",
        "api_check": "https://www.tiktok.com/@{}",
        "meta_patterns": {
            "display_name": r'"nickname":"([^"]+)"',
            "followers": r'"followerCount":(\d+)',
        },
    },
    "youtube": {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{}",
        "api_check": "https://www.youtube.com/@{}",
        "meta_patterns": {
            "title": r"<title>([^<]+)</title>",
        },
    },
    "pinterest": {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{}/",
        "api_check": "https://www.pinterest.com/{}/",
        "meta_patterns": {},
    },
    "medium": {
        "name": "Medium",
        "url": "https://medium.com/@{}",
        "api_check": "https://medium.com/@{}",
        "meta_patterns": {
            "title": r"<title>([^<]+)</title>",
        },
    },
    "twitch": {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{}",
        "api_check": "https://www.twitch.tv/{}",
        "meta_patterns": {},
    },
}


class SocialAnalyzerModule(AtsModule):
    """Analyze social media profiles across multiple platforms."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_analyzer",
            category=ModuleCategory.OSINT,
            description="Social media profile discovery and public metadata analysis",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="username", type=ParameterType.STRING,
                    description="Username/handle to search across platforms", required=True,
                ),
                Parameter(
                    name="platforms", type=ParameterType.CHOICE,
                    description="Platforms to check",
                    choices=["all", "twitter", "instagram", "linkedin"], default="all",
                ),
                Parameter(
                    name="depth", type=ParameterType.CHOICE,
                    description="Analysis depth: basic checks existence, detailed extracts metadata",
                    choices=["basic", "detailed"], default="basic",
                ),
            ],
            outputs=[
                OutputField(name="profiles", type="list", description="Discovered profiles"),
                OutputField(name="metadata", type="dict", description="Extracted public metadata"),
                OutputField(name="total_found", type="integer", description="Total profiles found"),
                OutputField(name="consistency_score", type="integer", description="Cross-platform consistency"),
            ],
            tags=["osint", "social-media", "profiles", "enumeration"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        username = config.get("username", "").strip()
        if not username:
            return False, "Username is required"
        if len(username) < 2:
            return False, "Username must be at least 2 characters"
        if len(username) > 64:
            return False, "Username must be 64 characters or fewer"
        return True, ""

    def _get_target_platforms(self, selection: str) -> dict[str, dict[str, Any]]:
        """Return platforms based on selection."""
        if selection == "all":
            return dict(SOCIAL_PLATFORMS)
        if selection in SOCIAL_PLATFORMS:
            return {selection: SOCIAL_PLATFORMS[selection]}
        return dict(SOCIAL_PLATFORMS)

    async def _check_profile(
        self, session: aiohttp.ClientSession, platform_key: str,
        platform_info: dict[str, Any], username: str, detailed: bool,
    ) -> dict[str, Any]:
        """Check profile existence and optionally extract metadata."""
        result: dict[str, Any] = {
            "platform": platform_info["name"],
            "platform_key": platform_key,
            "url": platform_info["url"].format(username),
            "found": False,
            "metadata": {},
        }

        check_url = platform_info.get("api_url", platform_info.get("api_check", ""))
        if not check_url:
            check_url = platform_info["url"]
        check_url = check_url.format(username)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            # Use API endpoint if available (e.g., GitHub, Reddit)
            if "api_url" in platform_info:
                api_url = platform_info["api_url"].format(username)
                async with session.get(
                    api_url, timeout=aiohttp.ClientTimeout(total=8), headers=headers,
                ) as resp:
                    if resp.status == 200:
                        result["found"] = True
                        if detailed:
                            try:
                                api_data = await resp.json(content_type=None)
                                if platform_key == "github":
                                    result["metadata"] = {
                                        "name": api_data.get("name", ""),
                                        "bio": api_data.get("bio", ""),
                                        "public_repos": api_data.get("public_repos", 0),
                                        "followers": api_data.get("followers", 0),
                                        "following": api_data.get("following", 0),
                                        "created_at": api_data.get("created_at", ""),
                                        "location": api_data.get("location", ""),
                                        "company": api_data.get("company", ""),
                                        "blog": api_data.get("blog", ""),
                                    }
                                elif platform_key == "reddit":
                                    rd = api_data.get("data", {})
                                    result["metadata"] = {
                                        "name": rd.get("name", ""),
                                        "total_karma": rd.get("total_karma", 0),
                                        "created_utc": rd.get("created_utc", 0),
                                        "is_gold": rd.get("is_gold", False),
                                    }
                            except Exception:
                                pass
                    elif resp.status == 404:
                        result["found"] = False
                    return result

            # Standard HTTP check
            async with session.get(
                check_url, timeout=aiohttp.ClientTimeout(total=8),
                headers=headers, allow_redirects=True,
            ) as resp:
                result["status_code"] = resp.status
                if resp.status == 200:
                    result["found"] = True
                    if detailed and platform_info.get("meta_patterns"):
                        body = await resp.text()
                        for field, pattern in platform_info["meta_patterns"].items():
                            match = re.search(pattern, body)
                            if match:
                                result["metadata"][field] = match.group(1)
                elif resp.status == 404:
                    result["found"] = False

        except asyncio.TimeoutError:
            result["error"] = "Request timed out"
        except aiohttp.ClientError as exc:
            result["error"] = str(exc)

        return result

    def _calculate_consistency(self, profiles: list[dict[str, Any]]) -> int:
        """Calculate cross-platform profile consistency score."""
        found_profiles = [p for p in profiles if p["found"]]
        if len(found_profiles) < 2:
            return 100 if found_profiles else 0

        names: set[str] = set()
        for p in found_profiles:
            meta = p.get("metadata", {})
            name = meta.get("name", "") or meta.get("display_name", "")
            if name:
                names.add(name.lower().strip())

        if len(names) <= 1:
            return 100
        return max(0, 100 - (len(names) - 1) * 20)

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        username = config["username"].strip()
        platform_choice = config.get("platforms", "all")
        depth = config.get("depth", "basic")
        detailed = depth == "detailed"

        platforms = self._get_target_platforms(platform_choice)

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._check_profile(session, key, info, username, detailed)
                for key, info in platforms.items()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        profiles: list[dict[str, Any]] = []
        for res in results:
            if isinstance(res, Exception):
                profiles.append({"error": str(res)})
            else:
                profiles.append(res)

        found = [p for p in profiles if p.get("found")]
        consistency = self._calculate_consistency(profiles)

        # Aggregate metadata
        all_metadata: dict[str, Any] = {}
        for p in found:
            if p.get("metadata"):
                all_metadata[p.get("platform_key", p.get("platform", ""))] = p["metadata"]

        return {
            "username": username,
            "profiles": profiles,
            "total_found": len(found),
            "total_checked": len(platforms),
            "found_on": [p["platform"] for p in found],
            "metadata": all_metadata,
            "consistency_score": consistency,
        }
