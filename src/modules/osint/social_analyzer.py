"""Social media analyzer module.

Analyze social media profiles and extract information.
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


class SocialAnalyzerModule(AtsModule):
    """Analyze social media presence and extract profile information."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="social_analyzer",
            category=ModuleCategory.OSINT,
            description="Analyze social media profiles and extract information",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="username",
                    type=ParameterType.STRING,
                    description="Username to analyze",
                    required=True,
                    min_length=1,
                    max_length=64,
                ),
                Parameter(
                    name="platforms",
                    type=ParameterType.CHOICE,
                    description="Platforms to analyze",
                    required=False,
                    default="all",
                    choices=["all", "social", "professional", "developer"],
                ),
            ],
            outputs=[
                OutputField(name="profiles", type="list", description="Found profiles"),
                OutputField(name="summary", type="dict", description="Analysis summary"),
            ],
            tags=["social", "profile", "osint", "analysis"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        username = config.get("username", "")
        if not username or " " in username:
            return False, "Invalid username format"
        return True, ""

    def _get_platform_config(self, selection: str) -> Dict[str, Dict]:
        """Get platform configurations based on selection."""
        all_platforms = {
            "github": {
                "url": "https://api.github.com/users/{username}",
                "type": "api",
                "category": "developer",
            },
            "twitter": {
                "url": "https://twitter.com/{username}",
                "type": "page",
                "category": "social",
            },
            "instagram": {
                "url": "https://www.instagram.com/{username}/",
                "type": "page",
                "category": "social",
            },
            "linkedin": {
                "url": "https://www.linkedin.com/in/{username}",
                "type": "page",
                "category": "professional",
            },
            "reddit": {
                "url": "https://www.reddit.com/user/{username}/about.json",
                "type": "api",
                "category": "social",
            },
            "medium": {
                "url": "https://medium.com/@{username}",
                "type": "page",
                "category": "professional",
            },
            "devto": {
                "url": "https://dev.to/api/users/by_username?url={username}",
                "type": "api",
                "category": "developer",
            },
            "gitlab": {
                "url": "https://gitlab.com/api/v4/users?username={username}",
                "type": "api",
                "category": "developer",
            },
        }

        if selection == "all":
            return all_platforms
        else:
            return {k: v for k, v in all_platforms.items() if v["category"] == selection}

    async def _check_github(
        self,
        session: aiohttp.ClientSession,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch GitHub profile information."""
        try:
            url = f"https://api.github.com/users/{username}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "platform": "github",
                        "url": f"https://github.com/{username}",
                        "exists": True,
                        "data": {
                            "name": data.get("name"),
                            "bio": data.get("bio"),
                            "company": data.get("company"),
                            "location": data.get("location"),
                            "email": data.get("email"),
                            "blog": data.get("blog"),
                            "public_repos": data.get("public_repos"),
                            "followers": data.get("followers"),
                            "following": data.get("following"),
                            "created_at": data.get("created_at"),
                            "avatar": data.get("avatar_url"),
                        }
                    }
        except:
            pass
        return None

    async def _check_reddit(
        self,
        session: aiohttp.ClientSession,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch Reddit profile information."""
        try:
            url = f"https://www.reddit.com/user/{username}/about.json"
            headers = {"User-Agent": "ATS-Toolkit/2.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    user_data = data.get("data", {})
                    return {
                        "platform": "reddit",
                        "url": f"https://reddit.com/user/{username}",
                        "exists": True,
                        "data": {
                            "name": user_data.get("name"),
                            "comment_karma": user_data.get("comment_karma"),
                            "link_karma": user_data.get("link_karma"),
                            "created_utc": user_data.get("created_utc"),
                            "is_gold": user_data.get("is_gold"),
                            "verified": user_data.get("verified"),
                        }
                    }
        except:
            pass
        return None

    async def _check_devto(
        self,
        session: aiohttp.ClientSession,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch Dev.to profile information."""
        try:
            url = f"https://dev.to/api/users/by_username?url={username}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "platform": "devto",
                        "url": f"https://dev.to/{username}",
                        "exists": True,
                        "data": {
                            "name": data.get("name"),
                            "summary": data.get("summary"),
                            "location": data.get("location"),
                            "joined_at": data.get("joined_at"),
                            "github_username": data.get("github_username"),
                            "twitter_username": data.get("twitter_username"),
                        }
                    }
        except:
            pass
        return None

    async def _check_page_exists(
        self,
        session: aiohttp.ClientSession,
        platform: str,
        url: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a profile page exists."""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True
            ) as response:
                if response.status == 200:
                    # Basic check - page exists
                    return {
                        "platform": platform,
                        "url": url,
                        "exists": True,
                        "data": {}
                    }
        except:
            pass
        return None

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        username = config["username"].strip()
        platform_selection = config.get("platforms", "all")

        self.logger.info("starting_social_analysis", username=username)

        results = {
            "username": username,
            "profiles": [],
            "summary": {
                "platforms_checked": 0,
                "profiles_found": 0,
                "categories": {},
            }
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            # Check specific platforms with API
            github_result = await self._check_github(session, username)
            if github_result:
                results["profiles"].append(github_result)

            reddit_result = await self._check_reddit(session, username)
            if reddit_result:
                results["profiles"].append(reddit_result)

            devto_result = await self._check_devto(session, username)
            if devto_result:
                results["profiles"].append(devto_result)

            # Check other platforms
            platforms = self._get_platform_config(platform_selection)
            for platform_name, config in platforms.items():
                if platform_name in ["github", "reddit", "devto"]:
                    continue  # Already checked

                url = config["url"].format(username=username)
                result = await self._check_page_exists(session, platform_name, url)
                if result:
                    results["profiles"].append(result)

        # Build summary
        results["summary"]["platforms_checked"] = len(platforms) + 3
        results["summary"]["profiles_found"] = len(results["profiles"])

        for profile in results["profiles"]:
            cat = platforms.get(profile["platform"], {}).get("category", "other")
            results["summary"]["categories"][cat] = results["summary"]["categories"].get(cat, 0) + 1

        # Cross-reference analysis
        results["cross_reference"] = self._analyze_cross_references(results["profiles"])

        self.logger.info(
            "social_analysis_complete",
            username=username,
            profiles_found=len(results["profiles"])
        )

        return results

    def _analyze_cross_references(self, profiles: List[Dict]) -> Dict[str, Any]:
        """Analyze cross-references between profiles."""
        analysis = {
            "names": [],
            "locations": [],
            "emails": [],
            "links": [],
        }

        for profile in profiles:
            data = profile.get("data", {})

            if data.get("name"):
                name = data["name"]
                if name not in analysis["names"]:
                    analysis["names"].append(name)

            if data.get("location"):
                loc = data["location"]
                if loc not in analysis["locations"]:
                    analysis["locations"].append(loc)

            if data.get("email"):
                email = data["email"]
                if email not in analysis["emails"]:
                    analysis["emails"].append(email)

            if data.get("blog"):
                analysis["links"].append(data["blog"])

        return analysis
