"""Username enumeration across multiple platforms.

Checks username existence across 20+ social, developer, and gaming platforms
using concurrent HTTP requests with configurable timeout.
"""

import asyncio
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

PLATFORMS = {
    "social": {
        "Twitter/X": "https://x.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Facebook": "https://www.facebook.com/{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Reddit": "https://www.reddit.com/user/{}/",
        "Tumblr": "https://{}.tumblr.com",
        "Medium": "https://medium.com/@{}",
        "Mastodon.social": "https://mastodon.social/@{}",
    },
    "dev": {
        "GitHub": "https://github.com/{}",
        "GitLab": "https://gitlab.com/{}",
        "Bitbucket": "https://bitbucket.org/{}/",
        "StackOverflow": "https://stackoverflow.com/users/{}",
        "Dev.to": "https://dev.to/{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
        "Replit": "https://replit.com/@{}",
        "NPM": "https://www.npmjs.com/~{}",
        "PyPI": "https://pypi.org/user/{}/",
    },
    "gaming": {
        "Steam": "https://steamcommunity.com/id/{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Roblox": "https://www.roblox.com/user.aspx?username={}",
        "Chess.com": "https://www.chess.com/member/{}",
        "Lichess": "https://lichess.org/@/{}",
        "Xbox Gamertag": "https://xboxgamertag.com/search/{}",
    },
}


class UsernameEnumModule(AtsModule):
    """Check username existence across 20+ platforms concurrently."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="username_enum",
            category=ModuleCategory.OSINT,
            description="Check username existence across 20+ social, dev, and gaming platforms",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="username", type=ParameterType.STRING,
                    description="Username to search for across platforms", required=True,
                ),
                Parameter(
                    name="platforms", type=ParameterType.CHOICE,
                    description="Platform category to search",
                    choices=["all", "social", "dev", "gaming"], default="all",
                ),
                Parameter(
                    name="timeout", type=ParameterType.INTEGER,
                    description="HTTP request timeout in seconds per platform",
                    default=5, min_value=1, max_value=30,
                ),
            ],
            outputs=[
                OutputField(name="found", type="list", description="Platforms where username was found"),
                OutputField(name="not_found", type="list", description="Platforms where username was not found"),
                OutputField(name="errors", type="list", description="Platforms that returned errors"),
                OutputField(name="total_checked", type="integer", description="Total platforms checked"),
            ],
            tags=["osint", "username", "enumeration", "social"],
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
        if " " in username:
            return False, "Username must not contain spaces"
        return True, ""

    def _get_platforms(self, category: str) -> dict[str, str]:
        """Return the platform dictionary for the requested category."""
        if category == "all":
            merged: dict[str, str] = {}
            for cat_platforms in PLATFORMS.values():
                merged.update(cat_platforms)
            return merged
        return dict(PLATFORMS.get(category, {}))

    async def _check_platform(
        self, session: aiohttp.ClientSession, platform_name: str,
        url: str, timeout: int,
    ) -> dict[str, Any]:
        """Check if a username exists on a single platform."""
        result: dict[str, Any] = {"platform": platform_name, "url": url, "status": "unknown"}
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
            ) as resp:
                result["status_code"] = resp.status
                if resp.status == 200:
                    result["status"] = "found"
                elif resp.status == 404:
                    result["status"] = "not_found"
                elif resp.status in (301, 302, 303):
                    result["status"] = "redirect"
                    result["redirect_url"] = str(resp.url)
                else:
                    result["status"] = "uncertain"
        except asyncio.TimeoutError:
            result["status"] = "timeout"
            result["error"] = "Request timed out"
        except aiohttp.ClientError as exc:
            result["status"] = "error"
            result["error"] = str(exc)
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        username = config["username"].strip()
        category = config.get("platforms", "all")
        timeout = config.get("timeout", 5)

        platforms = self._get_platforms(category)
        found: list[dict[str, Any]] = []
        not_found: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        }

        connector = aiohttp.TCPConnector(limit=15, ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = []
            for name, url_pattern in platforms.items():
                url = url_pattern.format(username)
                tasks.append(self._check_platform(session, name, url, timeout))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception):
                    errors.append({"error": str(res)})
                    continue
                if res["status"] == "found":
                    found.append(res)
                elif res["status"] == "not_found":
                    not_found.append(res)
                else:
                    errors.append(res)

        return {
            "username": username,
            "category": category,
            "total_checked": len(platforms),
            "found": found,
            "not_found": not_found,
            "errors": errors,
            "summary": {
                "found_count": len(found),
                "not_found_count": len(not_found),
                "error_count": len(errors),
            },
        }
