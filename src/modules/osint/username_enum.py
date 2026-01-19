"""Username enumeration across multiple platforms.

Checks if a username exists on various social media and web platforms.
"""

import asyncio
import aiohttp
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


PLATFORMS = {
    "github": {"url": "https://github.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "twitter": {"url": "https://twitter.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "instagram": {"url": "https://www.instagram.com/{username}/", "check_type": "status_code", "valid_codes": [200]},
    "reddit": {"url": "https://www.reddit.com/user/{username}", "check_type": "status_code", "valid_codes": [200]},
    "linkedin": {"url": "https://www.linkedin.com/in/{username}", "check_type": "status_code", "valid_codes": [200]},
    "pinterest": {"url": "https://www.pinterest.com/{username}/", "check_type": "status_code", "valid_codes": [200]},
    "tiktok": {"url": "https://www.tiktok.com/@{username}", "check_type": "status_code", "valid_codes": [200]},
    "youtube": {"url": "https://www.youtube.com/@{username}", "check_type": "status_code", "valid_codes": [200]},
    "twitch": {"url": "https://www.twitch.tv/{username}", "check_type": "status_code", "valid_codes": [200]},
    "medium": {"url": "https://medium.com/@{username}", "check_type": "status_code", "valid_codes": [200]},
    "devto": {"url": "https://dev.to/{username}", "check_type": "status_code", "valid_codes": [200]},
    "gitlab": {"url": "https://gitlab.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "bitbucket": {"url": "https://bitbucket.org/{username}/", "check_type": "status_code", "valid_codes": [200]},
    "keybase": {"url": "https://keybase.io/{username}", "check_type": "status_code", "valid_codes": [200]},
    "hackernews": {"url": "https://news.ycombinator.com/user?id={username}", "check_type": "content", "valid_content": "karma"},
    "spotify": {"url": "https://open.spotify.com/user/{username}", "check_type": "status_code", "valid_codes": [200]},
    "soundcloud": {"url": "https://soundcloud.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "vimeo": {"url": "https://vimeo.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "patreon": {"url": "https://www.patreon.com/{username}", "check_type": "status_code", "valid_codes": [200]},
    "flickr": {"url": "https://www.flickr.com/people/{username}/", "check_type": "status_code", "valid_codes": [200]},
}


class UsernameEnumModule(AtsModule):
    """Enumerate username across multiple platforms."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="username_enum",
            category=ModuleCategory.OSINT,
            description="Check username existence across 20+ social platforms",
            version="1.0.0",
            parameters=[
                Parameter(name="username", type=ParameterType.STRING, description="Username to search for", required=True, min_length=1, max_length=64),
                Parameter(name="platforms", type=ParameterType.CHOICE, description="Platforms to check", required=False, default="popular", choices=["all", "popular", "social", "dev"]),
                Parameter(name="timeout", type=ParameterType.INTEGER, description="Request timeout in seconds", required=False, default=10, min_value=5, max_value=60),
            ],
            outputs=[
                OutputField(name="found", type="list", description="Platforms where username exists"),
                OutputField(name="not_found", type="list", description="Platforms where username doesn't exist"),
                OutputField(name="errors", type="list", description="Platforms that couldn't be checked"),
            ],
            tags=["username", "social", "enumeration", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        username = config.get("username", "")
        invalid_chars = set(' !@#$%^&*()+=[]{}|\\:;"\'<>,?/')
        if any(c in username for c in invalid_chars):
            return False, "Username contains invalid characters"
        return True, ""

    def _get_platforms(self, selection: str) -> Dict[str, dict]:
        if selection == "all":
            return PLATFORMS
        popular = ["github", "twitter", "instagram", "reddit", "linkedin", "tiktok", "youtube"]
        social = ["twitter", "instagram", "tiktok", "pinterest", "reddit", "twitch"]
        dev = ["github", "gitlab", "bitbucket", "devto", "hackernews", "medium", "keybase"]
        if selection == "popular":
            return {k: v for k, v in PLATFORMS.items() if k in popular}
        elif selection == "social":
            return {k: v for k, v in PLATFORMS.items() if k in social}
        elif selection == "dev":
            return {k: v for k, v in PLATFORMS.items() if k in dev}
        return PLATFORMS

    async def _check_platform(self, session: aiohttp.ClientSession, platform: str, config: dict, username: str, timeout: int) -> Dict[str, Any]:
        url = config["url"].format(username=username)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as response:
                if config["check_type"] == "status_code":
                    exists = response.status in config["valid_codes"]
                else:
                    text = await response.text()
                    exists = config.get("valid_content", "") in text
                return {"platform": platform, "exists": exists, "url": url if exists else None, "status": response.status}
        except asyncio.TimeoutError:
            return {"platform": platform, "error": "timeout"}
        except Exception as e:
            return {"platform": platform, "error": str(e)}

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        username = config["username"]
        platform_selection = config.get("platforms", "popular")
        timeout = config.get("timeout", 10)
        platforms = self._get_platforms(platform_selection)

        self.logger.info("starting_enumeration", username=username, platform_count=len(platforms))

        found, not_found, errors = [], [], []
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = [self._check_platform(session, name, cfg, username, timeout) for name, cfg in platforms.items()]
            results = await asyncio.gather(*tasks)

            for result in results:
                if "error" in result:
                    errors.append({"platform": result["platform"], "error": result["error"]})
                elif result["exists"]:
                    found.append({"platform": result["platform"], "url": result["url"], "status": result["status"]})
                else:
                    not_found.append(result["platform"])

        self.logger.info("enumeration_complete", found=len(found), not_found=len(not_found), errors=len(errors))

        return {
            "username": username,
            "found": found,
            "not_found": not_found,
            "errors": errors,
            "summary": {"total_checked": len(platforms), "found_count": len(found), "not_found_count": len(not_found), "error_count": len(errors)}
        }
