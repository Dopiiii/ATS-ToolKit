"""WiFi password strength auditor.

Audits WiFi password hashes against common password lists and evaluates
hash integrity and password strength characteristics.
"""

import asyncio
import re
import hashlib
import hmac
import math
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

COMMON_PASSWORDS = [
    "password", "12345678", "123456789", "1234567890", "qwerty123", "abc12345",
    "password1", "iloveyou", "sunshine1", "princess1", "football1", "charlie1",
    "welcome1", "shadow12", "master12", "dragon12", "monkey12", "letmein1",
    "trustno1", "baseball1", "batman12", "access12", "hello123", "admin123",
    "qwerty12", "starwars1", "whatever1", "freedom1", "ninja123", "mustang1",
    "passwd12", "internet", "computer1", "superman1", "1q2w3e4r", "q1w2e3r4",
    "changeme1", "secret12", "network1", "wireless", "wifipass", "homewifi",
    "mywifi123", "guest1234", "default1", "password123", "12345678a", "wifi1234",
    "internet1", "security1", "guest12345", "welcome123", "home12345", "office123",
]

EXTENDED_PASSWORDS = COMMON_PASSWORDS + [
    "qwertyuiop", "1234qwer", "pass1234", "test1234", "temp1234", "user1234",
    "p@ssword1", "P@ssw0rd", "Passw0rd", "Summer2023", "Winter2023", "Spring2024",
    "Company1", "company123", "Wifi12345", "MyWifi123", "HomeWifi1", "GuestWifi",
    "!QAZ2wsx", "zaq1@WSX", "WiFi@1234", "Net@work1", "Secur1ty!", "W1reless!",
    "abcdefgh", "87654321", "11111111", "22222222", "00000000", "99999999",
    "asdfghjk", "zxcvbnm1", "poiuytre", "lkjhgfds", "mnbvcxza", "qazwsxed",
    "aaaaaaaa", "abcd1234", "1a2b3c4d", "a1b2c3d4", "qwer1234", "asdf1234",
]


class WifiPasswordAuditorModule(AtsModule):
    """Audit WiFi password strength against common password dictionaries."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="wifi_password_auditor",
            category=ModuleCategory.ADVANCED,
            description="Audit WiFi password hashes against common passwords and evaluate strength",
            version="1.0.0",
            parameters=[
                Parameter(name="password_hash", type=ParameterType.STRING,
                          description="The captured password hash to audit"),
                Parameter(name="hash_type", type=ParameterType.CHOICE,
                          description="Type of hash captured",
                          choices=["wpa2_pmkid", "wpa2_4way", "wep"], default="wpa2_pmkid"),
                Parameter(name="wordlist_mode", type=ParameterType.CHOICE,
                          description="Wordlist size for comparison",
                          choices=["common", "extended"], default="common"),
                Parameter(name="ssid", type=ParameterType.STRING,
                          description="Network SSID (needed for WPA2 PMK derivation)", required=False, default=""),
            ],
            outputs=[
                OutputField(name="hash_valid", type="boolean", description="Whether hash format is valid"),
                OutputField(name="cracked", type="boolean", description="Whether password was found"),
                OutputField(name="password_analysis", type="dict", description="Password strength analysis"),
            ],
            tags=["advanced", "wireless", "wifi", "password", "audit"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        hash_val = config.get("password_hash", "").strip()
        if not hash_val:
            return False, "Password hash is required"
        if len(hash_val) < 8:
            return False, "Hash value is too short to be valid"
        return True, ""

    def _validate_hash_format(self, hash_val: str, hash_type: str) -> dict[str, Any]:
        result = {"valid": False, "format_info": ""}
        if hash_type == "wpa2_pmkid":
            if re.match(r'^[a-fA-F0-9]{32}$', hash_val):
                result["valid"] = True
                result["format_info"] = "Valid PMKID format (16 bytes hex)"
            elif re.match(r'^[a-fA-F0-9*:]{50,}$', hash_val.replace(":", "").replace("*", "")):
                result["valid"] = True
                result["format_info"] = "Hashcat PMKID format detected"
            else:
                result["format_info"] = "Expected 32 hex chars for PMKID"
        elif hash_type == "wpa2_4way":
            if len(hash_val) >= 64 and all(c in "0123456789abcdefABCDEF" for c in hash_val[:64]):
                result["valid"] = True
                result["format_info"] = "Possible 4-way handshake PMK (256-bit)"
            else:
                result["format_info"] = "Expected hex-encoded handshake data"
        elif hash_type == "wep":
            if re.match(r'^[a-fA-F0-9]{10}$', hash_val) or re.match(r'^[a-fA-F0-9]{26}$', hash_val):
                result["valid"] = True
                key_bits = 40 if len(hash_val) == 10 else 104
                result["format_info"] = f"WEP {key_bits}-bit key format"
            else:
                result["format_info"] = "Expected 10 or 26 hex chars for WEP key"
        return result

    def _compute_wpa2_pmk(self, password: str, ssid: str) -> str:
        """Derive WPA2 PMK using PBKDF2-SHA1."""
        pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                   ssid.encode("utf-8"), 4096, dklen=32)
        return pmk.hex()

    def _analyze_password_strength(self, password: str) -> dict[str, Any]:
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        charset_size = (26 * has_upper + 26 * has_lower + 10 * has_digit + 32 * has_special)
        charset_size = max(charset_size, 1)
        entropy = length * math.log2(charset_size)
        is_pattern = bool(re.match(r'^(.)\1+$', password)) or password in ("12345678", "abcdefgh")
        score = min(10, entropy / 8)
        if is_pattern:
            score = max(1, score - 4)
        return {
            "length": length, "charset_size": charset_size, "entropy_bits": round(entropy, 1),
            "has_uppercase": has_upper, "has_lowercase": has_lower,
            "has_digits": has_digit, "has_special": has_special,
            "is_pattern": is_pattern, "strength_score": round(score, 1),
            "strength_label": ("very_weak" if score < 3 else "weak" if score < 5
                               else "moderate" if score < 7 else "strong"),
        }

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        hash_val = config["password_hash"].strip()
        hash_type = config.get("hash_type", "wpa2_pmkid")
        wordlist_mode = config.get("wordlist_mode", "common")
        ssid = config.get("ssid", "").strip()

        format_check = self._validate_hash_format(hash_val, hash_type)
        wordlist = EXTENDED_PASSWORDS if wordlist_mode == "extended" else COMMON_PASSWORDS
        cracked = False
        found_password = None
        tested_count = 0

        if format_check["valid"] and hash_type == "wpa2_pmkid" and ssid:
            hash_lower = hash_val.lower()[:32]
            for pw in wordlist:
                tested_count += 1
                pmk = self._compute_wpa2_pmk(pw, ssid)
                if hash_lower in pmk:
                    cracked = True
                    found_password = pw
                    break
                if tested_count % 50 == 0:
                    await asyncio.sleep(0)
        elif format_check["valid"] and hash_type == "wep":
            for pw in wordlist:
                tested_count += 1
                pw_hex = pw.encode("utf-8").hex()
                md5_hash = hashlib.md5(pw.encode("utf-8")).hexdigest()
                if hash_val.lower() in (pw_hex[:len(hash_val)], md5_hash[:len(hash_val)]):
                    cracked = True
                    found_password = pw
                    break

        result: dict[str, Any] = {
            "hash_valid": format_check["valid"],
            "hash_format": format_check["format_info"],
            "hash_type": hash_type,
            "cracked": cracked,
            "passwords_tested": tested_count,
            "wordlist_size": len(wordlist),
        }
        if cracked and found_password:
            result["found_password"] = found_password
            result["password_analysis"] = self._analyze_password_strength(found_password)
        else:
            result["password_analysis"] = {"note": "Password not found in wordlist",
                                            "recommendation": "Use extended wordlist or specialized cracking tools"}
        return result
