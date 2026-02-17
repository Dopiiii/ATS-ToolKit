"""Hash identification and dictionary attack module.

Auto-identifies hash types by length and format, then tests against a built-in
wordlist of common passwords using hashlib.
"""

import asyncio
import re
import math
import hashlib
import binascii
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
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "minecraft", "william", "corvette",
    "hello", "martin", "heather", "secret", "merlin", "diamond", "1234qwer",
    "gfhjkm", "hammer", "silver", "222222", "88888888", "anthony", "justin",
    "test", "bailey", "q1w2e3r4t5", "patrick", "internet", "scooter",
    "orange", "golfer", "cookie", "richard", "samantha", "bigdog", "guitar",
    "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy", "maverick",
    "phoenix", "camaro", "peanut", "morgan", "welcome", "falcon", "cowboy",
    "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph", "mercedes",
    "dakota", "arsenal", "eagles", "melissa", "boomer", "booboo", "spider",
    "nascar", "monster", "tigers", "yellow", "xxxxxx", "123123123", "gateway",
    "marina", "diablo", "bulldog", "qwer1234", "compaq", "purple", "hardcore",
    "banana", "junior", "hannah", "123654", "porsche", "lakers", "iceman",
    "money", "cowboys", "987654", "london", "tennis", "999999", "ncc1701",
    "coffee", "scooby", "0000", "miller", "boston", "q1w2e3r4", "brandon",
    "yamaha", "chester", "mother", "forever", "johnny", "edward", "333333",
    "oliver", "redsox", "player", "nikita", "knight", "fender", "barney",
    "midnight", "please", "brandy", "badboy", "iwantu", "slayer", "rangers",
    "charles", "flower", "bigdaddy", "rabbit", "wizard", "jasper", "enter",
    "rachel", "chris", "steven", "winner", "adidas", "victoria", "natasha",
    "1q2w3e4r", "jasmine", "winter", "prince", "panties", "marine", "ghbdtn",
    "fishing", "cocacola", "casper", "oscar", "tucker", "patrick1",
]

EXTENDED_PASSWORDS = COMMON_PASSWORDS + [
    "Pa$$w0rd", "P@ssw0rd", "Welcome1", "Password1", "Admin123", "Root123",
    "Qwerty123", "Letmein1", "Changeme", "Passw0rd!", "Welcome1!", "Test1234",
    "Summer2024", "Winter2024", "Spring2024", "Company1", "Password!", "P@ss1234",
    "Admin@123", "User1234", "Temp1234", "Guest123", "Default1", "System1",
    "Security1", "Network1", "Server01", "Database1", "Cloud123", "Azure123",
    "Aws12345", "Google1!", "Apple123", "Office365", "Microsoft1", "Windows10",
    "Linux123", "Ubuntu22", "Docker01", "Jenkins1", "Github01", "Gitlab01",
]

HASH_PATTERNS = {
    "md5": {"length": 32, "regex": r'^[a-fA-F0-9]{32}$'},
    "sha1": {"length": 40, "regex": r'^[a-fA-F0-9]{40}$'},
    "sha256": {"length": 64, "regex": r'^[a-fA-F0-9]{64}$'},
    "sha512": {"length": 128, "regex": r'^[a-fA-F0-9]{128}$'},
    "ntlm": {"length": 32, "regex": r'^[a-fA-F0-9]{32}$'},
    "sha384": {"length": 96, "regex": r'^[a-fA-F0-9]{96}$'},
    "md4": {"length": 32, "regex": r'^[a-fA-F0-9]{32}$'},
}


class CryptoHashCrackerModule(AtsModule):
    """Identify hash types and perform dictionary attacks using common passwords."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_hash_cracker",
            category=ModuleCategory.ADVANCED,
            description="Auto-identify hash types and test against common password wordlists",
            version="1.0.0",
            parameters=[
                Parameter(name="hash_value", type=ParameterType.STRING,
                          description="Hash value to crack", required=True),
                Parameter(name="hash_type", type=ParameterType.CHOICE,
                          description="Hash algorithm (auto to detect)",
                          choices=["auto", "md5", "sha1", "sha256", "ntlm"],
                          default="auto"),
                Parameter(name="wordlist", type=ParameterType.CHOICE,
                          description="Wordlist size to use",
                          choices=["common", "extended"], default="common"),
            ],
            outputs=[
                OutputField(name="identified_type", type="string",
                            description="Detected or specified hash type"),
                OutputField(name="cracked", type="boolean",
                            description="Whether the hash was cracked"),
                OutputField(name="plaintext", type="string",
                            description="Recovered plaintext if cracked"),
            ],
            tags=["advanced", "crypto", "hash", "cracking", "password"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        hash_val = config.get("hash_value", "").strip()
        if not hash_val:
            return False, "Hash value is required"
        if not re.match(r'^[a-fA-F0-9]+$', hash_val) and not hash_val.startswith("$"):
            return False, "Hash must be hexadecimal or a standard hash format"
        return True, ""

    def _identify_hash(self, hash_value: str) -> list[str]:
        """Identify possible hash types based on length and format."""
        candidates = []
        h = hash_value.strip().lower()
        length = len(h)

        if h.startswith("$2b$") or h.startswith("$2a$"):
            return ["bcrypt"]
        if h.startswith("$6$"):
            return ["sha512crypt"]
        if h.startswith("$5$"):
            return ["sha256crypt"]
        if h.startswith("$1$"):
            return ["md5crypt"]

        for name, info in HASH_PATTERNS.items():
            if length == info["length"] and re.match(info["regex"], h):
                candidates.append(name)

        if length == 32:
            candidates = ["md5", "ntlm"]
        elif not candidates:
            closest = min(HASH_PATTERNS.items(), key=lambda x: abs(x[1]["length"] - length))
            candidates.append(f"unknown (closest: {closest[0]})")

        return candidates

    def _hash_password(self, password: str, hash_type: str) -> str:
        """Hash a password with the specified algorithm."""
        encoded = password.encode("utf-8")
        if hash_type == "md5":
            return hashlib.md5(encoded).hexdigest()
        elif hash_type == "sha1":
            return hashlib.sha1(encoded).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(encoded).hexdigest()
        elif hash_type == "sha512":
            return hashlib.sha512(encoded).hexdigest()
        elif hash_type == "sha384":
            return hashlib.sha384(encoded).hexdigest()
        elif hash_type == "ntlm":
            return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
        return ""

    def _generate_mutations(self, word: str) -> list[str]:
        """Generate common password mutations."""
        mutations = [word]
        mutations.append(word.capitalize())
        mutations.append(word.upper())
        mutations.append(word + "1")
        mutations.append(word + "123")
        mutations.append(word + "!")
        mutations.append(word + "2024")
        mutations.append(word + "2025")
        if len(word) >= 4:
            leet = word.replace("a", "@").replace("e", "3").replace("o", "0").replace("i", "1").replace("s", "$")
            if leet != word:
                mutations.append(leet)
        return mutations

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        hash_value = config["hash_value"].strip().lower()
        hash_type = config.get("hash_type", "auto")
        wordlist_choice = config.get("wordlist", "common")

        identified_types = self._identify_hash(hash_value)

        if hash_type == "auto":
            types_to_try = [t for t in identified_types
                            if t in ("md5", "sha1", "sha256", "sha512", "ntlm", "sha384")]
            if not types_to_try:
                types_to_try = ["md5", "sha1", "sha256"]
        else:
            types_to_try = [hash_type]

        passwords = COMMON_PASSWORDS if wordlist_choice == "common" else EXTENDED_PASSWORDS
        all_candidates: list[str] = []
        for pw in passwords:
            all_candidates.extend(self._generate_mutations(pw))

        seen: set[str] = set()
        unique_candidates: list[str] = []
        for c in all_candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)

        cracked = False
        plaintext = ""
        cracked_type = ""
        attempts = 0

        for ht in types_to_try:
            if cracked:
                break
            for candidate in unique_candidates:
                attempts += 1
                computed = self._hash_password(candidate, ht)
                if computed == hash_value:
                    cracked = True
                    plaintext = candidate
                    cracked_type = ht
                    break

                if attempts % 5000 == 0:
                    await asyncio.sleep(0)

        entropy = 0.0
        if cracked:
            charset_size = 0
            if any(c.islower() for c in plaintext):
                charset_size += 26
            if any(c.isupper() for c in plaintext):
                charset_size += 26
            if any(c.isdigit() for c in plaintext):
                charset_size += 10
            if any(not c.isalnum() for c in plaintext):
                charset_size += 32
            if charset_size > 0:
                entropy = round(len(plaintext) * math.log2(charset_size), 1)

        return {
            "hash_value": hash_value,
            "identified_types": identified_types,
            "hash_type_used": cracked_type if cracked else ", ".join(types_to_try),
            "wordlist": wordlist_choice,
            "candidates_tested": attempts,
            "cracked": cracked,
            "plaintext": plaintext if cracked else None,
            "password_entropy": entropy if cracked else None,
            "password_strength": "weak" if entropy < 30 else "moderate" if entropy < 50 else "strong"
                                 if cracked else "unknown",
        }
