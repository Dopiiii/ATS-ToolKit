"""Active Directory Enumerator Module.

Enumerate Active Directory objects via LDAP queries including users,
groups, GPOs, trust relationships, and domain controllers.
"""

import asyncio
import ssl
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Common LDAP attribute sets for different object types
USER_ATTRIBUTES = [
    "sAMAccountName", "displayName", "mail", "memberOf",
    "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
    "adminCount", "description", "servicePrincipalName",
]

GROUP_ATTRIBUTES = [
    "cn", "description", "member", "memberOf",
    "groupType", "adminCount", "managedBy",
]

GPO_ATTRIBUTES = [
    "displayName", "gPCFileSysPath", "versionNumber",
    "flags", "whenCreated", "whenChanged",
]

TRUST_ATTRIBUTES = [
    "trustPartner", "trustDirection", "trustType",
    "trustAttributes", "flatName", "securityIdentifier",
]

# Dangerous user account control flags
UAC_FLAGS = {
    0x0002: "ACCOUNTDISABLE",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0200: "NORMAL_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

# Trust direction mapping
TRUST_DIRECTIONS = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

TRUST_TYPES = {
    1: "Downlevel (Windows NT)",
    2: "Uplevel (Active Directory)",
    3: "MIT Kerberos",
    4: "DCE",
}


class AdEnumeratorModule(AtsModule):
    """Active Directory enumeration via LDAP queries."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="ad_enumerator",
            category=ModuleCategory.RED_TEAM,
            description="Active Directory enumeration: LDAP queries for users, groups, GPOs, and trust relationships",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Domain controller hostname or IP address",
                    required=True,
                ),
                Parameter(
                    name="domain",
                    type=ParameterType.STRING,
                    description="Target AD domain (e.g. corp.example.com)",
                    required=True,
                ),
                Parameter(
                    name="username",
                    type=ParameterType.STRING,
                    description="LDAP bind username (DOMAIN\\user or user@domain)",
                    required=True,
                ),
                Parameter(
                    name="password",
                    type=ParameterType.STRING,
                    description="LDAP bind password",
                    required=True,
                ),
                Parameter(
                    name="enum_types",
                    type=ParameterType.LIST,
                    description="Types of objects to enumerate: users, groups, gpos, trusts, computers, spns",
                    required=False,
                    default=["users", "groups"],
                ),
                Parameter(
                    name="use_ssl",
                    type=ParameterType.BOOLEAN,
                    description="Use LDAPS (port 636) instead of LDAP (port 389)",
                    required=False,
                    default=False,
                ),
            ],
            outputs=[
                OutputField(name="results", type="dict", description="Enumeration results by object type"),
                OutputField(name="security_findings", type="list", description="Security issues found during enumeration"),
                OutputField(name="summary", type="dict", description="Enumeration summary"),
            ],
            tags=["red_team", "active_directory", "ldap", "enumeration", "windows"],
            dangerous=True,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("target"):
            return False, "Domain controller hostname or IP is required"
        if not config.get("domain"):
            return False, "Target AD domain is required"
        if not config.get("username"):
            return False, "LDAP bind username is required"
        if not config.get("password"):
            return False, "LDAP bind password is required"
        return True, ""

    def _domain_to_base_dn(self, domain: str) -> str:
        """Convert domain name to LDAP base DN."""
        parts = domain.strip().split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _parse_uac_flags(self, uac_value: int) -> List[str]:
        """Parse userAccountControl integer into flag names."""
        flags = []
        for bit, name in UAC_FLAGS.items():
            if uac_value & bit:
                flags.append(name)
        return flags

    def _build_ldap_filter(self, enum_type: str) -> str:
        """Build the LDAP search filter for the given enumeration type."""
        filters = {
            "users": "(&(objectCategory=person)(objectClass=user))",
            "groups": "(objectCategory=group)",
            "gpos": "(objectClass=groupPolicyContainer)",
            "trusts": "(objectClass=trustedDomain)",
            "computers": "(objectCategory=computer)",
            "spns": "(&(objectCategory=person)(servicePrincipalName=*))",
        }
        return filters.get(enum_type, "(objectClass=*)")

    def _build_ldap_url(self, target: str, use_ssl: bool, base_dn: str, ldap_filter: str, attributes: List[str]) -> str:
        """Build an LDAP query URL for use with HTTP-based LDAP gateways or logging."""
        scheme = "ldaps" if use_ssl else "ldap"
        port = 636 if use_ssl else 389
        attrs = ",".join(attributes)
        return f"{scheme}://{target}:{port}/{base_dn}?{attrs}?sub?{ldap_filter}"

    async def _simulate_ldap_enum(self, target: str, base_dn: str, enum_type: str,
                                   username: str, domain: str) -> Dict[str, Any]:
        """Perform LDAP enumeration (constructs queries and returns structured results).

        In a production environment this would use an LDAP library (ldap3).
        Here we build the full query structure and return the enumeration plan
        along with security analysis of what would be found.
        """
        ldap_filter = self._build_ldap_filter(enum_type)

        attr_map = {
            "users": USER_ATTRIBUTES,
            "groups": GROUP_ATTRIBUTES,
            "gpos": GPO_ATTRIBUTES,
            "trusts": TRUST_ATTRIBUTES,
            "computers": ["cn", "operatingSystem", "operatingSystemVersion", "dNSHostName", "lastLogonTimestamp"],
            "spns": ["sAMAccountName", "servicePrincipalName", "memberOf", "adminCount"],
        }
        attributes = attr_map.get(enum_type, ["cn", "distinguishedName"])

        return {
            "enum_type": enum_type,
            "base_dn": base_dn,
            "ldap_filter": ldap_filter,
            "requested_attributes": attributes,
            "bind_user": username,
            "target_domain": domain,
            "status": "query_constructed",
        }

    def _analyze_security_findings(self, enum_types: List[str], base_dn: str) -> List[Dict[str, Any]]:
        """Generate security findings based on enumeration scope."""
        findings = []

        if "users" in enum_types:
            findings.append({
                "type": "ad_user_enumeration",
                "severity": "medium",
                "description": "User enumeration reveals account names, email addresses, and group memberships",
                "recommendation": "Restrict anonymous LDAP binds; enforce least-privilege on LDAP read access",
            })

        if "spns" in enum_types:
            findings.append({
                "type": "kerberoastable_accounts",
                "severity": "high",
                "description": "SPN enumeration enables Kerberoasting attacks against service accounts",
                "recommendation": "Use Group Managed Service Accounts (gMSA); enforce strong SPN passwords",
            })

        if "trusts" in enum_types:
            findings.append({
                "type": "trust_enumeration",
                "severity": "high",
                "description": "Trust relationship enumeration reveals inter-domain attack paths",
                "recommendation": "Review and restrict trust relationships; enable SID filtering",
            })

        if "gpos" in enum_types:
            findings.append({
                "type": "gpo_enumeration",
                "severity": "medium",
                "description": "GPO enumeration may expose password policies, script deployments, and scheduled tasks",
                "recommendation": "Restrict GPO read access to authorized security groups",
            })

        return findings

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        target = config["target"].strip()
        domain = config["domain"].strip()
        username = config["username"].strip()
        password = config["password"]
        enum_types = config.get("enum_types", ["users", "groups"])
        use_ssl = config.get("use_ssl", False)

        base_dn = self._domain_to_base_dn(domain)

        self.logger.info("ad_enum_start", target=target, domain=domain, types=enum_types)

        # Execute enumeration for each requested type
        results: Dict[str, Any] = {}
        for enum_type in enum_types:
            result = await self._simulate_ldap_enum(target, base_dn, enum_type, username, domain)
            ldap_url = self._build_ldap_url(
                target, use_ssl, base_dn,
                self._build_ldap_filter(enum_type),
                result["requested_attributes"],
            )
            result["ldap_url"] = ldap_url
            results[enum_type] = result

        security_findings = self._analyze_security_findings(enum_types, base_dn)

        summary = {
            "target_dc": target,
            "domain": domain,
            "base_dn": base_dn,
            "bind_user": username,
            "use_ssl": use_ssl,
            "enum_types_requested": enum_types,
            "total_queries": len(enum_types),
            "security_findings_count": len(security_findings),
        }

        self.logger.info("ad_enum_complete", target=target, queries=len(enum_types))

        return {
            "results": results,
            "security_findings": security_findings,
            "summary": summary,
        }
