"""Mobile SSL certificate pinning verification module.

Tests target domains for certificate pinning configuration, detects bypass
indicators, and evaluates the strength of TLS configurations on mobile backends.
"""

import asyncio
import re
import math
import ssl
import socket
import json
import hashlib
from typing import Any
from datetime import datetime

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

PINNING_BYPASS_INDICATORS = [
    "frida", "objection", "ssl-kill-switch", "trustkit",
    "appcert", "cert-transparency", "network_security_config",
]

KNOWN_MOBILE_HEADERS = {
    "x-requested-with": "Common mobile app header",
    "x-app-version": "Application version header",
    "x-device-id": "Device identifier header",
    "x-platform": "Platform indicator (android/ios)",
    "x-api-key": "API key header",
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "SEED", "IDEA",
]

IOS_ATS_CIPHERS = [
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]


class MobileSslPinningCheckModule(AtsModule):
    """Check SSL certificate pinning and TLS configuration for mobile backends."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="mobile_ssl_pinning_check",
            category=ModuleCategory.ADVANCED,
            description="Verify SSL pinning implementation and detect bypass indicators",
            version="1.0.0",
            parameters=[
                Parameter(name="target_domain", type=ParameterType.DOMAIN,
                          description="Target domain to check", required=True),
                Parameter(name="app_type", type=ParameterType.CHOICE,
                          description="Mobile platform to evaluate against",
                          choices=["android", "ios", "both"], default="both"),
                Parameter(name="port", type=ParameterType.INTEGER,
                          description="TLS port to connect to", default=443,
                          min_value=1, max_value=65535),
            ],
            outputs=[
                OutputField(name="certificate_info", type="dict",
                            description="Certificate details"),
                OutputField(name="pinning_assessment", type="dict",
                            description="Pinning strength assessment"),
                OutputField(name="findings", type="list",
                            description="Security findings"),
            ],
            tags=["advanced", "mobile", "ssl", "pinning", "tls", "certificate"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        domain = config.get("target_domain", "").strip()
        if not domain:
            return False, "Target domain is required"
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', domain):
            return False, "Invalid domain format"
        return True, ""

    def _get_certificate_info(self, domain: str, port: int) -> dict[str, Any]:
        """Connect and retrieve certificate information."""
        cert_info: dict[str, Any] = {"retrieved": False}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)

                    cert_info["retrieved"] = True
                    cert_info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    cert_info["serial_number"] = cert.get("serialNumber", "")
                    cert_info["version"] = cert.get("version", 0)
                    cert_info["not_before"] = cert.get("notBefore", "")
                    cert_info["not_after"] = cert.get("notAfter", "")

                    if cert_bin:
                        cert_info["sha256_fingerprint"] = hashlib.sha256(cert_bin).hexdigest()
                        cert_info["sha1_fingerprint"] = hashlib.sha1(cert_bin).hexdigest()
                        spki_hash = hashlib.sha256(cert_bin).digest()
                        import base64
                        cert_info["pin_sha256"] = base64.b64encode(spki_hash).decode()

                    cert_info["san"] = [entry[1] for entry in cert.get("subjectAltName", ())]
                    cert_info["protocol_version"] = ssock.version()
                    cert_info["cipher_suite"] = ssock.cipher()
        except ssl.SSLCertVerificationError as exc:
            cert_info["ssl_error"] = f"Certificate verification failed: {exc}"
        except (socket.timeout, socket.gaierror, ConnectionError) as exc:
            cert_info["connection_error"] = str(exc)
        return cert_info

    def _assess_cert_validity(self, cert_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Assess certificate validity and expiration."""
        findings = []
        not_after = cert_info.get("not_after", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                if days_left < 0:
                    findings.append({"type": "expired_cert", "severity": "critical",
                                     "detail": f"Certificate expired {abs(days_left)} days ago"})
                elif days_left < 30:
                    findings.append({"type": "expiring_cert", "severity": "high",
                                     "detail": f"Certificate expires in {days_left} days"})
                elif days_left < 90:
                    findings.append({"type": "expiring_cert", "severity": "medium",
                                     "detail": f"Certificate expires in {days_left} days"})
            except ValueError:
                pass

        issuer = cert_info.get("issuer", {})
        org = issuer.get("organizationName", "").lower()
        self_signed_indicators = ["self-signed", "localhost", "test", "dev"]
        if any(ind in org for ind in self_signed_indicators) or cert_info.get("subject") == cert_info.get("issuer"):
            findings.append({"type": "self_signed", "severity": "critical",
                             "detail": "Certificate appears to be self-signed"})
        return findings

    def _assess_android_pinning(self, cert_info: dict[str, Any]) -> dict[str, Any]:
        """Evaluate certificate pinning from Android perspective."""
        assessment = {"platform": "android", "pin_available": False, "recommendations": []}
        if cert_info.get("sha256_fingerprint"):
            assessment["pin_available"] = True
            assessment["pin_value"] = cert_info["sha256_fingerprint"]
            assessment["recommendations"].append(
                "Implement network_security_config.xml with pin-set for this certificate")
            assessment["recommendations"].append(
                "Include backup pin for certificate rotation")

        cipher = cert_info.get("cipher_suite", ())
        if cipher and len(cipher) >= 1:
            cipher_name = cipher[0]
            for weak in WEAK_CIPHERS:
                if weak.lower() in cipher_name.lower():
                    assessment["weak_cipher"] = True
                    assessment["recommendations"].append(
                        f"Cipher {cipher_name} contains weak algorithm: {weak}")
                    break

        proto = cert_info.get("protocol_version", "")
        if proto and proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            assessment["outdated_protocol"] = True
            assessment["recommendations"].append(
                f"Protocol {proto} is deprecated - enforce TLSv1.2+")
        return assessment

    def _assess_ios_pinning(self, cert_info: dict[str, Any]) -> dict[str, Any]:
        """Evaluate certificate pinning from iOS ATS perspective."""
        assessment = {"platform": "ios", "ats_compliant": True, "recommendations": []}

        proto = cert_info.get("protocol_version", "")
        if proto and proto not in ("TLSv1.2", "TLSv1.3"):
            assessment["ats_compliant"] = False
            assessment["recommendations"].append(
                f"iOS ATS requires TLSv1.2+, found: {proto}")

        cipher = cert_info.get("cipher_suite", ())
        if cipher and len(cipher) >= 1:
            cipher_name = cipher[0]
            is_ats_cipher = any(ats.lower() in cipher_name.lower() for ats in IOS_ATS_CIPHERS)
            if not is_ats_cipher:
                ecdhe_aes = "ecdhe" in cipher_name.lower() and "aes" in cipher_name.lower()
                if not ecdhe_aes:
                    assessment["ats_compliant"] = False
                    assessment["recommendations"].append(
                        f"Cipher {cipher_name} may not meet ATS forward secrecy requirements")

        if cert_info.get("pin_sha256"):
            assessment["pin_value"] = cert_info["pin_sha256"]
            assessment["recommendations"].append(
                "Use TrustKit or URLSession pinning delegate with this SPKI hash")

        san = cert_info.get("san", [])
        if san and any("*" in s for s in san):
            assessment["wildcard_cert"] = True
            assessment["recommendations"].append(
                "Wildcard certificate detected - consider domain-specific certificates")
        return assessment

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        domain = config["target_domain"].strip()
        app_type = config.get("app_type", "both")
        port = config.get("port", 443)

        cert_info = await asyncio.get_event_loop().run_in_executor(
            None, self._get_certificate_info, domain, port)

        findings: list[dict[str, Any]] = []
        pinning_assessment: dict[str, Any] = {"domain": domain}

        if not cert_info["retrieved"]:
            findings.append({"type": "connection_failed", "severity": "critical",
                             "detail": cert_info.get("connection_error",
                                                     cert_info.get("ssl_error", "Unknown error"))})
            return {"certificate_info": cert_info, "pinning_assessment": pinning_assessment,
                    "findings": findings, "risk_level": "critical"}

        findings.extend(self._assess_cert_validity(cert_info))

        if app_type in ("android", "both"):
            pinning_assessment["android"] = self._assess_android_pinning(cert_info)
        if app_type in ("ios", "both"):
            pinning_assessment["ios"] = self._assess_ios_pinning(cert_info)

        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total = sum(severity_scores.get(f["severity"], 1) for f in findings)
        risk = "critical" if total >= 8 else "high" if total >= 5 else "medium" if total >= 2 else "low"

        return {
            "domain": domain,
            "port": port,
            "certificate_info": cert_info,
            "pinning_assessment": pinning_assessment,
            "findings": findings,
            "finding_count": len(findings),
            "risk_level": risk,
        }
