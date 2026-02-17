"""Deep TLS/SSL configuration audit for remote servers.

Connects to a target host, inspects TLS protocol version, cipher suite,
certificate details, and checks against security best practices.
"""

import asyncio
import ssl
import socket
import re
import math
import hashlib
from datetime import datetime, timezone
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "RC2", "IDEA", "SEED", "NULL", "EXPORT", "anon"}
FORWARD_SECRECY_CIPHERS = {"ECDHE", "DHE"}


class CryptoTlsAuditModule(AtsModule):
    """Audit TLS configuration for security weaknesses."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="crypto_tls_audit",
            category=ModuleCategory.ADVANCED,
            description="Deep TLS/SSL configuration audit checking protocols, ciphers, and certificates",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.DOMAIN,
                          description="Target hostname to audit", required=True),
                Parameter(name="port", type=ParameterType.INTEGER,
                          description="TLS port number", default=443,
                          min_value=1, max_value=65535),
                Parameter(name="check_level", type=ParameterType.CHOICE,
                          description="Depth of audit checks",
                          choices=["basic", "thorough"], default="basic"),
            ],
            outputs=[
                OutputField(name="protocol_info", type="dict",
                            description="TLS protocol version and support details"),
                OutputField(name="cipher_analysis", type="dict",
                            description="Cipher suite analysis and weaknesses"),
                OutputField(name="certificate_info", type="dict",
                            description="Certificate details, validity, and chain info"),
                OutputField(name="score", type="string",
                            description="Overall security grade A-F"),
            ],
            tags=["advanced", "crypto", "tls", "ssl", "audit", "certificate"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target hostname is required"
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", target):
            return False, "Invalid domain format"
        return True, ""

    def _connect_tls(self, host: str, port: int) -> dict[str, Any]:
        """Establish TLS connection and extract info."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        info: dict[str, Any] = {"connected": False}
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    info["connected"] = True
                    info["protocol_version"] = ssock.version()
                    info["cipher"] = ssock.cipher()
                    cert = ssock.getpeercert()
                    info["certificate"] = cert
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        info["cert_fingerprint_sha256"] = hashlib.sha256(der_cert).hexdigest()
        except ssl.SSLCertVerificationError as exc:
            info["ssl_error"] = f"Certificate verification failed: {exc}"
            # Retry without verification to still get details
            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                        info["connected"] = True
                        info["protocol_version"] = ssock.version()
                        info["cipher"] = ssock.cipher()
                        info["cert_verification_failed"] = True
            except Exception:
                pass
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            info["connection_error"] = str(exc)
        return info

    def _analyze_protocol(self, version: str | None) -> dict[str, Any]:
        """Analyze the negotiated protocol version."""
        if not version:
            return {"version": None, "secure": False, "note": "Could not determine protocol"}
        deprecated = version in DEPRECATED_PROTOCOLS
        return {
            "version": version,
            "secure": not deprecated,
            "deprecated": deprecated,
            "note": "Deprecated protocol - upgrade immediately" if deprecated else "Protocol version acceptable",
        }

    def _analyze_cipher(self, cipher_info: tuple | None) -> dict[str, Any]:
        """Analyze the negotiated cipher suite."""
        if not cipher_info:
            return {"suite": None, "secure": False}
        name, proto, bits = cipher_info[0], cipher_info[1], cipher_info[2]
        weak = any(w.lower() in name.lower() for w in WEAK_CIPHERS)
        fs = any(fs_kw in name for fs_kw in FORWARD_SECRECY_CIPHERS)
        strength = "strong"
        if bits < 128:
            strength = "weak"
        elif bits < 256:
            strength = "acceptable"

        return {
            "suite": name,
            "protocol": proto,
            "bits": bits,
            "strength": strength,
            "has_forward_secrecy": fs,
            "uses_weak_cipher": weak,
            "note": "Weak cipher detected - disable immediately" if weak else "Cipher suite acceptable",
        }

    def _analyze_certificate(self, cert: dict | None, host: str) -> dict[str, Any]:
        """Analyze certificate details."""
        if not cert:
            return {"valid": False, "note": "No certificate data available"}

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        # Parse dates
        date_fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            not_before = datetime.strptime(not_before_str, date_fmt).replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(not_after_str, date_fmt).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days
            expired = days_remaining < 0
            expiring_soon = 0 <= days_remaining <= 30
        except (ValueError, TypeError):
            not_before = None
            not_after = None
            days_remaining = -1
            expired = True
            expiring_soon = False

        # SAN check
        san_list = [entry[1] for entry in cert.get("subjectAltName", [])]
        hostname_match = any(
            host == san or (san.startswith("*.") and host.endswith(san[1:]))
            for san in san_list
        )

        return {
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "not_before": not_before_str,
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "expired": expired,
            "expiring_soon": expiring_soon,
            "san_names": san_list[:20],
            "hostname_match": hostname_match,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", 0),
            "self_signed": subject == issuer,
        }

    def _compute_score(self, proto: dict, cipher: dict, cert: dict, verified: bool) -> str:
        """Compute overall grade A-F."""
        score = 100
        if proto.get("deprecated"):
            score -= 40
        if not proto.get("secure"):
            score -= 20
        if cipher.get("uses_weak_cipher"):
            score -= 35
        if not cipher.get("has_forward_secrecy"):
            score -= 10
        if cipher.get("bits", 0) < 128:
            score -= 25
        if cert.get("expired"):
            score -= 30
        if cert.get("expiring_soon"):
            score -= 10
        if cert.get("self_signed"):
            score -= 15
        if not cert.get("hostname_match"):
            score -= 20
        if not verified:
            score -= 15

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 65:
            return "C"
        elif score >= 50:
            return "D"
        return "F"

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        host = config["target"].strip()
        port = config.get("port", 443)
        check_level = config.get("check_level", "basic")

        conn = await asyncio.get_event_loop().run_in_executor(
            None, self._connect_tls, host, port
        )

        if not conn["connected"]:
            return {
                "target": host, "port": port,
                "protocol_info": {"error": conn.get("connection_error", conn.get("ssl_error", "Connection failed"))},
                "cipher_analysis": {}, "certificate_info": {}, "score": "F",
            }

        proto_analysis = self._analyze_protocol(conn.get("protocol_version"))
        cipher_analysis = self._analyze_cipher(conn.get("cipher"))
        cert_analysis = self._analyze_certificate(conn.get("certificate"), host)
        verified = not conn.get("cert_verification_failed", False)
        grade = self._compute_score(proto_analysis, cipher_analysis, cert_analysis, verified)

        result: dict[str, Any] = {
            "target": host,
            "port": port,
            "protocol_info": proto_analysis,
            "cipher_analysis": cipher_analysis,
            "certificate_info": cert_analysis,
            "certificate_verified": verified,
            "score": grade,
        }

        if conn.get("cert_fingerprint_sha256"):
            result["certificate_info"]["fingerprint_sha256"] = conn["cert_fingerprint_sha256"]

        if check_level == "thorough":
            findings: list[str] = []
            if proto_analysis.get("deprecated"):
                findings.append("CRITICAL: Deprecated TLS protocol in use")
            if cipher_analysis.get("uses_weak_cipher"):
                findings.append("CRITICAL: Weak cipher suite negotiated")
            if not cipher_analysis.get("has_forward_secrecy"):
                findings.append("WARNING: No forward secrecy support")
            if cert_analysis.get("expired"):
                findings.append("CRITICAL: Certificate has expired")
            if cert_analysis.get("expiring_soon"):
                findings.append(f"WARNING: Certificate expires in {cert_analysis['days_remaining']} days")
            if cert_analysis.get("self_signed"):
                findings.append("WARNING: Self-signed certificate")
            if not cert_analysis.get("hostname_match"):
                findings.append("CRITICAL: Certificate hostname mismatch")
            if not verified:
                findings.append("WARNING: Certificate chain could not be verified")
            result["findings"] = findings
            result["total_issues"] = len(findings)

        return result
