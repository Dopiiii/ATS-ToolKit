"""SSL/TLS interception and MITM detection module.

Analyzes SSL certificate chains for signs of interception, proxy CAs,
known MITM certificate patterns, and fingerprint mismatches.
"""

import asyncio
import hashlib
import json
import re
import ssl
import socket
from typing import Any
from datetime import datetime, timezone

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

KNOWN_MITM_ISSUERS = [
    "blue coat", "symantec ssl visibility", "forcepoint", "palo alto",
    "zscaler", "websense", "barracuda", "sophos", "fortinet",
    "checkpoint", "mcafee web gateway", "cisco umbrella", "netskope",
    "charles proxy", "fiddler", "mitmproxy", "burp suite", "portswigger",
    "superfish", "komodia", "e-dentifier", "privdog", "wajam",
]
KNOWN_PROXY_CA_PATTERNS = [
    r"firewall", r"proxy", r"intercept", r"inspect", r"decrypt",
    r"ssl[\s_-]?visibility", r"content[\s_-]?filter", r"web[\s_-]?gateway",
    r"deep[\s_-]?packet", r"transparent[\s_-]?proxy",
]
SELF_SIGNED_RISK = 40
MITM_ISSUER_RISK = 80
PROXY_CA_RISK = 70
FINGERPRINT_MISMATCH_RISK = 90
SHORT_VALIDITY_DAYS = 30


class NetSslInterceptDetectorModule(AtsModule):
    """Detect SSL/TLS interception and MITM proxy certificates."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="net_ssl_intercept_detector",
            category=ModuleCategory.ADVANCED,
            description="Detect SSL/TLS interception and MITM proxy patterns in certificate chains",
            version="1.0.0",
            parameters=[
                Parameter(name="target", type=ParameterType.DOMAIN,
                          description="Target domain to check for SSL interception"),
                Parameter(name="port", type=ParameterType.INTEGER,
                          description="Target port for SSL connection",
                          default=443, min_value=1, max_value=65535),
                Parameter(name="reference_fingerprint", type=ParameterType.STRING,
                          description="Optional known-good SHA-256 fingerprint for comparison",
                          required=False, default=""),
            ],
            outputs=[
                OutputField(name="interception_detected", type="boolean", description="Whether interception was detected"),
                OutputField(name="risk_score", type="float", description="Interception risk score 0-100"),
                OutputField(name="indicators", type="list", description="Interception indicators found"),
                OutputField(name="certificate_info", type="dict", description="Certificate chain details"),
            ],
            tags=["advanced", "network", "ssl", "tls", "mitm", "interception"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        target = config.get("target", "").strip()
        if not target:
            return False, "Target domain is required"
        domain_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")
        if not domain_pattern.match(target):
            return False, f"Invalid domain format: {target}"
        return True, ""

    def _fetch_certificate(self, target: str, port: int) -> dict[str, Any]:
        """Fetch SSL certificate from target host."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        cert_info = {}
        try:
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    sha256_fp = hashlib.sha256(cert_bin).hexdigest()
                    sha1_fp = hashlib.sha1(cert_bin).hexdigest()

                    cert_info = {
                        "subject": dict(x[0] for x in cert_dict.get("subject", ())) if cert_dict else {},
                        "issuer": dict(x[0] for x in cert_dict.get("issuer", ())) if cert_dict else {},
                        "serial_number": cert_dict.get("serialNumber", "") if cert_dict else "",
                        "not_before": cert_dict.get("notBefore", "") if cert_dict else "",
                        "not_after": cert_dict.get("notAfter", "") if cert_dict else "",
                        "san": [entry[1] for entry in cert_dict.get("subjectAltName", ())] if cert_dict else [],
                        "sha256_fingerprint": sha256_fp,
                        "sha1_fingerprint": sha1_fp,
                        "cipher_suite": cipher[0] if cipher else "",
                        "protocol_version": protocol or "",
                        "cert_pem_size": len(cert_bin),
                        "fetch_success": True,
                    }
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            cert_info = {"fetch_success": False, "error": str(exc)}
        return cert_info

    def _analyze_issuer(self, issuer: dict) -> list[dict]:
        """Analyze certificate issuer for MITM indicators."""
        indicators = []
        issuer_cn = issuer.get("commonName", "").lower()
        issuer_org = issuer.get("organizationName", "").lower()
        issuer_text = f"{issuer_cn} {issuer_org}"

        for mitm_name in KNOWN_MITM_ISSUERS:
            if mitm_name in issuer_text:
                indicators.append({
                    "type": "known_mitm_issuer",
                    "severity": "critical",
                    "detail": f"Known MITM/proxy CA detected: {mitm_name}",
                    "matched_value": mitm_name,
                    "risk_contribution": MITM_ISSUER_RISK,
                })
                break

        for pattern in KNOWN_PROXY_CA_PATTERNS:
            if re.search(pattern, issuer_text, re.IGNORECASE):
                indicators.append({
                    "type": "proxy_ca_pattern",
                    "severity": "high",
                    "detail": f"Proxy/interception CA pattern matched: {pattern}",
                    "matched_value": issuer_text,
                    "risk_contribution": PROXY_CA_RISK,
                })
                break

        return indicators

    def _check_self_signed(self, subject: dict, issuer: dict) -> list[dict]:
        """Check if certificate is self-signed."""
        indicators = []
        subj_cn = subject.get("commonName", "")
        iss_cn = issuer.get("commonName", "")
        subj_org = subject.get("organizationName", "")
        iss_org = issuer.get("organizationName", "")

        if subj_cn == iss_cn and subj_org == iss_org and subj_cn:
            indicators.append({
                "type": "self_signed",
                "severity": "high",
                "detail": f"Self-signed certificate detected (subject=issuer: {subj_cn})",
                "risk_contribution": SELF_SIGNED_RISK,
            })
        return indicators

    def _check_fingerprint_mismatch(self, observed_fp: str, reference_fp: str) -> list[dict]:
        """Compare observed fingerprint against reference."""
        indicators = []
        if reference_fp and observed_fp:
            ref_clean = reference_fp.replace(":", "").replace(" ", "").lower()
            obs_clean = observed_fp.replace(":", "").replace(" ", "").lower()
            if ref_clean != obs_clean:
                indicators.append({
                    "type": "fingerprint_mismatch",
                    "severity": "critical",
                    "detail": f"Certificate fingerprint mismatch: expected {ref_clean[:16]}..., got {obs_clean[:16]}...",
                    "expected": ref_clean,
                    "observed": obs_clean,
                    "risk_contribution": FINGERPRINT_MISMATCH_RISK,
                })
        return indicators

    def _check_validity_anomalies(self, cert_info: dict) -> list[dict]:
        """Check for certificate validity period anomalies."""
        indicators = []
        not_before = cert_info.get("not_before", "")
        not_after = cert_info.get("not_after", "")

        if not_before and not_after:
            try:
                fmt = "%b %d %H:%M:%S %Y %Z"
                start = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
                end = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
                validity_days = (end - start).days

                if validity_days < SHORT_VALIDITY_DAYS:
                    indicators.append({
                        "type": "short_validity",
                        "severity": "medium",
                        "detail": f"Very short certificate validity period: {validity_days} days",
                        "validity_days": validity_days,
                        "risk_contribution": 20,
                    })

                now = datetime.now(timezone.utc)
                if now > end:
                    indicators.append({
                        "type": "expired_cert",
                        "severity": "high",
                        "detail": f"Certificate expired on {not_after}",
                        "risk_contribution": 30,
                    })
                elif now < start:
                    indicators.append({
                        "type": "not_yet_valid",
                        "severity": "high",
                        "detail": f"Certificate not yet valid until {not_before}",
                        "risk_contribution": 25,
                    })
            except (ValueError, TypeError):
                pass
        return indicators

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        target = config["target"].strip()
        port = config.get("port", 443)
        reference_fp = config.get("reference_fingerprint", "").strip()

        # Fetch certificate in a thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        cert_info = await loop.run_in_executor(None, self._fetch_certificate, target, port)

        if not cert_info.get("fetch_success"):
            return {
                "interception_detected": False,
                "risk_score": 0.0,
                "indicators": [],
                "certificate_info": cert_info,
                "error": cert_info.get("error", "Failed to fetch certificate"),
            }

        all_indicators: list[dict] = []
        subject = cert_info.get("subject", {})
        issuer = cert_info.get("issuer", {})

        # Issuer analysis for MITM patterns
        all_indicators.extend(self._analyze_issuer(issuer))

        # Self-signed check
        all_indicators.extend(self._check_self_signed(subject, issuer))

        # Fingerprint mismatch
        all_indicators.extend(self._check_fingerprint_mismatch(
            cert_info.get("sha256_fingerprint", ""), reference_fp))

        # Validity anomalies
        all_indicators.extend(self._check_validity_anomalies(cert_info))

        # SAN mismatch check
        san_list = cert_info.get("san", [])
        if san_list and target not in san_list:
            wildcard_match = any(
                s.startswith("*.") and target.endswith(s[1:]) for s in san_list
            )
            if not wildcard_match:
                all_indicators.append({
                    "type": "san_mismatch",
                    "severity": "medium",
                    "detail": f"Target {target} not found in SAN list",
                    "san_list": san_list[:10],
                    "risk_contribution": 15,
                })

        risk_score = sum(ind.get("risk_contribution", 0) for ind in all_indicators)
        risk_score = min(round(float(risk_score), 1), 100.0)
        interception_detected = risk_score >= 50.0

        return {
            "interception_detected": interception_detected,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 80 else "high" if risk_score >= 50 else "medium" if risk_score >= 20 else "low",
            "indicators": all_indicators,
            "indicator_count": len(all_indicators),
            "certificate_info": cert_info,
            "target": target,
            "port": port,
        }
