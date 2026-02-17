"""Mobile backend API security scanner.

Scans mobile application backend APIs for broken authentication, excessive data
exposure, BOLA (Broken Object Level Authorization), and other OWASP Mobile Top 10 issues.
"""

import asyncio
import re
import math
import json
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

COMMON_API_PATHS = [
    "/api/v1/user", "/api/v1/users", "/api/v1/profile", "/api/v1/account",
    "/api/v1/me", "/api/v2/user", "/api/v2/users", "/api/v2/profile",
    "/api/user", "/api/users", "/api/profile", "/api/account",
    "/user", "/users", "/profile", "/account", "/me",
    "/api/v1/settings", "/api/v1/config", "/api/v1/data",
    "/api/v1/admin", "/api/v1/debug", "/api/v1/status", "/api/v1/health",
    "/graphql", "/api/graphql", "/.well-known/openapi.json",
    "/swagger.json", "/api-docs", "/openapi.json",
]

BOLA_ENDPOINTS = [
    "/api/v1/users/{id}", "/api/v1/orders/{id}", "/api/v1/accounts/{id}",
    "/api/v1/documents/{id}", "/api/v1/messages/{id}", "/api/v1/payments/{id}",
]

SENSITIVE_DATA_PATTERNS = {
    "password": r'"(?:password|passwd|pass)":\s*"[^"]*"',
    "token": r'"(?:token|access_token|refresh_token|api_key|secret)":\s*"[^"]*"',
    "email": r'"email":\s*"[^"@]+@[^"]+\.[^"]+"',
    "phone": r'"(?:phone|mobile|tel)":\s*"[\d\+\-\(\)\s]+"',
    "ssn": r'"(?:ssn|social_security)":\s*"\d{3}-?\d{2}-?\d{4}"',
    "credit_card": r'"(?:card|cc|credit_card)":\s*"[\d\-\s]+"',
    "private_key": r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
    "internal_ip": r'"(?:ip|host|server)":\s*"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)',
}

AUTH_BYPASS_HEADERS = [
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]


class MobileApiScannerModule(AtsModule):
    """Scan mobile backend APIs for common security vulnerabilities."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="mobile_api_scanner",
            category=ModuleCategory.ADVANCED,
            description="Scan mobile backend APIs for broken auth, data exposure, and BOLA",
            version="1.0.0",
            parameters=[
                Parameter(name="base_url", type=ParameterType.URL,
                          description="Base URL of the mobile API", required=True),
                Parameter(name="auth_token", type=ParameterType.STRING,
                          description="Bearer token for authenticated scanning",
                          required=False, default=""),
                Parameter(name="scan_type", type=ParameterType.CHOICE,
                          description="Type of security scan to perform",
                          choices=["auth", "data", "all"], default="all"),
            ],
            outputs=[
                OutputField(name="endpoints_tested", type="integer",
                            description="Number of endpoints tested"),
                OutputField(name="vulnerabilities", type="list",
                            description="Detected vulnerabilities"),
                OutputField(name="risk_score", type="float",
                            description="Overall risk score 0-10"),
            ],
            tags=["advanced", "mobile", "api", "security", "owasp"],
            author="ATS-Toolkit",
            dangerous=True,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        base_url = config.get("base_url", "").strip()
        if not base_url:
            return False, "Base URL is required"
        if not re.match(r"^https?://", base_url):
            return False, "Base URL must start with http:// or https://"
        return True, ""

    def _build_headers(self, auth_token: str) -> dict[str, str]:
        """Build request headers mimicking a mobile client."""
        headers = {
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    async def _probe_endpoint(self, session: aiohttp.ClientSession, url: str,
                              headers: dict[str, str]) -> dict[str, Any]:
        """Probe an endpoint and capture response details."""
        try:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=False) as resp:
                body = await resp.text()
                return {"url": url, "status": resp.status,
                        "headers": dict(resp.headers), "body": body[:5000],
                        "content_length": len(body), "error": None}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"url": url, "status": 0, "headers": {}, "body": "",
                    "content_length": 0, "error": str(exc)}

    def _check_sensitive_data(self, body: str) -> list[dict[str, str]]:
        """Scan response body for sensitive data exposure."""
        found = []
        for label, pattern in SENSITIVE_DATA_PATTERNS.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found.append({"type": label, "count": len(matches),
                              "preview": matches[0][:60] + "..." if len(matches[0]) > 60
                              else matches[0]})
        return found

    def _check_security_headers(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Check for missing security headers in API responses."""
        findings = []
        required_headers = {
            "strict-transport-security": "Missing HSTS header",
            "x-content-type-options": "Missing X-Content-Type-Options",
            "cache-control": "Missing Cache-Control (sensitive data may be cached)",
        }
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for header, message in required_headers.items():
            if header not in lower_headers:
                findings.append({"type": "missing_header", "severity": "medium",
                                 "detail": message, "header": header})
        cors = lower_headers.get("access-control-allow-origin", "")
        if cors == "*":
            findings.append({"type": "open_cors", "severity": "high",
                             "detail": "CORS allows all origins - potential data theft"})
        return findings

    async def _test_bola(self, session: aiohttp.ClientSession, base_url: str,
                         headers: dict[str, str]) -> list[dict[str, Any]]:
        """Test for Broken Object Level Authorization."""
        findings = []
        test_ids = ["1", "2", "0", "999999", "admin"]

        for endpoint_tmpl in BOLA_ENDPOINTS:
            for test_id in test_ids:
                url = urljoin(base_url, endpoint_tmpl.replace("{id}", test_id))
                result = await self._probe_endpoint(session, url, headers)

                if result["status"] == 200 and result["body"]:
                    try:
                        data = json.loads(result["body"])
                        if isinstance(data, dict) and any(
                            k in data for k in ("email", "name", "phone", "address", "id")):
                            findings.append({
                                "type": "bola", "severity": "critical",
                                "detail": f"BOLA: Accessed object {test_id} at {endpoint_tmpl}",
                                "url": url, "status": result["status"],
                            })
                            break
                    except json.JSONDecodeError:
                        pass
                await asyncio.sleep(0.15)
        return findings

    async def _test_auth_bypass(self, session: aiohttp.ClientSession, base_url: str) -> list[dict[str, Any]]:
        """Test for authentication bypass via header manipulation."""
        findings = []
        admin_paths = ["/api/v1/admin", "/admin", "/api/admin", "/api/v1/internal"]
        for path in admin_paths:
            url = urljoin(base_url, path)
            for bypass_headers in AUTH_BYPASS_HEADERS:
                headers = {"User-Agent": "okhttp/4.12.0", "Accept": "application/json"}
                headers.update(bypass_headers)
                result = await self._probe_endpoint(session, url, headers)
                if result["status"] == 200:
                    findings.append({
                        "type": "auth_bypass", "severity": "critical",
                        "detail": f"Potential auth bypass at {path} using {list(bypass_headers.keys())[0]}",
                        "url": url, "bypass_header": bypass_headers,
                    })
                await asyncio.sleep(0.1)
        return findings

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        base_url = config["base_url"].strip().rstrip("/")
        auth_token = config.get("auth_token", "").strip()
        scan_type = config.get("scan_type", "all")

        headers = self._build_headers(auth_token)
        vulnerabilities: list[dict[str, Any]] = []
        endpoints_tested = 0

        connector = aiohttp.TCPConnector(limit=8, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            for path in COMMON_API_PATHS:
                url = urljoin(base_url + "/", path.lstrip("/"))
                result = await self._probe_endpoint(session, url, headers)
                endpoints_tested += 1

                if result["error"] or result["status"] == 0:
                    continue

                if result["status"] == 200 and not auth_token:
                    vulnerabilities.append({
                        "type": "no_auth_required", "severity": "high",
                        "detail": f"Endpoint accessible without auth: {path}",
                        "url": url,
                    })

                if scan_type in ("data", "all"):
                    sensitive = self._check_sensitive_data(result["body"])
                    for item in sensitive:
                        vulnerabilities.append({
                            "type": "data_exposure", "severity": "critical",
                            "detail": f"Sensitive {item['type']} data exposed at {path}",
                            "url": url, "data_type": item["type"],
                        })

                    header_issues = self._check_security_headers(result["headers"])
                    vulnerabilities.extend(header_issues)

                await asyncio.sleep(0.1)

            if scan_type in ("auth", "all"):
                bola_findings = await self._test_bola(session, base_url, headers)
                vulnerabilities.extend(bola_findings)
                endpoints_tested += len(BOLA_ENDPOINTS) * 5

                bypass_findings = await self._test_auth_bypass(session, base_url)
                vulnerabilities.extend(bypass_findings)
                endpoints_tested += 4 * len(AUTH_BYPASS_HEADERS)

        severity_weights = {"critical": 3.5, "high": 2.5, "medium": 1.5, "low": 0.5}
        raw_score = sum(severity_weights.get(v.get("severity", "low"), 0.5) for v in vulnerabilities)
        risk_score = round(min(10.0, raw_score / max(1, endpoints_tested) * 20), 1)

        return {
            "base_url": base_url,
            "scan_type": scan_type,
            "endpoints_tested": endpoints_tested,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 7 else "high" if risk_score >= 5
                          else "medium" if risk_score >= 3 else "low",
        }
