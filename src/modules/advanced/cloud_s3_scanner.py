"""Cloud S3 bucket permission and misconfiguration scanner.

Checks S3 bucket permissions, ACLs, and public access settings via HTTP probing.
"""

import asyncio
import re
import json
from typing import Any
from urllib.parse import urlparse

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

COMMON_BUCKET_SUFFIXES = [
    "", "-backup", "-backups", "-assets", "-static", "-media", "-data",
    "-dev", "-staging", "-prod", "-logs", "-uploads", "-public", "-private",
    "-archive", "-cdn", "-images", "-files", "-documents", "-config",
]

S3_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2",
]


class CloudS3ScannerModule(AtsModule):
    """Check S3 bucket permissions and misconfigurations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_s3_scanner",
            category=ModuleCategory.ADVANCED,
            description="Scan S3 buckets for permission misconfigurations and public access",
            version="1.0.0",
            parameters=[
                Parameter(name="bucket_name", type=ParameterType.STRING,
                          description="S3 bucket name or base name to test", required=True),
                Parameter(name="check_type", type=ParameterType.CHOICE,
                          description="Type of check to perform",
                          choices=["permissions", "content", "policy"], default="permissions"),
                Parameter(name="enumerate_variants", type=ParameterType.BOOLEAN,
                          description="Test common bucket name variations", default=False),
            ],
            outputs=[
                OutputField(name="buckets_tested", type="integer", description="Number of buckets tested"),
                OutputField(name="findings", type="list", description="Security findings"),
                OutputField(name="public_buckets", type="list", description="Publicly accessible buckets"),
            ],
            tags=["advanced", "cloud", "s3", "aws", "storage"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        bucket = config.get("bucket_name", "").strip()
        if not bucket:
            return False, "Bucket name is required"
        if not re.match(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$', bucket):
            if not re.match(r'^[a-zA-Z0-9\-]+$', bucket):
                return False, "Invalid bucket name format"
        return True, ""

    def _generate_bucket_names(self, base_name: str, enumerate_variants: bool) -> list[str]:
        """Generate bucket name permutations for testing."""
        base = base_name.lower().strip().replace(" ", "-")
        names = [base]
        if enumerate_variants:
            for suffix in COMMON_BUCKET_SUFFIXES:
                candidate = f"{base}{suffix}"
                if candidate not in names:
                    names.append(candidate)
        return names

    async def _check_bucket_permissions(self, session: aiohttp.ClientSession,
                                         bucket: str) -> dict[str, Any]:
        """Probe a bucket for permission misconfigurations."""
        result = {"bucket": bucket, "exists": False, "public_read": False,
                  "public_write": False, "issues": []}
        s3_url = f"https://{bucket}.s3.amazonaws.com"
        try:
            async with session.head(s3_url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                result["status_code"] = resp.status
                if resp.status == 200:
                    result["exists"] = True
                    result["public_read"] = True
                    result["issues"].append("Bucket allows unauthenticated HEAD requests")
                elif resp.status == 403:
                    result["exists"] = True
                elif resp.status == 301:
                    result["exists"] = True
                    location = resp.headers.get("x-amz-bucket-region", "unknown")
                    result["region"] = location
        except (aiohttp.ClientError, asyncio.TimeoutError):
            result["error"] = "Connection failed"
            return result

        if result["exists"]:
            try:
                async with session.get(s3_url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        result["public_read"] = True
                        if "<ListBucketResult" in body:
                            result["directory_listing"] = True
                            result["issues"].append("Directory listing enabled - contents exposed")
                            keys = re.findall(r"<Key>([^<]+)</Key>", body)
                            result["sample_keys"] = keys[:20]
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        return result

    async def _check_bucket_policy(self, session: aiohttp.ClientSession,
                                    bucket: str) -> dict[str, Any]:
        """Attempt to retrieve bucket policy."""
        result = {"bucket": bucket, "policy_accessible": False, "issues": []}
        policy_url = f"https://{bucket}.s3.amazonaws.com/?policy"
        try:
            async with session.get(policy_url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    policy_text = await resp.text()
                    result["policy_accessible"] = True
                    result["issues"].append("Bucket policy is publicly readable")
                    try:
                        policy = json.loads(policy_text)
                        for stmt in policy.get("Statement", []):
                            principal = stmt.get("Principal", "")
                            if principal == "*" or (isinstance(principal, dict) and
                                                     principal.get("AWS") == "*"):
                                result["issues"].append(
                                    f"Policy allows wildcard principal: {stmt.get('Effect')} "
                                    f"{stmt.get('Action')}")
                        result["policy"] = policy
                    except json.JSONDecodeError:
                        result["raw_policy"] = policy_text[:500]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            result["error"] = "Could not retrieve policy"
        return result

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        bucket_name = config["bucket_name"].strip()
        check_type = config.get("check_type", "permissions")
        enumerate_variants = config.get("enumerate_variants", False)

        bucket_names = self._generate_bucket_names(bucket_name, enumerate_variants)
        findings = []
        public_buckets = []

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for name in bucket_names:
                if check_type == "permissions" or check_type == "content":
                    tasks.append(self._check_bucket_permissions(session, name))
                if check_type == "policy":
                    tasks.append(self._check_bucket_policy(session, name))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception):
                    findings.append({"error": str(res)})
                    continue
                if res.get("issues"):
                    findings.append(res)
                if res.get("public_read") or res.get("policy_accessible"):
                    public_buckets.append(res.get("bucket", "unknown"))

        return {
            "bucket_base": bucket_name,
            "check_type": check_type,
            "buckets_tested": len(bucket_names),
            "findings": findings,
            "public_buckets": public_buckets,
            "risk_level": "critical" if public_buckets else "info",
        }
