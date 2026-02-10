"""Cloud storage endpoint enumerator.

Generates and tests common bucket/blob/container names using company name permutations
across AWS S3, Azure Blob Storage, and Google Cloud Storage.
"""

import asyncio
import re
import json
from typing import Any

import aiohttp

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

BUCKET_PATTERNS = [
    "{name}", "{name}-backup", "{name}-backups", "{name}-dev", "{name}-staging",
    "{name}-prod", "{name}-production", "{name}-data", "{name}-assets",
    "{name}-static", "{name}-media", "{name}-uploads", "{name}-files",
    "{name}-logs", "{name}-archive", "{name}-public", "{name}-private",
    "{name}-cdn", "{name}-images", "{name}-config", "{name}-temp",
    "{name}-internal", "{name}-external", "{name}-web", "{name}-api",
    "{name}-db", "{name}-database", "{name}-storage", "{name}-bucket",
    "backup-{name}", "dev-{name}", "staging-{name}", "prod-{name}",
]

PROVIDER_ENDPOINTS = {
    "aws": {"url": "https://{bucket}.s3.amazonaws.com", "label": "AWS S3"},
    "azure": {"url": "https://{bucket}.blob.core.windows.net", "label": "Azure Blob"},
    "gcp": {"url": "https://storage.googleapis.com/{bucket}", "label": "GCP Storage"},
}


class CloudStorageEnumModule(AtsModule):
    """Enumerate cloud storage endpoints using company name permutations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_storage_enum",
            category=ModuleCategory.ADVANCED,
            description="Enumerate cloud storage buckets and blobs using company name permutations",
            version="1.0.0",
            parameters=[
                Parameter(name="company_name", type=ParameterType.STRING,
                          description="Company or organization name to enumerate", required=True),
                Parameter(name="providers", type=ParameterType.CHOICE,
                          description="Cloud providers to check",
                          choices=["all", "aws", "azure", "gcp"], default="all"),
                Parameter(name="concurrency", type=ParameterType.INTEGER,
                          description="Max concurrent requests", default=15,
                          min_value=1, max_value=50),
            ],
            outputs=[
                OutputField(name="discovered", type="list", description="Discovered storage endpoints"),
                OutputField(name="total_tested", type="integer", description="Total endpoints tested"),
                OutputField(name="accessible_count", type="integer", description="Number of accessible endpoints"),
            ],
            tags=["advanced", "cloud", "storage", "enumeration", "recon"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        name = config.get("company_name", "").strip()
        if not name:
            return False, "Company name is required"
        if len(name) < 2:
            return False, "Company name too short"
        return True, ""

    def _generate_bucket_names(self, company_name: str) -> list[str]:
        """Generate bucket name permutations from company name."""
        base = re.sub(r'[^a-z0-9\-]', '', company_name.lower().strip())
        base_parts = base.split("-") if "-" in base else [base]
        names = set()

        for pattern in BUCKET_PATTERNS:
            names.add(pattern.format(name=base))

        if " " in company_name:
            dotted = company_name.lower().replace(" ", ".")
            dashed = company_name.lower().replace(" ", "-")
            no_space = company_name.lower().replace(" ", "")
            for variant in [dotted, dashed, no_space]:
                clean = re.sub(r'[^a-z0-9.\-]', '', variant)
                names.add(clean)
                names.add(f"{clean}-backup")
                names.add(f"{clean}-dev")

        if len(base_parts) > 1:
            abbrev = "".join(p[0] for p in base_parts if p)
            names.add(abbrev)
            names.add(f"{abbrev}-data")
            names.add(f"{abbrev}-backup")

        return [n for n in sorted(names) if 3 <= len(n) <= 63 and re.match(r'^[a-z0-9]', n)]

    async def _check_endpoint(self, session: aiohttp.ClientSession, bucket: str,
                                provider: str, semaphore: asyncio.Semaphore) -> dict[str, Any] | None:
        """Check if a storage endpoint exists and its access level."""
        async with semaphore:
            endpoint = PROVIDER_ENDPOINTS[provider]
            url = endpoint["url"].format(bucket=bucket)
            result = {"bucket": bucket, "provider": endpoint["label"], "url": url,
                      "exists": False, "public": False, "status": None}
            try:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=8),
                                         allow_redirects=True) as resp:
                    result["status"] = resp.status
                    if resp.status == 200:
                        result["exists"] = True
                        result["public"] = True
                        result["access_level"] = "public_read"
                    elif resp.status == 403:
                        result["exists"] = True
                        result["access_level"] = "private"
                    elif resp.status in (301, 307):
                        result["exists"] = True
                        result["redirect"] = resp.headers.get("Location", "")
                    elif resp.status == 404:
                        return None

                if result["exists"] and result.get("public"):
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                if "<ListBucketResult" in body or "<EnumerationResults" in body:
                                    result["directory_listing"] = True
                                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                                    result["sample_files"] = keys[:10]
                                    result["file_count"] = len(keys)
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass

            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

            return result if result["exists"] else None

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        company_name = config["company_name"].strip()
        providers_choice = config.get("providers", "all")
        concurrency = config.get("concurrency", 15)

        providers = list(PROVIDER_ENDPOINTS.keys()) if providers_choice == "all" else [providers_choice]
        bucket_names = self._generate_bucket_names(company_name)
        semaphore = asyncio.Semaphore(concurrency)

        discovered = []
        total_tested = 0

        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for bucket in bucket_names:
                for provider in providers:
                    tasks.append(self._check_endpoint(session, bucket, provider, semaphore))
                    total_tested += 1

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, dict) and res.get("exists"):
                    discovered.append(res)

        public_endpoints = [d for d in discovered if d.get("public")]
        return {
            "company_name": company_name,
            "providers_checked": providers,
            "bucket_names_generated": len(bucket_names),
            "total_tested": total_tested,
            "discovered": discovered,
            "discovered_count": len(discovered),
            "accessible_count": len(public_endpoints),
            "public_endpoints": public_endpoints,
            "risk_level": "critical" if public_endpoints else "info" if discovered else "none",
        }
