"""Wayback Machine module.

Search and retrieve historical snapshots from the Internet Archive.
"""

import asyncio
import aiohttp
from typing import Any, Dict, List, Tuple
from datetime import datetime
from urllib.parse import quote

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)


class WaybackMachineModule(AtsModule):
    """Search Internet Archive's Wayback Machine."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="wayback_machine",
            category=ModuleCategory.OSINT,
            description="Search Wayback Machine for historical snapshots",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="url",
                    type=ParameterType.STRING,
                    description="URL to search for",
                    required=True,
                ),
                Parameter(
                    name="limit",
                    type=ParameterType.INTEGER,
                    description="Maximum snapshots to retrieve",
                    required=False,
                    default=100,
                    min_value=1,
                    max_value=1000,
                ),
                Parameter(
                    name="from_year",
                    type=ParameterType.INTEGER,
                    description="Start year (optional)",
                    required=False,
                    min_value=1996,
                    max_value=2030,
                ),
                Parameter(
                    name="to_year",
                    type=ParameterType.INTEGER,
                    description="End year (optional)",
                    required=False,
                    min_value=1996,
                    max_value=2030,
                ),
            ],
            outputs=[
                OutputField(name="snapshots", type="list", description="Historical snapshots"),
                OutputField(name="timeline", type="dict", description="Snapshots by year"),
            ],
            tags=["wayback", "archive", "history", "osint"],
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        url = config.get("url", "").strip()
        if not url:
            return False, "URL is required"
        return True, ""

    async def _get_cdx_results(
        self,
        session: aiohttp.ClientSession,
        url: str,
        limit: int,
        from_date: str = None,
        to_date: str = None
    ) -> List[Dict[str, Any]]:
        """Query CDX API for snapshots."""
        snapshots = []

        params = {
            "url": url,
            "output": "json",
            "limit": limit,
            "fl": "timestamp,original,mimetype,statuscode,digest,length",
        }

        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        try:
            api_url = "https://web.archive.org/cdx/search/cdx"
            async with session.get(
                api_url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    # First row is header
                    if data and len(data) > 1:
                        headers = data[0]

                        for row in data[1:]:
                            snapshot = dict(zip(headers, row))

                            # Parse timestamp
                            ts = snapshot.get("timestamp", "")
                            if len(ts) >= 8:
                                try:
                                    dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                                    snapshot["datetime"] = dt.isoformat()
                                    snapshot["year"] = dt.year
                                    snapshot["month"] = dt.month
                                except:
                                    pass

                            # Build archive URL
                            snapshot["archive_url"] = f"https://web.archive.org/web/{ts}/{snapshot.get('original', url)}"

                            snapshots.append(snapshot)

        except Exception as e:
            self.logger.warning("cdx_query_failed", error=str(e))

        return snapshots

    async def _get_availability(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Dict[str, Any]:
        """Check URL availability in Wayback Machine."""
        try:
            api_url = f"https://archive.org/wayback/available?url={quote(url)}"
            async with session.get(
                api_url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("archived_snapshots", {})
        except Exception as e:
            self.logger.warning("availability_check_failed", error=str(e))

        return {}

    def _build_timeline(self, snapshots: List[Dict]) -> Dict[str, Any]:
        """Build timeline from snapshots."""
        timeline = {}

        for snapshot in snapshots:
            year = snapshot.get("year")
            if year:
                if year not in timeline:
                    timeline[year] = {
                        "count": 0,
                        "months": {},
                        "first": None,
                        "last": None,
                    }

                timeline[year]["count"] += 1

                month = snapshot.get("month")
                if month:
                    timeline[year]["months"][month] = timeline[year]["months"].get(month, 0) + 1

                # Track first and last
                if not timeline[year]["first"]:
                    timeline[year]["first"] = snapshot.get("datetime")
                timeline[year]["last"] = snapshot.get("datetime")

        return dict(sorted(timeline.items()))

    def _analyze_changes(self, snapshots: List[Dict]) -> Dict[str, Any]:
        """Analyze changes between snapshots."""
        analysis = {
            "total_snapshots": len(snapshots),
            "unique_digests": 0,
            "status_codes": {},
            "mime_types": {},
            "date_range": {
                "first": None,
                "last": None,
            }
        }

        digests = set()

        for snapshot in snapshots:
            # Unique content versions
            digest = snapshot.get("digest")
            if digest:
                digests.add(digest)

            # Status codes
            status = snapshot.get("statuscode", "unknown")
            analysis["status_codes"][status] = analysis["status_codes"].get(status, 0) + 1

            # MIME types
            mime = snapshot.get("mimetype", "unknown")
            analysis["mime_types"][mime] = analysis["mime_types"].get(mime, 0) + 1

            # Date range
            dt = snapshot.get("datetime")
            if dt:
                if not analysis["date_range"]["first"]:
                    analysis["date_range"]["first"] = dt
                analysis["date_range"]["last"] = dt

        analysis["unique_digests"] = len(digests)

        return analysis

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        url = config["url"].strip()
        limit = config.get("limit", 100)
        from_year = config.get("from_year")
        to_year = config.get("to_year")

        # Format dates for API
        from_date = f"{from_year}0101" if from_year else None
        to_date = f"{to_year}1231" if to_year else None

        self.logger.info("starting_wayback_search", url=url, limit=limit)

        results = {
            "url": url,
            "snapshots": [],
            "timeline": {},
            "analysis": {},
            "availability": {},
        }

        async with aiohttp.ClientSession() as session:
            # Check current availability
            availability = await self._get_availability(session, url)
            results["availability"] = availability

            # Get historical snapshots
            snapshots = await self._get_cdx_results(
                session, url, limit, from_date, to_date
            )
            results["snapshots"] = snapshots

        # Build timeline
        results["timeline"] = self._build_timeline(snapshots)

        # Analyze changes
        results["analysis"] = self._analyze_changes(snapshots)

        # Get closest snapshot info
        if availability.get("closest"):
            closest = availability["closest"]
            results["closest_snapshot"] = {
                "url": closest.get("url"),
                "timestamp": closest.get("timestamp"),
                "available": closest.get("available"),
            }

        self.logger.info(
            "wayback_search_complete",
            url=url,
            snapshots=len(snapshots)
        )

        return results
