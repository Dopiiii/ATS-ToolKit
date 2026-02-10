"""
Health check endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src import __version__
from src.core.database import get_db
from src.schemas.common import HealthCheck

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthCheck,
    summary="Health Check",
    description="Check the health status of the API and its dependencies.",
)
async def health_check(db: AsyncSession = Depends(get_db)) -> HealthCheck:
    """
    Health check endpoint.

    Returns the status of the API and its dependencies:
    - Database connection
    - Redis connection (future)
    """
    # Check database
    db_status = "down"
    try:
        await db.execute(text("SELECT 1"))
        db_status = "up"
    except Exception:
        db_status = "down"

    # TODO: Check Redis in Phase 2
    redis_status = "not_configured"

    # Overall status
    overall = "healthy" if db_status == "up" else "degraded"

    return HealthCheck(
        status=overall,
        version=__version__,
        database=db_status,
        redis=redis_status,
    )


@router.get(
    "/",
    summary="API Root",
    description="Get basic API information.",
)
async def api_root():
    """API root endpoint with basic information."""
    return {
        "name": "OSINT Platform API",
        "version": __version__,
        "docs": "/docs",
        "health": "/api/v1/health",
    }
