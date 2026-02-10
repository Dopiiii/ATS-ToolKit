"""
API v1 routes.
"""

from fastapi import APIRouter

from src.api.v1 import auth, health, users

router = APIRouter(prefix="/v1")

# Include sub-routers
router.include_router(health.router, tags=["Health"])
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(users.router, prefix="/users", tags=["Users"])
