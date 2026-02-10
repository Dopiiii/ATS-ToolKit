"""
Core infrastructure modules.

This package contains the foundational components:
- database: SQLAlchemy async database setup
- security: Authentication, JWT, password hashing
- logging: Structured logging with structlog
- exceptions: Custom exception hierarchy
"""

from src.core.database import get_db
from src.core.exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from src.core.logging import get_logger, setup_logging
from src.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)

__all__ = [
    # Database
    "get_db",
    # Security
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "get_password_hash",
    "verify_password",
    # Logging
    "setup_logging",
    "get_logger",
    # Exceptions
    "APIError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ValidationError",
]
