"""
Structured logging configuration using structlog.

Provides:
- Consistent log formatting across the application
- JSON output for production (machine parseable)
- Console output for development (human readable)
- Request ID tracking
- Performance timing
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import Processor

from src.config import settings


def setup_logging() -> None:
    """
    Configure structured logging for the application.

    Call this once at application startup.
    """
    # Shared processors for all outputs
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if settings.LOG_FORMAT == "json":
        # JSON format for production
        processors: list[Processor] = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console format for development
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging to use structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.LOG_LEVEL),
    )

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.DEBUG if settings.DEBUG else logging.WARNING
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a bound logger instance.

    Args:
        name: Logger name (usually module name)

    Returns:
        Configured structlog logger

    Example:
        logger = get_logger(__name__)
        logger.info("Processing request", user_id=user.id)
    """
    return structlog.get_logger(name)


class LoggerMixin:
    """
    Mixin class that provides logging capabilities.

    Usage:
        class MyService(LoggerMixin):
            def do_something(self):
                self.log.info("Doing something", data={"key": "value"})
    """

    @property
    def log(self) -> structlog.stdlib.BoundLogger:
        """Get a logger bound to this class."""
        return get_logger(self.__class__.__name__)


def log_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    **extra: Any,
) -> None:
    """
    Log an HTTP request.

    Args:
        method: HTTP method
        path: Request path
        status_code: Response status code
        duration_ms: Request duration in milliseconds
        **extra: Additional context
    """
    logger = get_logger("http")

    log_data = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
        **extra,
    }

    if status_code >= 500:
        logger.error("Request failed", **log_data)
    elif status_code >= 400:
        logger.warning("Request error", **log_data)
    else:
        logger.info("Request completed", **log_data)


def log_audit(
    action: str,
    user_id: str | None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    **details: Any,
) -> None:
    """
    Log an audit event.

    Args:
        action: Action performed (e.g., "user.login", "collection.start")
        user_id: ID of user performing action
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        **details: Additional context
    """
    logger = get_logger("audit")

    logger.info(
        "audit_event",
        action=action,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        **details,
    )
