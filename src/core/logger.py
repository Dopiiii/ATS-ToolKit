"""Structured logging and audit trail for ATS-Toolkit.

Provides structured logging via structlog and an SQLite-backed
audit logger for tracking module executions.
"""

import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "console",
    log_file: Optional[str] = None,
) -> None:
    """Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format - 'json' for machine-readable, 'console' for human-readable
        log_file: Optional file path to write logs to
    """
    # Determine the renderer
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.format_exc_info,
        renderer,
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging bridge
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(message)s",
        handlers=_build_handlers(log_file),
    )


def _build_handlers(log_file: Optional[str] = None) -> list[logging.Handler]:
    """Build logging handlers list.

    Args:
        log_file: Optional file path to write logs to

    Returns:
        List of logging handlers
    """
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path)))
    return handlers


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structlog logger.

    Args:
        name: Logger name (typically module or class name)

    Returns:
        A bound structlog logger instance
    """
    return structlog.get_logger(name)


class AuditLogger:
    """SQLite-backed audit logger for module executions.

    Records every module execution with its configuration, result,
    and duration for compliance and debugging purposes.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize the audit logger.

        Args:
            db_path: Path to SQLite database file. Defaults to data/audit.db.
        """
        if db_path is None:
            db_path = str(Path(__file__).resolve().parents[2] / "data" / "audit.db")

        self._db_path = db_path
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._logger = get_logger("audit")

    def _init_db(self) -> None:
        """Create the audit table if it does not exist."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    config TEXT,
                    result TEXT,
                    success INTEGER,
                    duration_ms INTEGER,
                    errors TEXT
                )
                """
            )
            conn.commit()

    def log_execution(
        self,
        module_name: str,
        config: dict[str, Any],
        result: dict[str, Any],
        duration_ms: int,
    ) -> None:
        """Record a module execution in the audit log.

        Args:
            module_name: Name of the executed module
            config: Input configuration that was used
            result: Execution result data
            duration_ms: Execution duration in milliseconds
        """
        import json

        timestamp = datetime.now(timezone.utc).isoformat()
        success = 1 if result.get("success", False) else 0
        errors = json.dumps(result.get("errors", []))

        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log
                        (timestamp, module_name, config, result, success, duration_ms, errors)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        module_name,
                        json.dumps(config),
                        json.dumps(result),
                        success,
                        duration_ms,
                        errors,
                    ),
                )
                conn.commit()

            self._logger.info(
                "audit_recorded",
                module=module_name,
                success=bool(success),
                duration_ms=duration_ms,
            )
        except Exception as e:
            self._logger.error(
                "audit_write_failed",
                module=module_name,
                error=str(e),
            )
