"""Logging setup with structlog and SQLite audit trail.

Provides structured logging with JSON output and SQLite persistence.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import structlog
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLAlchemy Base
Base = declarative_base()


class AuditLog(Base):
    """SQLite table for audit logs."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    level = Column(String(10), nullable=False)
    logger = Column(String(100), nullable=False)
    event = Column(String(100), nullable=False)
    message = Column(Text)
    module = Column(String(100))
    user = Column(String(100))
    context = Column(Text)  # JSON string


class SQLiteAuditProcessor:
    """Structlog processor that writes to SQLite."""

    def __init__(self, db_path: Path):
        """Initialize SQLite audit processor.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)

        # Create tables
        Base.metadata.create_all(self.engine)

        # Create session factory
        self.Session = sessionmaker(bind=self.engine)

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Process log event and write to SQLite.

        Args:
            logger: Logger instance
            method_name: Log level name
            event_dict: Event dictionary

        Returns:
            Unmodified event dictionary
        """
        # Only audit certain log levels
        if method_name not in ("info", "warning", "error", "critical"):
            return event_dict

        # Extract fields
        timestamp = event_dict.get("timestamp", datetime.utcnow())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except (ValueError, AttributeError):
                timestamp = datetime.utcnow()

        level = method_name.upper()
        logger_name = event_dict.get("logger", "unknown")
        event = event_dict.get("event", "")
        module = event_dict.get("module")
        user = event_dict.get("user")

        # Build context from remaining keys
        context_keys = set(event_dict.keys()) - {
            "timestamp",
            "level",
            "logger",
            "event",
            "module",
            "user",
        }
        context = {k: event_dict[k] for k in context_keys if k not in ("_record", "_from_structlog")}

        # Convert context to JSON string
        import json
        context_json = json.dumps(context, default=str)

        # Build message
        message_parts = [event]
        for key in ["domain", "target", "url", "ip", "username"]:
            if key in event_dict:
                message_parts.append(f"{key}={event_dict[key]}")
        message = " ".join(message_parts)

        # Write to database
        try:
            session = self.Session()
            try:
                audit_entry = AuditLog(
                    timestamp=timestamp,
                    level=level,
                    logger=logger_name,
                    event=event,
                    message=message,
                    module=module,
                    user=user,
                    context=context_json,
                )
                session.add(audit_entry)
                session.commit()
            finally:
                session.close()
        except Exception as e:
            # Don't break logging if audit fails
            print(f"Audit log failed: {e}", file=sys.stderr)

        return event_dict


def setup_logging(
    level: str = "INFO",
    console: bool = True,
    json_output: bool = False,
    audit_db: Optional[Path] = None,
) -> None:
    """Setup structured logging with structlog.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console: Enable console output
        json_output: Output JSON format instead of human-readable
        audit_db: Path to SQLite audit database (default: logs/audit.db)
    """
    # Determine audit database path
    if audit_db is None:
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        audit_db = logs_dir / "audit.db"
    else:
        audit_db.parent.mkdir(parents=True, exist_ok=True)

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout if console else None,
        level=getattr(logging, level.upper()),
    )

    # Build processor chain
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    # Add SQLite audit processor
    processors.append(SQLiteAuditProcessor(audit_db))

    # Add final rendering processor
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "ats") -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.

    Args:
        name: Logger name

    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


def configure_module_logger(
    module_name: str,
    **context: Any,
) -> structlog.stdlib.BoundLogger:
    """Get a logger configured for a specific module.

    Args:
        module_name: Name of the module
        **context: Additional context to bind to logger

    Returns:
        Structured logger with module context
    """
    logger = get_logger(module_name)
    return logger.bind(module=module_name, **context)


class LoggerMixin:
    """Mixin to add logging capabilities to classes."""

    @property
    def logger(self) -> structlog.stdlib.BoundLogger:
        """Get logger instance for this class."""
        if not hasattr(self, "_logger"):
            name = self.__class__.__name__
            self._logger = get_logger(name.lower())
        return self._logger

    def log_event(
        self,
        event: str,
        level: str = "info",
        **kwargs: Any,
    ) -> None:
        """Log an event with context.

        Args:
            event: Event name/description
            level: Log level (debug, info, warning, error, critical)
            **kwargs: Additional context
        """
        log_func = getattr(self.logger, level.lower())
        log_func(event, **kwargs)


def query_audit_logs(
    db_path: Optional[Path] = None,
    level: Optional[str] = None,
    module: Optional[str] = None,
    event: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query audit logs from SQLite database.

    Args:
        db_path: Path to SQLite database
        level: Filter by log level
        module: Filter by module name
        event: Filter by event name
        limit: Maximum number of results

    Returns:
        List of log entries as dictionaries
    """
    if db_path is None:
        db_path = Path("logs") / "audit.db"

    if not db_path.exists():
        return []

    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        query = session.query(AuditLog)

        if level:
            query = query.filter(AuditLog.level == level.upper())
        if module:
            query = query.filter(AuditLog.module == module)
        if event:
            query = query.filter(AuditLog.event.like(f"%{event}%"))

        query = query.order_by(AuditLog.timestamp.desc()).limit(limit)

        results = []
        for log in query.all():
            import json
            try:
                context = json.loads(log.context) if log.context else {}
            except json.JSONDecodeError:
                context = {}

            results.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "level": log.level,
                "logger": log.logger,
                "event": log.event,
                "message": log.message,
                "module": log.module,
                "user": log.user,
                "context": context,
            })

        return results
    finally:
        session.close()
