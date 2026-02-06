"""
Audit Log model for tracking all user actions.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import BigInteger, DateTime, String, func, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class AuditLog(Base):
    """
    Audit log for tracking all user actions.

    This table is append-only and should never be modified or deleted.
    It provides a complete audit trail for compliance and debugging.

    Attributes:
        user_id: User who performed the action (null for system actions)
        action: Action performed (e.g., "user.login", "collection.start")
        resource_type: Type of resource affected (e.g., "user", "collection")
        resource_id: ID of resource affected
        ip_address: IP address of the request
        user_agent: User agent string
        details: Additional context as JSON
        timestamp: When the action occurred
    """

    __tablename__ = "audit_logs"

    # Override id to use BigInteger for better performance with many rows
    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    # Remove inherited created_at/updated_at and use timestamp instead
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        init=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        init=False,
    )

    # Actor
    user_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False),
        nullable=True,
        index=True,
    )

    # Action
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    # Resource
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False),
        nullable=True,
    )

    # Request context
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # Additional data
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        default=None,
    )

    # Timestamp (separate from created_at for explicit querying)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"


# Common audit actions
class AuditActions:
    """Predefined audit action strings."""

    # Authentication
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    USER_PASSWORD_CHANGE = "user.password_change"
    USER_PASSWORD_RESET = "user.password_reset"
    USER_MFA_ENABLE = "user.mfa_enable"
    USER_MFA_DISABLE = "user.mfa_disable"

    # Users
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_ROLE_CHANGE = "user.role_change"

    # API Keys
    API_KEY_CREATE = "api_key.create"
    API_KEY_DELETE = "api_key.delete"
    API_KEY_USE = "api_key.use"

    # Collections (Phase 2)
    COLLECTION_START = "collection.start"
    COLLECTION_COMPLETE = "collection.complete"
    COLLECTION_FAIL = "collection.fail"
    COLLECTION_CANCEL = "collection.cancel"

    # Entities (Phase 2)
    ENTITY_CREATE = "entity.create"
    ENTITY_UPDATE = "entity.update"
    ENTITY_DELETE = "entity.delete"
    ENTITY_MERGE = "entity.merge"

    # Reports (Phase 7)
    REPORT_GENERATE = "report.generate"
    REPORT_EXPORT = "report.export"

    # System
    SYSTEM_CONFIG_CHANGE = "system.config_change"
    SYSTEM_BACKUP = "system.backup"
    SYSTEM_RESTORE = "system.restore"
