"""
API Key model for programmatic access.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class APIKey(Base):
    """
    API Key model for programmatic access.

    API keys allow users to authenticate without using email/password.
    Each key has scopes that limit what operations can be performed.

    Attributes:
        user_id: Owner of the API key
        key_hash: Bcrypt hash of the API key (key is shown once on creation)
        name: Human-readable name for the key
        scopes: List of allowed scopes (e.g., ["collections:read", "entities:write"])
        expires_at: Optional expiration date
        last_used: Last time the key was used
        last_used_ip: IP address of last use
        is_active: Whether the key is active
    """

    __tablename__ = "api_keys"

    # Owner
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Key data
    key_hash: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    # Permissions
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)),
        nullable=False,
        default=list,
        server_default=text("'{}'::text[]"),
    )

    # Lifecycle
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(
        default=True,
        server_default=text("true"),
    )

    # Usage tracking
    last_used: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="api_keys",
    )

    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name={self.name}, user_id={self.user_id})>"

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(self.expires_at.tzinfo) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if the key is valid (active and not expired)."""
        return self.is_active and not self.is_expired

    def has_scope(self, scope: str) -> bool:
        """
        Check if the key has a specific scope.

        Supports wildcard matching:
        - "collections:*" matches "collections:read", "collections:write", etc.
        - "*" matches everything

        Args:
            scope: Scope to check (e.g., "collections:read")

        Returns:
            True if scope is allowed
        """
        if "*" in self.scopes:
            return True

        if scope in self.scopes:
            return True

        # Check for wildcard scopes
        resource = scope.split(":")[0]
        if f"{resource}:*" in self.scopes:
            return True

        return False

    def has_any_scope(self, *scopes: str) -> bool:
        """Check if the key has any of the specified scopes."""
        return any(self.has_scope(scope) for scope in scopes)


# Common scope definitions
class APIScopes:
    """Common API scopes."""

    # Collections
    COLLECTIONS_READ = "collections:read"
    COLLECTIONS_WRITE = "collections:write"
    COLLECTIONS_DELETE = "collections:delete"
    COLLECTIONS_ALL = "collections:*"

    # Entities
    ENTITIES_READ = "entities:read"
    ENTITIES_WRITE = "entities:write"
    ENTITIES_DELETE = "entities:delete"
    ENTITIES_ALL = "entities:*"

    # Search
    SEARCH_READ = "search:read"

    # Reports
    REPORTS_READ = "reports:read"
    REPORTS_WRITE = "reports:write"
    REPORTS_ALL = "reports:*"

    # Admin
    ADMIN_ALL = "admin:*"

    # Full access
    ALL = "*"
