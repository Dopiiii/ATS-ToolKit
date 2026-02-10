"""
User model for authentication and authorization.
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.api_key import APIKey


class UserRole(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"  # Full access
    ANALYST = "analyst"  # Can run collections, view data, create reports
    VIEWER = "viewer"  # Read-only access
    API_USER = "api_user"  # API-only access (no UI)


class User(Base):
    """
    User account model.

    Attributes:
        email: Unique email address (used for login)
        password_hash: Bcrypt hashed password
        role: User role for authorization
        is_active: Whether user can log in
        is_verified: Whether email has been verified
        mfa_enabled: Whether MFA is enabled
        mfa_secret: TOTP secret for MFA (encrypted)
        last_login: Last successful login timestamp
        last_login_ip: IP address of last login
    """

    __tablename__ = "users"

    # Authentication
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Authorization
    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=UserRole.ANALYST.value,
        server_default=text("'analyst'"),
    )

    # Account status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    mfa_secret: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # Login tracking
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_login_ip: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
    )

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"

    @property
    def is_admin(self) -> bool:
        """Check if user is an admin."""
        return self.role == UserRole.ADMIN.value

    def has_role(self, *roles: UserRole) -> bool:
        """Check if user has any of the specified roles."""
        return self.role in [r.value for r in roles]

    def can_access(self, resource: str, action: str) -> bool:
        """
        Check if user can perform action on resource.

        This is a simple RBAC check. For more complex permissions,
        use a dedicated permission system.
        """
        if self.role == UserRole.ADMIN.value:
            return True

        if self.role == UserRole.VIEWER.value:
            return action == "read"

        if self.role == UserRole.ANALYST.value:
            # Analysts can do most things except admin actions
            return action != "delete" or resource not in ["users", "settings"]

        if self.role == UserRole.API_USER.value:
            # API users have limited access
            return resource in ["collections", "entities", "search"] and action in [
                "read",
                "create",
            ]

        return False
