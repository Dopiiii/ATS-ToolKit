"""
User and API Key schemas.
"""

from datetime import datetime
from typing import Optional

from pydantic import EmailStr, Field

from src.models.user import UserRole
from src.schemas.common import BaseSchema


# =============================================================================
# User Schemas
# =============================================================================


class UserBase(BaseSchema):
    """Base user fields."""

    email: EmailStr = Field(
        description="User email address",
        examples=["user@example.com"],
    )


class UserCreate(UserBase):
    """Schema for creating a user (admin only)."""

    password: str = Field(
        min_length=8,
        max_length=128,
        description="User password",
    )
    role: UserRole = Field(
        default=UserRole.ANALYST,
        description="User role",
    )
    is_active: bool = Field(
        default=True,
        description="Whether user is active",
    )


class UserUpdate(BaseSchema):
    """Schema for updating a user."""

    email: Optional[EmailStr] = Field(
        default=None,
        description="New email address",
    )
    role: Optional[UserRole] = Field(
        default=None,
        description="New role (admin only)",
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Active status (admin only)",
    )


class UserResponse(UserBase):
    """User response schema."""

    id: str = Field(description="User ID")
    role: str = Field(description="User role")
    is_active: bool = Field(description="Whether user is active")
    is_verified: bool = Field(description="Whether email is verified")
    mfa_enabled: bool = Field(description="Whether MFA is enabled")
    last_login: Optional[datetime] = Field(
        default=None,
        description="Last login timestamp",
    )
    created_at: datetime = Field(description="Account creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")


class UserProfile(BaseSchema):
    """Current user profile (includes more details)."""

    id: str
    email: EmailStr
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    created_at: datetime
    api_key_count: int = Field(description="Number of active API keys")


# =============================================================================
# API Key Schemas
# =============================================================================


class APIKeyCreate(BaseSchema):
    """Schema for creating an API key."""

    name: str = Field(
        min_length=1,
        max_length=100,
        description="Human-readable name for the key",
        examples=["Production API Key", "Development Testing"],
    )
    scopes: list[str] = Field(
        default=["collections:read", "entities:read", "search:read"],
        description="Allowed scopes for this key",
        examples=[["collections:*", "entities:read"]],
    )
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Key expiration in days (null for no expiration)",
    )


class APIKeyResponse(BaseSchema):
    """API key response (without the actual key)."""

    id: str = Field(description="API key ID")
    name: str = Field(description="Key name")
    scopes: list[str] = Field(description="Allowed scopes")
    expires_at: Optional[datetime] = Field(description="Expiration timestamp")
    last_used: Optional[datetime] = Field(description="Last use timestamp")
    is_active: bool = Field(description="Whether key is active")
    created_at: datetime = Field(description="Creation timestamp")


class APIKeyCreated(APIKeyResponse):
    """
    API key creation response (includes the actual key).

    The key is only shown once at creation time.
    """

    key: str = Field(
        description="The API key (only shown once!)",
        examples=["osint_AbCdEf123456..."],
    )


class APIKeyList(BaseSchema):
    """List of API keys."""

    keys: list[APIKeyResponse]
    total: int
