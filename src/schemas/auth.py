"""
Authentication schemas for login, register, and token management.
"""

from pydantic import EmailStr, Field, field_validator

from src.schemas.common import BaseSchema


class LoginRequest(BaseSchema):
    """Login request with email and password."""

    email: EmailStr = Field(
        description="User email address",
        examples=["user@example.com"],
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="User password",
        examples=["SecurePass123!"],
    )


class LoginResponse(BaseSchema):
    """Login response with tokens."""

    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Access token expiry in seconds")


class RegisterRequest(BaseSchema):
    """User registration request."""

    email: EmailStr = Field(
        description="User email address",
        examples=["user@example.com"],
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="User password (min 8 characters)",
        examples=["SecurePass123!"],
    )
    password_confirm: str = Field(
        min_length=8,
        max_length=128,
        description="Password confirmation",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Ensure password meets security requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)

        if not (has_upper and has_lower and has_digit):
            raise ValueError(
                "Password must contain uppercase, lowercase, and digit"
            )

        return v

    @field_validator("password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Ensure passwords match."""
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class RefreshRequest(BaseSchema):
    """Token refresh request."""

    refresh_token: str = Field(description="JWT refresh token")


class RefreshResponse(BaseSchema):
    """Token refresh response."""

    access_token: str = Field(description="New JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Access token expiry in seconds")


class PasswordChangeRequest(BaseSchema):
    """Password change request."""

    current_password: str = Field(
        min_length=8,
        max_length=128,
        description="Current password",
    )
    new_password: str = Field(
        min_length=8,
        max_length=128,
        description="New password",
    )
    new_password_confirm: str = Field(
        min_length=8,
        max_length=128,
        description="New password confirmation",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Ensure password meets security requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)

        if not (has_upper and has_lower and has_digit):
            raise ValueError(
                "Password must contain uppercase, lowercase, and digit"
            )

        return v

    @field_validator("new_password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Ensure passwords match."""
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class PasswordResetRequest(BaseSchema):
    """Password reset request (forgot password)."""

    email: EmailStr = Field(
        description="Email to send reset link to",
        examples=["user@example.com"],
    )


class PasswordResetConfirm(BaseSchema):
    """Password reset confirmation with token."""

    token: str = Field(description="Password reset token from email")
    new_password: str = Field(
        min_length=8,
        max_length=128,
        description="New password",
    )
    new_password_confirm: str = Field(
        min_length=8,
        max_length=128,
        description="New password confirmation",
    )

    @field_validator("new_password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Ensure passwords match."""
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v
