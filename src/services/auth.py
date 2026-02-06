"""
Authentication service.

Handles:
- User registration
- Login/logout
- Token management
- Password changes
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.core.exceptions import AuthenticationError, ConflictError, ValidationError
from src.core.logging import get_logger, log_audit
from src.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from src.models.audit import AuditActions
from src.models.user import User, UserRole
from src.schemas.auth import LoginRequest, LoginResponse, RegisterRequest

logger = get_logger(__name__)


class AuthService:
    """Authentication service for user management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(
        self,
        data: RegisterRequest,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Register a new user.

        Args:
            data: Registration data
            ip_address: Client IP for audit

        Returns:
            Created user

        Raises:
            ConflictError: If email already exists
        """
        # Check if email exists
        existing = await self._get_user_by_email(data.email)
        if existing:
            raise ConflictError(
                message="Email already registered",
                code="email_exists",
            )

        # Create user
        user = User(
            email=data.email.lower(),
            password_hash=get_password_hash(data.password),
            role=UserRole.ANALYST.value,
            is_active=True,
            is_verified=False,  # TODO: Email verification
        )

        self.db.add(user)
        await self.db.flush()

        # Audit log
        log_audit(
            action=AuditActions.USER_REGISTER,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=ip_address,
            email=user.email,
        )

        logger.info(
            "User registered",
            user_id=user.id,
            email=user.email,
        )

        return user

    async def login(
        self,
        data: LoginRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResponse:
        """
        Authenticate a user and return tokens.

        Args:
            data: Login credentials
            ip_address: Client IP for tracking
            user_agent: Client user agent

        Returns:
            Login response with tokens

        Raises:
            AuthenticationError: If credentials are invalid
        """
        # Find user
        user = await self._get_user_by_email(data.email)

        if not user:
            # Log failed attempt (don't reveal if email exists)
            log_audit(
                action=AuditActions.USER_LOGIN_FAILED,
                user_id=None,
                ip_address=ip_address,
                email=data.email,
                reason="user_not_found",
            )
            raise AuthenticationError(
                message="Invalid email or password",
                code="invalid_credentials",
            )

        # Verify password
        if not verify_password(data.password, user.password_hash):
            log_audit(
                action=AuditActions.USER_LOGIN_FAILED,
                user_id=user.id,
                ip_address=ip_address,
                email=data.email,
                reason="invalid_password",
            )
            raise AuthenticationError(
                message="Invalid email or password",
                code="invalid_credentials",
            )

        # Check if active
        if not user.is_active:
            log_audit(
                action=AuditActions.USER_LOGIN_FAILED,
                user_id=user.id,
                ip_address=ip_address,
                reason="account_disabled",
            )
            raise AuthenticationError(
                message="Account is disabled",
                code="account_disabled",
            )

        # Update login tracking
        user.last_login = datetime.now(timezone.utc)
        user.last_login_ip = ip_address

        # Create tokens
        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role},
        )
        refresh_token = create_refresh_token(subject=user.id)

        # Audit log
        log_audit(
            action=AuditActions.USER_LOGIN,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info(
            "User logged in",
            user_id=user.id,
            email=user.email,
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def refresh_tokens(
        self,
        refresh_token: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token
            ip_address: Client IP

        Returns:
            New access token

        Raises:
            AuthenticationError: If refresh token is invalid
        """
        # Verify refresh token
        payload = verify_token(refresh_token, token_type="refresh")

        if not payload:
            raise AuthenticationError(
                message="Invalid or expired refresh token",
                code="invalid_refresh_token",
            )

        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError(
                message="Invalid token payload",
                code="invalid_token_payload",
            )

        # Verify user still exists and is active
        user = await self._get_user_by_id(user_id)
        if not user or not user.is_active:
            raise AuthenticationError(
                message="User not found or disabled",
                code="user_not_found",
            )

        # Create new access token
        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role},
        )

        logger.debug("Token refreshed", user_id=user.id)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """
        Change user's password.

        Args:
            user_id: User ID
            current_password: Current password for verification
            new_password: New password

        Returns:
            True if successful

        Raises:
            AuthenticationError: If current password is wrong
            ValidationError: If new password is same as current
        """
        user = await self._get_user_by_id(user_id)
        if not user:
            raise AuthenticationError(message="User not found")

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError(
                message="Current password is incorrect",
                code="invalid_current_password",
            )

        # Ensure new password is different
        if verify_password(new_password, user.password_hash):
            raise ValidationError(
                message="New password must be different from current password"
            )

        # Update password
        user.password_hash = get_password_hash(new_password)

        log_audit(
            action=AuditActions.USER_PASSWORD_CHANGE,
            user_id=user.id,
            ip_address=ip_address,
        )

        logger.info("Password changed", user_id=user.id)

        return True

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    async def _get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email address."""
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
