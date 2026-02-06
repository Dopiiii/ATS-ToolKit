"""
FastAPI dependencies for authentication, database, etc.
"""

from typing import Annotated, Optional

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.core.security import verify_token
from src.models.user import User, UserRole
from src.services.user import UserService

# Security scheme for JWT
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials], Depends(security)
    ],
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get the current authenticated user.

    Supports both JWT Bearer token and API key authentication.

    Args:
        credentials: JWT bearer credentials
        x_api_key: API key from header
        db: Database session

    Returns:
        Authenticated user

    Raises:
        AuthenticationError: If not authenticated
    """
    user_service = UserService(db)

    # Try API key first
    if x_api_key:
        result = await user_service.validate_api_key(x_api_key)
        if result:
            api_key, user = result
            return user

    # Try JWT token
    if credentials:
        token = credentials.credentials
        payload = verify_token(token, token_type="access")

        if payload:
            user_id = payload.get("sub")
            if user_id:
                user = await user_service.get_user(user_id)
                if user and user.is_active:
                    return user

    raise AuthenticationError(
        message="Invalid or missing authentication",
        code="not_authenticated",
    )


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Get current user and verify they are active.

    Args:
        current_user: User from get_current_user

    Returns:
        Active user

    Raises:
        AuthenticationError: If user is not active
    """
    if not current_user.is_active:
        raise AuthenticationError(
            message="User account is disabled",
            code="account_disabled",
        )
    return current_user


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """
    Get current user and verify they are an admin.

    Args:
        current_user: Active user

    Returns:
        Admin user

    Raises:
        AuthorizationError: If user is not admin
    """
    if not current_user.is_admin:
        raise AuthorizationError(
            message="Admin access required",
            code="admin_required",
        )
    return current_user


def require_role(*roles: UserRole):
    """
    Factory for role-checking dependency.

    Usage:
        @router.get("/protected")
        async def protected(
            user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))
        ):
            ...
    """

    async def role_checker(
        current_user: Annotated[User, Depends(get_current_active_user)],
    ) -> User:
        if not current_user.has_role(*roles):
            raise AuthorizationError(
                message=f"Required role: {', '.join(r.value for r in roles)}",
                code="insufficient_role",
            )
        return current_user

    return role_checker


def get_client_ip(request: Request) -> Optional[str]:
    """
    Get client IP address from request.

    Handles X-Forwarded-For header for proxy setups.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Get first IP in chain
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_user_agent(request: Request) -> Optional[str]:
    """Get user agent from request headers."""
    return request.headers.get("user-agent")


# Type aliases for cleaner dependency injection
CurrentUser = Annotated[User, Depends(get_current_user)]
ActiveUser = Annotated[User, Depends(get_current_active_user)]
AdminUser = Annotated[User, Depends(get_current_admin_user)]
DbSession = Annotated[AsyncSession, Depends(get_db)]
ClientIP = Annotated[Optional[str], Depends(get_client_ip)]
UserAgent = Annotated[Optional[str], Depends(get_user_agent)]
