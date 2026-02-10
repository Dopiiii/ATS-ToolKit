"""
Authentication endpoints.
"""

from fastapi import APIRouter, Depends, status

from src.api.deps import ActiveUser, ClientIP, DbSession, UserAgent
from src.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
)
from src.schemas.common import SuccessResponse
from src.schemas.user import UserResponse
from src.services.auth import AuthService

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register",
    description="Register a new user account.",
)
async def register(
    data: RegisterRequest,
    db: DbSession,
    ip: ClientIP,
) -> UserResponse:
    """
    Register a new user.

    Creates a new user account with the provided email and password.
    The user will have the 'analyst' role by default.
    """
    auth_service = AuthService(db)
    user = await auth_service.register(data, ip_address=ip)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login",
    description="Authenticate with email and password.",
)
async def login(
    data: LoginRequest,
    db: DbSession,
    ip: ClientIP,
    user_agent: UserAgent,
) -> LoginResponse:
    """
    Login with email and password.

    Returns access and refresh tokens on successful authentication.
    The access token expires after the configured time (default 30 minutes).
    Use the refresh token to get a new access token.
    """
    auth_service = AuthService(db)
    return await auth_service.login(
        data,
        ip_address=ip,
        user_agent=user_agent,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Refresh Token",
    description="Get a new access token using a refresh token.",
)
async def refresh_token(
    data: RefreshRequest,
    db: DbSession,
    ip: ClientIP,
) -> RefreshResponse:
    """
    Refresh the access token.

    Use the refresh token from login to get a new access token
    without requiring the user to log in again.
    """
    auth_service = AuthService(db)
    result = await auth_service.refresh_tokens(
        data.refresh_token,
        ip_address=ip,
    )
    return RefreshResponse(**result)


@router.post(
    "/logout",
    response_model=SuccessResponse,
    summary="Logout",
    description="Logout the current user (client-side token invalidation).",
)
async def logout(
    current_user: ActiveUser,
) -> SuccessResponse:
    """
    Logout the current user.

    Note: This endpoint is mainly for audit purposes.
    Actual token invalidation should be done client-side.
    For full server-side invalidation, implement token blacklisting.
    """
    # In a production system, you would add the token to a blacklist here
    return SuccessResponse(message="Logged out successfully")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Current User",
    description="Get the current authenticated user's profile.",
)
async def get_current_user_profile(
    current_user: ActiveUser,
) -> UserResponse:
    """Get the current user's profile."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/change-password",
    response_model=SuccessResponse,
    summary="Change Password",
    description="Change the current user's password.",
)
async def change_password(
    data: PasswordChangeRequest,
    current_user: ActiveUser,
    db: DbSession,
    ip: ClientIP,
) -> SuccessResponse:
    """
    Change the current user's password.

    Requires the current password for verification.
    The new password must be different from the current password.
    """
    auth_service = AuthService(db)
    await auth_service.change_password(
        user_id=current_user.id,
        current_password=data.current_password,
        new_password=data.new_password,
        ip_address=ip,
    )
    return SuccessResponse(message="Password changed successfully")
