"""
User management endpoints.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from src.api.deps import ActiveUser, AdminUser, ClientIP, DbSession
from src.models.user import UserRole
from src.schemas.common import PaginatedResponse, PaginationParams, SuccessResponse
from src.schemas.user import (
    APIKeyCreate,
    APIKeyCreated,
    APIKeyList,
    APIKeyResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from src.services.user import UserService

router = APIRouter()


# =============================================================================
# User CRUD (Admin only)
# =============================================================================


@router.get(
    "",
    response_model=PaginatedResponse[UserResponse],
    summary="List Users",
    description="List all users with pagination (admin only).",
)
async def list_users(
    admin: AdminUser,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    role: Optional[UserRole] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
) -> PaginatedResponse[UserResponse]:
    """
    List all users.

    Supports filtering by role and active status.
    Admin access required.
    """
    user_service = UserService(db)
    pagination = PaginationParams(page=page, per_page=per_page)

    result = await user_service.list_users(
        pagination=pagination,
        role=role,
        is_active=is_active,
    )

    return PaginatedResponse(
        data=[UserResponse.model_validate(u) for u in result["data"]],
        pagination=result["pagination"],
    )


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create User",
    description="Create a new user (admin only).",
)
async def create_user(
    data: UserCreate,
    admin: AdminUser,
    db: DbSession,
) -> UserResponse:
    """
    Create a new user.

    Admin can create users with any role.
    Users created by admin are automatically verified.
    """
    user_service = UserService(db)
    user = await user_service.create_user(data, created_by=admin.id)
    return UserResponse.model_validate(user)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User",
    description="Get a user by ID (admin only).",
)
async def get_user(
    user_id: str,
    admin: AdminUser,
    db: DbSession,
) -> UserResponse:
    """Get a specific user by ID."""
    user_service = UserService(db)
    user = await user_service.get_user_or_404(user_id)
    return UserResponse.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update User",
    description="Update a user (admin only).",
)
async def update_user(
    user_id: str,
    data: UserUpdate,
    admin: AdminUser,
    db: DbSession,
) -> UserResponse:
    """
    Update a user.

    Admin can update email, role, and active status.
    """
    user_service = UserService(db)
    user = await user_service.update_user(
        user_id=user_id,
        data=data,
        updated_by=admin.id,
    )
    return UserResponse.model_validate(user)


@router.delete(
    "/{user_id}",
    response_model=SuccessResponse,
    summary="Delete User",
    description="Delete a user (admin only).",
)
async def delete_user(
    user_id: str,
    admin: AdminUser,
    db: DbSession,
) -> SuccessResponse:
    """
    Delete a user.

    This permanently deletes the user and all their API keys.
    Admin cannot delete their own account.
    """
    user_service = UserService(db)
    await user_service.delete_user(user_id=user_id, deleted_by=admin.id)
    return SuccessResponse(message="User deleted successfully")


# =============================================================================
# API Keys (Current user)
# =============================================================================


@router.get(
    "/me/api-keys",
    response_model=APIKeyList,
    summary="List My API Keys",
    description="List all API keys for the current user.",
)
async def list_my_api_keys(
    current_user: ActiveUser,
    db: DbSession,
) -> APIKeyList:
    """List all API keys for the current user."""
    user_service = UserService(db)
    keys = await user_service.list_api_keys(current_user.id)
    return APIKeyList(
        keys=[APIKeyResponse.model_validate(k) for k in keys],
        total=len(keys),
    )


@router.post(
    "/me/api-keys",
    response_model=APIKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create API Key",
    description="Create a new API key.",
)
async def create_api_key(
    data: APIKeyCreate,
    current_user: ActiveUser,
    db: DbSession,
    ip: ClientIP,
) -> APIKeyCreated:
    """
    Create a new API key.

    The key is only shown once in the response.
    Store it securely - it cannot be retrieved later.
    """
    user_service = UserService(db)
    api_key, plain_key = await user_service.create_api_key(
        user_id=current_user.id,
        data=data,
        ip_address=ip,
    )

    response = APIKeyCreated.model_validate(api_key)
    response.key = plain_key
    return response


@router.delete(
    "/me/api-keys/{key_id}",
    response_model=SuccessResponse,
    summary="Delete API Key",
    description="Delete an API key.",
)
async def delete_api_key(
    key_id: str,
    current_user: ActiveUser,
    db: DbSession,
    ip: ClientIP,
) -> SuccessResponse:
    """Delete an API key."""
    user_service = UserService(db)
    await user_service.delete_api_key(
        key_id=key_id,
        user_id=current_user.id,
        ip_address=ip,
    )
    return SuccessResponse(message="API key deleted successfully")
