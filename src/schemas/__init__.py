"""
Pydantic schemas for API request/response validation.

Schemas are organized by resource:
- auth: Login, register, tokens
- user: User CRUD
- common: Shared schemas (pagination, responses)
"""

from src.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
)
from src.schemas.common import (
    ErrorDetail,
    ErrorResponse,
    PaginatedResponse,
    PaginationParams,
    SuccessResponse,
)
from src.schemas.user import (
    APIKeyCreate,
    APIKeyResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)

__all__ = [
    # Auth
    "LoginRequest",
    "LoginResponse",
    "RegisterRequest",
    "RefreshRequest",
    "RefreshResponse",
    # User
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "APIKeyCreate",
    "APIKeyResponse",
    # Common
    "PaginationParams",
    "PaginatedResponse",
    "SuccessResponse",
    "ErrorResponse",
    "ErrorDetail",
]
