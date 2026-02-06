"""
Common schemas used across the API.
"""

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,  # Allow ORM model conversion
        populate_by_name=True,  # Allow alias population
        str_strip_whitespace=True,  # Strip whitespace from strings
    )


# =============================================================================
# Pagination
# =============================================================================


class PaginationParams(BaseModel):
    """Query parameters for pagination."""

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    per_page: int = Field(
        default=20, ge=1, le=100, description="Items per page (max 100)"
    )

    @property
    def offset(self) -> int:
        """Calculate offset for database query."""
        return (self.page - 1) * self.per_page

    @property
    def limit(self) -> int:
        """Limit for database query."""
        return self.per_page


class PaginationMeta(BaseModel):
    """Pagination metadata in response."""

    page: int = Field(description="Current page number")
    per_page: int = Field(description="Items per page")
    total_items: int = Field(description="Total number of items")
    total_pages: int = Field(description="Total number of pages")
    has_next: bool = Field(description="Whether there's a next page")
    has_prev: bool = Field(description="Whether there's a previous page")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    data: list[T]
    pagination: PaginationMeta


def create_pagination_meta(
    page: int, per_page: int, total_items: int
) -> PaginationMeta:
    """Create pagination metadata from query params and total count."""
    total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 0

    return PaginationMeta(
        page=page,
        per_page=per_page,
        total_items=total_items,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_prev=page > 1,
    )


# =============================================================================
# Standard Responses
# =============================================================================


class SuccessResponse(BaseModel):
    """Generic success response."""

    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[dict[str, Any]] = None


class ErrorDetail(BaseModel):
    """Error detail for validation errors."""

    field: str = Field(description="Field that caused the error")
    message: str = Field(description="Error message")
    code: Optional[str] = Field(default=None, description="Error code")


class ErrorResponse(BaseModel):
    """Standard error response format."""

    error: dict[str, Any] = Field(
        description="Error details",
        examples=[
            {
                "code": "validation_error",
                "message": "Validation failed",
                "details": {"errors": [{"field": "email", "message": "Invalid email"}]},
            }
        ],
    )


# =============================================================================
# Health Check
# =============================================================================


class HealthCheck(BaseModel):
    """Health check response."""

    status: str = Field(description="Service status", examples=["healthy", "degraded"])
    version: str = Field(description="API version")
    database: str = Field(description="Database status")
    redis: str = Field(description="Redis status")


class ServiceStatus(BaseModel):
    """Individual service status."""

    name: str
    status: str  # "up", "down", "degraded"
    latency_ms: Optional[float] = None
    message: Optional[str] = None
