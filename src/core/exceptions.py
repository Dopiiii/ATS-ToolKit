"""
Custom exception hierarchy for the OSINT Platform.

All exceptions extend APIError which includes:
- HTTP status code
- Error code (machine-readable)
- Human-readable message
- Optional details

These exceptions are caught by the global exception handler
and converted to consistent API error responses.
"""

from typing import Any, Optional


class APIError(Exception):
    """
    Base exception for all API errors.

    Attributes:
        status_code: HTTP status code to return
        code: Machine-readable error code
        message: Human-readable error message
        details: Additional error context
    """

    def __init__(
        self,
        message: str,
        code: str = "error",
        status_code: int = 500,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API response."""
        response = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            response["error"]["details"] = self.details
        return response


# =============================================================================
# Authentication & Authorization Errors (4xx)
# =============================================================================


class AuthenticationError(APIError):
    """Raised when authentication fails (invalid credentials, expired token)."""

    def __init__(
        self,
        message: str = "Authentication failed",
        code: str = "authentication_failed",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=401,
            details=details,
        )


class AuthorizationError(APIError):
    """Raised when user lacks permission for an action."""

    def __init__(
        self,
        message: str = "You don't have permission to perform this action",
        code: str = "forbidden",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=403,
            details=details,
        )


class InvalidTokenError(AuthenticationError):
    """Raised when a token is invalid or expired."""

    def __init__(
        self,
        message: str = "Invalid or expired token",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="invalid_token",
            details=details,
        )


# =============================================================================
# Resource Errors (4xx)
# =============================================================================


class NotFoundError(APIError):
    """Raised when a requested resource is not found."""

    def __init__(
        self,
        resource: str = "Resource",
        resource_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        message = f"{resource} not found"
        if resource_id:
            message = f"{resource} with ID '{resource_id}' not found"

        super().__init__(
            message=message,
            code="not_found",
            status_code=404,
            details=details,
        )


class ConflictError(APIError):
    """Raised when there's a conflict (e.g., duplicate resource)."""

    def __init__(
        self,
        message: str = "Resource already exists",
        code: str = "conflict",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=409,
            details=details,
        )


class ValidationError(APIError):
    """Raised when request validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        errors: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="validation_error",
            status_code=422,
            details={"errors": errors} if errors else None,
        )


# =============================================================================
# Rate Limiting Errors (429)
# =============================================================================


class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
    ) -> None:
        details = {}
        if retry_after:
            details["retry_after"] = retry_after

        super().__init__(
            message=message,
            code="rate_limit_exceeded",
            status_code=429,
            details=details if details else None,
        )


# =============================================================================
# External Service Errors (5xx)
# =============================================================================


class ExternalServiceError(APIError):
    """Raised when an external service call fails."""

    def __init__(
        self,
        service: str,
        message: str = "External service error",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=f"{service}: {message}",
            code="external_service_error",
            status_code=502,
            details={"service": service, **(details or {})},
        )


class DatabaseError(APIError):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str = "Database error",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="database_error",
            status_code=500,
            details=details,
        )


# =============================================================================
# Collection & Analysis Errors
# =============================================================================


class CollectionError(APIError):
    """Raised when a data collection operation fails."""

    def __init__(
        self,
        collector: str,
        message: str = "Collection failed",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=f"{collector}: {message}",
            code="collection_error",
            status_code=500,
            details={"collector": collector, **(details or {})},
        )


class APIKeyMissingError(APIError):
    """Raised when a required API key is not configured."""

    def __init__(
        self,
        service: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            message=f"API key for {service} is not configured",
            code="api_key_missing",
            status_code=503,
            details={"service": service, **(details or {})},
        )
