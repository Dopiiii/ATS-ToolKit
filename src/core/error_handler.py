"""Custom exception classes for ATS-Toolkit.

All exceptions include error codes, messages, and remediation guidance.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ErrorDetails:
    """Structured error information."""

    code: str
    message: str
    remediation: str
    context: Optional[dict] = None


class AtsException(Exception):
    """Base exception for all ATS-Toolkit errors."""

    def __init__(
        self,
        code: str,
        message: str,
        remediation: str,
        context: Optional[dict] = None,
    ):
        self.code = code
        self.message = message
        self.remediation = remediation
        self.context = context or {}
        super().__init__(message)

    @property
    def details(self) -> ErrorDetails:
        """Get structured error details."""
        return ErrorDetails(
            code=self.code,
            message=self.message,
            remediation=self.remediation,
            context=self.context,
        )

    def __str__(self) -> str:
        """String representation with error code."""
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"{self.__class__.__name__}(code={self.code!r}, "
            f"message={self.message!r}, remediation={self.remediation!r})"
        )


class ValidationError(AtsException):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[str] = None,
        remediation: str = "Check input format and try again",
    ):
        context = {}
        if field:
            context["field"] = field
        if value:
            context["value"] = value

        super().__init__(
            code="VALIDATION_ERROR",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.field = field
        self.value = value


class APIKeyMissingError(AtsException):
    """Raised when a required API key is missing."""

    def __init__(
        self,
        service: str,
        env_var: str,
    ):
        message = f"API key for {service} is not configured"
        remediation = (
            f"Set the {env_var} environment variable in your .env file. "
            f"You can obtain an API key from the {service} service."
        )

        super().__init__(
            code="API_KEY_MISSING",
            message=message,
            remediation=remediation,
            context={"service": service, "env_var": env_var},
        )
        self.service = service
        self.env_var = env_var


class ExecutionError(AtsException):
    """Raised when module execution fails."""

    def __init__(
        self,
        message: str,
        module: Optional[str] = None,
        original_error: Optional[Exception] = None,
        remediation: str = "Check logs for details and retry",
    ):
        context = {}
        if module:
            context["module"] = module
        if original_error:
            context["original_error"] = str(original_error)
            context["error_type"] = type(original_error).__name__

        super().__init__(
            code="EXECUTION_ERROR",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.module = module
        self.original_error = original_error


class ModuleNotFoundError(AtsException):
    """Raised when a requested module is not found."""

    def __init__(
        self,
        module_name: str,
        available_modules: Optional[list[str]] = None,
    ):
        message = f"Module '{module_name}' not found"
        remediation = "Use 'python main.py list' to see available modules"

        context = {"module_name": module_name}
        if available_modules:
            context["available_modules"] = available_modules
            remediation += f". Available: {', '.join(available_modules[:5])}"
            if len(available_modules) > 5:
                remediation += f" and {len(available_modules) - 5} more"

        super().__init__(
            code="MODULE_NOT_FOUND",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.module_name = module_name
        self.available_modules = available_modules


class ConfigurationError(AtsException):
    """Raised when configuration is invalid or missing."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        remediation: str = "Check your configuration and .env file",
    ):
        context = {}
        if config_key:
            context["config_key"] = config_key

        super().__init__(
            code="CONFIG_ERROR",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.config_key = config_key


class DependencyError(AtsException):
    """Raised when a required dependency is missing or unavailable."""

    def __init__(
        self,
        dependency: str,
        message: Optional[str] = None,
        install_command: Optional[str] = None,
    ):
        if not message:
            message = f"Required dependency '{dependency}' is not available"

        remediation = f"Install {dependency}"
        if install_command:
            remediation = f"Run: {install_command}"

        super().__init__(
            code="DEPENDENCY_ERROR",
            message=message,
            remediation=remediation,
            context={"dependency": dependency},
        )
        self.dependency = dependency


class RateLimitError(AtsException):
    """Raised when API rate limit is exceeded."""

    def __init__(
        self,
        service: str,
        retry_after: Optional[int] = None,
    ):
        message = f"Rate limit exceeded for {service}"
        remediation = "Wait before retrying"

        context = {"service": service}
        if retry_after:
            context["retry_after_seconds"] = retry_after
            remediation = f"Wait {retry_after} seconds before retrying"

        super().__init__(
            code="RATE_LIMIT_ERROR",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.service = service
        self.retry_after = retry_after


class NetworkError(AtsException):
    """Raised when network operations fail."""

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        remediation: str = "Check network connection and try again",
    ):
        context = {}
        if url:
            context["url"] = url
        if status_code:
            context["status_code"] = status_code

        super().__init__(
            code="NETWORK_ERROR",
            message=message,
            remediation=remediation,
            context=context,
        )
        self.url = url
        self.status_code = status_code
