"""Custom exception hierarchy for ATS-Toolkit.

All toolkit-specific exceptions inherit from AtsException so they
can be caught with a single handler when needed.
"""


class AtsException(Exception):
    """Base exception for all ATS-Toolkit errors."""

    def __init__(self, message: str = "An ATS-Toolkit error occurred") -> None:
        self.message = message
        super().__init__(self.message)


class ValidationError(AtsException):
    """Raised when input validation fails."""

    def __init__(self, message: str = "Input validation failed") -> None:
        super().__init__(message)


class APIKeyMissingError(AtsException):
    """Raised when a required API key is not configured."""

    def __init__(self, service: str) -> None:
        self.service = service
        super().__init__(
            f"API key missing for service '{service}'. "
            f"Set {service.upper()}_API_KEY in your .env file."
        )


class ExecutionError(AtsException):
    """Raised when a module execution encounters an error."""

    def __init__(self, message: str = "Module execution failed") -> None:
        super().__init__(message)


class ModuleNotFoundError(AtsException):
    """Raised when a requested module is not found in the registry."""

    def __init__(self, module_name: str) -> None:
        self.module_name = module_name
        super().__init__(f"Module '{module_name}' not found in registry.")
