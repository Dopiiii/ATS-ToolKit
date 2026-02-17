"""ATS-Toolkit core infrastructure modules.

This package contains the foundational components:
- base_module: Abstract base class for all modules
- config_manager: Configuration management
- logger: Structured logging with structlog
- error_handler: Custom exception hierarchy
"""

from src.core.base_module import (
    AtsModule,
    ExecutionResult,
    ModuleCategory,
    ModuleSpec,
    OutputField,
    Parameter,
    ParameterType,
)
from src.core.config_manager import ConfigManager
from src.core.error_handler import (
    APIKeyMissingError,
    AtsException,
    ExecutionError,
    ModuleNotFoundError,
    ValidationError,
)
from src.core.logger import setup_logging

__all__ = [
    # Base module
    "AtsModule",
    "ExecutionResult",
    "ModuleCategory",
    "ModuleSpec",
    "OutputField",
    "Parameter",
    "ParameterType",
    # Config
    "ConfigManager",
    # Logging
    "setup_logging",
    # Exceptions
    "AtsException",
    "ValidationError",
    "APIKeyMissingError",
    "ExecutionError",
    "ModuleNotFoundError",
]
