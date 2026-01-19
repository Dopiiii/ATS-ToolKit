"""ATS-Toolkit Core Module.

Provides core functionality including:
- Configuration management with .env support
- Structured logging with SQLite audit trail
- Custom exception hierarchy
- Base module class for toolkit modules
"""

# Error Handling
from src.core.error_handler import (
    APIKeyMissingError,
    AtsException,
    ConfigurationError,
    DependencyError,
    ErrorDetails,
    ExecutionError,
    ModuleNotFoundError,
    NetworkError,
    RateLimitError,
    ValidationError,
)

# Configuration
from src.core.config_manager import (
    AtsConfig,
    ConfigManager,
    get_config,
    init_config,
    reload_config,
)

# Logging
from src.core.logger import (
    LoggerMixin,
    configure_module_logger,
    get_logger,
    query_audit_logs,
    setup_logging,
)

# Base Module
from src.core.base_module import (
    AtsModule,
    ExecutionResult,
    ModuleCategory,
    ModuleSpec,
    OutputField,
    Parameter,
    ParameterType,
)

__all__ = [
    # Error Handling
    "AtsException",
    "ValidationError",
    "APIKeyMissingError",
    "ExecutionError",
    "ModuleNotFoundError",
    "ConfigurationError",
    "DependencyError",
    "NetworkError",
    "RateLimitError",
    "ErrorDetails",
    # Configuration
    "AtsConfig",
    "ConfigManager",
    "init_config",
    "get_config",
    "reload_config",
    # Logging
    "setup_logging",
    "get_logger",
    "configure_module_logger",
    "LoggerMixin",
    "query_audit_logs",
    # Base Module
    "AtsModule",
    "ModuleSpec",
    "ModuleCategory",
    "Parameter",
    "ParameterType",
    "OutputField",
    "ExecutionResult",
]

__version__ = "2.0.0"
