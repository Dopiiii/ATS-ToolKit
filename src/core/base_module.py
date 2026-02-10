"""Base module class and specifications for ATS-Toolkit modules.

All toolkit modules inherit from AtsModule and implement the required methods.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import structlog


class ModuleCategory(Enum):
    """Module category classification."""

    OSINT = "osint"
    PENTEST = "pentest"
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    DEFENSE = "defense"
    FORENSICS = "forensics"
    CRYPTO = "crypto"
    SOCIAL = "social"
    WEB = "web"
    NETWORK = "network"
    WIRELESS = "wireless"
    CLOUD = "cloud"
    MOBILE = "mobile"
    RED_TEAM = "red_team"
    FUZZING = "fuzzing"
    ML_DETECTION = "ml_detection"
    MALWARE = "malware"
    DECEPTION = "deception"
    CONTINUOUS_PENTEST = "continuous_pentest"
    ADVANCED = "advanced"
    MISC = "misc"


class ParameterType(Enum):
    """Parameter type for validation."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    FLOAT = "float"
    LIST = "list"
    DICT = "dict"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    FILE = "file"
    CHOICE = "choice"


@dataclass
class Parameter:
    """Module parameter specification."""

    name: str
    type: ParameterType
    description: str
    required: bool = True
    default: Any = None
    choices: Optional[list[str]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None


@dataclass
class OutputField:
    """Module output field specification."""

    name: str
    type: str
    description: str


@dataclass
class ModuleSpec:
    """Module specification and metadata."""

    name: str
    category: ModuleCategory
    description: str
    version: str
    parameters: list[Parameter] = field(default_factory=list)
    outputs: list[OutputField] = field(default_factory=list)
    requires_api_key: bool = False
    api_key_service: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    author: str = "ATS-Toolkit"
    dangerous: bool = False


@dataclass
class ExecutionResult:
    """Result of module execution."""

    success: bool
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: int = 0
    module_name: str = ""
    timestamp: str = ""


class AtsModule(ABC):
    """Base class for all ATS-Toolkit modules.

    All modules must inherit from this class and implement:
    - get_spec(): Return module specification
    - validate_inputs(): Validate input parameters
    - execute(): Perform the module's main functionality
    """

    def __init__(self) -> None:
        """Initialize the module."""
        self._logger: Optional[structlog.stdlib.BoundLogger] = None
        self._spec: Optional[ModuleSpec] = None

    @property
    def logger(self) -> structlog.stdlib.BoundLogger:
        """Get logger instance for this module."""
        if self._logger is None:
            self._logger = structlog.get_logger(self.__class__.__name__)
        return self._logger

    @property
    def spec(self) -> ModuleSpec:
        """Get module specification."""
        if self._spec is None:
            self._spec = self.get_spec()
        return self._spec

    @abstractmethod
    def get_spec(self) -> ModuleSpec:
        """Return module specification.

        Returns:
            ModuleSpec with module metadata and parameters
        """
        pass

    @abstractmethod
    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        """Validate input parameters.

        Args:
            config: Input configuration dictionary

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass

    @abstractmethod
    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        """Execute the module's main functionality.

        Args:
            config: Input configuration dictionary

        Returns:
            Dictionary with execution results
        """
        pass

    async def run(self, config: dict[str, Any]) -> ExecutionResult:
        """Run the module with error handling and timing.

        Args:
            config: Input configuration dictionary

        Returns:
            ExecutionResult with success status, data, and errors
        """
        from datetime import datetime

        start_time = time.perf_counter()
        timestamp = datetime.utcnow().isoformat()
        errors: list[str] = []
        warnings: list[str] = []
        data: dict[str, Any] = {}

        try:
            # Validate inputs
            self.logger.info(
                "validating_inputs",
                module=self.spec.name,
                config=config,
            )

            is_valid, error_msg = self.validate_inputs(config)
            if not is_valid:
                errors.append(f"Validation failed: {error_msg}")
                return ExecutionResult(
                    success=False,
                    data={},
                    errors=errors,
                    warnings=warnings,
                    duration_ms=int((time.perf_counter() - start_time) * 1000),
                    module_name=self.spec.name,
                    timestamp=timestamp,
                )

            # Execute module
            self.logger.info(
                "executing_module",
                module=self.spec.name,
            )

            data = await self.execute(config)

            # Check for warnings in result
            if "warnings" in data:
                warnings.extend(data.pop("warnings"))

            duration_ms = int((time.perf_counter() - start_time) * 1000)

            self.logger.info(
                "module_completed",
                module=self.spec.name,
                duration_ms=duration_ms,
            )

            return ExecutionResult(
                success=True,
                data=data,
                errors=[],
                warnings=warnings,
                duration_ms=duration_ms,
                module_name=self.spec.name,
                timestamp=timestamp,
            )

        except Exception as e:
            duration_ms = int((time.perf_counter() - start_time) * 1000)

            self.logger.error(
                "module_failed",
                module=self.spec.name,
                error=str(e),
                error_type=type(e).__name__,
                duration_ms=duration_ms,
            )

            errors.append(f"{type(e).__name__}: {str(e)}")

            return ExecutionResult(
                success=False,
                data=data,
                errors=errors,
                warnings=warnings,
                duration_ms=duration_ms,
                module_name=self.spec.name,
                timestamp=timestamp,
            )

    def get_required_api_keys(self) -> list[str]:
        """Get list of required API key services.

        Returns:
            List of service names that require API keys
        """
        if self.spec.requires_api_key and self.spec.api_key_service:
            return [self.spec.api_key_service]
        return []

    def check_api_keys(self, config_manager: Any) -> tuple[bool, list[str]]:
        """Check if required API keys are available.

        Args:
            config_manager: ConfigManager instance

        Returns:
            Tuple of (all_keys_present, missing_services)
        """
        required = self.get_required_api_keys()
        if not required:
            return True, []

        missing = []
        for service in required:
            if not config_manager.config.has_api_key(service):
                missing.append(service)

        return len(missing) == 0, missing
