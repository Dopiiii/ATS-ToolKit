"""
ATS-Toolkit - Pipeline Engine
Asynchronous module orchestration and execution

Educational platform for authorized cybersecurity professionals.
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import json

from .module_registry import ModuleRegistry, ModuleInfo, ModuleStatus
from .exceptions import (
    PipelineExecutionError, ModuleNotFoundError,
    ConsentNotGivenError, InvalidTargetError
)
from .utils import print_info, print_success, print_error, print_warning


class ExecutionStatus(Enum):
    """Module execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleResult:
    """Individual module execution result"""
    module_id: str
    section: str
    status: ExecutionStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'module_id': self.module_id,
            'section': self.section,
            'status': self.status.value,
            'data': self.data,
            'error': self.error,
            'execution_time': self.execution_time,
            'timestamp': self.timestamp,
            'cached': self.cached
        }


@dataclass
class PipelineResult:
    """Complete pipeline execution result"""
    target: str
    modules_executed: int = 0
    modules_succeeded: int = 0
    modules_failed: int = 0
    total_time: float = 0.0
    results: List[ModuleResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'target': self.target,
            'summary': {
                'modules_executed': self.modules_executed,
                'modules_succeeded': self.modules_succeeded,
                'modules_failed': self.modules_failed,
                'total_time': self.total_time,
                'timestamp': self.timestamp
            },
            'results': [r.to_dict() for r in self.results],
            'metadata': self.metadata
        }


class PipelineEngine:
    """
    Orchestrates module execution with async support.
    Handles caching, consent verification, and result aggregation.
    """

    def __init__(self, registry: ModuleRegistry, consent_manager=None,
                 cache_manager=None, config: Optional[Dict] = None):
        """
        Initialize pipeline engine.

        Args:
            registry: Module registry instance
            consent_manager: Consent verification manager
            cache_manager: Result caching manager
            config: Additional configuration
        """
        self.registry = registry
        self.consent_manager = consent_manager
        self.cache_manager = cache_manager
        self.config = config or {}

    async def execute_module(self, section: str, module_id: str,
                            target: str, config: Optional[Dict] = None) -> ModuleResult:
        """
        Execute a single module.

        Args:
            section: Module section (osint, pentest, etc.)
            module_id: Module identifier
            target: Target to scan
            config: Module-specific configuration

        Returns:
            ModuleResult with execution data
        """
        start_time = time.time()
        module_config = {**(self.config or {}), **(config or {})}

        # Get module info
        module_info = self.registry.get_module(section, module_id)

        if not module_info:
            return ModuleResult(
                module_id=module_id,
                section=section,
                status=ExecutionStatus.FAILED,
                error=f"Module {section}/{module_id} not found",
                execution_time=time.time() - start_time
            )

        # Check if module is active
        if module_info.status != ModuleStatus.ACTIVE:
            return ModuleResult(
                module_id=module_id,
                section=section,
                status=ExecutionStatus.SKIPPED,
                error=f"Module status: {module_info.status.value}",
                execution_time=time.time() - start_time
            )

        # Check cache first
        if self.cache_manager and not module_config.get('no_cache'):
            cache_key = f"{section}:{module_id}:{target}"
            cached_result = self.cache_manager.get(cache_key)

            if cached_result:
                execution_time = time.time() - start_time
                return ModuleResult(
                    module_id=module_id,
                    section=section,
                    status=ExecutionStatus.SUCCESS,
                    data=cached_result,
                    execution_time=execution_time,
                    cached=True
                )

        # Execute module
        try:
            if module_config.get('verbose'):
                print_info(f"Executing {section}/{module_id} on {target}")

            result_data = await module_info.execute_func(target, module_config)

            execution_time = time.time() - start_time

            # Cache result
            if self.cache_manager and result_data.get('success'):
                cache_key = f"{section}:{module_id}:{target}"
                self.cache_manager.set(
                    key=cache_key,
                    value=result_data,
                    ttl=3600  # 1 hour default TTL
                )

            return ModuleResult(
                module_id=module_id,
                section=section,
                status=ExecutionStatus.SUCCESS if result_data.get('success') else ExecutionStatus.FAILED,
                data=result_data,
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time

            if module_config.get('verbose'):
                print_error(f"Module {section}/{module_id} failed: {e}")

            return ModuleResult(
                module_id=module_id,
                section=section,
                status=ExecutionStatus.FAILED,
                error=str(e),
                execution_time=execution_time
            )

    async def execute_pipeline(self, target: str, modules: List[tuple[str, str]],
                              config: Optional[Dict] = None) -> PipelineResult:
        """
        Execute multiple modules in sequence or parallel.

        Args:
            target: Target to scan
            modules: List of (section, module_id) tuples
            config: Pipeline configuration

        Returns:
            PipelineResult with all module results
        """
        start_time = time.time()
        pipeline_config = {**(self.config or {}), **(config or {})}

        result = PipelineResult(target=target)

        # Execution mode: sequential or parallel
        execution_mode = pipeline_config.get('execution_mode', 'sequential')

        if execution_mode == 'parallel':
            # Execute all modules concurrently
            tasks = [
                self.execute_module(section, module_id, target, pipeline_config)
                for section, module_id in modules
            ]
            module_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle exceptions from gather
            for i, res in enumerate(module_results):
                if isinstance(res, Exception):
                    section, module_id = modules[i]
                    res = ModuleResult(
                        module_id=module_id,
                        section=section,
                        status=ExecutionStatus.FAILED,
                        error=str(res)
                    )
                result.results.append(res)

        else:  # sequential
            for section, module_id in modules:
                module_result = await self.execute_module(
                    section, module_id, target, pipeline_config
                )
                result.results.append(module_result)

        # Calculate statistics
        result.total_time = time.time() - start_time
        result.modules_executed = len(result.results)
        result.modules_succeeded = sum(
            1 for r in result.results if r.status == ExecutionStatus.SUCCESS
        )
        result.modules_failed = sum(
            1 for r in result.results if r.status == ExecutionStatus.FAILED
        )

        return result

    def verify_consent(self, target: str, modules: List[tuple[str, str]],
                      consent_hash: str) -> bool:
        """
        Verify consent for pipeline execution.

        Args:
            target: Target to scan
            modules: List of (section, module_id) tuples
            consent_hash: Consent hash to verify

        Returns:
            True if consent is valid

        Raises:
            ConsentNotGivenError: If consent invalid
        """
        if not self.consent_manager:
            # No consent manager = assume consent given (for testing)
            if self.config.get('verbose'):
                print_warning("No consent manager - skipping verification")
            return True

        try:
            return self.consent_manager.verify_consent(consent_hash)
        except Exception as e:
            raise ConsentNotGivenError(f"Consent verification failed: {e}")

    def validate_target(self, target: str, target_type: str = "auto") -> bool:
        """
        Validate target format.

        Args:
            target: Target string (domain, IP, URL, etc.)
            target_type: Expected target type

        Returns:
            True if valid

        Raises:
            InvalidTargetError: If target format invalid
        """
        if not target or not target.strip():
            raise InvalidTargetError("Target cannot be empty")

        # Basic validation - can be extended
        if target_type == "domain":
            if not any(c.isalpha() for c in target):
                raise InvalidTargetError(f"Invalid domain: {target}")

        return True
