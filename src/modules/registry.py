"""Module Registry for ATS-Toolkit.

Auto-discovers, loads, and manages all toolkit modules.
"""

import asyncio
import importlib
import inspect
import os
import sys
from pathlib import Path
from typing import Any, Optional

import structlog

from src.core.base_module import AtsModule, ModuleCategory, ModuleSpec


logger = structlog.get_logger(__name__)


class ModuleRegistry:
    """Registry for auto-discovering and managing toolkit modules.

    Singleton registry that:
    - Auto-discovers modules in src/modules/* subdirectories
    - Dynamically imports and instantiates module classes
    - Provides search, filtering, and execution capabilities
    - Handles errors gracefully
    """

    _instance: Optional["ModuleRegistry"] = None
    _initialized: bool = False

    def __init__(self) -> None:
        """Initialize the module registry.

        Note: Use get_registry() instead of directly instantiating.
        """
        if ModuleRegistry._initialized:
            return

        self._modules: dict[str, AtsModule] = {}
        self._specs: dict[str, ModuleSpec] = {}
        self._categories: dict[ModuleCategory, list[str]] = {}
        self._tags: dict[str, list[str]] = {}
        self._logger = logger

        ModuleRegistry._initialized = True

    def discover(self) -> None:
        """Auto-discover and load all modules from src/modules/* subdirectories.

        Scans for Python files in module category directories, imports them,
        and instantiates any AtsModule subclasses found.
        """
        self._logger.info("starting_module_discovery")

        # Get the modules directory path
        modules_dir = Path(__file__).parent

        if not modules_dir.exists():
            self._logger.error("modules_directory_not_found", path=str(modules_dir))
            return

        discovered_count = 0
        error_count = 0

        # Scan each subdirectory (category directory)
        for category_dir in modules_dir.iterdir():
            if not category_dir.is_dir():
                continue

            # Skip private directories and __pycache__
            if category_dir.name.startswith("_") or category_dir.name == "__pycache__":
                continue

            category_name = category_dir.name
            self._logger.debug("scanning_category", category=category_name)

            # Scan Python files in the category directory
            for module_file in category_dir.glob("*.py"):
                # Skip __init__.py files
                if module_file.name.startswith("_"):
                    continue

                module_name = module_file.stem

                try:
                    # Import the module
                    module_path = f"src.modules.{category_name}.{module_name}"
                    self._logger.debug(
                        "importing_module",
                        path=module_path,
                        file=str(module_file)
                    )

                    module = importlib.import_module(module_path)

                    # Find AtsModule subclasses in the module
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        # Check if it's an AtsModule subclass (but not AtsModule itself)
                        if (
                            issubclass(obj, AtsModule) and
                            obj is not AtsModule and
                            obj.__module__ == module_path
                        ):
                            try:
                                # Instantiate the module
                                instance = obj()
                                spec = instance.get_spec()

                                # Register the module
                                self._register_module(spec.name, instance, spec)
                                discovered_count += 1

                                self._logger.debug(
                                    "module_registered",
                                    name=spec.name,
                                    category=spec.category.value,
                                    class_name=name
                                )

                            except Exception as e:
                                error_count += 1
                                self._logger.error(
                                    "module_instantiation_failed",
                                    class_name=name,
                                    error=str(e),
                                    error_type=type(e).__name__
                                )

                except Exception as e:
                    error_count += 1
                    self._logger.error(
                        "module_import_failed",
                        module=module_name,
                        category=category_name,
                        error=str(e),
                        error_type=type(e).__name__
                    )

        self._logger.info(
            "module_discovery_complete",
            discovered=discovered_count,
            errors=error_count,
            total_modules=len(self._modules)
        )

    def _register_module(
        self,
        name: str,
        instance: AtsModule,
        spec: ModuleSpec
    ) -> None:
        """Register a module instance and its metadata.

        Args:
            name: Module name
            instance: Module instance
            spec: Module specification
        """
        # Store module instance and spec
        self._modules[name] = instance
        self._specs[name] = spec

        # Index by category
        if spec.category not in self._categories:
            self._categories[spec.category] = []
        self._categories[spec.category].append(name)

        # Index by tags
        for tag in spec.tags:
            if tag not in self._tags:
                self._tags[tag] = []
            self._tags[tag].append(name)

    def get_spec(self, name: str) -> Optional[ModuleSpec]:
        """Get module specification by name.

        Args:
            name: Module name

        Returns:
            ModuleSpec if found, None otherwise
        """
        return self._specs.get(name)

    def list_modules(
        self,
        category: Optional[str] = None,
        tag: Optional[str] = None
    ) -> list[ModuleSpec]:
        """List modules with optional filtering.

        Args:
            category: Filter by category (e.g., "osint", "pentest")
            tag: Filter by tag

        Returns:
            List of ModuleSpec objects matching the filters
        """
        modules = []

        if category:
            # Filter by category
            try:
                cat_enum = ModuleCategory(category.lower())
                module_names = self._categories.get(cat_enum, [])
                modules = [self._specs[name] for name in module_names]
            except ValueError:
                self._logger.warning("invalid_category", category=category)
                return []
        elif tag:
            # Filter by tag
            module_names = self._tags.get(tag.lower(), [])
            modules = [self._specs[name] for name in module_names]
        else:
            # Return all modules
            modules = list(self._specs.values())

        # Sort by name
        return sorted(modules, key=lambda x: x.name)

    def list_categories(self) -> list[str]:
        """List all available module categories.

        Returns:
            List of category names
        """
        return sorted([cat.value for cat in self._categories.keys()])

    async def execute(
        self,
        name: str,
        config: dict[str, Any],
        timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """Execute a module by name with optional timeout.

        Args:
            name: Module name
            config: Module configuration parameters
            timeout: Execution timeout in seconds (optional)

        Returns:
            ExecutionResult as dictionary

        Raises:
            ValueError: If module not found
            asyncio.TimeoutError: If execution times out
        """
        # Get module instance
        module = self._modules.get(name)
        if not module:
            self._logger.error("module_not_found", name=name)
            raise ValueError(f"Module not found: {name}")

        self._logger.info(
            "executing_module",
            name=name,
            config=config,
            timeout=timeout
        )

        try:
            # Execute with timeout if specified
            if timeout:
                result = await asyncio.wait_for(
                    module.run(config),
                    timeout=timeout
                )
            else:
                result = await module.run(config)

            # Convert ExecutionResult to dict
            result_dict = {
                "success": result.success,
                "data": result.data,
                "errors": result.errors,
                "warnings": result.warnings,
                "duration_ms": result.duration_ms,
                "module_name": result.module_name,
                "timestamp": result.timestamp,
            }

            self._logger.info(
                "module_execution_complete",
                name=name,
                success=result.success,
                duration_ms=result.duration_ms
            )

            return result_dict

        except asyncio.TimeoutError:
            self._logger.error(
                "module_execution_timeout",
                name=name,
                timeout=timeout
            )
            raise
        except Exception as e:
            self._logger.error(
                "module_execution_failed",
                name=name,
                error=str(e),
                error_type=type(e).__name__
            )
            raise

    def search(self, query: str) -> list[ModuleSpec]:
        """Search modules by name, description, or tags.

        Args:
            query: Search query string

        Returns:
            List of ModuleSpec objects matching the query
        """
        query_lower = query.lower()
        results = []

        for spec in self._specs.values():
            # Search in name
            if query_lower in spec.name.lower():
                results.append(spec)
                continue

            # Search in description
            if query_lower in spec.description.lower():
                results.append(spec)
                continue

            # Search in tags
            if any(query_lower in tag.lower() for tag in spec.tags):
                results.append(spec)
                continue

            # Search in category
            if query_lower in spec.category.value.lower():
                results.append(spec)
                continue

        # Sort by relevance (exact name matches first, then alphabetically)
        results.sort(key=lambda x: (
            x.name.lower() != query_lower,  # Exact matches first
            x.name.lower().startswith(query_lower) == False,  # Prefix matches second
            x.name.lower()  # Then alphabetically
        ))

        self._logger.debug("search_complete", query=query, results=len(results))

        return results

    def get_module_count(self) -> int:
        """Get total number of registered modules.

        Returns:
            Number of modules
        """
        return len(self._modules)

    def get_module_names(self) -> list[str]:
        """Get list of all module names.

        Returns:
            Sorted list of module names
        """
        return sorted(self._modules.keys())

    def has_module(self, name: str) -> bool:
        """Check if a module is registered.

        Args:
            name: Module name

        Returns:
            True if module exists, False otherwise
        """
        return name in self._modules

    def clear(self) -> None:
        """Clear all registered modules.

        Mainly useful for testing.
        """
        self._modules.clear()
        self._specs.clear()
        self._categories.clear()
        self._tags.clear()
        self._logger.info("registry_cleared")


# Singleton accessor
_registry_instance: Optional[ModuleRegistry] = None


def get_registry() -> ModuleRegistry:
    """Get the singleton ModuleRegistry instance.

    Creates the registry on first call and auto-discovers modules.

    Returns:
        ModuleRegistry singleton instance
    """
    global _registry_instance

    if _registry_instance is None:
        _registry_instance = ModuleRegistry()
        _registry_instance.discover()

    return _registry_instance
