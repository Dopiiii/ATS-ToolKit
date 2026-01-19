"""
ATS-Toolkit - Module Registry
Dynamic module discovery and loading system

Educational platform for authorized cybersecurity professionals.
"""

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import sys

from .exceptions import ModuleNotFoundError, ModuleLoadError
from .utils import print_info, print_warning, print_error


class ModuleStatus(Enum):
    """Module availability status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    MISSING_DEPS = "missing_deps"


@dataclass
class ModuleInfo:
    """Module metadata"""
    id: str
    name: str
    description: str
    section: str  # osint, pentest, redteam, etc.
    version: str = "1.0.0"
    author: str = "ATS Team"
    requires: List[str] = field(default_factory=list)  # Python dependencies
    requires_tools: List[str] = field(default_factory=list)  # External tools (nmap, etc.)
    requires_api_keys: List[str] = field(default_factory=list)  # API keys needed
    status: ModuleStatus = ModuleStatus.ACTIVE
    file_path: Optional[Path] = None
    execute_func: Optional[Callable] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'section': self.section,
            'version': self.version,
            'author': self.author,
            'requires': self.requires,
            'requires_tools': self.requires_tools,
            'requires_api_keys': self.requires_api_keys,
            'status': self.status.value,
            'file_path': str(self.file_path) if self.file_path else None,
            'error_message': self.error_message
        }


class ModuleRegistry:
    """
    Central registry for all ATS modules.
    Handles dynamic discovery, loading, and execution.
    """

    def __init__(self, project_root: Path):
        """
        Initialize module registry.

        Args:
            project_root: Path to ATS-Toolkit root directory
        """
        self.project_root = project_root
        self.modules: Dict[str, Dict[str, ModuleInfo]] = {}
        self.sections = ['osint', 'pentest', 'redteam', 'forensics',
                        'ml_threat', 'fuzzing', 'deception', 'continuous']

        # Initialize empty sections
        for section in self.sections:
            self.modules[section] = {}

    def discover_modules(self, verbose: bool = False) -> int:
        """
        Scan project for available modules.

        Args:
            verbose: Print discovery progress

        Returns:
            Number of modules discovered
        """
        total_found = 0

        for section in self.sections:
            section_path = self.project_root / section / "modules"

            if not section_path.exists():
                if verbose:
                    print_warning(f"Section path not found: {section_path}")
                continue

            # Find all Python files (excluding __init__.py and __pycache__)
            module_files = [
                f for f in section_path.glob("*.py")
                if f.name != "__init__.py" and not f.name.startswith("_")
            ]

            for module_file in module_files:
                module_id = module_file.stem  # filename without .py

                try:
                    module_info = self._load_module_info(
                        section, module_id, module_file
                    )

                    if module_info:
                        self.modules[section][module_id] = module_info
                        total_found += 1

                        if verbose:
                            print_info(f"Loaded: {section}/{module_id}")

                except Exception as e:
                    if verbose:
                        print_error(f"Failed to load {section}/{module_id}: {e}")

                    # Register module with error status
                    self.modules[section][module_id] = ModuleInfo(
                        id=module_id,
                        name=module_id.replace('_', ' ').title(),
                        description="Module load failed",
                        section=section,
                        status=ModuleStatus.ERROR,
                        file_path=module_file,
                        error_message=str(e)
                    )

        return total_found

    def _load_module_info(self, section: str, module_id: str,
                         module_file: Path) -> Optional[ModuleInfo]:
        """
        Load module metadata and execute function.

        Args:
            section: Module section
            module_id: Module identifier
            module_file: Path to module file

        Returns:
            ModuleInfo or None if load fails
        """
        try:
            # Dynamic import
            spec = importlib.util.spec_from_file_location(
                f"{section}.modules.{module_id}",
                module_file
            )

            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Extract metadata
            metadata = getattr(module, 'MODULE_METADATA', {})

            # Find execute function
            execute_func = getattr(module, 'execute', None)

            if not execute_func or not callable(execute_func):
                raise ModuleLoadError(f"No 'execute' function found in {module_id}")

            # Check if execute is async
            if not inspect.iscoroutinefunction(execute_func):
                raise ModuleLoadError(f"'execute' must be async in {module_id}")

            # Create ModuleInfo
            return ModuleInfo(
                id=module_id,
                name=metadata.get('name', module_id.replace('_', ' ').title()),
                description=metadata.get('description', 'No description'),
                section=section,
                version=metadata.get('version', '1.0.0'),
                author=metadata.get('author', 'ATS Team'),
                requires=metadata.get('requires', []),
                requires_tools=metadata.get('requires_tools', []),
                requires_api_keys=metadata.get('requires_api_keys', []),
                status=ModuleStatus.ACTIVE,
                file_path=module_file,
                execute_func=execute_func
            )

        except Exception as e:
            raise ModuleLoadError(f"Failed to load {section}/{module_id}: {e}")

    def get_module(self, section: str, module_id: str) -> Optional[ModuleInfo]:
        """
        Get module by section and ID.

        Args:
            section: Module section
            module_id: Module identifier

        Returns:
            ModuleInfo or None if not found
        """
        return self.modules.get(section, {}).get(module_id)

    def list_modules(self, section: Optional[str] = None,
                    status_filter: Optional[ModuleStatus] = None) -> Dict[str, List[ModuleInfo]]:
        """
        List available modules.

        Args:
            section: Filter by section (None for all)
            status_filter: Filter by status (None for all)

        Returns:
            Dictionary of section -> list of modules
        """
        result = {}

        sections = [section] if section else self.sections

        for sec in sections:
            modules_list = list(self.modules.get(sec, {}).values())

            if status_filter:
                modules_list = [m for m in modules_list if m.status == status_filter]

            if modules_list:
                result[sec] = modules_list

        return result

    def get_module_count(self, section: Optional[str] = None) -> int:
        """
        Get total module count.

        Args:
            section: Specific section or None for all

        Returns:
            Number of modules
        """
        if section:
            return len(self.modules.get(section, {}))

        return sum(len(mods) for mods in self.modules.values())

    def validate_module_dependencies(self, module_info: ModuleInfo) -> tuple[bool, List[str]]:
        """
        Check if module dependencies are satisfied.

        Args:
            module_info: Module to validate

        Returns:
            (success, list of missing dependencies)
        """
        missing = []

        # Check Python packages
        for package in module_info.requires:
            try:
                importlib.import_module(package)
            except ImportError:
                missing.append(f"Python package: {package}")

        # Check external tools (simplified - could use shutil.which)
        # For now, just warn about missing tools

        return (len(missing) == 0, missing)

    def reload_module(self, section: str, module_id: str) -> bool:
        """
        Hot-reload a module (useful during development).

        Args:
            section: Module section
            module_id: Module identifier

        Returns:
            True if reload successful
        """
        module_file = self.project_root / section / "modules" / f"{module_id}.py"

        if not module_file.exists():
            return False

        try:
            module_info = self._load_module_info(section, module_id, module_file)

            if module_info:
                self.modules[section][module_id] = module_info
                return True

        except Exception:
            pass

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert registry to dictionary"""
        return {
            'sections': self.sections,
            'total_modules': self.get_module_count(),
            'modules': {
                section: {
                    mod_id: mod_info.to_dict()
                    for mod_id, mod_info in modules.items()
                }
                for section, modules in self.modules.items()
            }
        }
