"""Module Registry for ATS-Toolkit."""
import asyncio
import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Any, Type
from collections import defaultdict

from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, ExecutionResult
from src.core.logger import get_logger
from src.core.error_handler import ModuleNotFoundError


class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, AtsModule] = {}
        self._specs: Dict[str, ModuleSpec] = {}
        self._by_category: Dict[ModuleCategory, List[str]] = defaultdict(list)
        self._by_tag: Dict[str, List[str]] = defaultdict(list)
        self._logger = get_logger("registry")

    @property
    def count(self) -> int:
        return len(self._modules)

    def __contains__(self, name: str) -> bool:
        return name in self._modules

    def discover(self, modules_path: Optional[Path] = None) -> int:
        if modules_path is None:
            modules_path = Path(__file__).parent
        count = 0
        for category_dir in modules_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("_"):
                continue
            for module_file in category_dir.glob("*.py"):
                if module_file.name.startswith("_"):
                    continue
                try:
                    count += self._load_module_file(module_file, category_dir.name)
                except Exception as e:
                    self._logger.warning("module_load_failed", file=str(module_file), error=str(e))
        self._logger.info("discovery_complete", total=count)
        return count

    def _load_module_file(self, file_path: Path, category: str) -> int:
        module_name = f"src.modules.{category}.{file_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            return 0
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        count = 0
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, AtsModule) and obj is not AtsModule and not inspect.isabstract(obj):
                try:
                    self._register_module(obj)
                    count += 1
                except:
                    pass
        return count

    def _register_module(self, module_class: Type[AtsModule]) -> None:
        instance = module_class()
        spec = instance.spec
        self._modules[spec.name] = instance
        self._specs[spec.name] = spec
        self._by_category[spec.category].append(spec.name)
        for tag in spec.tags:
            self._by_tag[tag].append(spec.name)

    def get(self, name: str) -> AtsModule:
        if name not in self._modules:
            raise ModuleNotFoundError(name)
        return self._modules[name]

    def get_spec(self, name: str) -> ModuleSpec:
        if name not in self._specs:
            raise ModuleNotFoundError(name)
        return self._specs[name]

    def list_modules(self, category: Optional[ModuleCategory] = None, tag: Optional[str] = None) -> List[ModuleSpec]:
        if category:
            names = self._by_category.get(category, [])
        elif tag:
            names = self._by_tag.get(tag, [])
        else:
            names = list(self._modules.keys())
        return [self._specs[name] for name in sorted(names)]

    def list_categories(self) -> Dict[ModuleCategory, int]:
        return {cat: len(names) for cat, names in self._by_category.items()}

    def search(self, query: str) -> List[ModuleSpec]:
        query = query.lower()
        results = []
        for name, spec in self._specs.items():
            if query in name.lower() or query in spec.description.lower() or any(query in t.lower() for t in spec.tags):
                results.append(spec)
        return results

    async def execute(self, name: str, config: Dict[str, Any], timeout: Optional[int] = None) -> ExecutionResult:
        module = self.get(name)
        try:
            if timeout:
                return await asyncio.wait_for(module.run(config), timeout=timeout)
            return await module.run(config)
        except asyncio.TimeoutError:
            return ExecutionResult(success=False, data={}, errors=[f"Timeout after {timeout}s"])
        except Exception as e:
            return ExecutionResult(success=False, data={}, errors=[str(e)])

_registry: Optional[ModuleRegistry] = None

def get_registry() -> ModuleRegistry:
    global _registry
    if _registry is None:
        _registry = ModuleRegistry()
    return _registry
