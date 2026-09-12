"""
Module System for SHADOWSCOPE
Handles module discovery, loading, execution, and management.
"""

import asyncio
import importlib
import inspect
import os
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import requests
import yaml
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass(init=False)
class ModuleResult:
    """Result from module execution.

    Accepts the legacy ``start_time``/``end_time`` keyword aliases (used
    by older modules) and normalizes them onto ``started_at`` /
    ``completed_at``. ``datetime`` values are converted to ISO strings.
    """
    target: str
    module: str
    data: dict[str, Any]
    status: str = "success"  # success, failed, partial
    error: str | None = None
    started_at: str = ""
    completed_at: str = ""

    def __init__(
        self,
        target: str,
        module: str,
        data: dict[str, Any] | None = None,
        status: str = "success",
        error: str | None = None,
        started_at: Any = None,
        completed_at: Any = None,
        start_time: Any = None,  # legacy alias of started_at
        end_time: Any = None,  # legacy alias of completed_at
    ) -> None:
        self.target = target
        self.module = module
        if data is None:
            data = {}
        self.data = data if isinstance(data, dict) else {"result": data}
        self.status = status
        self.error = error
        now = datetime.now().isoformat()
        self.started_at = self._as_iso(start_time if start_time is not None
                                        else started_at) or now
        self.completed_at = self._as_iso(end_time if end_time is not None
                                          else completed_at) or now

    @staticmethod
    def _as_iso(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @property
    def start_time(self) -> str:
        """Legacy alias for :attr:`started_at` (read/write)."""
        return self.started_at

    @start_time.setter
    def start_time(self, value: Any) -> None:
        self.started_at = self._as_iso(value)

    @property
    def end_time(self) -> str:
        """Legacy alias for :attr:`completed_at` (read/write)."""
        return self.completed_at

    @end_time.setter
    def end_time(self, value: Any) -> None:
        self.completed_at = self._as_iso(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "data": self.data,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at
        }


class ModuleConfig:
    """Base configuration for all SHADOWSCOPE modules.

    Every module ships its own ``@dataclass`` config (e.g.
    ``DNSBruteConfig``) inheriting from this class. The base deliberately
    stays a plain (non-dataclass) class so subclass field ordering can
    never break, while still providing dict conversion helpers and
    framework-wide defaults.
    """

    #: Framework-wide defaults. Subclasses may override any of these.
    timeout: int = 300
    max_retries: int = 3
    verify_ssl: bool = True
    user_agent: str | None = None
    proxy: str | None = None
    cache_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize this config to a plain dict."""
        if is_dataclass(self):
            return {f.name: getattr(self, f.name) for f in fields(self)}
        return dict(vars(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None = None) -> "ModuleConfig":
        """Build a config from a plain dict, ignoring unknown keys."""
        data = data or {}
        if is_dataclass(cls):
            known = {f.name for f in fields(cls)}
            kwargs = {k: v for k, v in data.items() if k in known}
            try:
                return cls(**kwargs)  # type: ignore[call-arg]
            except TypeError:
                pass
        try:
            instance = cls()  # type: ignore[call-arg]
        except TypeError:
            instance = cls.__new__(cls)
        for key, value in data.items():
            if not hasattr(instance, key):
                continue
            if callable(getattr(instance, key)):
                continue
            try:
                setattr(instance, key, value)
            except (AttributeError, TypeError):
                continue
        return instance


class BaseModule:
    """Base class for every SHADOWSCOPE module.

    Concrete modules declare ``MODULE_*`` class attributes, accept an
    optional config object in ``__init__`` and implement
    ``async execute(target, options)``. :meth:`run` adapts that to the
    executor interface, and :meth:`get_metadata` exposes the declaration
    to discovery, the CLI and storage.
    """

    MODULE_NAME: str = "base"
    MODULE_VERSION: str = "1.0"
    MODULE_AUTHOR: str = "SHADOWSCOPE"
    MODULE_CATEGORY: str = "recon"
    MODULE_DESCRIPTION: str = ""
    MODULE_TARGET_TYPES: list[Any] = []
    MODULE_DEPENDENCIES: list[str] = []
    MODULE_TIMEOUT: int = 300

    def __init__(self, config: Any | None = None) -> None:
        self.config = config if config is not None else ModuleConfig()
        self.console = Console()

    # -- lifecycle hooks -------------------------------------------------
    async def initialize(self) -> None:
        """Prepare resources (sessions, wordlists). Optional override."""
        return None

    async def cleanup(self) -> None:
        """Release resources. Optional override."""
        return None

    # -- executor interface ----------------------------------------------
    async def run(self, target: str, options: dict[str, Any] | None = None) -> Any:
        """Entry point used by :class:`ModuleExecutor`.

        Delegates to :meth:`execute`, which is what concrete modules
        implement. Modules may also override :meth:`run` directly.
        """
        executor = getattr(self, "execute", None)
        if callable(executor):
            return await executor(target, options or {})
        raise NotImplementedError(
            f"{self.__class__.__name__} implements neither run() nor execute()"
        )

    def validate_target(self, target: str) -> bool:
        """Return True when *target* is acceptable. Modules override this."""
        return bool(target and target.strip())

    @classmethod
    def get_metadata(cls) -> dict[str, Any]:
        """Return JSON-serializable metadata for discovery/CLI/storage."""
        target_types: list[str] = []
        for item in getattr(cls, "MODULE_TARGET_TYPES", []) or []:
            if isinstance(item, Enum):
                target_types.append(str(item.value))
            else:
                target_types.append(str(item))
        return {
            "name": getattr(cls, "MODULE_NAME", cls.__name__),
            "version": getattr(cls, "MODULE_VERSION", "1.0"),
            "author": getattr(cls, "MODULE_AUTHOR", ""),
            "description": getattr(cls, "MODULE_DESCRIPTION", ""),
            "category": getattr(cls, "MODULE_CATEGORY", "recon"),
            "target_types": target_types,
            "dependencies": list(getattr(cls, "MODULE_DEPENDENCIES", []) or []),
            "config_schema": {},
            "enabled": True,
            "is_async": True,
            "is_sandboxed": True,
            "timeout": int(getattr(cls, "MODULE_TIMEOUT", 300) or 300),
        }


@dataclass
class ModuleMetadata:
    """Module metadata from manifest"""
    name: str
    version: str = "1.0"
    author: str = ""
    description: str = ""
    category: str = "recon"
    target_types: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    is_async: bool = True
    is_sandboxed: bool = True
    timeout: int = 300  # seconds

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleMetadata":
        """Create from dictionary"""
        return cls(
            name=data.get('name', ''),
            version=data.get('version', '1.0'),
            author=data.get('author', ''),
            description=data.get('description', ''),
            category=data.get('category', 'recon'),
            target_types=data.get('target_types', []),
            dependencies=data.get('dependencies', []),
            config_schema=data.get('config_schema', {}),
            enabled=data.get('enabled', True),
            is_async=data.get('is_async', True),
            is_sandboxed=data.get('is_sandboxed', True),
            timeout=data.get('timeout', 300)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "category": self.category,
            "target_types": self.target_types,
            "dependencies": self.dependencies,
            "config_schema": self.config_schema,
            "enabled": self.enabled,
            "is_async": self.is_async,
            "is_sandboxed": self.is_sandboxed,
            "timeout": self.timeout
        }


class ModuleLoader:
    """Loads modules from various sources"""

    def __init__(self, config=None):
        from .config import config as global_config
        self.config = config or global_config
        self._loaded_modules: dict[str, type] = {}
        self._modules_dir = Path("~/.shadowscope/modules").expanduser()
        self._local_modules_dir = Path("./modules")
        self._registry_url = "https://raw.githubusercontent.com/mraaisa-afk/shadowscope-registry/main"

    def _get_module_path(self, module_name: str) -> Path | None:
        """Find module path"""
        # Check local modules directory
        local_path = self._local_modules_dir / module_name
        if local_path.exists():
            return local_path

        # Check user modules directory
        user_path = self._modules_dir / module_name
        if user_path.exists():
            return user_path

        return None

    def load_local_module(self, module_name: str) -> type | None:
        """Load a module from local filesystem"""
        module_path = self._get_module_path(module_name)

        if not module_path:
            console.print(f"[yellow]Module {module_name} not found in local directories[/yellow]")
            return None

        # Check if already loaded
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]

        try:
            # Add to Python path
            sys.path.insert(0, str(module_path.parent))

            # Import module
            module = importlib.import_module(f"{module_name}")

            # Store loaded module
            self._loaded_modules[module_name] = module

            console.print(f"[green]+[/green] Loaded local module: {module_name}")
            return module

        except Exception as e:
            console.print(f"[red]Error loading module {module_name}: {e}[/red]")
            return None
        finally:
            # Remove from Python path
            if module_path.parent in sys.path:
                sys.path.remove(str(module_path.parent))

    def load_module_from_package(self, module_name: str) -> type | None:
        """Load a module from installed Python package.

        Built-in modules live in category subpackages
        (``shadowscope.modules.<category>.<name>``), so after the direct
        import attempt we scan every category directory for a match.
        """
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]
        try:
            # Try a direct submodule import first (flat layout / tests).
            module = importlib.import_module(f"shadowscope.modules.{module_name}")
            if not hasattr(module, "__path__"):
                self._loaded_modules[module_name] = module
                console.print(f"[green]+[/green] Loaded package module: {module_name}")
                return module
        except ImportError:
            pass
        try:
            package = importlib.import_module("shadowscope.modules")
            package_dir = Path(str(package.__file__)).parent
            for category_dir in sorted(package_dir.iterdir()):
                if not category_dir.is_dir() or category_dir.name.startswith(("_", ".")):
                    continue
                if not (category_dir / f"{module_name}.py").exists():
                    continue
                full_name = f"shadowscope.modules.{category_dir.name}.{module_name}"
                try:
                    module = importlib.import_module(full_name)
                except ImportError:
                    continue
                self._loaded_modules[module_name] = module
                console.print(f"[green]+[/green] Loaded package module: {module_name}")
                return module
        except Exception as e:
            console.print(f"[yellow]Module {module_name} not found as package: {e}[/yellow]")
            return None
        console.print(f"[yellow]Module {module_name} not found as package[/yellow]")
        return None

    def load_module(self, module_name: str) -> type | None:
        """Try to load a module from any available source"""
        # Try local first
        module = self.load_local_module(module_name)
        if module:
            return module

        # Try package
        module = self.load_module_from_package(module_name)
        if module:
            return module

        # Try to fetch from registry
        if self.config.storage.encryption.get('enabled', True):
            module = self._fetch_from_registry(module_name)
            if module:
                return module

        return None

    def _fetch_from_registry(self, module_name: str) -> type | None:
        """Fetch and load module from registry"""
        try:
            # Get module manifest from registry
            manifest_url = f"{self._registry_url}/modules/{module_name}/manifest.yaml"
            response = requests.get(manifest_url, timeout=10)

            if response.status_code != 200:
                console.print(f"[yellow]Module {module_name} not found in registry[/yellow]")
                return None

            manifest = yaml.safe_load(response.text)

            # Download module zip
            zip_url = f"{self._registry_url}/modules/{module_name}/{module_name}.zip"
            response = requests.get(zip_url, timeout=30)

            if response.status_code != 200:
                console.print(f"[yellow]Could not download module {module_name}[/yellow]")
                return None

            # Save to user modules directory
            self._modules_dir.mkdir(parents=True, exist_ok=True)
            module_dir = self._modules_dir / module_name
            module_dir.mkdir(exist_ok=True)

            # Save manifest
            with open(module_dir / "manifest.yaml", 'w') as f:
                yaml.dump(manifest, f)

            # Extract zip
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
                tmp.write(response.content)
                tmp_path = tmp.name

            with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                zip_ref.extractall(module_dir)

            os.unlink(tmp_path)

            # Load the module
            sys.path.insert(0, str(self._modules_dir))
            try:
                module = importlib.import_module(f"{module_name}")
                self._loaded_modules[module_name] = module
                console.print(f"[green]+[/green] Downloaded and loaded module: {module_name}")
                return module
            except Exception as e:
                console.print(f"[red]Error loading downloaded module {module_name}: {e}[/red]")
                return None
            finally:
                if self._modules_dir in sys.path:
                    sys.path.remove(str(self._modules_dir))

        except Exception as e:
            console.print(f"[yellow]Could not fetch module {module_name} from registry: {e}[/yellow]")
            return None

    def get_loaded_modules(self) -> dict[str, type]:
        """Get all loaded modules"""
        return self._loaded_modules

    def unload_module(self, module_name: str) -> bool:
        """Unload a module"""
        if module_name in self._loaded_modules:
            del self._loaded_modules[module_name]
            console.print(f"[yellow]-[/yellow] Unloaded module: {module_name}")
            return True
        return False


class ModuleExecutor:
    """Executes modules with sandboxing support"""

    def __init__(self, config=None):
        from .cache import cache
        from .config import config as global_config
        from .proxy import proxy
        from .sandbox import sandbox
        from .storage import storage

        self.config = config or global_config
        self.sandbox = sandbox
        self.storage = storage
        self.cache = cache
        self.proxy = proxy
        self._running_modules: dict[str, asyncio.Task] = {}

    async def execute(self, module_name: str, target: str,
                      config: dict[str, Any] | None = None,
                      timeout: int | None = None,
                      no_sandbox: bool = False) -> ModuleResult:
        """Execute a module on a target"""
        from .modules import modules

        # Get module metadata from storage or auto-register from discovery
        module_info = self.storage.get_module(module_name)
        if not module_info:
            metadata = modules.get_module(module_name)
            if metadata:
                try:
                    self.storage.add_module(metadata)
                    module_info = self.storage.get_module(module_name)
                except Exception:
                    pass
                if not module_info:
                    module_info = metadata

        if not module_info:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=f"Module {module_name} not found"
            )

        # Check if module is enabled
        if not module_info.enabled:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=f"Module {module_name} is disabled"
            )

        # Get module class
        module = modules.loader.load_module(module_name)
        if not module:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=f"Could not load module {module_name}"
            )

        # Get the module class
        module_class = self._get_module_class(module)
        if not module_class:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=f"No valid module class found in {module_name}"
            )

        # Determine timeout (ModuleInfo predates per-module overrides,
        # so fall back gracefully when the attributes are absent).
        module_timeout = (timeout
                          or getattr(module_info, "timeout", None)
                          or self.config.sandbox.timeout)

        # Check if module should be sandboxed
        should_sandbox = (getattr(module_info, "is_sandboxed", True)
                          and self.config.sandbox.enabled
                          and not no_sandbox)

        try:
            if should_sandbox:
                # Execute in sandbox
                result = await self._execute_sandboxed(module_class, target, config, module_timeout)
            else:
                # Execute directly
                result = await self._execute_direct(module_class, target, config, module_timeout)

            # Store result in database
            target_obj = self.storage.get_target_by_value(target)
            if target_obj:
                from .storage import Result
                result_obj = Result(
                    target_id=target_obj.id,
                    module=module_name,
                    module_version=module_info.version,
                    data=result.data,
                    status=result.status,
                    error=result.error,
                    started_at=result.started_at,
                    completed_at=result.completed_at
                )
                self.storage.add_result(result_obj)

            return result

        except asyncio.TimeoutError:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=f"Module execution timed out after {module_timeout} seconds"
            )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=module_name,
                data={},
                status="failed",
                error=str(e)
            )

    def _get_module_class(self, module) -> type | None:
        """Find the module class in a module.

        Only classes actually *defined* in the module file qualify. This
        keeps helper/base classes imported from elsewhere (e.g.
        ``BaseModule`` itself) from shadowing the real module class,
        while remaining compatible with duck-typed test modules.
        """
        owner = getattr(module, "__name__", None)
        for attr in dir(module):
            try:
                obj = getattr(module, attr)
            except Exception:
                continue
            if not (inspect.isclass(obj) and self._is_module_class(obj)):
                continue
            if obj is BaseModule:
                continue
            if owner and getattr(obj, "__module__", None) not in (None, owner):
                continue
            return obj
        return None

    def _is_module_class(self, cls: type) -> bool:
        """Check if a class is a valid module class"""
        # Check if it has the required methods
        required_methods = ['run', 'get_metadata']
        return all(hasattr(cls, method) for method in required_methods)

    async def _execute_direct(self, module_class: type, target: str,
                              config: dict[str, Any] | None,
                              timeout: int) -> ModuleResult:
        """Execute module directly (not sandboxed)"""
        try:
            # Built-in modules construct with zero args and own a dataclass
            # config; dict-style overrides (e.g. from `--config '{...}'`)
            # are overlaid onto known fields only.
            instance = module_class()
            if config and isinstance(config, dict):
                module_config = getattr(instance, "config", None)
                if is_dataclass(module_config):
                    known = {f.name for f in fields(module_config)}
                    for key, value in config.items():
                        if key in known:
                            try:
                                setattr(module_config, key, value)
                            except (AttributeError, TypeError):
                                continue

            # Execute with timeout
            raw = await asyncio.wait_for(
                instance.run(target),
                timeout=timeout
            )

            # Modules may return a ModuleResult directly or a plain dict.
            if isinstance(raw, ModuleResult):
                if raw.status == "error":
                    raw.status = "failed"  # normalize legacy status
                return raw
            data = raw if isinstance(raw, dict) else {"result": raw}
            return ModuleResult(
                target=target,
                module=instance.__class__.__name__,
                data=data,
                status="success"
            )

        except asyncio.TimeoutError:
            raise
        except Exception as e:
            raise Exception(f"Module execution failed: {str(e)}")

    async def _execute_sandboxed(self, module_class: type, target: str,
                                  config: dict[str, Any] | None,
                                  timeout: int) -> ModuleResult:
        """Execute module in sandbox"""
        # Create a temporary directory for the module
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Copy module files to temp directory
            module_file = inspect.getfile(module_class)
            if os.path.exists(module_file):
                shutil.copy2(module_file, tmpdir / os.path.basename(module_file))

            # Create sandbox config
            sandbox_config = {
                "timeout": timeout,
                "cpu_limit": self.config.sandbox.cpu_limit,
                "memory_limit": self.config.sandbox.memory_limit,
                "network_restrictions": self.config.sandbox.network_restrictions,
                "blocked_domains": self.config.sandbox.blocked_domains
            }

            # Execute in sandbox
            result = await self.sandbox.execute(
                module_class.__name__,
                target,
                config=config,
                sandbox_config=sandbox_config
            )

            return result

    async def execute_batch(self, module_name: str, targets: list[str],
                           config: dict[str, Any] | None = None,
                           max_concurrency: int | None = None) -> list[ModuleResult]:
        """Execute a module on multiple targets concurrently"""
        max_concurrency = max_concurrency or self.config.performance.max_concurrency

        semaphore = asyncio.Semaphore(max_concurrency)
        tasks = []

        async def execute_with_semaphore(target):
            async with semaphore:
                return await self.execute(module_name, target, config)

        for target in targets:
            tasks.append(execute_with_semaphore(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        final_results = []
        for result in results:
            if isinstance(result, Exception):
                # Find the target that caused this
                # This is a bit hacky, but we'll assume the error is for the current target
                final_results.append(ModuleResult(
                    target="",
                    module=module_name,
                    data={},
                    status="failed",
                    error=str(result)
                ))
            else:
                final_results.append(result)

        return final_results

    def cancel(self, module_name: str, target: str) -> bool:
        """Cancel a running module execution"""
        key = f"{module_name}:{target}"
        if key in self._running_modules:
            task = self._running_modules.pop(key)
            task.cancel()
            console.print(f"[yellow]![/yellow] Cancelled module {module_name} on {target}")
            return True
        return False


class ModuleManager:
    """Manages all aspects of modules"""

    def __init__(self, config=None):
        from .config import config as global_config
        from .storage import storage

        self.config = config or global_config
        self.storage = storage
        self.loader = ModuleLoader(config)
        self.executor = ModuleExecutor(config)
        self._discovered_modules: dict[str, ModuleMetadata] = {}

    def discover_modules(self) -> dict[str, ModuleMetadata]:
        """Discover all available modules"""
        modules = {}

        # Discover local modules
        local_modules = self._discover_local_modules()
        modules.update(local_modules)

        # Discover package modules
        package_modules = self._discover_package_modules()
        modules.update(package_modules)

        # Discover from registry (if enabled)
        if self.config.storage.encryption.get('enabled', True):
            registry_modules = self._discover_registry_modules()
            modules.update(registry_modules)

        self._discovered_modules = modules

        # Auto-register discovered built-ins into storage
        for name, meta in modules.items():
            if not self.storage.get_module(name):
                try:
                    self.storage.add_module(meta)
                except Exception:
                    pass

        return modules

    def _discover_local_modules(self) -> dict[str, ModuleMetadata]:
        """Discover modules in local directories"""
        modules = {}

        # Check local modules directory
        for modules_dir in [self.loader._local_modules_dir, self.loader._modules_dir]:
            if modules_dir.exists():
                for item in modules_dir.iterdir():
                    if item.is_dir():
                        manifest_path = item / "manifest.yaml"
                        if manifest_path.exists():
                            try:
                                with open(manifest_path) as f:
                                    manifest = yaml.safe_load(f)

                                metadata = ModuleMetadata.from_dict(manifest)
                                modules[metadata.name] = metadata
                            except Exception as e:
                                console.print(f"[yellow]Error loading manifest for {item.name}: {e}[/yellow]")

        return modules

    def _discover_package_modules(self) -> dict[str, ModuleMetadata]:
        """Discover modules in Python packages.

        Built-in modules live in category subpackages
        (``shadowscope.modules.<category>/<name>.py``). Every module file
        is imported and its metadata read from the module class, so
        ``module list`` always reflects the real codebase.
        """
        modules = {}

        try:
            modules_package = importlib.import_module("shadowscope.modules")
            modules_dir = Path(str(modules_package.__file__)).parent

            for category_dir in sorted(modules_dir.iterdir()):
                if not category_dir.is_dir() or category_dir.name.startswith(("_", ".")):
                    continue
                for module_file in sorted(category_dir.glob("*.py")):
                    if module_file.name.startswith("_"):
                        continue
                    full_name = f"shadowscope.modules.{category_dir.name}.{module_file.stem}"
                    try:
                        module = importlib.import_module(full_name)
                    except Exception as e:
                        console.print(f"[yellow]Could not import {full_name}: {e}[/yellow]")
                        continue
                    module_class = self.executor._get_module_class(module)
                    if not module_class:
                        continue
                    try:
                        meta = module_class.get_metadata()
                        if isinstance(meta, ModuleMetadata):
                            metadata = meta
                        else:
                            metadata = ModuleMetadata.from_dict(dict(meta))
                    except Exception:
                        metadata = ModuleMetadata(
                            name=module_file.stem,
                            description=(module.__doc__ or "").strip().splitlines()[0]
                            if (module.__doc__ or "").strip() else "",
                            category=category_dir.name,
                            target_types=[],
                            version="1.0"
                        )
                    modules[metadata.name] = metadata
        except Exception as e:
            console.print(f"[yellow]Error discovering package modules: {e}[/yellow]")

        return modules

    def _infer_metadata_from_module(self, module_name: str) -> ModuleMetadata | None:
        """Infer module metadata from module code"""
        try:
            module = self.loader.load_module_from_package(module_name)
            if module:
                # Look for module class
                module_class = self.executor._get_module_class(module)
                if module_class:
                    # Get metadata from class
                    if hasattr(module_class, 'get_metadata'):
                        metadata = module_class.get_metadata()
                        if isinstance(metadata, dict):
                            return ModuleMetadata.from_dict(metadata)

                    # Create basic metadata
                    return ModuleMetadata(
                        name=module_name,
                        description=module.__doc__ or "",
                        category="recon",
                        target_types=[],
                        version="1.0"
                    )
        except Exception:
            pass
        return None

    def _discover_registry_modules(self) -> dict[str, ModuleMetadata]:
        """Discover modules from registry"""
        modules = {}

        try:
            # Get modules list from registry
            response = requests.get(f"{self.loader._registry_url}/modules.json", timeout=10)

            if response.status_code == 200:
                registry_modules = response.json()
                for name, metadata in registry_modules.items():
                    modules[name] = ModuleMetadata.from_dict(metadata)
        except Exception as e:
            console.print(f"[yellow]Could not fetch registry modules: {e}[/yellow]")

        return modules

    def get_module(self, module_name: str) -> ModuleMetadata | None:
        """Get module metadata"""
        # Check storage first
        stored = self.storage.get_module(module_name)
        if stored:
            return ModuleMetadata.from_dict(stored.to_dict())

        # Check discovered modules
        if module_name in self._discovered_modules:
            meta = self._discovered_modules[module_name]
            try:
                self.storage.add_module(meta)
            except Exception:
                pass
            return meta

        # Try to discover
        self.discover_modules()
        meta = self._discovered_modules.get(module_name)
        if meta:
            try:
                self.storage.add_module(meta)
            except Exception:
                pass
        return meta

    def get_modules_by_category(self, category: str) -> list[ModuleMetadata]:
        """Get all modules in a category"""
        modules = []
        for metadata in self._discovered_modules.values():
            if metadata.category == category:
                modules.append(metadata)
        return sorted(modules, key=lambda x: x.name)

    def get_modules_by_target_type(self, target_type: str) -> list[ModuleMetadata]:
        """Get all modules that support a target type"""
        modules = []
        for metadata in self._discovered_modules.values():
            if target_type in metadata.target_types or not metadata.target_types:
                modules.append(metadata)
        return sorted(modules, key=lambda x: x.name)

    def install_module(self, module_name: str, source: str = "registry") -> bool:
        """Install a module from a source"""
        if source == "registry":
            # Download from registry
            try:
                # Get manifest
                manifest_url = f"{self.loader._registry_url}/modules/{module_name}/manifest.yaml"
                response = requests.get(manifest_url, timeout=10)

                if response.status_code != 200:
                    console.print(f"[red]Module {module_name} not found in registry[/red]")
                    return False

                manifest = yaml.safe_load(response.text)

                # Download zip
                zip_url = f"{self.loader._registry_url}/modules/{module_name}/{module_name}.zip"
                response = requests.get(zip_url, timeout=30)

                if response.status_code != 200:
                    console.print(f"[red]Could not download module {module_name}[/red]")
                    return False

                # Save to user modules directory
                self.loader._modules_dir.mkdir(parents=True, exist_ok=True)
                module_dir = self.loader._modules_dir / module_name
                module_dir.mkdir(exist_ok=True)

                # Save manifest
                with open(module_dir / "manifest.yaml", 'w') as f:
                    yaml.dump(manifest, f)

                # Extract zip
                with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
                    tmp.write(response.content)
                    tmp_path = tmp.name

                with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                    zip_ref.extractall(module_dir)

                os.unlink(tmp_path)

                # Register in storage
                metadata = ModuleMetadata.from_dict(manifest)
                self.storage.add_module(metadata)

                console.print(f"[green]+[/green] Installed module: {module_name}")
                return True

            except Exception as e:
                console.print(f"[red]Error installing module {module_name}: {e}[/red]")
                return False

        elif source == "local":
            # Install from local directory
            local_path = self.loader._local_modules_dir / module_name
            if not local_path.exists():
                console.print(f"[red]Local module {module_name} not found[/red]")
                return False

            # Copy to user modules directory
            user_path = self.loader._modules_dir / module_name
            if user_path.exists():
                shutil.rmtree(user_path)

            shutil.copytree(local_path, user_path)

            # Load manifest
            manifest_path = user_path / "manifest.yaml"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = yaml.safe_load(f)

                metadata = ModuleMetadata.from_dict(manifest)
                self.storage.add_module(metadata)

                console.print(f"[green]+[/green] Installed local module: {module_name}")
                return True

        return False

    def uninstall_module(self, module_name: str) -> bool:
        """Uninstall a module"""
        # Remove from user modules directory
        user_path = self.loader._modules_dir / module_name
        if user_path.exists():
            shutil.rmtree(user_path)

        # Remove from storage
        self.storage.delete_module(module_name)

        # Unload from memory
        self.loader.unload_module(module_name)

        console.print(f"[yellow]-[/yellow] Uninstalled module: {module_name}")
        return True

    def enable_module(self, module_name: str) -> bool:
        """Enable a module"""
        module_info = self.storage.get_module(module_name)
        if module_info:
            module_info.enabled = True
            self.storage.add_module(module_info)
            console.print(f"[green]+[/green] Enabled module: {module_name}")
            return True
        return False

    def disable_module(self, module_name: str) -> bool:
        """Disable a module"""
        module_info = self.storage.get_module(module_name)
        if module_info:
            module_info.enabled = False
            self.storage.add_module(module_info)
            console.print(f"[yellow]-[/yellow] Disabled module: {module_name}")
            return True
        return False

    def update_module(self, module_name: str) -> bool:
        """Update a module to the latest version"""
        # First uninstall
        self.uninstall_module(module_name)

        # Then reinstall
        return self.install_module(module_name, "registry")

    def list_modules(self, show_disabled: bool = False) -> list[ModuleMetadata]:
        """List all installed modules"""
        modules = []

        stored_modules = self.storage.get_all_modules()
        for stored in stored_modules:
            metadata = ModuleMetadata.from_dict(stored.to_dict())
            if show_disabled or metadata.enabled:
                modules.append(metadata)

        return sorted(modules, key=lambda x: x.name)

    def display_modules_table(self, category: str | None = None,
                              show_disabled: bool = False):
        """Display modules in a rich table"""
        modules = self.list_modules(show_disabled=show_disabled)

        if category:
            modules = [m for m in modules if m.category == category]

        table = Table(title="Available Modules", show_header=True, header_style="bold blue")
        table.add_column("Name", style="green")
        table.add_column("Version", style="dim")
        table.add_column("Category", style="cyan")
        table.add_column("Target Types", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Description", style="white")

        for module in modules:
            status = "[green]enabled[/green]" if module.enabled else "[red]disabled[/red]"
            target_types = ", ".join(module.target_types) if module.target_types else "all"
            description = module.description[:50] + "..." if len(module.description) > 50 else module.description

            table.add_row(
                module.name,
                module.version,
                module.category,
                target_types,
                status,
                description
            )

        console.print(table)
        console.print(f"[dim]Total: {len(modules)} modules[/dim]")


# Initialize module manager
modules = ModuleManager()
