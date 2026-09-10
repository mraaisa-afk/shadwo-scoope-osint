"""
Module System for SHADOWSCOPE
Handles module discovery, loading, execution, and management.
"""

import os
import sys
import json
import yaml
import importlib
import inspect
import asyncio
import subprocess
import tempfile
import shutil
import hashlib
import base64
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import threading
import zipfile
import requests

console = Console()


@dataclass
class ModuleResult:
    """Result from module execution"""
    target: str
    module: str
    data: Dict[str, Any]
    status: str = "success"  # success, failed, partial
    error: Optional[str] = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "data": self.data,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at
        }


@dataclass
class ModuleMetadata:
    """Module metadata from manifest"""
    name: str
    version: str = "1.0"
    author: str = ""
    description: str = ""
    category: str = "recon"
    target_types: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    is_async: bool = True
    is_sandboxed: bool = True
    timeout: int = 300  # seconds
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleMetadata":
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
    
    def to_dict(self) -> Dict[str, Any]:
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
        self._loaded_modules: Dict[str, Type] = {}
        self._modules_dir = Path("~/.shadowscope/modules").expanduser()
        self._local_modules_dir = Path("./modules")
        self._registry_url = "https://raw.githubusercontent.com/mraaisa-afk/shadowscope-registry/main"
    
    def _get_module_path(self, module_name: str) -> Optional[Path]:
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
    
    def load_local_module(self, module_name: str) -> Optional[Type]:
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
    
    def load_module_from_package(self, module_name: str) -> Optional[Type]:
        """Load a module from installed Python package"""
        try:
            # Try to import as Python package
            module = importlib.import_module(f"shadowscope.modules.{module_name}")
            self._loaded_modules[module_name] = module
            console.print(f"[green]+[/green] Loaded package module: {module_name}")
            return module
        except ImportError as e:
            console.print(f"[yellow]Module {module_name} not found as package: {e}[/yellow]")
            return None
    
    def load_module(self, module_name: str) -> Optional[Type]:
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
    
    def _fetch_from_registry(self, module_name: str) -> Optional[Type]:
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
    
    def get_loaded_modules(self) -> Dict[str, Type]:
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
        from .config import config as global_config
        from .sandbox import sandbox
        from .storage import storage
        from .cache import cache
        from .proxy import proxy
        
        self.config = config or global_config
        self.sandbox = sandbox
        self.storage = storage
        self.cache = cache
        self.proxy = proxy
        self._running_modules: Dict[str, asyncio.Task] = {}
    
    async def execute(self, module_name: str, target: str, 
                      config: Optional[Dict[str, Any]] = None, 
                      timeout: Optional[int] = None) -> ModuleResult:
        """Execute a module on a target"""
        from .modules import modules
        
        # Get module metadata
        module_info = self.storage.get_module(module_name)
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
        
        # Determine timeout
        module_timeout = timeout or module_info.timeout or self.config.sandbox.timeout
        
        # Check if module should be sandboxed
        should_sandbox = module_info.is_sandboxed and self.config.sandbox.enabled
        
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
    
    def _get_module_class(self, module) -> Optional[Type]:
        """Find the module class in a module"""
        # Look for common class names
        for attr in dir(module):
            obj = getattr(module, attr)
            if inspect.isclass(obj) and self._is_module_class(obj):
                return obj
        return None
    
    def _is_module_class(self, cls: Type) -> bool:
        """Check if a class is a valid module class"""
        # Check if it has the required methods
        required_methods = ['run', 'get_metadata']
        return all(hasattr(cls, method) for method in required_methods)
    
    async def _execute_direct(self, module_class: Type, target: str, 
                              config: Optional[Dict[str, Any]], 
                              timeout: int) -> ModuleResult:
        """Execute module directly (not sandboxed)"""
        try:
            # Create instance
            instance = module_class(config=config)
            
            # Execute with timeout
            result = await asyncio.wait_for(
                instance.run(target),
                timeout=timeout
            )
            
            return ModuleResult(
                target=target,
                module=instance.__class__.__name__,
                data=result,
                status="success"
            )
            
        except asyncio.TimeoutError:
            raise
        except Exception as e:
            raise Exception(f"Module execution failed: {str(e)}")
    
    async def _execute_sandboxed(self, module_class: Type, target: str,
                                  config: Optional[Dict[str, Any]],
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
    
    async def execute_batch(self, module_name: str, targets: List[str],
                           config: Optional[Dict[str, Any]] = None,
                           max_concurrency: Optional[int] = None) -> List[ModuleResult]:
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
        self._discovered_modules: Dict[str, ModuleMetadata] = {}
    
    def discover_modules(self) -> Dict[str, ModuleMetadata]:
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
        return modules
    
    def _discover_local_modules(self) -> Dict[str, ModuleMetadata]:
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
                                with open(manifest_path, 'r') as f:
                                    manifest = yaml.safe_load(f)
                                
                                metadata = ModuleMetadata.from_dict(manifest)
                                modules[metadata.name] = metadata
                            except Exception as e:
                                console.print(f"[yellow]Error loading manifest for {item.name}: {e}[/yellow]")
        
        return modules
    
    def _discover_package_modules(self) -> Dict[str, ModuleMetadata]:
        """Discover modules in Python packages"""
        modules = {}
        
        # List all modules in shadowscope.modules package
        try:
            modules_package = importlib.import_module("shadowscope.modules")
            modules_dir = Path(modules_package.__file__).parent
            
            for item in modules_dir.iterdir():
                if item.is_dir() and not item.name.startswith('_'):
                    manifest_path = item / "manifest.yaml"
                    if manifest_path.exists():
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest = yaml.safe_load(f)
                            
                            metadata = ModuleMetadata.from_dict(manifest)
                            modules[metadata.name] = metadata
                        except Exception as e:
                            console.print(f"[yellow]Error loading manifest for {item.name}: {e}[/yellow]")
                    else:
                        # Try to infer metadata from module
                        module_name = item.name
                        metadata = self._infer_metadata_from_module(module_name)
                        if metadata:
                            modules[module_name] = metadata
        except Exception as e:
            console.print(f"[yellow]Error discovering package modules: {e}[/yellow]")
        
        return modules
    
    def _infer_metadata_from_module(self, module_name: str) -> Optional[ModuleMetadata]:
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
    
    def _discover_registry_modules(self) -> Dict[str, ModuleMetadata]:
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
    
    def get_module(self, module_name: str) -> Optional[ModuleMetadata]:
        """Get module metadata"""
        # Check storage first
        stored = self.storage.get_module(module_name)
        if stored:
            return ModuleMetadata.from_dict(stored.to_dict())
        
        # Check discovered modules
        if module_name in self._discovered_modules:
            return self._discovered_modules[module_name]
        
        # Try to discover
        self.discover_modules()
        return self._discovered_modules.get(module_name)
    
    def get_modules_by_category(self, category: str) -> List[ModuleMetadata]:
        """Get all modules in a category"""
        modules = []
        for metadata in self._discovered_modules.values():
            if metadata.category == category:
                modules.append(metadata)
        return sorted(modules, key=lambda x: x.name)
    
    def get_modules_by_target_type(self, target_type: str) -> List[ModuleMetadata]:
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
                with open(manifest_path, 'r') as f:
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
    
    def list_modules(self, show_disabled: bool = False) -> List[ModuleMetadata]:
        """List all installed modules"""
        modules = []
        
        stored_modules = self.storage.get_all_modules()
        for stored in stored_modules:
            metadata = ModuleMetadata.from_dict(stored.to_dict())
            if show_disabled or metadata.enabled:
                modules.append(metadata)
        
        return sorted(modules, key=lambda x: x.name)
    
    def display_modules_table(self, category: Optional[str] = None, 
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
