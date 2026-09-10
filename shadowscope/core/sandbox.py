"""
Sandbox System for SHADOWSCOPE
Provides isolated execution environments for modules.
"""

import os
import sys
import json
import asyncio
import subprocess
import tempfile
import shutil
import signal
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import docker
import time

console = Console()


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution"""
    backend: str = "docker"  # docker, gvisor, firejail
    timeout: int = 300  # seconds
    cpu_limit: str = "1.0"  # CPU cores
    memory_limit: str = "512m"  # Memory
    network_restrictions: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    ])
    blocked_domains: List[str] = field(default_factory=lambda: [
        "google.com",
        "facebook.com",
        "twitter.com",
        "microsoft.com"
    ])
    allowed_outbound: List[str] = field(default_factory=list)
    temp_dir: str = "/tmp/shadowscope"
    read_only: bool = True


@dataclass
class SandboxResult:
    """Result from sandbox execution"""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    execution_time: float = 0.0
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "execution_time": self.execution_time,
            "error": self.error,
            "data": self.data
        }


class DockerSandbox:
    """Docker-based sandbox implementation"""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self._client = None
        self._docker_available = False
        self._init_docker()
    
    def _init_docker(self):
        """Initialize Docker client"""
        try:
            self._client = docker.from_env()
            self._client.ping()
            self._docker_available = True
            console.print("[green]+[/green] Docker sandbox initialized")
        except Exception as e:
            console.print(f"[yellow]Docker not available: {e}[/yellow]")
            self._docker_available = False
    
    async def execute(self, module_name: str, target: str,
                      config: Optional[Dict[str, Any]] = None,
                      sandbox_config: Optional[SandboxConfig] = None) -> SandboxResult:
        """Execute code in Docker sandbox"""
        if not self._docker_available:
            return SandboxResult(
                error="Docker not available",
                returncode=1
            )
        
        cfg = sandbox_config or self.config
        start_time = time.time()
        result = SandboxResult()
        
        try:
            # Create a temporary directory for the container
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                
                # Create input file with target and config
                input_data = {
                    "module": module_name,
                    "target": target,
                    "config": config or {},
                    "sandbox_config": {
                        "timeout": cfg.timeout,
                        "cpu_limit": cfg.cpu_limit,
                        "memory_limit": cfg.memory_limit
                    }
                }
                
                input_file = tmpdir / "input.json"
                with open(input_file, 'w') as f:
                    json.dump(input_data, f)
                
                # Create Docker container
                container = self._client.containers.run(
                    image="python:3.11-slim",
                    command=[
                        "python", "-c",
                        f"import json, sys; data = json.load(open('/input/input.json')); "
                        f"print(json.dumps(data))"
                    ],
                    volumes={
                        str(tmpdir): {"bind": "/input", "mode": "ro"},
                        str(tmpdir): {"bind": "/output", "mode": "rw"}
                    },
                    working_dir="/output",
                    cpu_period=100000,
                    cpu_quota=int(float(cfg.cpu_limit) * 100000),
                    mem_limit=cfg.memory_limit,
                    network_mode="none",  # No network access by default
                    auto_remove=True,
                    detach=True
                )
                
                # Wait for container to finish with timeout
                try:
                    output = container.wait(timeout=cfg.timeout)
                    result.returncode = output.get('StatusCode', 0)
                except Exception as e:
                    result.error = str(e)
                    result.returncode = 1
                    container.kill()
                    return result
                
                # Get logs
                logs = container.logs(out=True, err=True)
                result.stdout = logs[0].decode('utf-8') if logs[0] else ""
                result.stderr = logs[1].decode('utf-8') if logs[1] else ""
                
                result.execution_time = time.time() - start_time
                
                # Parse output if it's JSON
                if result.stdout:
                    try:
                        result.data = json.loads(result.stdout)
                    except json.JSONDecodeError:
                        result.data = {"output": result.stdout}
                
                return result
                
        except Exception as e:
            result.error = str(e)
            result.returncode = 1
            return result


class FirejailSandbox:
    """Firejail-based sandbox implementation"""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self._firejail_available = self._check_firejail()
    
    def _check_firejail(self) -> bool:
        """Check if firejail is available"""
        try:
            result = subprocess.run(
                ["firejail", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def execute(self, module_name: str, target: str,
                      config: Optional[Dict[str, Any]] = None,
                      sandbox_config: Optional[SandboxConfig] = None) -> SandboxResult:
        """Execute code in Firejail sandbox"""
        if not self._firejail_available:
            return SandboxResult(
                error="Firejail not available",
                returncode=1
            )
        
        cfg = sandbox_config or self.config
        start_time = time.time()
        result = SandboxResult()
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                
                # Create input file
                input_data = {
                    "module": module_name,
                    "target": target,
                    "config": config or {}
                }
                
                input_file = tmpdir / "input.json"
                with open(input_file, 'w') as f:
                    json.dump(input_data, f)
                
                # Build firejail command
                cmd = [
                    "firejail",
                    "--noprofile",
                    "--private",
                    "--net=none",
                    "--cpu=1",
                    f"--memory={cfg.memory_limit}",
                    "--time={cfg.timeout}",
                    "python3",
                    "-c",
                    f"import json; data = json.load(open('{input_file}')); print(json.dumps(data))"
                ]
                
                # Execute
                process = subprocess.Popen(
                    cmd,
                    cwd=str(tmpdir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
                
                # Wait with timeout
                try:
                    stdout, stderr = process.communicate(timeout=cfg.timeout)
                    result.stdout = stdout.decode('utf-8')
                    result.stderr = stderr.decode('utf-8')
                    result.returncode = process.returncode
                except subprocess.TimeoutExpired:
                    # Kill the process group
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    result.error = "Execution timed out"
                    result.returncode = 1
                    return result
                
                result.execution_time = time.time() - start_time
                
                # Parse output
                if result.stdout:
                    try:
                        result.data = json.loads(result.stdout)
                    except json.JSONDecodeError:
                        result.data = {"output": result.stdout}
                
                return result
                
        except Exception as e:
            result.error = str(e)
            result.returncode = 1
            return result


class GVisorSandbox:
    """gVisor-based sandbox implementation"""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self._gvisor_available = self._check_gvisor()
    
    def _check_gvisor(self) -> bool:
        """Check if gVisor is available"""
        try:
            result = subprocess.run(
                ["runsc", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def execute(self, module_name: str, target: str,
                      config: Optional[Dict[str, Any]] = None,
                      sandbox_config: Optional[SandboxConfig] = None) -> SandboxResult:
        """Execute code in gVisor sandbox"""
        if not self._gvisor_available:
            return SandboxResult(
                error="gVisor not available",
                returncode=1
            )
        
        cfg = sandbox_config or self.config
        start_time = time.time()
        result = SandboxResult()
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                
                # Create input file
                input_data = {
                    "module": module_name,
                    "target": target,
                    "config": config or {}
                }
                
                input_file = tmpdir / "input.json"
                with open(input_file, 'w') as f:
                    json.dump(input_data, f)
                
                # Build runsc command
                cmd = [
                    "runsc",
                    "--rootless",
                    "--network=none",
                    "--cpu=1",
                    f"--memory={cfg.memory_limit}",
                    "python3",
                    "-c",
                    f"import json; data = json.load(open('{input_file}')); print(json.dumps(data))"
                ]
                
                # Execute
                process = subprocess.Popen(
                    cmd,
                    cwd=str(tmpdir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Wait with timeout
                try:
                    stdout, stderr = process.communicate(timeout=cfg.timeout)
                    result.stdout = stdout.decode('utf-8')
                    result.stderr = stderr.decode('utf-8')
                    result.returncode = process.returncode
                except subprocess.TimeoutExpired:
                    process.kill()
                    result.error = "Execution timed out"
                    result.returncode = 1
                    return result
                
                result.execution_time = time.time() - start_time
                
                # Parse output
                if result.stdout:
                    try:
                        result.data = json.loads(result.stdout)
                    except json.JSONDecodeError:
                        result.data = {"output": result.stdout}
                
                return result
                
        except Exception as e:
            result.error = str(e)
            result.returncode = 1
            return result


class SandboxManager:
    """Manages sandbox backends and provides unified interface"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self._backends: Dict[str, Any] = {}
        self._current_backend: Optional[Any] = None
        self._init_backends()
    
    def _init_backends(self):
        """Initialize all available sandbox backends"""
        sandbox_config = SandboxConfig(
            backend=self.config.sandbox.backend,
            timeout=self.config.sandbox.timeout,
            cpu_limit=self.config.sandbox.cpu_limit,
            memory_limit=self.config.sandbox.memory_limit,
            network_restrictions=self.config.sandbox.network_restrictions,
            blocked_domains=self.config.sandbox.blocked_domains
        )
        
        # Initialize Docker
        self._backends["docker"] = DockerSandbox(sandbox_config)
        
        # Initialize Firejail
        self._backends["firejail"] = FirejailSandbox(sandbox_config)
        
        # Initialize gVisor
        self._backends["gvisor"] = GVisorSandbox(sandbox_config)
        
        # Set current backend
        self._current_backend = self._backends.get(self.config.sandbox.backend)
        
        if not self._current_backend:
            console.print(f"[yellow]Sandbox backend '{self.config.sandbox.backend}' not available, falling back to docker[/yellow]")
            self._current_backend = self._backends.get("docker")
    
    async def execute(self, module_name: str, target: str,
                      config: Optional[Dict[str, Any]] = None,
                      sandbox_config: Optional[SandboxConfig] = None) -> SandboxResult:
        """Execute code in sandbox using configured backend"""
        if not self._current_backend:
            return SandboxResult(
                error="No sandbox backend available",
                returncode=1
            )
        
        return await self._current_backend.execute(
            module_name, target, config, sandbox_config
        )
    
    def set_backend(self, backend: str) -> bool:
        """Set the current sandbox backend"""
        if backend in self._backends:
            self._current_backend = self._backends[backend]
            self.config.sandbox.backend = backend
            console.print(f"[green]+[/green] Switched sandbox backend to: {backend}")
            return True
        
        console.print(f"[red]Sandbox backend '{backend}' not available[/red]")
        return False
    
    def get_backends(self) -> List[str]:
        """Get list of available backends"""
        return list(self._backends.keys())
    
    def check_backend(self, backend: str) -> bool:
        """Check if a backend is available"""
        return backend in self._backends
    
    def create_isolated_env(self, module_name: str) -> Optional[Path]:
        """Create an isolated environment for a module"""
        try:
            # Create temporary directory
            env_dir = Path(tempfile.mkdtemp(prefix=f"shadowscope_{module_name}_"))
            
            # Create basic structure
            (env_dir / "input").mkdir()
            (env_dir / "output").mkdir()
            (env_dir / "tmp").mkdir()
            
            # Set permissions
            os.chmod(env_dir, 0o700)
            
            return env_dir
            
        except Exception as e:
            console.print(f"[red]Error creating isolated environment: {e}[/red]")
            return None
    
    def cleanup_env(self, env_dir: Path) -> bool:
        """Clean up an isolated environment"""
        try:
            if env_dir.exists():
                shutil.rmtree(env_dir, ignore_errors=True)
                return True
        except Exception as e:
            console.print(f"[yellow]Error cleaning up environment: {e}[/yellow]")
        return False
    
    def restrict_network(self, allowed_ips: List[str] = None, 
                        blocked_domains: List[str] = None) -> Dict[str, Any]:
        """Create network restrictions configuration"""
        restrictions = {
            "allowed_ips": allowed_ips or self.config.sandbox.network_restrictions,
            "blocked_domains": blocked_domains or self.config.sandbox.blocked_domains,
            "use_tor": False,
            "use_proxy": False
        }
        
        # Check if Tor is configured
        if self.config.api.tor.get('enabled', False):
            restrictions["use_tor"] = True
            restrictions["tor_port"] = self.config.api.tor.get('port', 9050)
        
        # Check if proxies are configured
        if self.config.proxy.http or self.config.proxy.https or self.config.proxy.socks5:
            restrictions["use_proxy"] = True
            restrictions["proxies"] = {
                "http": self.config.proxy.http,
                "https": self.config.proxy.https,
                "socks5": self.config.proxy.socks5
            }
        
        return restrictions


# Initialize sandbox manager
sandbox = SandboxManager()
