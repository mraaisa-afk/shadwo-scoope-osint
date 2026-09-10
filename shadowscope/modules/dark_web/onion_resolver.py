"""
Onion Resolver Module for SHADOWSCOPE
Resolves .onion addresses and checks their status.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import re
import socket

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class OnionResolverConfig(ModuleConfig):
    """Configuration for onion resolver module"""
    tor_proxy: str = "socks5://127.0.0.1:9050"
    tor_control_port: int = 9051
    tor_control_password: Optional[str] = None
    timeout: float = 60.0
    use_tor: bool = True
    max_retries: int = 3
    check_connectivity: bool = True
    check_service: bool = True
    check_hsdir: bool = True
    
    def __post_init__(self):
        # Ensure tor_proxy is properly formatted
        if not self.tor_proxy.startswith("socks5://") and not self.tor_proxy.startswith("socks4://"):
            self.tor_proxy = f"socks5://{self.tor_proxy}"


class OnionResolverModule(BaseModule):
    """
    Onion Resolver Module
    
    Resolves .onion addresses and checks their status.
    Uses Tor network to connect to hidden services.
    """
    
    MODULE_NAME = "onion_resolver"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Dark Web"
    MODULE_DESCRIPTION = "Onion address resolution and hidden service status checking"
    MODULE_TARGET_TYPES = [TargetType.ONION, TargetType.URL]
    
    DEFAULT_CONFIG = OnionResolverConfig
    
    def __init__(self, config: Optional[OnionResolverConfig] = None):
        super().__init__(config or OnionResolverConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.tor_session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        # Regular session
        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        
        # Tor session
        try:
            if self.config.use_tor:
                self.tor_session = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=timeout,
                    proxy=self.config.tor_proxy
                )
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to initialize Tor session: {e}[/yellow]")
            self.tor_session = None
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the onion resolver module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )
        
        try:
            # Validate target
            target_type = self.validate_target(target)
            if not target_type:
                result.status = "error"
                result.error = f"Invalid target: {target}"
                return result
            
            # Normalize onion address
            onion = self.normalize_onion(target)
            
            # Check cache
            cache_key = f"onion_resolver:{onion}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Resolve onion
            resolution_data = await self.resolve_onion(onion)
            
            # Store in cache
            cache.set(cache_key, resolution_data, ttl=3600)  # 1 hour
            
            result.status = "success"
            result.data = resolution_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
            if self.tor_session:
                await self.tor_session.close()
        
        return result
    
    def normalize_onion(self, target: str) -> str:
        """Normalize onion address"""
        # Remove protocol if present
        onion = target.replace("http://", "").replace("https://", "")
        
        # Remove path if present
        onion = onion.split("/")[0]
        
        # Remove port if present
        onion = onion.split(":")[0]
        
        # Ensure it ends with .onion
        if not onion.endswith(".onion"):
            onion = f"{onion}.onion"
        
        return onion.lower()
    
    async def resolve_onion(self, onion: str) -> Dict[str, Any]:
        """Resolve onion address and check status"""
        data = {
            "onion": onion,
            "version": None,
            "is_valid": False,
            "is_reachable": False,
            "response_time": None,
            "status_code": None,
            "service_info": {},
            "hsdir_info": {},
            "connectivity": {},
            "analysis": {}
        }
        
        # Validate onion address
        data["is_valid"] = self.validate_onion(onion)
        data["version"] = self.get_onion_version(onion)
        
        if not data["is_valid"]:
            data["error"] = "Invalid onion address"
            return data
        
        # Check connectivity
        if self.config.check_connectivity:
            data["connectivity"] = await self.check_connectivity(onion)
            data["is_reachable"] = data["connectivity"].get("reachable", False)
            data["response_time"] = data["connectivity"].get("response_time")
            data["status_code"] = data["connectivity"].get("status_code")
        
        # Check service info
        if self.config.check_service and data["is_reachable"]:
            data["service_info"] = await self.check_service_info(onion)
        
        # Check HSDir info
        if self.config.check_hsdir:
            data["hsdir_info"] = await self.check_hsdir_info(onion)
        
        # Analyze the data
        data["analysis"] = self.analyze_onion_data(data)
        
        return data
    
    def validate_onion(self, onion: str) -> bool:
        """Validate onion address format"""
        # Version 2: 16 characters + .onion
        v2_pattern = r"^[a-z2-7]{16}\.onion$"
        
        # Version 3: 56 characters + .onion
        v3_pattern = r"^[a-z2-7]{56}\.onion$"
        
        return bool(re.match(v2_pattern, onion)) or bool(re.match(v3_pattern, onion))
    
    def get_onion_version(self, onion: str) -> str:
        """Get onion address version"""
        # Count characters before .onion
        base = onion.replace(".onion", "")
        
        if len(base) == 16:
            return "v2"
        elif len(base) == 56:
            return "v3"
        else:
            return "unknown"
    
    async def check_connectivity(self, onion: str) -> Dict[str, Any]:
        """Check if onion address is reachable"""
        result = {
            "onion": onion,
            "reachable": False,
            "response_time": None,
            "status_code": None,
            "error": None
        }
        
        if not self.tor_session:
            result["error"] = "Tor session not available"
            return result
        
        try:
            import time
            
            # Try both HTTP and HTTPS
            urls = [
                f"http://{onion}",
                f"https://{onion}"
            ]
            
            for url in urls:
                start_time = time.time()
                
                try:
                    async with self.tor_session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        result["reachable"] = True
                        result["response_time"] = time.time() - start_time
                        result["status_code"] = response.status
                        result["url"] = url
                        return result
                except asyncio.TimeoutError:
                    continue
                except aiohttp.ClientError as e:
                    continue
                except Exception as e:
                    result["error"] = str(e)
                    continue
            
            result["error"] = "Connection failed"
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def check_service_info(self, onion: str) -> Dict[str, Any]:
        """Check service information"""
        info = {
            "onion": onion,
            "server": None,
            "title": None,
            "content_type": None,
            "content_length": None,
            "headers": {}
        }
        
        if not self.tor_session:
            info["error"] = "Tor session not available"
            return info
        
        try:
            url = f"http://{onion}"
            
            async with self.tor_session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                info["status_code"] = response.status
                info["content_type"] = response.headers.get("Content-Type")
                info["content_length"] = response.headers.get("Content-Length")
                info["server"] = response.headers.get("Server")
                info["headers"] = dict(response.headers)
                
                # Try to get title
                if response.status == 200:
                    html = await response.text()
                    if "<title>" in html:
                        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
                        if title_match:
                            info["title"] = title_match.group(1).strip()
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    async def check_hsdir_info(self, onion: str) -> Dict[str, Any]:
        """Check Hidden Service Directory information"""
        info = {
            "onion": onion,
            "version": self.get_onion_version(onion),
            "hsdir_nodes": [],
            "descriptor_available": False,
            "intro_points": []
        }
        
        # This would typically query the Tor network for HSDir information
        # For now, we'll provide placeholder data
        
        if info["version"] == "v2":
            info["hsdir_nodes"] = ["placeholder_node_1", "placeholder_node_2"]
        elif info["version"] == "v3":
            info["hsdir_nodes"] = ["placeholder_node_1", "placeholder_node_2", "placeholder_node_3"]
        
        info["descriptor_available"] = True
        info["intro_points"] = ["ip1:port1", "ip2:port2", "ip3:port3"]
        
        return info
    
    def analyze_onion_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze onion data"""
        analysis = {
            "onion": data["onion"],
            "version": data["version"],
            "is_valid": data["is_valid"],
            "is_reachable": data["is_reachable"],
            "response_time": data["response_time"],
            "status_code": data["status_code"],
            "has_service_info": bool(data["service_info"]),
            "has_hsdir_info": bool(data["hsdir_info"]),
            "is_v2": data["version"] == "v2",
            "is_v3": data["version"] == "v3",
            "recommendations": []
        }
        
        # Generate recommendations
        if not data["is_valid"]:
            analysis["recommendations"].append(
                "INVALID: Onion address format is invalid"
            )
        else:
            if data["is_reachable"]:
                analysis["recommendations"].append(
                    f"REACHABLE: Onion service is accessible (response time: {data['response_time']:.2f}s)"
                )
            else:
                analysis["recommendations"].append(
                    "UNREACHABLE: Onion service is not currently accessible"
                )
            
            if analysis["is_v2"]:
                analysis["recommendations"].append(
                    "V2: This is a version 2 onion address (16 characters)"
                )
            elif analysis["is_v3"]:
                analysis["recommendations"].append(
                    "V3: This is a version 3 onion address (56 characters)"
                )
            
            if data["status_code"] == 200:
                analysis["recommendations"].append(
                    "SUCCESS: HTTP 200 OK"
                )
            elif data["status_code"]:
                analysis["recommendations"].append(
                    f"STATUS: HTTP {data['status_code']}"
                )
            
            if data["service_info"].get("title"):
                analysis["recommendations"].append(
                    f"TITLE: {data['service_info']['title']}"
                )
            
            if analysis["is_v2"]:
                analysis["recommendations"].append(
                    "SECURITY: V2 onion addresses are deprecated and less secure"
                )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's a URL with .onion
        url_pattern = r"^https?://[a-z2-7]{16,56}\.onion(/[^\s]*)?$"
        if re.match(url_pattern, target):
            return TargetType.URL
        
        # Check if it's an onion address
        onion_pattern = r"^[a-z2-7]{16,56}\.onion$"
        if re.match(onion_pattern, target):
            return TargetType.ONION
        
        return None


# Module instance
onion_resolver_module = OnionResolverModule
