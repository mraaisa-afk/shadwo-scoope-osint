"""
Censys Query Module for SHADOWSCOPE
Queries Censys database for IP and domain intelligence.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import json

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class CensysQueryConfig(ModuleConfig):
    """Configuration for Censys query module"""
    api_id: Optional[str] = None
    api_secret: Optional[str] = None
    api_url: str = "https://api.censys.io/v2"
    timeout: float = 60.0
    use_proxy: bool = True
    max_results: int = 100
    pages: int = 1
    include_raw_data: bool = False


class CensysQueryModule(BaseModule):
    """
    Censys Query Module
    
    Queries the Censys database for comprehensive internet-wide scan data.
    Provides information about hosts, services, and certificates.
    """
    
    MODULE_NAME = "censys_query"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "IP/Network"
    MODULE_DESCRIPTION = "Censys database queries for IP and domain intelligence"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.DOMAIN]
    
    DEFAULT_CONFIG = CensysQueryConfig
    
    def __init__(self, config: Optional[CensysQueryConfig] = None):
        super().__init__(config or CensysQueryConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.access_token: Optional[str] = None
    
    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
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
        
        # Authenticate if credentials are provided
        if self.config.api_id and self.config.api_secret:
            await self.authenticate()
    
    async def authenticate(self) -> None:
        """Authenticate with Censys API"""
        url = f"{self.config.api_url}/authentication"
        
        try:
            auth_data = {
                "api_id": self.config.api_id,
                "api_secret": self.config.api_secret
            }
            
            async with self.session.post(url, json=auth_data) as response:
                if response.status == 200:
                    data = await response.json()
                    self.access_token = data.get("token")
                    console.print("[green]+[/green] Censys authentication successful")
                else:
                    console.print(f"[red]-[/red] Censys authentication failed: {response.status}")
        except Exception as e:
            console.print(f"[yellow]Warning: Censys authentication error: {e}[/yellow]")
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the Censys query module"""
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
            
            # Check cache
            cache_key = f"censys_query:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Check authentication
            if not self.access_token and (self.config.api_id or self.config.api_secret):
                result.status = "error"
                result.error = "Censys authentication failed"
                return result
            
            # Query Censys
            censys_data = await self.query_censys(target, target_type)
            
            # Store in cache
            cache.set(cache_key, censys_data, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = censys_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def query_censys(self, target: str, target_type: TargetType) -> Dict[str, Any]:
        """Query Censys for target information"""
        data = {
            "target": target,
            "target_type": target_type.value,
            "censys": {},
            "analysis": {}
        }
        
        if target_type == TargetType.IP:
            host_data = await self.get_host_data(target)
            if host_data:
                data["censys"]["host"] = host_data
                data["analysis"] = self.analyze_host_data(host_data)
        elif target_type == TargetType.DOMAIN:
            domain_data = await self.get_domain_data(target)
            if domain_data:
                data["censys"]["domain"] = domain_data
                data["analysis"] = self.analyze_domain_data(domain_data)
        
        return data
    
    async def get_host_data(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get host data from Censys"""
        url = f"{self.config.api_url}/hosts/{ip}"
        
        try:
            headers = {}
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    console.print("[red]Error: Invalid Censys API credentials[/red]")
                elif response.status == 404:
                    console.print(f"[yellow]Warning: No Censys data for IP: {ip}[/yellow]")
                elif response.status == 429:
                    console.print("[yellow]Warning: Censys API rate limit exceeded[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get host data: {e}[/yellow]")
        
        return None
    
    async def get_domain_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain data from Censys"""
        url = f"{self.config.api_url}/domains/{domain}"
        
        try:
            headers = {}
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    console.print(f"[yellow]Warning: No Censys data for domain: {domain}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get domain data: {e}[/yellow]")
        
        return None
    
    async def search_hosts(self, query: str, per_page: int = 100) -> Optional[Dict[str, Any]]:
        """Search Censys for hosts matching a query"""
        url = f"{self.config.api_url}/hosts/search?q={query}&per_page={per_page}"
        
        try:
            headers = {}
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: Search failed: {e}[/yellow]")
        
        return None
    
    def analyze_host_data(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Censys host data"""
        analysis = {
            "ip": host_data.get("ip"),
            "services": {},
            "open_ports": 0,
            "vulnerabilities": [],
            "organization": host_data.get("organization"),
            "location": {},
            "recommendations": []
        }
        
        # Extract location
        location = host_data.get("location", {})
        if location:
            analysis["location"]["country"] = location.get("country")
            analysis["location"]["city"] = location.get("city")
            analysis["location"]["coordinates"] = location.get("coordinates")
        
        # Extract services and ports
        services = host_data.get("services", [])
        if services:
            analysis["open_ports"] = len(services)
            for service in services:
                port = service.get("port")
                service_name = service.get("service_name")
                transport = service.get("transport_protocol")
                
                if port:
                    analysis["services"][port] = {
                        "service": service_name,
                        "transport": transport
                    }
        
        # Check for common vulnerabilities
        for service in services:
            service_name = service.get("service_name", "").lower()
            version = service.get("version", "")
            
            # Check for known vulnerable services
            vulnerable_services = {
                "apache": ["2.2", "2.4"],
                "nginx": ["1.0", "1.1", "1.2"],
                "openssh": ["7.2", "7.3", "7.4"],
                "mysql": ["5.0", "5.1", "5.5", "5.6"],
                "postgresql": ["9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6"],
                "redis": ["3.0", "3.2", "4.0"],
                "mongodb": ["2.4", "2.6", "3.0", "3.2", "3.4", "3.6"],
                "memcached": ["1.4", "1.5"],
                "elasticsearch": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"],
            }
            
            for service, versions in vulnerable_services.items():
                if service in service_name:
                    for vuln_version in versions:
                        if version and version.startswith(vuln_version):
                            analysis["vulnerabilities"].append({
                                "service": service_name,
                                "version": version,
                                "issue": f"Potentially vulnerable {service} {vuln_version}"
                            })
        
        # Generate recommendations
        if analysis["open_ports"] > 10:
            analysis["recommendations"].append(
                f"Multiple open ports ({analysis['open_ports']}) - consider reducing attack surface"
            )
        
        if analysis["vulnerabilities"]:
            analysis["recommendations"].append(
                f"Found {len(analysis['vulnerabilities'])} potentially vulnerable services"
            )
        
        return analysis
    
    def analyze_domain_data(self, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Censys domain data"""
        analysis = {
            "domain": domain_data.get("name"),
            "subdomains": [],
            "ips": [],
            "certificates": [],
            "recommendations": []
        }
        
        # Extract subdomains
        subdomains = domain_data.get("subdomains", [])
        if subdomains:
            analysis["subdomains"] = subdomains
        
        # Extract IPs
        ips = domain_data.get("ips", [])
        if ips:
            analysis["ips"] = ips
        
        # Extract certificates
        certs = domain_data.get("certificates", [])
        if certs:
            analysis["certificates"] = certs
        
        # Generate recommendations
        if len(analysis["subdomains"]) > 50:
            analysis["recommendations"].append(
                f"Large subdomain count ({len(analysis['subdomains'])}) - check for wildcard DNS"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's an IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            return TargetType.IP
        
        # Check if it's a domain
        domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        if re.match(domain_pattern, target):
            return TargetType.DOMAIN
        
        return None


# Module instance
censys_query_module = CensysQueryModule
