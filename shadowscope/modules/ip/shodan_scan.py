"""
Shodan Scan Module for SHADOWSCOPE
Performs comprehensive IP reconnaissance using Shodan API.
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
from shadowscope.core import proxy, cache, storage

console = Console()


@dataclass
class ShodanScanConfig(ModuleConfig):
    """Configuration for Shodan scan module"""
    api_key: Optional[str] = None
    api_url: str = "https://api.shodan.io"
    timeout: float = 60.0
    use_proxy: bool = True
    max_results: int = 100
    facets: List[str] = field(default_factory=lambda: [
        "org", "domain", "port", "asn", "country", "city", "isp"
    ])
    include_vulnerabilities: bool = True
    include_ports: bool = True
    include_banners: bool = True
    min_confidence: int = 50


class ShodanScanModule(BaseModule):
    """
    Shodan Scan Module
    
    Performs comprehensive reconnaissance on IP addresses using the Shodan API.
    Retrieves open ports, services, vulnerabilities, and organizational data.
    """
    
    MODULE_NAME = "shodan_scan"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "IP/Network"
    MODULE_DESCRIPTION = "Comprehensive IP reconnaissance using Shodan API"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.DOMAIN]
    
    DEFAULT_CONFIG = ShodanScanConfig
    
    def __init__(self, config: Optional[ShodanScanConfig] = None):
        super().__init__(config or ShodanScanConfig())
        self.session: Optional[aiohttp.ClientSession] = None
    
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
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the Shodan scan module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )
        
        try:
            # Validate and normalize target
            target_type = self.validate_and_normalize(target)
            if not target_type:
                result.status = "error"
                result.error = f"Invalid target: {target}"
                return result
            
            # Check cache
            cache_key = f"shodan_scan:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Check API key
            if not self.config.api_key:
                result.status = "error"
                result.error = "Shodan API key not configured"
                return result
            
            # Determine if we're scanning an IP or need to resolve a domain
            if target_type == TargetType.DOMAIN:
                # Resolve domain to IP
                ip_address = await self.resolve_domain(target)
                if not ip_address:
                    result.status = "error"
                    result.error = f"Could not resolve domain: {target}"
                    return result
                scan_target = ip_address
            else:
                scan_target = target
            
            # Run Shodan scan
            scan_data = await self.scan_ip(scan_target)
            
            # Store in cache
            cache.set(cache_key, scan_data, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = scan_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            import socket
            import concurrent.futures
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(socket.gethostbyname, domain)
                return await asyncio.wrap_future(future)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not resolve {domain}: {e}[/yellow]")
            return None
    
    async def scan_ip(self, ip: str) -> Dict[str, Any]:
        """Scan an IP address using Shodan API"""
        data = {
            "ip": ip,
            "target": self.target,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "shodan": {}
        }
        
        try:
            # Get host information
            host_info = await self.get_host_info(ip)
            if host_info:
                data["shodan"]["host"] = host_info
            
            # Get port information
            ports = await self.get_ports(ip)
            if ports:
                data["shodan"]["ports"] = ports
            
            # Get vulnerabilities
            if self.config.include_vulnerabilities:
                vulns = await self.get_vulnerabilities(ip)
                if vulns:
                    data["shodan"]["vulnerabilities"] = vulns
            
            # Analyze the data
            data["analysis"] = self.analyze_scan_data(data["shodan"])
            
        except Exception as e:
            data["error"] = str(e)
        
        return data
    
    async def get_host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get host information from Shodan"""
        url = f"{self.config.api_url}/shodan/host/{ip}?key={self.config.api_key}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    console.print("[red]Error: Invalid Shodan API key[/red]")
                elif response.status == 429:
                    console.print("[yellow]Warning: Shodan API rate limit exceeded[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get host info: {e}[/yellow]")
        
        return None
    
    async def get_ports(self, ip: str) -> Optional[List[Dict[str, Any]]]:
        """Get open ports for an IP"""
        url = f"{self.config.api_url}/shodan/host/{ip}/ports?key={self.config.api_key}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get ports: {e}[/yellow]")
        
        return None
    
    async def get_vulnerabilities(self, ip: str) -> Optional[List[Dict[str, Any]]]:
        """Get vulnerabilities for an IP"""
        url = f"{self.config.api_url}/shodan/host/{ip}/vulns?key={self.config.api_key}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    vulns = await response.json()
                    # Filter by confidence
                    if self.config.min_confidence > 0:
                        vulns = [
                            v for v in vulns 
                            if v.get("confidence", 0) >= self.config.min_confidence
                        ]
                    return vulns
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get vulnerabilities: {e}[/yellow]")
        
        return None
    
    def analyze_scan_data(self, shodan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Shodan scan data"""
        analysis = {
            "open_ports": 0,
            "services": {},
            "vulnerabilities": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "organizations": [],
            "asns": [],
            "countries": [],
            "isp": None,
            "recommendations": []
        }
        
        host_info = shodan_data.get("host", {})
        ports = shodan_data.get("ports", [])
        vulns = shodan_data.get("vulnerabilities", [])
        
        # Analyze ports
        if ports:
            analysis["open_ports"] = len(ports)
            for port_info in ports:
                port = port_info.get("port")
                service = port_info.get("service", "unknown")
                analysis["services"][port] = service
        elif host_info:
            # Extract from host info
            ports_list = host_info.get("ports", [])
            analysis["open_ports"] = len(ports_list)
        
        # Analyze vulnerabilities
        if vulns:
            analysis["vulnerabilities"]["total"] = len(vulns)
            for vuln in vulns:
                severity = vuln.get("severity", "").lower()
                if severity == "critical":
                    analysis["vulnerabilities"]["critical"] += 1
                elif severity == "high":
                    analysis["vulnerabilities"]["high"] += 1
                elif severity == "medium":
                    analysis["vulnerabilities"]["medium"] += 1
                else:
                    analysis["vulnerabilities"]["low"] += 1
        
        # Analyze host info
        if host_info:
            orgs = host_info.get("org", "")
            if orgs:
                analysis["organizations"] = [o.strip() for o in orgs.split(",")]
            
            asns = host_info.get("asn", "")
            if asns:
                analysis["asns"] = [a.strip() for a in asns.split(",")]
            
            country = host_info.get("country_name")
            if country:
                analysis["countries"].append(country)
            
            isp = host_info.get("isp")
            if isp:
                analysis["isp"] = isp
        
        # Generate recommendations
        if analysis["vulnerabilities"]["critical"] > 0:
            analysis["recommendations"].append(
                f"CRITICAL: {analysis['vulnerabilities']['critical']} critical vulnerabilities found"
            )
        
        if analysis["vulnerabilities"]["high"] > 0:
            analysis["recommendations"].append(
                f"HIGH: {analysis['vulnerabilities']['high']} high severity vulnerabilities found"
            )
        
        if analysis["open_ports"] > 10:
            analysis["recommendations"].append(
                f"Multiple open ports ({analysis['open_ports']}) - consider reducing attack surface"
            )
        
        return analysis
    
    def validate_and_normalize(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        # Check if it's an IP
        import re
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            return TargetType.IP
        
        # Check if it's a domain
        domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        if re.match(domain_pattern, target):
            return TargetType.DOMAIN
        
        return None


# Module instance
shodan_scan_module = ShodanScanModule
