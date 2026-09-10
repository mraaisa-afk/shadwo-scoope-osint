"""
ASN Lookup Module for SHADOWSCOPE
Performs ASN and BGP information lookup for IP addresses.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class ASNLookupConfig(ModuleConfig):
    """Configuration for ASN lookup module"""
    api_endpoints: Dict[str, str] = None
    timeout: float = 30.0
    use_proxy: bool = True
    max_retries: int = 3
    preferred_sources: List[str] = None
    
    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "ipinfo": "https://ipinfo.io",
                "ipapi": "https://ipapi.co",
                "ipwhois": "https://ipwhois.app",
                "rdap": "https://rdap.verisign.com",
                "ripe": "https://stat.ripe.net/data",
                "bgpview": "https://api.bgpview.io",
            }
        if self.preferred_sources is None:
            self.preferred_sources = ["ipinfo", "ipapi", "ripe", "bgpview"]


class ASNLookupModule(BaseModule):
    """
    ASN Lookup Module
    
    Performs comprehensive ASN and BGP information lookup for IP addresses.
    Retrieves autonomous system information, routing details, and network ownership.
    """
    
    MODULE_NAME = "asn_lookup"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "IP/Network"
    MODULE_DESCRIPTION = "ASN and BGP information lookup for IP addresses"
    MODULE_TARGET_TYPES = [TargetType.IP]
    
    DEFAULT_CONFIG = ASNLookupConfig
    
    def __init__(self, config: Optional[ASNLookupConfig] = None):
        super().__init__(config or ASNLookupConfig())
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
        """Execute the ASN lookup module"""
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
            cache_key = f"asn_lookup:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Lookup ASN information
            asn_data = await self.lookup_asn(target)
            
            # Store in cache
            cache.set(cache_key, asn_data, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = asn_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def lookup_asn(self, ip: str) -> Dict[str, Any]:
        """Lookup ASN information for an IP address"""
        data = {
            "ip": ip,
            "asn": {},
            "bgp": {},
            "network": {},
            "analysis": {}
        }
        
        # Try multiple sources in parallel
        tasks = []
        for source in self.config.preferred_sources:
            if source in self.config.api_endpoints:
                tasks.append(self.query_source(source, ip))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                console.print(f"[yellow]Warning: {result}[/yellow]")
                continue
            if result:
                self.merge_asn_data(data, result)
        
        # Analyze the data
        data["analysis"] = self.analyze_asn_data(data)
        
        return data
    
    async def query_source(self, source: str, ip: str) -> Optional[Dict[str, Any]]:
        """Query a specific ASN data source"""
        base_url = self.config.api_endpoints.get(source)
        if not base_url:
            return None
        
        try:
            if source == "ipinfo":
                return await self.query_ipinfo(ip, base_url)
            elif source == "ipapi":
                return await self.query_ipapi(ip, base_url)
            elif source == "ipwhois":
                return await self.query_ipwhois(ip, base_url)
            elif source == "rdap":
                return await self.query_rdap(ip, base_url)
            elif source == "ripe":
                return await self.query_ripe(ip, base_url)
            elif source == "bgpview":
                return await self.query_bgpview(ip, base_url)
            else:
                return None
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to query {source}: {e}[/yellow]")
            return None
    
    async def query_ipinfo(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query ipinfo.io for ASN information"""
        url = f"{base_url}/{ip}/json"
        
        try:
            headers = {"Authorization": f"Bearer {self.config.api_endpoints.get('ipinfo_token', '')}"}
            if not headers["Authorization"] or headers["Authorization"] == "Bearer ":
                del headers["Authorization"]
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    console.print("[yellow]Warning: ipinfo.io requires API token[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: ipinfo.io query failed: {e}[/yellow]")
        
        return None
    
    async def query_ipapi(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query ipapi.co for ASN information"""
        url = f"{base_url}/{ip}/json/"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: ipapi.co query failed: {e}[/yellow]")
        
        return None
    
    async def query_ipwhois(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query ipwhois.app for ASN information"""
        url = f"{base_url}/json/{ip}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: ipwhois.app query failed: {e}[/yellow]")
        
        return None
    
    async def query_rdap(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query RDAP for ASN information"""
        url = f"{base_url}/ip/{ip}"
        
        try:
            async with self.session.get(url, headers={"Accept": "application/rdap+json"}) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: RDAP query failed: {e}[/yellow]")
        
        return None
    
    async def query_ripe(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query RIPE NCC for ASN information"""
        # Use RIPE's whois API
        url = f"{base_url}/whois/data.json?resource={ip}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: RIPE query failed: {e}[/yellow]")
        
        return None
    
    async def query_bgpview(self, ip: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Query BGPView for ASN information"""
        url = f"{base_url}/ip/{ip}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: BGPView query failed: {e}[/yellow]")
        
        return None
    
    def merge_asn_data(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Merge ASN data from a source into the target"""
        # Extract ASN
        asn = source.get("asn") or source.get("autnum", {}).get("asn")
        if asn:
            target["asn"]["asn"] = asn
        
        # Extract AS name
        as_name = source.get("org") or source.get("name") or source.get("autnum", {}).get("name")
        if as_name:
            target["asn"]["name"] = as_name
        
        # Extract AS description
        as_desc = source.get("org") or source.get("descr") or source.get("autnum", {}).get("descr")
        if as_desc:
            target["asn"]["description"] = as_desc
        
        # Extract country
        country = source.get("country") or source.get("country_name")
        if country:
            target["asn"]["country"] = country
        
        # Extract ISP
        isp = source.get("isp") or source.get("org")
        if isp:
            target["network"]["isp"] = isp
        
        # Extract network range
        network = source.get("network") or source.get("prefix")
        if network:
            target["network"]["range"] = network
        
        # Extract BGP data
        bgp = source.get("bgp") or source.get("prefixes")
        if bgp:
            target["bgp"] = bgp
        
        # Extract registry
        registry = source.get("registry") or source.get("source")
        if registry:
            target["asn"]["registry"] = registry
        
        # Extract allocated date
        allocated = source.get("allocated") or source.get("created")
        if allocated:
            target["asn"]["allocated"] = allocated
        
        # Extract peering information
        peers = source.get("peers") or source.get("neighbors")
        if peers:
            target["bgp"]["peers"] = peers
    
    def analyze_asn_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze ASN data"""
        analysis = {
            "asn": data["asn"].get("asn"),
            "as_name": data["asn"].get("name"),
            "country": data["asn"].get("country"),
            "isp": data["network"].get("isp"),
            "network_range": data["network"].get("range"),
            "registry": data["asn"].get("registry"),
            "is_cloud_provider": False,
            "is_hosting_provider": False,
            "is_cdn": False,
            "is_malicious": False,
            "recommendations": []
        }
        
        # Check for known cloud providers
        cloud_providers = [
            "amazon", "google", "microsoft", "azure", "aws", "cloudflare",
            "digitalocean", "linode", "vultr", "hetzner", "ovh", "ibm"
        ]
        
        as_name_lower = (analysis["as_name"] or "").lower()
        isp_lower = (analysis["isp"] or "").lower()
        
        for provider in cloud_providers:
            if provider in as_name_lower or provider in isp_lower:
                analysis["is_cloud_provider"] = True
                analysis["recommendations"].append(
                    f"Target is hosted on {provider.capitalize()} cloud infrastructure"
                )
        
        # Check for CDN
        cdn_providers = ["cloudflare", "akamai", "fastly", "incapsula", "edgecast"]
        for cdn in cdn_providers:
            if cdn in as_name_lower or cdn in isp_lower:
                analysis["is_cdn"] = True
                analysis["recommendations"].append(
                    f"Target uses {cdn.capitalize()} CDN"
                )
        
        # Check for hosting providers
        hosting_providers = ["hostgator", "bluehost", "godaddy", "namecheap", "hostinger"]
        for hoster in hosting_providers:
            if hoster in as_name_lower or hoster in isp_lower:
                analysis["is_hosting_provider"] = True
        
        # Generate recommendations
        if analysis["is_cloud_provider"]:
            analysis["recommendations"].append(
                "Cloud provider detected - check for misconfigured storage buckets"
            )
        
        if analysis["is_cdn"]:
            analysis["recommendations"].append(
                "CDN detected - check for origin IP exposure"
            )
        
        if not analysis["asn"]:
            analysis["recommendations"].append(
                "No ASN information found - target may be using privacy protection"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's an IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            return TargetType.IP
        
        return None


# Module instance
asn_lookup_module = ASNLookupModule
