"""
Certificate Transparency Log Module for SHADOWSCOPE
Analyzes Certificate Transparency logs for domain certificates.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from rich.console import Console
import json

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class CertTransparencyConfig(ModuleConfig):
    """Configuration for Certificate Transparency module"""
    api_urls: List[str] = field(default_factory=lambda: [
        "https://crt.sh/?q=%25.{domain}&output=json",
        "https://api.certspotter.com/v1/issuances?domain={domain}&expand=cert&expand=issuer",
        "https://transparencyreport.google.com/https/certificates?domain={domain}"
    ])
    api_keys: Dict[str, Optional[str]] = field(default_factory=dict)
    timeout: float = 30.0
    use_proxy: bool = True
    max_results: int = 100
    days_back: int = 365
    include_expired: bool = True
    include_precerts: bool = True


class CertTransparencyModule(BaseModule):
    """
    Certificate Transparency Log Module
    
    Queries Certificate Transparency logs to find all SSL/TLS certificates
    issued for a domain, including subdomains and historical certificates.
    """
    
    MODULE_NAME = "cert_transparency"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Domain Recon"
    MODULE_DESCRIPTION = "Certificate Transparency log analysis"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN]
    
    DEFAULT_CONFIG = CertTransparencyConfig
    
    def __init__(self, config: Optional[CertTransparencyConfig] = None):
        super().__init__(config or CertTransparencyConfig())
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
        """Execute the Certificate Transparency module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )
        
        try:
            if not self.validate_target(target):
                result.status = "error"
                result.error = f"Invalid target: {target}"
                return result
            
            cache_key = f"cert_transparency:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            await self.initialize()
            
            # Query multiple CT log sources
            all_certs = []
            for api_url in self.config.api_urls:
                certs = await self.query_ct_log(api_url, target)
                all_certs.extend(certs)
            
            # Deduplicate and process
            unique_certs = self.deduplicate_certs(all_certs)
            processed = self.process_certificates(unique_certs, target)
            
            cache.set(cache_key, processed, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = processed
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def query_ct_log(self, api_url: str, domain: str) -> List[Dict[str, Any]]:
        """Query a Certificate Transparency log"""
        certs = []
        
        try:
            # Format URL with domain
            url = api_url.format(domain=domain)
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    
                    if "json" in content_type:
                        data = await response.json()
                        certs = self.parse_cert_response(data, api_url)
                    else:
                        text = await response.text()
                        certs = self.parse_text_response(text, api_url)
        except Exception as e:
            console.print(f"[yellow]Warning: CT log query failed for {api_url}: {e}[/yellow]")
        
        return certs
    
    def parse_cert_response(self, data: Any, source: str) -> List[Dict[str, Any]]:
        """Parse JSON response from CT log"""
        certs = []
        
        if source == "https://crt.sh/?q=%25.{domain}&output=json":
            # crt.sh format
            if isinstance(data, list):
                for item in data:
                    cert = {
                        "source": source,
                        "common_name": item.get("common_name"),
                        "name_value": item.get("name_value"),
                        "issuer": item.get("issuer_name"),
                        "not_before": item.get("not_before"),
                        "not_after": item.get("not_after"),
                        "serial_number": item.get("serial_number"),
                        "entry_timestamp": item.get("entry_timestamp")
                    }
                    certs.append(cert)
        
        elif source == "https://api.certspotter.com/v1/issuances?domain={domain}&expand=cert&expand=issuer":
            # CertSpotter format
            if isinstance(data, list):
                for item in data:
                    cert_info = item.get("cert", {})
                    issuer_info = item.get("issuer", {})
                    cert = {
                        "source": source,
                        "common_name": cert_info.get("common_name"),
                        "dns_names": cert_info.get("dns_names", []),
                        "issuer": issuer_info.get("name"),
                        "not_before": cert_info.get("not_before"),
                        "not_after": cert_info.get("not_after"),
                        "serial_number": cert_info.get("serial_number"),
                        "entry_timestamp": item.get("timestamp")
                    }
                    certs.append(cert)
        
        return certs
    
    def parse_text_response(self, text: str, source: str) -> List[Dict[str, Any]]:
        """Parse text response from CT log"""
        certs = []
        lines = text.strip().split("\n")
        
        if not lines:
            return certs
        
        # Try to parse as JSON lines
        for line in lines:
            try:
                item = json.loads(line)
                certs.append({
                    "source": source,
                    "raw": item
                })
            except json.JSONDecodeError:
                continue
        
        return certs
    
    def deduplicate_certs(self, certs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate certificates"""
        unique = []
        seen_serials = set()
        
        for cert in certs:
            serial = cert.get("serial_number") or cert.get("raw", {}).get("serial_number")
            if serial and serial not in seen_serials:
                seen_serials.add(serial)
                unique.append(cert)
        
        return unique
    
    def process_certificates(self, certs: List[Dict[str, Any]], domain: str) -> Dict[str, Any]:
        """Process and analyze certificates"""
        processed = {
            "domain": domain,
            "certificates": [],
            "subdomains": set(),
            "issuers": set(),
            "analysis": {
                "total_certificates": len(certs),
                "unique_subdomains": 0,
                "active_certificates": 0,
                "expired_certificates": 0,
                "wildcard_certificates": 0,
                "earliest_issuance": None,
                "latest_issuance": None,
                "earliest_expiry": None,
                "latest_expiry": None
            }
        }
        
        now = datetime.utcnow()
        
        for cert in certs:
            cert_data = {
                "common_name": cert.get("common_name", ""),
                "dns_names": cert.get("dns_names", []),
                "issuer": cert.get("issuer", ""),
                "serial_number": cert.get("serial_number", ""),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "entry_timestamp": cert.get("entry_timestamp"),
                "source": cert.get("source", ""),
                "raw": cert.get("raw", {})
            }
            
            # Parse dates
            if cert_data["not_before"]:
                if isinstance(cert_data["not_before"], str):
                    try:
                        cert_data["not_before"] = datetime.strptime(
                            cert_data["not_before"], "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        pass
            
            if cert_data["not_after"]:
                if isinstance(cert_data["not_after"], str):
                    try:
                        cert_data["not_after"] = datetime.strptime(
                            cert_data["not_after"], "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        pass
            
            if cert_data["entry_timestamp"]:
                if isinstance(cert_data["entry_timestamp"], str):
                    try:
                        cert_data["entry_timestamp"] = datetime.strptime(
                            cert_data["entry_timestamp"], "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        pass
            
            # Extract subdomains
            subdomains = set()
            
            # From common_name
            if cert_data["common_name"]:
                cn = cert_data["common_name"].lower()
                if cn.endswith(domain.lower()):
                    subdomains.add(cn)
            
            # From dns_names
            for dns_name in cert_data.get("dns_names", []):
                dn = dns_name.lower()
                if dn.endswith(domain.lower()):
                    subdomains.add(dn)
            
            # From name_value (crt.sh)
            name_value = cert.get("name_value", "")
            if name_value:
                for nv in name_value.split("\n"):
                    nv = nv.strip().lower()
                    if nv.endswith(domain.lower()):
                        subdomains.add(nv)
            
            # Check for wildcard
            is_wildcard = any(
                name.startswith("*.") or name == "*"
                for name in subdomains
            )
            
            # Update analysis
            if cert_data["not_after"] and isinstance(cert_data["not_after"], datetime):
                if cert_data["not_after"] > now:
                    processed["analysis"]["active_certificates"] += 1
                else:
                    processed["analysis"]["expired_certificates"] += 1
            
            if is_wildcard:
                processed["analysis"]["wildcard_certificates"] += 1
            
            # Update earliest/latest
            if cert_data["entry_timestamp"] and isinstance(cert_data["entry_timestamp"], datetime):
                if processed["analysis"]["earliest_issuance"] is None or \
                   cert_data["entry_timestamp"] < processed["analysis"]["earliest_issuance"]:
                    processed["analysis"]["earliest_issuance"] = cert_data["entry_timestamp"]
                
                if processed["analysis"]["latest_issuance"] is None or \
                   cert_data["entry_timestamp"] > processed["analysis"]["latest_issuance"]:
                    processed["analysis"]["latest_issuance"] = cert_data["entry_timestamp"]
            
            if cert_data["not_after"] and isinstance(cert_data["not_after"], datetime):
                if processed["analysis"]["earliest_expiry"] is None or \
                   cert_data["not_after"] < processed["analysis"]["earliest_expiry"]:
                    processed["analysis"]["earliest_expiry"] = cert_data["not_after"]
                
                if processed["analysis"]["latest_expiry"] is None or \
                   cert_data["not_after"] > processed["analysis"]["latest_expiry"]:
                    processed["analysis"]["latest_expiry"] = cert_data["not_after"]
            
            # Add to results
            processed["certificates"].append(cert_data)
            processed["subdomains"].update(subdomains)
            processed["issuers"].add(cert_data["issuer"])
        
        processed["analysis"]["unique_subdomains"] = len(processed["subdomains"])
        
        # Convert sets to lists for JSON serialization
        processed["subdomains"] = sorted(list(processed["subdomains"]))
        processed["issuers"] = sorted(list(processed["issuers"]))
        
        return processed
    
    def validate_target(self, target: str) -> bool:
        """Validate that the target is a domain"""
        import re
        pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, target))


# Module instance
cert_transparency_module = CertTransparencyModule
