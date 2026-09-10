"""
DNSSEC Check Module for SHADOWSCOPE
Checks DNSSEC configuration and potential misconfigurations.
"""

import asyncio
import aiohttp
import dns.resolver
import dns.message
import dns.rdatatype
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class DNSSECCheckConfig(ModuleConfig):
    """Configuration for DNSSEC check module"""
    timeout: float = 10.0
    nameservers: List[str] = None
    validate_chain: bool = True
    check_expiration: bool = True
    
    def __post_init__(self):
        if self.nameservers is None:
            self.nameservers = [
                "8.8.8.8",       # Google DNS
                "1.1.1.1",       # Cloudflare DNS
                "9.9.9.9",       # Quad9 DNS
            ]


class DNSSECCheckModule(BaseModule):
    """
    DNSSEC Check Module
    
    Verifies DNSSEC configuration, validates the chain of trust,
    and checks for misconfigurations that could be exploited.
    """
    
    MODULE_NAME = "dnssec_check"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Domain Recon"
    MODULE_DESCRIPTION = "DNSSEC configuration and validation"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN]
    
    DEFAULT_CONFIG = DNSSECCheckConfig
    
    def __init__(self, config: Optional[DNSSECCheckConfig] = None):
        super().__init__(config or DNSSECCheckConfig())
        self.resolver = None
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the DNSSEC check module"""
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
            
            cache_key = f"dnssec_check:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize resolver
            self.resolver = dns.resolver.Resolver()
            self.resolver.lifetime = self.config.timeout
            self.resolver.timeout = self.config.timeout
            
            if self.config.nameservers:
                self.resolver.nameservers = self.config.nameservers
            
            # Run checks
            dnssec_info = await self.check_dnssec(target)
            
            cache.set(cache_key, dnssec_info, ttl=3600)
            
            result.status = "success"
            result.data = dnssec_info
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        
        return result
    
    async def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC configuration for a domain"""
        loop = asyncio.get_event_loop()
        
        info = {
            "domain": domain,
            "dnssec_enabled": False,
            "dnskey_records": [],
            "ds_records": [],
            "validation": {},
            "warnings": [],
            "errors": []
        }
        
        try:
            # Check for DNSKEY records
            dnskey = await loop.run_in_executor(
                None, self.query_dnskey, domain
            )
            info["dnskey_records"] = dnskey
            info["dnssec_enabled"] = len(dnskey) > 0
            
            if info["dnssec_enabled"]:
                # Check for DS records at parent zone
                parent_zone = self.get_parent_zone(domain)
                ds_records = await loop.run_in_executor(
                    None, self.query_ds, parent_zone, domain
                )
                info["ds_records"] = ds_records
                
                # Validate chain
                if self.config.validate_chain:
                    validation = await loop.run_in_executor(
                        None, self.validate_chain, domain, dnskey, ds_records
                    )
                    info["validation"] = validation
                
                # Check for common misconfigurations
                warnings = self.check_misconfigurations(dnskey, ds_records)
                info["warnings"] = warnings
            
        except Exception as e:
            info["errors"].append(f"DNSSEC check failed: {str(e)}")
        
        return info
    
    def query_dnskey(self, domain: str) -> List[Dict[str, Any]]:
        """Query DNSKEY records for a domain"""
        records = []
        
        try:
            answers = self.resolver.resolve(domain, dns.rdatatype.DNSKEY)
            for rdata in answers:
                records.append({
                    "algorithm": rdata.algorithm,
                    "key_tag": rdata.key_tag,
                    "flags": rdata.flags,
                    "protocol": rdata.protocol,
                    "public_key": rdata.to_text().split(" ", 3)[-1].strip()
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            console.print(f"[yellow]Warning: DNSKEY query failed: {e}[/yellow]")
        
        return records
    
    def query_ds(self, zone: str, domain: str) -> List[Dict[str, Any]]:
        """Query DS records for a domain at its parent zone"""
        records = []
        
        try:
            answers = self.resolver.resolve(zone, dns.rdatatype.DS)
            for rdata in answers:
                if rdata.name.to_text().lower() == domain.lower():
                    records.append({
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "digest_type": rdata.digest_type,
                        "digest": rdata.digest.hex()
                    })
        except Exception as e:
            console.print(f"[yellow]Warning: DS query failed: {e}[/yellow]")
        
        return records
    
    def validate_chain(self, domain: str, dnskey_records: List[Dict[str, Any]], 
                      ds_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate the DNSSEC chain of trust"""
        validation = {
            "chain_valid": False,
            "dnskey_matches_ds": False,
            "algorithm_consistency": True,
            "key_signing_key_present": False
        }
        
        if not dnskey_records or not ds_records:
            return validation
        
        # Check if DNSKEY matches DS
        dnskey_tags = {r["key_tag"] for r in dnskey_records}
        ds_tags = {r["key_tag"] for r in ds_records}
        validation["dnskey_matches_ds"] = dnskey_tags & ds_tags != set()
        
        # Check algorithm consistency
        algorithms = {r["algorithm"] for r in dnskey_records}
        validation["algorithm_consistency"] = len(algorithms) <= 2  # Usually 1-2 algorithms
        
        # Check for KSK (Key Signing Key)
        for r in dnskey_records:
            if r["flags"] == 257:  # KSK flag
                validation["key_signing_key_present"] = True
                break
        
        validation["chain_valid"] = (
            validation["dnskey_matches_ds"] and
            validation["algorithm_consistency"] and
            validation["key_signing_key_present"]
        )
        
        return validation
    
    def check_misconfigurations(self, dnskey_records: List[Dict[str, Any]], 
                                ds_records: List[Dict[str, Any]]) -> List[str]:
        """Check for common DNSSEC misconfigurations"""
        warnings = []
        
        if not dnskey_records:
            return warnings
        
        # Check for multiple algorithms (can cause compatibility issues)
        algorithms = {r["algorithm"] for r in dnskey_records}
        if len(algorithms) > 2:
            warnings.append("Multiple DNSSEC algorithms detected (potential compatibility issues)")
        
        # Check for weak algorithms
        weak_algorithms = {5, 6}  # RSA/SHA-1 is deprecated
        for r in dnskey_records:
            if r["algorithm"] in weak_algorithms:
                warnings.append(f"Weak algorithm detected: {r['algorithm']}")
                break
        
        # Check if DS records are missing for DNSSEC-enabled domain
        if dnskey_records and not ds_records:
            warnings.append("DNSSEC enabled but no DS records found at parent zone")
        
        # Check for non-existent key tags in DS
        if dnskey_records and ds_records:
            dnskey_tags = {r["key_tag"] for r in dnskey_records}
            ds_tags = {r["key_tag"] for r in ds_records}
            missing_tags = ds_tags - dnskey_tags
            if missing_tags:
                warnings.append(f"DS records reference non-existent key tags: {missing_tags}")
        
        return warnings
    
    def get_parent_zone(self, domain: str) -> str:
        """Get the parent zone for a domain"""
        parts = domain.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return domain
    
    def validate_target(self, target: str) -> bool:
        """Validate that the target is a domain"""
        import re
        pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, target))


# Module instance
dnssec_check_module = DNSSECCheckModule
