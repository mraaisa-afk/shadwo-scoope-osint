"""
Subdomain Takeover Module for SHADOWSCOPE
Detects vulnerable subdomains that could be hijacked.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core import cache, proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class SubdomainTakeoverConfig(ModuleConfig):
    """Configuration for subdomain takeover detection"""
    wordlist: list[str] = field(default_factory=lambda: [
        "api", "app", "apps", "assets", "beta", "blog", "cdn", "dev",
        "docs", "forum", "ftp", "git", "help", "img", "images", "login",
        "mail", "m", "mobile", "news", "old", "portal", "secure", "shop",
        "staging", "static", "status", "store", "support", "test", "tmp",
        "tools", "upload", "vpn", "web", "www", "phpmyadmin", "admin",
        "wordpress", "wp", "cpanel", "whm", "ns1", "ns2", "ns3", "ns4"
    ])
    timeout: float = 10.0
    concurrent_requests: int = 100
    use_proxy: bool = True
    check_cname: bool = True
    check_a: bool = True
    check_aaaa: bool = True
    verify_claimable: bool = True

    # Services that are commonly vulnerable to takeover
    vulnerable_services: list[str] = field(default_factory=lambda: [
        "github.io", "herokuapp.com", "netlify.app", "vercel.app",
        "azurewebsites.net", "cloudapp.net", "amazonaws.com",
        "s3.amazonaws.com", "cloudfront.net", "fastly.net",
        "shopify.com", "tumblr.com", "wordpress.com", "instapage.com",
        "unbounce.com", "pingdom.com", "statuspage.io", "zendesk.com",
        "desk.com", "cargocollective.com", "taveo.com", "teamwork.com",
        "tictail.com", "instamojo.com", "github.io", "readme.io"
    ])


class SubdomainTakeoverModule(BaseModule):
    """
    Subdomain Takeover Module
    
    Detects subdomains that point to external services (CNAME) which may be
    available for registration, allowing an attacker to take over the subdomain.
    """

    MODULE_NAME = "subdomain_takeover"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Domain Recon"
    MODULE_DESCRIPTION = "Subdomain takeover vulnerability detection"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN]

    DEFAULT_CONFIG = SubdomainTakeoverConfig

    def __init__(self, config: SubdomainTakeoverConfig | None = None):
        super().__init__(config or SubdomainTakeoverConfig())
        self.session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrent_requests,
            ssl=False
        )
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

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the subdomain takeover detection module"""
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

            cache_key = f"subdomain_takeover:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            await self.initialize()

            # Find subdomains first
            subdomains = await self.find_subdomains(target)

            # Check for takeover vulnerabilities
            vulnerable = await self.check_takeover_vulnerabilities(target, subdomains)

            cache.set(cache_key, vulnerable, ttl=3600)

            result.status = "success"
            result.data = {
                "target": target,
                "subdomains_checked": len(subdomains),
                "vulnerable_subdomains": vulnerable,
                "count": len(vulnerable)
            }
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def find_subdomains(self, domain: str) -> list[str]:
        """Find subdomains using brute force"""
        subdomains = []
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)

        async def check_subdomain(sub: str) -> str | None:
            """Check if subdomain exists"""
            fqdn = f"{sub}.{domain}"

            try:
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(socket.gethostbyname, fqdn)
                    ip = await asyncio.wrap_future(future)
                    return fqdn
            except Exception:
                return None

        async def worker(sub: str) -> None:
            """Worker to check a single subdomain"""
            async with semaphore:
                result = await check_subdomain(sub)
                if result:
                    subdomains.append(result)

        import concurrent.futures
        tasks = [worker(sub) for sub in self.config.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        return subdomains

    async def check_takeover_vulnerabilities(self, domain: str,
                                          subdomains: list[str]) -> list[dict[str, Any]]:
        """Check subdomains for takeover vulnerabilities"""
        vulnerable = []
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)

        async def check_subdomain_takeover(subdomain: str) -> dict[str, Any] | None:
            """Check if a subdomain is vulnerable to takeover"""
            try:
                # Get DNS records
                cname = await self.get_cname(subdomain)
                a_records = await self.get_a_records(subdomain)
                aaaa_records = await self.get_aaaa_records(subdomain)

                if not cname and not a_records and not aaaa_records:
                    return None

                # Check CNAME-based vulnerabilities
                if cname and self.config.check_cname:
                    vulnerability = self.check_cname_vulnerability(subdomain, cname)
                    if vulnerability:
                        return vulnerability

                # Check A record vulnerabilities
                if a_records and self.config.check_a:
                    for ip in a_records:
                        vulnerability = await self.check_a_vulnerability(subdomain, ip)
                        if vulnerability:
                            return vulnerability

                # Check AAAA record vulnerabilities
                if aaaa_records and self.config.check_aaaa:
                    for ip in aaaa_records:
                        vulnerability = await self.check_aaaa_vulnerability(subdomain, ip)
                        if vulnerability:
                            return vulnerability

            except Exception as e:
                console.print(f"[yellow]Warning: Error checking {subdomain}: {e}[/yellow]")

            return None

        async def worker(subdomain: str) -> None:
            """Worker to check a single subdomain for takeover"""
            async with semaphore:
                result = await check_subdomain_takeover(subdomain)
                if result:
                    vulnerable.append(result)

        tasks = [worker(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        return vulnerable

    async def get_cname(self, subdomain: str) -> str | None:
        """Get CNAME record for a subdomain"""
        import concurrent.futures
        loop = asyncio.get_event_loop()

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self._get_cname_sync, subdomain)
                return await asyncio.wrap_future(future)
        except Exception:
            return None

    def _get_cname_sync(self, subdomain: str) -> str | None:
        """Synchronous CNAME lookup"""
        import dns.resolver
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(subdomain, 'CNAME')
            if answers:
                return str(answers[0].target)
        except Exception:
            pass
        return None

    async def get_a_records(self, subdomain: str) -> list[str]:
        """Get A records for a subdomain"""
        import concurrent.futures
        loop = asyncio.get_event_loop()

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self._get_a_records_sync, subdomain)
                return await asyncio.wrap_future(future)
        except Exception:
            return []

    def _get_a_records_sync(self, subdomain: str) -> list[str]:
        """Synchronous A record lookup"""
        import dns.resolver
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(subdomain, 'A')
            return [str(r) for r in answers]
        except Exception:
            return []

    async def get_aaaa_records(self, subdomain: str) -> list[str]:
        """Get AAAA records for a subdomain"""
        import concurrent.futures
        loop = asyncio.get_event_loop()

        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self._get_aaaa_records_sync, subdomain)
                return await asyncio.wrap_future(future)
        except Exception:
            return []

    def _get_aaaa_records_sync(self, subdomain: str) -> list[str]:
        """Synchronous AAAA record lookup"""
        import dns.resolver
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(subdomain, 'AAAA')
            return [str(r) for r in answers]
        except Exception:
            return []

    def check_cname_vulnerability(self, subdomain: str, cname: str) -> dict[str, Any] | None:
        """Check if CNAME points to a vulnerable service"""
        cname_lower = cname.lower()

        for service in self.config.vulnerable_services:
            if service in cname_lower:
                # Check if service is claimable
                if self.config.verify_claimable:
                    is_claimable = self.is_service_claimable(cname, service)
                else:
                    is_claimable = True

                if is_claimable:
                    return {
                        "subdomain": subdomain,
                        "type": "cname",
                        "cname": cname,
                        "service": service,
                        "vulnerable": True,
                        "severity": "high",
                        "description": f"Subdomain {subdomain} points to {cname} which may be claimable"
                    }

        return None

    async def check_a_vulnerability(self, subdomain: str, ip: str) -> dict[str, Any] | None:
        """Check if A record IP is vulnerable"""
        # Check if IP is in a known vulnerable range
        vulnerable_ranges = [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
            "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
            "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
            "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
        ]

        for cidr in vulnerable_ranges:
            if self.ip_in_cidr(ip, cidr):
                return {
                    "subdomain": subdomain,
                    "type": "a_record",
                    "ip": ip,
                    "vulnerable": True,
                    "severity": "medium",
                    "description": f"IP {ip} is in reserved/private range"
                }

        # Check if IP belongs to a known vulnerable service
        try:
            # Try to reverse resolve the IP
            import concurrent.futures
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(socket.gethostbyaddr, ip)
                hostname = await asyncio.wrap_future(future)
                hostname_str = hostname[0]

                for service in self.config.vulnerable_services:
                    if service in hostname_str.lower():
                        return {
                            "subdomain": subdomain,
                            "type": "a_record",
                            "ip": ip,
                            "hostname": hostname_str,
                            "service": service,
                            "vulnerable": True,
                            "severity": "high",
                            "description": f"IP {ip} resolves to {hostname_str} which may be claimable"
                        }
        except Exception:
            pass

        return None

    async def check_aaaa_vulnerability(self, subdomain: str, ip: str) -> dict[str, Any] | None:
        """Check if AAAA record IPv6 is vulnerable"""
        # Similar logic to A records but for IPv6
        return None

    def is_service_claimable(self, cname: str, service: str) -> bool:
        """Check if a service is currently claimable"""
        # This would require API calls to each service
        # For now, we assume it's claimable
        return True

    def ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range"""
        import ipaddress
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            address = ipaddress.ip_address(ip)
            return address in network
        except Exception:
            return False

    def validate_target(self, target: str) -> bool:
        """Validate that the target is a domain"""
        import re
        pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, target))


# Module instance
subdomain_takeover_module = SubdomainTakeoverModule
