"""
DNS Brute Force Module for SHADOWSCOPE
Performs DNS brute-forcing with custom wordlists to discover subdomains.
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
class DNSBruteConfig(ModuleConfig):
    """Configuration for DNS brute force module"""
    wordlist: list[str] = field(default_factory=lambda: [
        "admin", "api", "beta", "blog", "cdn", "dev", "docs", "forum",
        "ftp", "git", "mail", "m", "mobile", "news", "old", "portal",
        "secure", "shop", "staging", "static", "test", "vpn", "web", "www",
        "app", "apps", "assets", "backup", "beta", "cgi", "cloud", "config",
        "demo", "download", "files", "help", "img", "images", "info", "intra",
        "login", "media", "ns1", "ns2", "ns3", "ns4", "office", "online",
        "phpmyadmin", "pop", "pop3", "proxy", "public", "remote", "smtp",
        "sql", "ssh", "stage", "stats", "status", "store", "support",
        "tmp", "tools", "upload", "video", "vpn", "webmail", "wiki"
    ])
    wordlist_url: str | None = None
    concurrent_requests: int = 50
    timeout: float = 5.0
    use_proxy: bool = True
    resolve_ip: bool = True
    filter_wildcard: bool = True


class DNSBruteModule(BaseModule):
    """
    DNS Brute Force Module
    
    Discovers subdomains by brute-forcing common prefixes against a target domain.
    Supports custom wordlists, concurrent requests, and proxy rotation.
    """

    MODULE_NAME = "dns_brute"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Domain Recon"
    MODULE_DESCRIPTION = "DNS brute-forcing with custom wordlists"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN]

    DEFAULT_CONFIG = DNSBruteConfig

    def __init__(self, config: DNSBruteConfig | None = None):
        super().__init__(config or DNSBruteConfig())
        self.session: aiohttp.ClientSession | None = None
        self.wordlist: list[str] = []

    async def initialize(self) -> None:
        """Initialize the module"""
        # Load wordlist
        if self.config.wordlist_url:
            self.wordlist = await self.load_wordlist_from_url(self.config.wordlist_url)
        else:
            self.wordlist = self.config.wordlist

        # Create HTTP session with proxy support
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

    async def load_wordlist_from_url(self, url: str) -> list[str]:
        """Load wordlist from a URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        return [line.strip() for line in content.splitlines() if line.strip()]
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load wordlist from {url}: {e}[/yellow]")
        return self.config.wordlist

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the DNS brute force module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            # Validate target
            if not self.validate_target(target):
                result.status = "error"
                result.error = f"Invalid target: {target}. Expected domain."
                return result

            # Check cache
            cache_key = f"dns_brute:{target}:{hash(frozenset(self.wordlist))}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Run brute force
            subdomains = await self.brute_force_dns(target)

            # Filter wildcards
            if self.config.filter_wildcard:
                subdomains = await self.filter_wildcards(target, subdomains)

            # Resolve IPs if enabled
            if self.config.resolve_ip:
                subdomains = await self.resolve_ips(subdomains)

            # Store in cache
            cache.set(cache_key, subdomains, ttl=3600)

            result.status = "success"
            result.data = {
                "target": target,
                "subdomains": subdomains,
                "count": len(subdomains),
                "wordlist_size": len(self.wordlist)
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

    async def brute_force_dns(self, domain: str) -> list[dict[str, Any]]:
        """Perform DNS brute forcing"""
        results = []
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)

        async def check_subdomain(sub: str) -> dict[str, Any] | None:
            """Check if a subdomain exists"""
            fqdn = f"{sub}.{domain}"

            try:
                # Try to resolve the subdomain
                loop = asyncio.get_event_loop()
                resolver = loop.getaddrinfo

                # Use thread pool for DNS resolution (aiohttp doesn't support UDP)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        socket.gethostbyname_ex,
                        fqdn
                    )
                    try:
                        ip = await asyncio.wrap_future(future)
                        return {
                            "subdomain": fqdn,
                            "ip": ip[2][0] if ip[2] else None,
                            "resolved": True
                        }
                    except socket.gaierror:
                        return None
                    except Exception:
                        return None

            except Exception:
                return None

            return None

        async def worker(sub: str) -> None:
            """Worker to check a single subdomain"""
            async with semaphore:
                result = await check_subdomain(sub)
                if result:
                    results.append(result)

        # Create tasks for all subdomains
        tasks = [worker(sub) for sub in self.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        return results

    async def filter_wildcards(self, domain: str, subdomains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter out wildcard DNS entries"""
        if len(subdomains) < 3:
            return subdomains

        # Check if all IPs are the same (wildcard)
        unique_ips = set(s.get("ip") for s in subdomains if s.get("ip"))
        if len(unique_ips) == 1:
            # All resolve to same IP - likely wildcard
            # Keep only common subdomains
            common = ["www", "mail", "ftp", "api", "web", "app", "m"]
            return [s for s in subdomains if s["subdomain"].split(".")[0] in common]

        return subdomains

    async def resolve_ips(self, subdomains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Resolve IPs for all subdomains"""
        for sub in subdomains:
            if not sub.get("ip"):
                try:
                    import concurrent.futures
                    loop = asyncio.get_event_loop()
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(socket.gethostbyname_ex, sub["subdomain"])
                        ip = await asyncio.wrap_future(future)
                        sub["ip"] = ip[2][0] if ip[2] else None
                except Exception:
                    sub["ip"] = None
        return subdomains

    def validate_target(self, target: str) -> bool:
        """Validate that the target is a domain"""
        # Simple domain validation
        if not target or len(target) > 253:
            return False

        # Check for valid domain characters
        import re
        pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, target))


# Module instance
dns_brute_module = DNSBruteModule
