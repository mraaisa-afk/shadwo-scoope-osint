"""
Proxy Management for SHADOWSCOPE
Handles proxy rotation, Tor integration, and user-agent spoofing.
"""

import os
import re
import json
import random
import asyncio
import aiohttp
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import requests
import threading

console = Console()


@dataclass
class ProxyConfig:
    """Configuration for a single proxy"""
    url: str
    protocol: str = "http"  # http, https, socks5
    username: Optional[str] = None
    password: Optional[str] = None
    location: Optional[str] = None
    speed: Optional[float] = None
    uptime: Optional[float] = None
    last_used: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "protocol": self.protocol,
            "username": self.username,
            "password": self.password,
            "location": self.location,
            "speed": self.speed,
            "uptime": self.uptime,
            "last_used": self.last_used,
            "success_count": self.success_count,
            "failure_count": self.failure_count
        }
    
    @classmethod
    def from_string(cls, proxy_str: str) -> "ProxyConfig":
        """Parse proxy from string (e.g., http://user:pass@host:port)"""
        # Parse protocol
        protocol = "http"
        if "://" in proxy_str:
            protocol, proxy_str = proxy_str.split("://", 1)
        
        # Parse auth and host
        username = None
        password = None
        host_port = proxy_str
        
        if "@" in proxy_str:
            auth, host_port = proxy_str.split("@", 1)
            if ":" in auth:
                username, password = auth.split(":", 1)
            else:
                username = auth
        
        return cls(
            url=f"{protocol}://{host_port}",
            protocol=protocol,
            username=username,
            password=password
        )
    
    def get_proxy_url(self) -> str:
        """Get full proxy URL with authentication"""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.url.split('://')[-1]}"
        return self.url
    
    def get_aiohttp_proxy(self) -> str:
        """Get proxy URL for aiohttp"""
        if self.protocol == "socks5":
            return f"socks5://{self.url.split('://')[-1]}"
        return self.url


@dataclass
class ProxyStats:
    """Statistics for proxy usage"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_time: float = 0.0
    avg_response_time: float = 0.0
    proxies_tested: int = 0
    working_proxies: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "total_time": self.total_time,
            "avg_response_time": self.avg_response_time,
            "proxies_tested": self.proxies_tested,
            "working_proxies": self.working_proxies
        }


class ProxyPool:
    """Manages a pool of proxies with rotation and failover"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self._proxies: List[ProxyConfig] = []
        self._current_index = 0
        self._lock = threading.Lock()
        self._stats = ProxyStats()
        self._user_agents: List[str] = []
        self._init_proxies()
        self._init_user_agents()
    
    def _init_proxies(self):
        """Initialize proxies from configuration"""
        # Add HTTP proxies
        for proxy_url in self.config.proxy.http:
            self._proxies.append(ProxyConfig.from_string(proxy_url))
        
        # Add HTTPS proxies
        for proxy_url in self.config.proxy.https:
            self._proxies.append(ProxyConfig.from_string(proxy_url))
        
        # Add SOCKS5 proxies
        for proxy_url in self.config.proxy.socks5:
            self._proxies.append(ProxyConfig.from_string(proxy_url))
        
        # Add Tor if enabled
        if self.config.api.tor.get('enabled', False):
            tor_port = self.config.api.tor.get('port', 9050)
            self._proxies.append(ProxyConfig(
                url=f"socks5://127.0.0.1:{tor_port}",
                protocol="socks5",
                location="Tor Network"
            ))
        
        console.print(f"[green]+[/green] Loaded {len(self._proxies)} proxies")
    
    def _init_user_agents(self):
        """Initialize user agents"""
        # Default user agents
        default_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        ]
        
        # Add configured user agents
        self._user_agents = list(set(self.config.proxy.user_agents + default_uas))
    
    def add_proxy(self, proxy: Union[str, ProxyConfig]) -> ProxyConfig:
        """Add a proxy to the pool"""
        with self._lock:
            if isinstance(proxy, str):
                proxy = ProxyConfig.from_string(proxy)
            
            # Check for duplicates
            for existing in self._proxies:
                if existing.url == proxy.url:
                    return existing
            
            self._proxies.append(proxy)
            console.print(f"[green]+[/green] Added proxy: {proxy.url}")
            return proxy
    
    def remove_proxy(self, proxy: Union[str, ProxyConfig]) -> bool:
        """Remove a proxy from the pool"""
        with self._lock:
            if isinstance(proxy, str):
                proxy_url = proxy
            else:
                proxy_url = proxy.url
            
            for i, p in enumerate(self._proxies):
                if p.url == proxy_url:
                    self._proxies.pop(i)
                    console.print(f"[red]-[/red] Removed proxy: {proxy_url}")
                    return True
        return False
    
    def get_proxy(self, protocol: Optional[str] = None) -> Optional[ProxyConfig]:
        """Get a proxy from the pool with rotation"""
        with self._lock:
            if not self._proxies:
                return None
            
            # Filter by protocol if specified
            if protocol:
                filtered = [p for p in self._proxies if p.protocol == protocol]
                if not filtered:
                    return None
                proxies = filtered
            else:
                proxies = self._proxies
            
            # Round-robin rotation
            proxy = proxies[self._current_index % len(proxies)]
            self._current_index += 1
            
            # Update last used time
            proxy.last_used = datetime.now().isoformat()
            
            return proxy
    
    def get_random_proxy(self, protocol: Optional[str] = None) -> Optional[ProxyConfig]:
        """Get a random proxy from the pool"""
        with self._lock:
            if not self._proxies:
                return None
            
            # Filter by protocol if specified
            if protocol:
                filtered = [p for p in self._proxies if p.protocol == protocol]
                if not filtered:
                    return None
                proxies = filtered
            else:
                proxies = self._proxies
            
            return random.choice(proxies)
    
    def get_working_proxy(self, protocol: Optional[str] = None, 
                          test_url: str = "http://httpbin.org/ip") -> Optional[ProxyConfig]:
        """Get a working proxy (tests proxies if needed)"""
        with self._lock:
            if not self._proxies:
                return None
            
            # Filter by protocol if specified
            if protocol:
                proxies = [p for p in self._proxies if p.protocol == protocol]
            else:
                proxies = self._proxies
            
            # Sort by success rate (descending)
            proxies.sort(key=lambda p: p.success_count - p.failure_count, reverse=True)
            
            # Try each proxy until we find a working one
            for proxy in proxies:
                if self._test_proxy(proxy, test_url):
                    return proxy
            
            return None
    
    def _test_proxy(self, proxy: ProxyConfig, test_url: str = "http://httpbin.org/ip") -> bool:
        """Test if a proxy is working"""
        try:
            proxies = {
                "http": proxy.get_proxy_url(),
                "https": proxy.get_proxy_url()
            }
            
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                proxy.success_count += 1
                return True
            else:
                proxy.failure_count += 1
                return False
                
        except Exception:
            proxy.failure_count += 1
            return False
    
    def get_user_agent(self) -> str:
        """Get a random user agent"""
        if self._user_agents:
            return random.choice(self._user_agents)
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    def get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers with random user agent"""
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1"
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def get_session(self, proxy: Optional[ProxyConfig] = None) -> requests.Session:
        """Get a requests session with proxy and headers"""
        session = requests.Session()
        
        # Set headers
        session.headers.update(self.get_headers())
        
        # Set proxy if specified
        if proxy:
            proxies = {
                "http": proxy.get_proxy_url(),
                "https": proxy.get_proxy_url()
            }
            session.proxies.update(proxies)
        elif self._proxies:
            # Use rotation if no specific proxy
            current_proxy = self.get_proxy()
            if current_proxy:
                proxies = {
                    "http": current_proxy.get_proxy_url(),
                    "https": current_proxy.get_proxy_url()
                }
                session.proxies.update(proxies)
        
        return session
    
    async def get_async_session(self, proxy: Optional[ProxyConfig] = None) -> aiohttp.ClientSession:
        """Get an aiohttp session with proxy and headers"""
        headers = self.get_headers()
        
        if proxy:
            proxy_url = proxy.get_aiohttp_proxy()
            connector = aiohttp.TCPConnector(ssl=False)
            return aiohttp.ClientSession(
                headers=headers,
                connector=connector
            )
        else:
            return aiohttp.ClientSession(headers=headers)
    
    def rotate_proxy(self) -> Optional[ProxyConfig]:
        """Rotate to the next proxy"""
        with self._lock:
            if not self._proxies:
                return None
            
            self._current_index = (self._current_index + 1) % len(self._proxies)
            return self._proxies[self._current_index]
    
    def get_all_proxies(self) -> List[ProxyConfig]:
        """Get all proxies in the pool"""
        with self._lock:
            return list(self._proxies)
    
    def get_stats(self) -> ProxyStats:
        """Get proxy usage statistics"""
        with self._lock:
            return self._stats
    
    def clear_stats(self):
        """Clear proxy statistics"""
        with self._lock:
            self._stats = ProxyStats()
            for proxy in self._proxies:
                proxy.success_count = 0
                proxy.failure_count = 0
    
    def add_proxies_from_file(self, file_path: str) -> int:
        """Add proxies from a file"""
        file_path = Path(file_path)
        count = 0
        
        if not file_path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            return 0
        
        content = file_path.read_text()
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                self.add_proxy(line)
                count += 1
        
        console.print(f"[green]+[/green] Added {count} proxies from {file_path}")
        return count
    
    def add_proxies_from_url(self, url: str) -> int:
        """Add proxies from a URL (e.g., proxy list API)"""
        try:
            response = requests.get(url, timeout=30)
            
            if response.status_code != 200:
                console.print(f"[red]Error: Could not fetch proxies from {url}[/red]")
                return 0
            
            # Try to parse as JSON
            try:
                data = response.json()
                if isinstance(data, list):
                    proxies = data
                elif isinstance(data, dict):
                    proxies = data.get('proxies', data.get('data', []))
                else:
                    proxies = []
            except json.JSONDecodeError:
                # Treat as text
                proxies = response.text.split('\n')
            
            count = 0
            for proxy in proxies:
                if isinstance(proxy, dict):
                    proxy_str = proxy.get('url') or proxy.get('ip')
                    if proxy_str:
                        self.add_proxy(proxy_str)
                        count += 1
                elif isinstance(proxy, str):
                    proxy = proxy.strip()
                    if proxy:
                        self.add_proxy(proxy)
                        count += 1
            
            console.print(f"[green]+[/green] Added {count} proxies from {url}")
            return count
            
        except Exception as e:
            console.print(f"[red]Error adding proxies from URL: {e}[/red]")
            return 0


class TorManager:
    """Manages Tor integration"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self._tor_available = False
        self._tor_process = None
        self._init_tor()
    
    def _init_tor(self):
        """Initialize Tor"""
        try:
            # Check if Tor is already running
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            port = self.config.api.tor.get('port', 9050)
            result = sock.connect_ex(('127.0.0.1', port))
            
            if result == 0:
                self._tor_available = True
                console.print("[green]+[/green] Tor is running")
            else:
                # Try to start Tor
                if self._start_tor():
                    self._tor_available = True
                    console.print("[green]+[/green] Tor started successfully")
                else:
                    console.print("[yellow]Tor not available[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Tor initialization error: {e}[/yellow]")
    
    def _start_tor(self) -> bool:
        """Start Tor process"""
        try:
            # Try different Tor commands
            for cmd in ["tor", "tor.browser", "/usr/bin/tor"]:
                try:
                    self._tor_process = subprocess.Popen(
                        [cmd],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    
                    # Wait for Tor to start
                    import time
                    time.sleep(5)
                    
                    # Check if port is open
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    port = self.config.api.tor.get('port', 9050)
                    result = sock.connect_ex(('127.0.0.1', port))
                    
                    if result == 0:
                        return True
                    else:
                        self._tor_process.terminate()
                        self._tor_process = None
                except FileNotFoundError:
                    continue
            
            return False
            
        except Exception as e:
            console.print(f"[red]Error starting Tor: {e}[/red]")
            return False
    
    def is_available(self) -> bool:
        """Check if Tor is available"""
        return self._tor_available
    
    def get_socks5_proxy(self) -> Optional[ProxyConfig]:
        """Get Tor SOCKS5 proxy configuration"""
        if self._tor_available:
            port = self.config.api.tor.get('port', 9050)
            return ProxyConfig(
                url=f"socks5://127.0.0.1:{port}",
                protocol="socks5",
                location="Tor Network"
            )
        return None
    
    def get_http_proxy(self, port: int = 8118) -> Optional[ProxyConfig]:
        """Get Tor HTTP proxy (Privoxy) configuration"""
        if self._tor_available:
            return ProxyConfig(
                url=f"http://127.0.0.1:{port}",
                protocol="http",
                location="Tor Network (HTTP)"
            )
        return None
    
    def change_identity(self) -> bool:
        """Change Tor identity (new circuit)"""
        try:
            control_port = self.config.api.tor.get('control_port', 9051)
            password = self.config.api.tor.get('password', '')
            
            # Send SIGNAL NEWNYM to Tor
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', control_port))
            
            # Authenticate
            if password:
                sock.send(f"AUTHENTICATE {password}\r\n".encode())
                response = sock.recv(1024).decode()
                if "250 OK" not in response:
                    sock.close()
                    return False
            
            # Send NEWNYM signal
            sock.send(b"SIGNAL NEWNYM\r\n")
            response = sock.recv(1024).decode()
            sock.close()
            
            if "250 OK" in response:
                console.print("[green]+[/green] Tor identity changed")
                return True
            
            return False
            
        except Exception as e:
            console.print(f"[yellow]Error changing Tor identity: {e}[/yellow]")
            return False
    
    def stop(self) -> bool:
        """Stop Tor"""
        if self._tor_process:
            try:
                self._tor_process.terminate()
                self._tor_process.wait(timeout=10)
                self._tor_process = None
                self._tor_available = False
                console.print("[yellow]-[/yellow] Tor stopped")
                return True
            except Exception as e:
                console.print(f"[red]Error stopping Tor: {e}[/red]")
                return False
        return True


class CAPTCHAManager:
    """Manages CAPTCHA solving services"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self._providers = {
            "2captcha": {
                "api_key": self.config.api.get("2captcha", {}).get("api_key"),
                "enabled": self.config.api.get("2captcha", {}).get("enabled", False)
            },
            "anti_captcha": {
                "api_key": self.config.api.get("anti_captcha", {}).get("api_key"),
                "enabled": self.config.api.get("anti_captcha", {}).get("enabled", False)
            },
            "deathbycaptcha": {
                "api_key": self.config.api.get("deathbycaptcha", {}).get("api_key"),
                "enabled": self.config.api.get("deathbycaptcha", {}).get("enabled", False)
            }
        }
    
    async def solve_captcha(self, captcha_data: Union[str, Dict[str, Any]], 
                          provider: str = "2captcha") -> Optional[str]:
        """Solve a CAPTCHA using the specified provider"""
        if provider not in self._providers:
            console.print(f"[red]CAPTCHA provider {provider} not available[/red]")
            return None
        
        if not self._providers[provider].get("enabled"):
            console.print(f"[yellow]CAPTCHA provider {provider} is disabled[/yellow]")
            return None
        
        api_key = self._providers[provider].get("api_key")
        if not api_key:
            console.print(f"[yellow]No API key for CAPTCHA provider {provider}[/yellow]")
            return None
        
        try:
            if provider == "2captcha":
                return await self._solve_2captcha(captcha_data, api_key)
            elif provider == "anti_captcha":
                return await self._solve_anti_captcha(captcha_data, api_key)
            elif provider == "deathbycaptcha":
                return await self._solve_deathbycaptcha(captcha_data, api_key)
        except Exception as e:
            console.print(f"[red]Error solving CAPTCHA: {e}[/red]")
        
        return None
    
    async def _solve_2captcha(self, captcha_data: Union[str, Dict[str, Any]], 
                              api_key: str) -> Optional[str]:
        """Solve CAPTCHA using 2Captcha"""
        import base64
        
        # Prepare request
        if isinstance(captcha_data, str):
            # Assume it's a base64 encoded image
            method = "base64"
            body = {
                "key": api_key,
                "method": method,
                "body": captcha_data,
                "json": 1
            }
        elif isinstance(captcha_data, dict):
            # Handle different CAPTCHA types
            if captcha_data.get("type") == "image":
                method = "base64"
                body = {
                    "key": api_key,
                    "method": method,
                    "body": captcha_data.get("image"),
                    "json": 1
                }
            elif captcha_data.get("type") == "recaptcha":
                method = "userrecaptcha"
                body = {
                    "key": api_key,
                    "method": method,
                    "googlekey": captcha_data.get("sitekey"),
                    "pageurl": captcha_data.get("pageurl"),
                    "json": 1
                }
            else:
                return None
        else:
            return None
        
        # Send request
        try:
            response = requests.post("https://2captcha.com/in.php", data=body, timeout=30)
            result = response.json()
            
            if result.get("status") == 1:
                captcha_id = result.get("request")
                
                # Poll for result
                for _ in range(30):  # 30 attempts with 5 second delay
                    await asyncio.sleep(5)
                    
                    poll_response = requests.get(
                        f"https://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}&json=1",
                        timeout=10
                    )
                    poll_result = poll_response.json()
                    
                    if poll_result.get("status") == 1:
                        return poll_result.get("request")
                    elif poll_result.get("request") == "CAPCHA_NOT_READY":
                        continue
                    else:
                        console.print(f"[yellow]2Captcha error: {poll_result.get('request')}[/yellow]")
                        return None
            else:
                console.print(f"[yellow]2Captcha error: {result.get('request')}[/yellow]")
        except Exception as e:
            console.print(f"[red]2Captcha request failed: {e}[/red]")
        
        return None
    
    async def _solve_anti_captcha(self, captcha_data: Union[str, Dict[str, Any]], 
                                  api_key: str) -> Optional[str]:
        """Solve CAPTCHA using Anti-Captcha"""
        # Similar implementation for Anti-Captcha
        # Placeholder - would need Anti-Captcha API integration
        console.print("[yellow]Anti-Captcha not yet implemented[/yellow]")
        return None
    
    async def _solve_deathbycaptcha(self, captcha_data: Union[str, Dict[str, Any]], 
                                     api_key: str) -> Optional[str]:
        """Solve CAPTCHA using DeathByCaptcha"""
        # Similar implementation for DeathByCaptcha
        # Placeholder - would need DeathByCaptcha API integration
        console.print("[yellow]DeathByCaptcha not yet implemented[/yellow]")
        return None
    
    def get_balance(self, provider: str = "2captcha") -> Optional[float]:
        """Get account balance for a CAPTCHA provider"""
        if provider not in self._providers:
            return None
        
        api_key = self._providers[provider].get("api_key")
        if not api_key:
            return None
        
        try:
            if provider == "2captcha":
                response = requests.get(
                    f"https://2captcha.com/res.php?key={api_key}&action=getbalance&json=1",
                    timeout=10
                )
                result = response.json()
                if result.get("status") == 1:
                    return float(result.get("request", 0))
        except Exception:
            pass
        
        return None


class ProxyManager:
    """Main proxy manager that combines all proxy functionality"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self.pool = ProxyPool(config)
        self.tor = TorManager(config)
        self.captcha = CAPTCHAManager(config)
        self._dns_over_https = True
        self._doh_providers = [
            "https://1.1.1.1/dns-query",  # Cloudflare
            "https://8.8.8.8/dns-query",   # Google
            "https://9.9.9.9/dns-query"   # Quad9
        ]
    
    def get_proxy(self, protocol: Optional[str] = None, 
                  prefer_working: bool = True) -> Optional[ProxyConfig]:
        """Get a proxy for use"""
        if prefer_working:
            return self.pool.get_working_proxy(protocol)
        return self.pool.get_proxy(protocol)
    
    def get_random_proxy(self, protocol: Optional[str] = None) -> Optional[ProxyConfig]:
        """Get a random proxy"""
        return self.pool.get_random_proxy(protocol)
    
    def get_session(self, use_proxy: bool = True) -> requests.Session:
        """Get a requests session with proxy and headers"""
        if use_proxy:
            proxy = self.get_proxy()
            return self.pool.get_session(proxy)
        return self.pool.get_session()
    
    async def get_async_session(self, use_proxy: bool = True) -> aiohttp.ClientSession:
        """Get an aiohttp session with proxy and headers"""
        if use_proxy:
            proxy = self.get_proxy()
            return await self.pool.get_async_session(proxy)
        return await self.pool.get_async_session()
    
    def get_user_agent(self) -> str:
        """Get a random user agent"""
        return self.pool.get_user_agent()
    
    def get_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers with random user agent"""
        return self.pool.get_headers(custom_headers)
    
    def rotate_identity(self) -> bool:
        """Rotate proxy and user agent"""
        self.pool.rotate_proxy()
        return True
    
    def use_tor(self) -> bool:
        """Switch to using Tor"""
        if self.tor.is_available():
            return True
        return self.tor._start_tor()
    
    def change_tor_identity(self) -> bool:
        """Change Tor identity"""
        return self.tor.change_identity()
    
    def set_dns_over_https(self, enabled: bool = True, 
                          provider: str = "cloudflare") -> bool:
        """Enable/disable DNS over HTTPS"""
        self._dns_over_https = enabled
        
        if provider.lower() == "cloudflare":
            self._doh_providers = ["https://1.1.1.1/dns-query"]
        elif provider.lower() == "google":
            self._doh_providers = ["https://8.8.8.8/dns-query"]
        elif provider.lower() == "quad9":
            self._doh_providers = ["https://9.9.9.9/dns-query"]
        
        console.print(f"[green]+[/green] DNS over HTTPS {'enabled' if enabled else 'disabled'} with {provider}")
        return True
    
    def resolve_dns(self, hostname: str) -> Optional[str]:
        """Resolve DNS using DoH"""
        if not self._dns_over_https:
            import socket
            try:
                return socket.gethostbyname(hostname)
            except:
                return None
        
        import dns.resolver
        
        for provider in self._doh_providers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [provider]
                answer = resolver.resolve(hostname, 'A')
                if answer:
                    return str(answer[0])
            except Exception:
                continue
        
        return None
    
    async def solve_captcha(self, captcha_data: Union[str, Dict[str, Any]], 
                          provider: str = "2captcha") -> Optional[str]:
        """Solve a CAPTCHA"""
        return await self.captcha.solve_captcha(captcha_data, provider)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get proxy statistics"""
        return {
            "pool": self.pool.get_stats(),
            "tor_available": self.tor.is_available(),
            "dns_over_https": self._dns_over_https,
            "doh_provider": self._doh_providers[0] if self._doh_providers else None
        }


# Initialize proxy manager
proxy = ProxyManager()
