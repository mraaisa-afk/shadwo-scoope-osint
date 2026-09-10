"""
I2P Crawler Module for SHADOWSCOPE
Crawls I2P network for hidden services and content.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import re

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class I2PCrawlerConfig(ModuleConfig):
    """Configuration for I2P crawler module"""
    i2p_proxy: str = "http://127.0.0.1:4444"
    i2p_proxy_http: str = "http://127.0.0.1:4444"
    i2p_proxy_https: str = "http://127.0.0.1:4445"
    timeout: float = 60.0
    use_i2p: bool = True
    max_retries: int = 3
    max_depth: int = 2
    max_pages: int = 50
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    crawl_delay: float = 1.0
    
    def __post_init__(self):
        # Ensure proxy URLs are properly formatted
        if not self.i2p_proxy.startswith("http://") and not self.i2p_proxy.startswith("https://"):
            self.i2p_proxy = f"http://{self.i2p_proxy}"
        if not self.i2p_proxy_http.startswith("http://") and not self.i2p_proxy_http.startswith("https://"):
            self.i2p_proxy_http = f"http://{self.i2p_proxy_http}"
        if not self.i2p_proxy_https.startswith("http://") and not self.i2p_proxy_https.startswith("https://"):
            self.i2p_proxy_https = f"http://{self.i2p_proxy_https}"


class I2PCrawlerModule(BaseModule):
    """
    I2P Crawler Module
    
    Crawls I2P network for hidden services and content.
    Uses I2P proxy to access .i2p and .b32.i2p addresses.
    """
    
    MODULE_NAME = "i2p_crawler"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Dark Web"
    MODULE_DESCRIPTION = "I2P network crawling and hidden service discovery"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.I2P]
    
    DEFAULT_CONFIG = I2PCrawlerConfig
    
    def __init__(self, config: Optional[I2PCrawlerConfig] = None):
        super().__init__(config or I2PCrawlerConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.i2p_session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: set = set()
        self.discovered_urls: set = set()
    
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
                proxy=proxy_url,
                headers={"User-Agent": self.config.user_agent}
            )
        else:
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": self.config.user_agent}
            )
        
        # I2P session
        try:
            if self.config.use_i2p:
                # Use the HTTP proxy for both HTTP and HTTPS
                self.i2p_session = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=timeout,
                    proxy=self.config.i2p_proxy_http
                )
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to initialize I2P session: {e}[/yellow]")
            self.i2p_session = None
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the I2P crawler module"""
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
            
            # Normalize I2P address
            i2p_url = self.normalize_i2p(target)
            
            # Check cache
            cache_key = f"i2p_crawler:{i2p_url}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Crawl I2P
            crawl_data = await self.crawl_i2p(i2p_url)
            
            # Store in cache
            cache.set(cache_key, crawl_data, ttl=3600)  # 1 hour
            
            result.status = "success"
            result.data = crawl_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
            if self.i2p_session:
                await self.i2p_session.close()
        
        return result
    
    def normalize_i2p(self, target: str) -> str:
        """Normalize I2P address"""
        # Remove protocol if present
        i2p = target.replace("http://", "").replace("https://", "")
        
        # Remove path if present
        i2p = i2p.split("/")[0]
        
        # Remove port if present
        i2p = i2p.split(":")[0]
        
        # Ensure it ends with .i2p or .b32.i2p
        if not i2p.endswith(".i2p") and not i2p.endswith(".b32.i2p"):
            # Try to determine the correct suffix
            if len(i2p) == 52:  # b32 address
                i2p = f"{i2p}.b32.i2p"
            else:
                i2p = f"{i2p}.i2p"
        
        # Add http:// prefix
        if not i2p.startswith("http://") and not i2p.startswith("https://"):
            i2p = f"http://{i2p}"
        
        return i2p.lower()
    
    async def crawl_i2p(self, start_url: str) -> Dict[str, Any]:
        """Crawl I2P starting from a URL"""
        data = {
            "start_url": start_url,
            "visited": [],
            "discovered": [],
            "pages": [],
            "links": [],
            "domains": [],
            "analysis": {}
        }
        
        # Reset visited and discovered sets
        self.visited_urls = set()
        self.discovered_urls = set()
        
        # Start crawling
        await self.crawl_page(start_url, depth=0, max_depth=self.config.max_depth)
        
        # Convert sets to lists
        data["visited"] = list(self.visited_urls)
        data["discovered"] = list(self.discovered_urls)
        
        # Analyze the data
        data["analysis"] = self.analyze_crawl_data(data)
        
        return data
    
    async def crawl_page(self, url: str, depth: int, max_depth: int) -> None:
        """Crawl a single page"""
        # Check if we've reached max depth
        if depth > max_depth:
            return
        
        # Check if we've already visited this URL
        if url in self.visited_urls:
            return
        
        # Check if we've reached max pages
        if len(self.visited_urls) >= self.config.max_pages:
            return
        
        # Add to visited
        self.visited_urls.add(url)
        
        # Check if this is an I2P URL
        if not self.is_i2p_url(url):
            return
        
        try:
            # Fetch the page
            async with self.i2p_session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    # Parse the page
                    page_data = await self.parse_page(url, html, depth)
                    
                    # Extract links
                    links = self.extract_links(html, url)
                    
                    # Add discovered URLs
                    for link in links:
                        if link not in self.visited_urls and link not in self.discovered_urls:
                            self.discovered_urls.add(link)
                            
                            # Crawl the link if within depth limit
                            if depth < max_depth:
                                await self.crawl_page(link, depth + 1, max_depth)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to crawl {url}: {e}[/yellow]")
        
        # Delay between requests
        await asyncio.sleep(self.config.crawl_delay)
    
    async def parse_page(self, url: str, html: str, depth: int) -> Dict[str, Any]:
        """Parse a page and extract information"""
        page_data = {
            "url": url,
            "depth": depth,
            "status_code": 200,
            "content_type": None,
            "content_length": len(html),
            "title": None,
            "links": [],
            "keywords": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract title
            title_element = soup.find("title")
            if title_element:
                page_data["title"] = title_element.get_text().strip()
            
            # Extract content type
            meta_content_type = soup.find("meta", {"http-equiv": "Content-Type"})
            if meta_content_type:
                page_data["content_type"] = meta_content_type.get("content", "")
            
            # Extract keywords
            meta_keywords = soup.find("meta", {"name": "keywords"})
            if meta_keywords:
                page_data["keywords"] = meta_keywords.get("content", "").split(",")
            
        except Exception as e:
            page_data["error"] = str(e)
        
        return page_data
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract all anchor tags
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                
                # Skip empty and javascript links
                if not href or href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                    continue
                
                # Join with base URL
                full_url = urljoin(base_url, href)
                
                # Normalize URL
                full_url = self.normalize_url(full_url)
                
                # Only include I2P URLs
                if self.is_i2p_url(full_url):
                    links.append(full_url)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to extract links: {e}[/yellow]")
        
        return links
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL"""
        # Remove fragment
        url = url.split("#")[0]
        
        # Remove query parameters
        url = url.split("?")[0]
        
        # Ensure trailing slash
        if not url.endswith("/"):
            url = f"{url}/"
        
        return url
    
    def is_i2p_url(self, url: str) -> bool:
        """Check if URL is an I2P URL"""
        # Check for .i2p or .b32.i2p
        if ".i2p" in url or ".b32.i2p" in url:
            return True
        
        # Check for localhost proxy URLs
        if "127.0.0.1" in url or "localhost" in url:
            return True
        
        return False
    
    def analyze_crawl_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze crawl data"""
        analysis = {
            "start_url": data["start_url"],
            "total_visited": len(data["visited"]),
            "total_discovered": len(data["discovered"]),
            "total_pages": len(data["pages"]),
            "total_links": len(data["links"]),
            "total_domains": len(data["domains"]),
            "average_depth": 0.0,
            "max_depth": 0,
            "is_active": False,
            "recommendations": []
        }
        
        # Calculate average depth
        if data["pages"]:
            depths = [page.get("depth", 0) for page in data["pages"]]
            analysis["average_depth"] = sum(depths) / len(depths)
            analysis["max_depth"] = max(depths)
        
        # Check if active
        if analysis["total_visited"] > 0:
            analysis["is_active"] = True
        
        # Generate recommendations
        if analysis["is_active"]:
            analysis["recommendations"].append(
                f"ACTIVE: Crawled {analysis['total_visited']} pages"
            )
        else:
            analysis["recommendations"].append(
                "No pages crawled - check I2P proxy configuration"
            )
        
        if analysis["total_discovered"] > analysis["total_visited"]:
            analysis["recommendations"].append(
                f"DISCOVERED: Found {analysis['total_discovered'] - analysis['total_visited']} additional URLs"
            )
        
        if analysis["average_depth"] > 1:
            analysis["recommendations"].append(
                f"DEEP: Average crawl depth of {analysis['average_depth']:.1f}"
            )
        
        if analysis["total_domains"] > 1:
            analysis["recommendations"].append(
                f"MULTI-DOMAIN: Found content on {analysis['total_domains']} domains"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's a URL with .i2p or .b32.i2p
        url_pattern = r"^https?://[a-zA-Z0-9.-]+(\.i2p|\.b32\.i2p)(/[^\s]*)?$"
        if re.match(url_pattern, target):
            return TargetType.URL
        
        # Check if it's an I2P address
        i2p_pattern = r"^[a-zA-Z0-9.-]+(\.i2p|\.b32\.i2p)$"
        if re.match(i2p_pattern, target):
            return TargetType.I2P
        
        return None


# Module instance
i2p_crawler_module = I2PCrawlerModule
