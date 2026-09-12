"""
Marketplace Scraper Module for SHADOWSCOPE
Scrapes darknet marketplaces for products, vendors, and reviews.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
from bs4 import BeautifulSoup
from rich.console import Console

from shadowscope.core import proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class MarketplaceScraperConfig(ModuleConfig):
    """Configuration for marketplace scraper module"""
    tor_proxy: str = "socks5://127.0.0.1:9050"
    i2p_proxy: str = "http://127.0.0.1:4444"
    timeout: float = 120.0
    max_depth: int = 3
    max_pages: int = 50
    max_concurrent_requests: int = 10
    scrape_products: bool = True
    scrape_vendors: bool = True
    scrape_reviews: bool = True
    scrape_categories: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

    def __post_init__(self):
        if not self.tor_proxy.startswith("socks"):
            self.tor_proxy = f"socks5://{self.tor_proxy}"


@dataclass
class ProductInfo:
    """Information about a marketplace product"""
    name: str
    price: float | None = None
    currency: str = "BTC"
    description: str = ""
    category: str = ""
    vendor: str = ""
    rating: float | None = None
    num_reviews: int = 0
    stock: int | None = None
    shipping_from: str = ""
    shipping_to: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    listed_date: str | None = None
    last_updated: str | None = None
    product_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "price": self.price,
            "currency": self.currency,
            "description": self.description,
            "category": self.category,
            "vendor": self.vendor,
            "rating": self.rating,
            "num_reviews": self.num_reviews,
            "stock": self.stock,
            "shipping_from": self.shipping_from,
            "shipping_to": self.shipping_to,
            "images": self.images,
            "listed_date": self.listed_date,
            "last_updated": self.last_updated,
            "product_url": self.product_url
        }


@dataclass
class VendorInfo:
    """Information about a marketplace vendor"""
    username: str
    pgp_key: str = ""
    join_date: str | None = None
    last_active: str | None = None
    total_sales: int = 0
    total_revenue: float = 0.0
    rating: float | None = None
    num_reviews: int = 0
    num_products: int = 0
    shipping_origin: str = ""
    description: str = ""
    vendor_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "pgp_key": self.pgp_key,
            "join_date": self.join_date,
            "last_active": self.last_active,
            "total_sales": self.total_sales,
            "total_revenue": self.total_revenue,
            "rating": self.rating,
            "num_reviews": self.num_reviews,
            "num_products": self.num_products,
            "shipping_origin": self.shipping_origin,
            "description": self.description,
            "vendor_url": self.vendor_url
        }


@dataclass
class ReviewInfo:
    """Information about a product review"""
    product: str
    vendor: str
    rating: int
    title: str = ""
    content: str = ""
    reviewer: str = ""
    date: str | None = None
    verified_purchase: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "vendor": self.vendor,
            "rating": self.rating,
            "title": self.title,
            "content": self.content,
            "reviewer": self.reviewer,
            "date": self.date,
            "verified_purchase": self.verified_purchase
        }


class MarketplaceScraperModule(BaseModule):
    """
    Marketplace Scraper Module
    
    Scrapes darknet marketplaces for products, vendors, and reviews.
    Supports Tor and I2P network access.
    """

    MODULE_NAME = "marketplace_scraper"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Dark Web"
    MODULE_DESCRIPTION = "Darknet marketplace scraping for products, vendors, and reviews"
    MODULE_TARGET_TYPES = [TargetType.ONION, TargetType.URL]

    DEFAULT_CONFIG = MarketplaceScraperConfig

    def __init__(self, config: MarketplaceScraperConfig | None = None):
        super().__init__(config or MarketplaceScraperConfig())
        self.session: aiohttp.ClientSession | None = None
        self.semaphore: asyncio.Semaphore | None = None
        self.visited_urls: set = set()

    async def initialize(self) -> None:
        """Initialize the module"""
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def cleanup(self) -> None:
        """Clean up resources"""
        if self.session:
            await self.session.close()
        self.visited_urls.clear()

    def _is_onion_url(self, url: str) -> bool:
        """Check if URL is an onion address"""
        onion_pattern = r'\.onion(\s*:\d+)?($|/|\?)'
        return bool(re.search(onion_pattern, url, re.IGNORECASE))

    def _is_i2p_url(self, url: str) -> bool:
        """Check if URL is an I2P address"""
        i2p_pattern = r'\.i2p(\s*:\d+)?($|/|\?)'
        return bool(re.search(i2p_pattern, url, re.IGNORECASE))

    def _get_session_for_url(self, url: str) -> aiohttp.ClientSession:
        """Get appropriate session based on URL type"""
        if self._is_onion_url(url):
            if not hasattr(self, '_tor_session'):
                self._tor_session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    proxy=self.config.tor_proxy
                )
            return self._tor_session
        elif self._is_i2p_url(url):
            if not hasattr(self, '_i2p_session'):
                self._i2p_session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    proxy=self.config.i2p_proxy
                )
            return self._i2p_session
        return self.session

    async def _fetch_page(self, url: str) -> str | None:
        """Fetch a page with rate limiting and error handling"""
        if url in self.visited_urls:
            return None

        async with self.semaphore:
            try:
                session = self._get_session_for_url(url)
                headers = {
                    "User-Agent": self.config.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }

                async with session.get(url, headers=headers, allow_redirects=True) as response:
                    if response.status == 200:
                        self.visited_urls.add(url)
                        return await response.text()
                    elif response.status == 404:
                        console.print(f"[yellow]Page not found: {url}[/yellow]")
                    elif response.status == 403:
                        console.print(f"[red]Access denied: {url}[/red]")
                    elif response.status == 503:
                        console.print(f"[yellow]Service unavailable: {url}[/yellow]")
                    else:
                        console.print(f"[yellow]HTTP {response.status}: {url}[/yellow]")

            except asyncio.TimeoutError:
                console.print(f"[red]Timeout fetching: {url}[/red]")
            except aiohttp.ClientError as e:
                console.print(f"[red]Error fetching {url}: {e}[/red]")
            except Exception as e:
                console.print(f"[red]Unexpected error fetching {url}: {e}[/red]")

        return None

    async def _extract_product_info(self, soup: BeautifulSoup, url: str) -> ProductInfo | None:
        """Extract product information from marketplace page"""
        try:
            product = ProductInfo(product_url=url)

            # Extract name
            name_elem = soup.find(class_=re.compile(r'product.*name|title', re.I))
            if name_elem:
                product.name = name_elem.get_text(strip=True)
            else:
                product.name = soup.title.string if soup.title else "Unknown Product"

            # Extract price
            price_elem = soup.find(class_=re.compile(r'price|cost|amount', re.I))
            if price_elem:
                price_text = price_elem.get_text(strip=True)
                price_match = re.search(r'[\d,]+\.?\d*', price_text)
                if price_match:
                    product.price = float(price_match.group().replace(',', ''))

            # Extract currency
            currency_elem = soup.find(class_=re.compile(r'currency|btc|coin', re.I))
            if currency_elem:
                product.currency = currency_elem.get_text(strip=True).upper()

            # Extract description
            desc_elem = soup.find(class_=re.compile(r'description|details|info', re.I))
            if desc_elem:
                product.description = desc_elem.get_text(strip=True)

            # Extract vendor
            vendor_elem = soup.find(class_=re.compile(r'vendor|seller|shop', re.I))
            if vendor_elem:
                product.vendor = vendor_elem.get_text(strip=True)

            # Extract rating
            rating_elem = soup.find(class_=re.compile(r'rating|stars|score', re.I))
            if rating_elem:
                rating_text = rating_elem.get_text(strip=True)
                rating_match = re.search(r'(\d+\.?\d*)', rating_text)
                if rating_match:
                    product.rating = float(rating_match.group(1))

            # Extract category
            category_elem = soup.find(class_=re.compile(r'category|type|class', re.I))
            if category_elem:
                product.category = category_elem.get_text(strip=True)

            return product

        except Exception as e:
            console.print(f"[red]Error extracting product info: {e}[/red]")
            return None

    async def _extract_vendor_info(self, soup: BeautifulSoup, url: str) -> VendorInfo | None:
        """Extract vendor information from profile page"""
        try:
            vendor = VendorInfo(vendor_url=url)

            # Extract username
            username_elem = soup.find(class_=re.compile(r'username|name|vendor.*name', re.I))
            if username_elem:
                vendor.username = username_elem.get_text(strip=True)

            # Extract PGP key
            pgp_elem = soup.find(class_=re.compile(r'pgp|gpg|key', re.I))
            if pgp_elem:
                vendor.pgp_key = pgp_elem.get_text(strip=True)

            # Extract join date
            join_elem = soup.find(class_=re.compile(r'join|member.*since|registered', re.I))
            if join_elem:
                vendor.join_date = join_elem.get_text(strip=True)

            # Extract rating
            rating_elem = soup.find(class_=re.compile(r'rating|trust|score', re.I))
            if rating_elem:
                rating_text = rating_elem.get_text(strip=True)
                rating_match = re.search(r'(\d+\.?\d*)', rating_text)
                if rating_match:
                    vendor.rating = float(rating_match.group(1))

            # Extract sales count
            sales_elem = soup.find(class_=re.compile(r'sales|orders|completed', re.I))
            if sales_elem:
                sales_text = sales_elem.get_text(strip=True)
                sales_match = re.search(r'(\d+)', sales_text)
                if sales_match:
                    vendor.total_sales = int(sales_match.group(1))

            # Extract description
            desc_elem = soup.find(class_=re.compile(r'bio|about|description', re.I))
            if desc_elem:
                vendor.description = desc_elem.get_text(strip=True)

            return vendor

        except Exception as e:
            console.print(f"[red]Error extracting vendor info: {e}[/red]")
            return None

    async def _extract_reviews(self, soup: BeautifulSoup) -> list[ReviewInfo]:
        """Extract reviews from page"""
        reviews = []
        try:
            review_sections = soup.find_all(class_=re.compile(r'review|feedback|rating', re.I))

            for section in review_sections:
                try:
                    review = ReviewInfo(
                        title=section.find(class_=re.compile(r'title', re.I)).get_text(strip=True) if section.find(class_=re.compile(r'title', re.I)) else "",
                        content=section.find(class_=re.compile(r'content|comment|text', re.I)).get_text(strip=True) if section.find(class_=re.compile(r'content|comment|text', re.I)) else "",
                        reviewer=section.find(class_=re.compile(r'user|author|reviewer', re.I)).get_text(strip=True) if section.find(class_=re.compile(r'user|author|reviewer', re.I)) else "Anonymous",
                        rating=int(section.find(class_=re.compile(r'rating|stars', re.I)).get_text(strip=True)) if section.find(class_=re.compile(r'rating|stars', re.I)) else 5,
                        date=section.find(class_=re.compile(r'date|time', re.I)).get_text(strip=True) if section.find(class_=re.compile(r'date|time', re.I)) else None
                    )
                    reviews.append(review)
                except:
                    continue

        except Exception as e:
            console.print(f"[red]Error extracting reviews: {e}[/red]")

        return reviews

    async def _scrape_page(self, url: str, depth: int = 0) -> dict[str, Any]:
        """Scrape a marketplace page recursively"""
        if depth > self.config.max_depth or len(self.visited_urls) >= self.config.max_pages:
            return {}

        html = await self._fetch_page(url)
        if not html:
            return {}

        soup = BeautifulSoup(html, 'html.parser')
        results = {}

        # Extract products
        if self.config.scrape_products:
            product = await self._extract_product_info(soup, url)
            if product:
                results['product'] = product.to_dict()

        # Extract vendor info
        if self.config.scrape_vendors:
            vendor = await self._extract_vendor_info(soup, url)
            if vendor:
                results['vendor'] = vendor.to_dict()

        # Extract reviews
        if self.config.scrape_reviews:
            reviews = await self._extract_reviews(soup)
            if reviews:
                results['reviews'] = [r.to_dict() for r in reviews]

        # Extract categories
        if self.config.scrape_categories:
            categories = []
            category_links = soup.find_all('a', href=re.compile(r'/category|/browse', re.I))
            for link in category_links:
                if link.get_text(strip=True):
                    categories.append(link.get_text(strip=True))
            if categories:
                results['categories'] = list(set(categories))

        # Follow links
        if depth < self.config.max_depth:
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    from urllib.parse import urljoin
                    links.append(urljoin(url, href))

            for link in links[:10]:
                if link not in self.visited_urls:
                    nested_results = await self._scrape_page(link, depth + 1)
                    if nested_results:
                        if 'products' not in results:
                            results['products'] = []
                        if 'product' in nested_results:
                            results['products'].append(nested_results['product'])
                        if 'vendor' in nested_results:
                            if 'vendors' not in results:
                                results['vendors'] = []
                            results['vendors'].append(nested_results['vendor'])

        return results

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the marketplace scraper module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            options = options or {}
            depth = options.get('depth', 0)

            console.print(f"[blue]Scraping marketplace: {target}[/blue]")

            scrape_result = await self._scrape_page(target, depth)

            if scrape_result:
                result.status = "success"
                result.data = scrape_result
                result.summary = f"Found {len(scrape_result.get('products', []))} products, {len(scrape_result.get('vendors', []))} vendors, {len(scrape_result.get('reviews', []))} reviews"
            else:
                result.status = "partial"
                result.error = "No data extracted from marketplace"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            console.print(f"[red]Error scraping marketplace: {e}[/red]")

        result.end_time = datetime.utcnow()
        return result

    async def execute_batch(self, targets: list[str], options: dict[str, Any] | None = None) -> list[ModuleResult]:
        """Execute on multiple targets"""
        results = []
        for target in targets:
            result = await self.execute(target, options)
            results.append(result)
            if len(self.visited_urls) >= self.config.max_pages:
                break
        return results


# Module instance
marketplace_scraper_module = MarketplaceScraperModule()
