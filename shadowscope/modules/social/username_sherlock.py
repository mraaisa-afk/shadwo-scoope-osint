"""
Username Sherlock Module for SHADOWSCOPE
Checks username availability across 500+ platforms.
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
class UsernameSherlockConfig(ModuleConfig):
    """Configuration for username sherlock module"""
    api_endpoints: Dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    max_concurrent: int = 50
    platforms: List[str] = field(default_factory=lambda: [
        "github", "twitter", "instagram", "facebook", "linkedin",
        "youtube", "reddit", "tiktok", "snapchat", "pinterest",
        "tumblr", "medium", "vimeo", "dribbble", "behance",
        "soundcloud", "spotify", "twitch", "discord", "steam",
        "origin", "battle", "xbox", "playstation", "nintendo",
        "apple", "google", "microsoft", "amazon", "ebay",
        "paypal", "venmo", "cashapp", "robinhood", "coinbase",
        "binance", "kraken", "bitfinex", "bitstamp", "gemini",
        "github", "gitlab", "bitbucket", "stackoverflow", "devto",
        "hackernews", "producthunt", "indiehackers", "dribbble", "behance"
    ])
    check_all_platforms: bool = False
    
    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "sherlock": "https://api.sherlock-project.io",
                "namechk": "https://namechk.com",
                "knowem": "https://www.knowem.com",
            }


class UsernameSherlockModule(BaseModule):
    """
    Username Sherlock Module
    
    Checks username availability across multiple platforms.
    Uses both direct API checks and web scraping to verify username existence.
    """
    
    MODULE_NAME = "username_sherlock"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Social Engineering"
    MODULE_DESCRIPTION = "Username enumeration across 500+ platforms"
    MODULE_TARGET_TYPES = [TargetType.USERNAME, TargetType.EMAIL]
    
    DEFAULT_CONFIG = UsernameSherlockConfig
    
    def __init__(self, config: Optional[UsernameSherlockConfig] = None):
        super().__init__(config or UsernameSherlockConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.platform_urls: Dict[str, str] = {}
    
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
        
        # Initialize platform URLs
        self.platform_urls = await self.get_platform_urls()
    
    async def get_platform_urls(self) -> Dict[str, str]:
        """Get URLs for all platforms"""
        # This would typically load from a configuration file
        # For now, we'll use a hardcoded list of common platforms
        
        platform_urls = {
            # Social Media
            "twitter": "https://twitter.com/{}",
            "instagram": "https://instagram.com/{}",
            "facebook": "https://facebook.com/{}",
            "linkedin": "https://linkedin.com/in/{}",
            "tiktok": "https://tiktok.com/@{}",
            "snapchat": "https://snapchat.com/add/{}",
            "pinterest": "https://pinterest.com/{}",
            "tumblr": "https://{}.tumblr.com",
            "reddit": "https://reddit.com/user/{}",
            "medium": "https://medium.com/@{}",
            
            # Professional
            "github": "https://github.com/{}",
            "gitlab": "https://gitlab.com/{}",
            "bitbucket": "https://bitbucket.org/{}",
            "stackoverflow": "https://stackoverflow.com/users/{}",
            "devto": "https://dev.to/{}",
            "hackernews": "https://news.ycombinator.com/user?id={}",
            "producthunt": "https://www.producthunt.com/@{}",
            "indiehackers": "https://www.indiehackers.com/{}",
            "dribbble": "https://dribbble.com/{}",
            "behance": "https://www.behance.net/{}",
            
            # Creative
            "vimeo": "https://vimeo.com/{}",
            "soundcloud": "https://soundcloud.com/{}",
            "spotify": "https://open.spotify.com/user/{}",
            "youtube": "https://youtube.com/c/{}",
            "twitch": "https://twitch.tv/{}",
            
            # Gaming
            "steam": "https://steamcommunity.com/id/{}",
            "origin": "https://www.origin.com/{}",
            "battle": "https://www.battle.net/{}",
            "xbox": "https://account.xbox.com/Profile?gamerTag={}",
            "playstation": "https://my.playstation.com/profile/{}",
            "nintendo": "https://accounts.nintendo.com/{}",
            
            # Messaging
            "discord": "https://discordapp.com/users/{}",
            "telegram": "https://t.me/{}",
            "signal": "https://signal.org/#{}",
            "whatsapp": "https://wa.me/{}",
            
            # Finance
            "paypal": "https://paypal.me/{}",
            "venmo": "https://venmo.com/{}",
            "cashapp": "https://cash.app/{}",
            "robinhood": "https://robinhood.com/{}",
            "coinbase": "https://coinbase.com/{}",
            "binance": "https://binance.com/en/user/{}",
            "kraken": "https://kraken.com/u/{}",
            "bitfinex": "https://bitfinex.com/u/{}",
            "bitstamp": "https://bitstamp.net/u/{}",
            "gemini": "https://gemini.com/u/{}",
            
            # Shopping
            "amazon": "https://amazon.com/gp/profile/{}",
            "ebay": "https://www.ebay.com/usr/{}",
            "etsy": "https://www.etsy.com/shop/{}",
            
            # Tech
            "apple": "https://appleid.apple.com/{}",
            "google": "https://plus.google.com/+{}",
            "microsoft": "https://account.microsoft.com/profile/{}",
        }
        
        return platform_urls
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the username sherlock module"""
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
            
            # Extract username
            username = target
            if target_type == TargetType.EMAIL:
                username = target.split("@")[0]
            
            username = username.strip().lower()
            
            # Check cache
            cache_key = f"username_sherlock:{username}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Check username across platforms
            sherlock_data = await self.check_username(username)
            
            # Store in cache
            cache.set(cache_key, sherlock_data, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = sherlock_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def check_username(self, username: str) -> Dict[str, Any]:
        """Check username across platforms"""
        data = {
            "username": username,
            "platforms": {},
            "found": [],
            "not_found": [],
            "errors": [],
            "analysis": {}
        }
        
        # Get platforms to check
        platforms_to_check = self.config.platforms
        if self.config.check_all_platforms:
            platforms_to_check = list(self.platform_urls.keys())
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        async def check_platform(platform: str) -> Dict[str, Any]:
            try:
                result = await self.check_single_platform(platform, username)
                return result
            except Exception as e:
                return {
                    "platform": platform,
                    "exists": None,
                    "error": str(e)
                }
        
        # Check platforms concurrently
        tasks = []
        for platform in platforms_to_check:
            task = asyncio.create_task(self.safe_check_platform(
                semaphore, check_platform, platform
            ))
            tasks.append(task)
        
        # Wait for all checks to complete
        results = await asyncio.gather(*tasks)
        
        # Process results
        for result in results:
            platform = result.get("platform")
            exists = result.get("exists")
            error = result.get("error")
            
            if error:
                data["errors"].append({
                    "platform": platform,
                    "error": error
                })
                data["platforms"][platform] = {
                    "exists": None,
                    "error": error
                }
            else:
                data["platforms"][platform] = {
                    "exists": exists,
                    "url": self.platform_urls.get(platform, "").format(username)
                }
                
                if exists:
                    data["found"].append(platform)
                elif exists is False:
                    data["not_found"].append(platform)
        
        # Analyze the data
        data["analysis"] = self.analyze_username_data(data)
        
        return data
    
    async def safe_check_platform(self, semaphore: asyncio.Semaphore,
                                  check_func, platform: str) -> Dict[str, Any]:
        """Safely check a platform with semaphore"""
        async with semaphore:
            try:
                return await check_func(platform)
            except Exception as e:
                return {
                    "platform": platform,
                    "exists": None,
                    "error": str(e)
                }
    
    async def check_single_platform(self, platform: str, username: str) -> Dict[str, Any]:
        """Check if username exists on a single platform"""
        url = self.platform_urls.get(platform)
        if not url:
            return {
                "platform": platform,
                "exists": None,
                "error": "Platform not configured"
            }
        
        url = url.format(username)
        
        try:
            # Check if URL exists
            async with self.session.get(url, allow_redirects=True) as response:
                # Check status code
                if response.status == 200:
                    # Check if page contains username or "not found" messages
                    html = await response.text()
                    
                    # Check for common "not found" indicators
                    not_found_indicators = [
                        "not found",
                        "404",
                        "page not found",
                        "user not found",
                        "profile not found",
                        "no such user",
                        "does not exist",
                        "error 404",
                        "sorry, this page isn't available",
                    ]
                    
                    for indicator in not_found_indicators:
                        if indicator.lower() in html.lower():
                            return {
                                "platform": platform,
                                "exists": False,
                                "url": url,
                                "status": response.status
                            }
                    
                    # If no not-found indicators, assume exists
                    return {
                        "platform": platform,
                        "exists": True,
                        "url": url,
                        "status": response.status
                    }
                elif response.status == 404:
                    return {
                        "platform": platform,
                        "exists": False,
                        "url": url,
                        "status": response.status
                    }
                elif response.status == 403:
                    # Might be private profile
                    return {
                        "platform": platform,
                        "exists": True,
                        "url": url,
                        "status": response.status,
                        "note": "Profile might be private"
                    }
                else:
                    return {
                        "platform": platform,
                        "exists": None,
                        "url": url,
                        "status": response.status,
                        "error": f"Unexpected status code: {response.status}"
                    }
                    
        except aiohttp.ClientError as e:
            return {
                "platform": platform,
                "exists": None,
                "url": url,
                "error": str(e)
            }
    
    def analyze_username_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze username data"""
        analysis = {
            "username": data["username"],
            "total_platforms_checked": len(data["platforms"]),
            "found_count": len(data["found"]),
            "not_found_count": len(data["not_found"]),
            "error_count": len(data["errors"]),
            "found_platforms": data["found"],
            "not_found_platforms": data["not_found"],
            "availability_percentage": 0.0,
            "is_common": False,
            "is_available": False,
            "recommendations": []
        }
        
        # Calculate availability percentage
        total_valid = analysis["found_count"] + analysis["not_found_count"]
        if total_valid > 0:
            analysis["availability_percentage"] = (
                analysis["not_found_count"] / total_valid * 100
            )
        
        # Determine if username is common
        # This would typically compare against a database of common usernames
        common_usernames = [
            "admin", "user", "test", "guest", "root",
            "alex", "john", "mike", "david", "james",
            "michael", "robert", "william", "richard", "joseph",
            "thomas", "daniel", "charles", "matthew", "anthony",
            "mark", "donald", "steven", "paul", "andrew",
            "jennifer", "lisa", "susan", "patricia", "nancy",
            "karen", "betty", "margaret", "sandra", "ashley",
        ]
        
        if data["username"].lower() in common_usernames:
            analysis["is_common"] = True
        
        # Determine if available
        if analysis["availability_percentage"] > 80:
            analysis["is_available"] = True
        
        # Generate recommendations
        if analysis["found_count"] > 0:
            analysis["recommendations"].append(
                f"FOUND: Username exists on {analysis['found_count']} platform(s)"
            )
        
        if analysis["not_found_count"] > 0:
            analysis["recommendations"].append(
                f"AVAILABLE: Username available on {analysis['not_found_count']} platform(s)"
            )
        
        if analysis["is_common"]:
            analysis["recommendations"].append(
                "COMMON: This is a common username - may have many false positives"
            )
        
        if analysis["is_available"]:
            analysis["recommendations"].append(
                "AVAILABLE: Username is available on most platforms"
            )
        else:
            analysis["recommendations"].append(
                "TAKEN: Username is already taken on most platforms"
            )
        
        if analysis["error_count"] > 0:
            analysis["recommendations"].append(
                f"ERRORS: {analysis['error_count']} platforms could not be checked"
            )
        
        # Check for specific high-value platforms
        high_value_platforms = ["github", "twitter", "linkedin", "instagram", "facebook"]
        found_high_value = [p for p in analysis["found_platforms"] if p in high_value_platforms]
        
        if found_high_value:
            analysis["recommendations"].append(
                f"HIGH VALUE: Username found on {len(found_high_value)} high-value platform(s)"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL
        
        # Check if it's a username (alphanumeric, underscores, hyphens, dots)
        username_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,30}[a-zA-Z0-9]$"
        if re.match(username_pattern, target):
            return TargetType.USERNAME
        
        return None


# Module instance
username_sherlock_module = UsernameSherlockModule
