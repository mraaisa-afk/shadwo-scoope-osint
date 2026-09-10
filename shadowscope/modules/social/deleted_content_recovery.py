"""
Deleted Content Recovery Module for SHADOWSCOPE
Recovers deleted content from social media and web archives.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import re
from bs4 import BeautifulSoup

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class DeletedContentRecoveryConfig(ModuleConfig):
    """Configuration for deleted content recovery module"""
    api_endpoints: Dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    check_wayback_machine: bool = True
    check_google_cache: bool = True
    check_archive_today: bool = True
    check_social_archives: bool = True
    max_results: int = 20
    
    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "wayback_machine": "https://web.archive.org",
                "google_cache": "https://webcache.googleusercontent.com",
                "archive_today": "https://archive.today",
                "ghostarchive": "https://ghostarchive.org",
                "unddit": "https://unddit.com",
                "reveddit": "https://www.reveddit.com",
                "snew": "https://snew.github.io",
            }


class DeletedContentRecoveryModule(BaseModule):
    """
    Deleted Content Recovery Module
    
    Recovers deleted content from social media and web archives.
    Uses Wayback Machine, Google Cache, and other archival services.
    """
    
    MODULE_NAME = "deleted_content_recovery"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Social Engineering"
    MODULE_DESCRIPTION = "Recover deleted social media posts and web content"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.USERNAME]
    
    DEFAULT_CONFIG = DeletedContentRecoveryConfig
    
    def __init__(self, config: Optional[DeletedContentRecoveryConfig] = None):
        super().__init__(config or DeletedContentRecoveryConfig())
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
        """Execute the deleted content recovery module"""
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
            cache_key = f"deleted_content_recovery:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Recover deleted content
            recovery_data = await self.recover_content(target)
            
            # Store in cache
            cache.set(cache_key, recovery_data, ttl=86400)  # 24 hours
            
            result.status = "success"
            result.data = recovery_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def recover_content(self, target: str) -> Dict[str, Any]:
        """Recover deleted content"""
        data = {
            "target": target,
            "wayback_machine": {},
            "google_cache": {},
            "archive_today": {},
            "social_archives": {},
            "results": [],
            "analysis": {}
        }
        
        # Check Wayback Machine
        if self.config.check_wayback_machine:
            data["wayback_machine"] = await self.check_wayback_machine(target)
            if data["wayback_machine"].get("results"):
                data["results"].extend(data["wayback_machine"]["results"])
        
        # Check Google Cache
        if self.config.check_google_cache:
            data["google_cache"] = await self.check_google_cache(target)
            if data["google_cache"].get("url"):
                data["results"].append(data["google_cache"])
        
        # Check Archive.today
        if self.config.check_archive_today:
            data["archive_today"] = await self.check_archive_today(target)
            if data["archive_today"].get("results"):
                data["results"].extend(data["archive_today"]["results"])
        
        # Check social archives
        if self.config.check_social_archives:
            data["social_archives"] = await self.check_social_archives(target)
            if data["social_archives"].get("results"):
                data["results"].extend(data["social_archives"]["results"])
        
        # Limit results
        data["results"] = data["results"][:self.config.max_results]
        
        # Analyze the data
        data["analysis"] = self.analyze_recovery_data(data)
        
        return data
    
    async def check_wayback_machine(self, target: str) -> Dict[str, Any]:
        """Check Wayback Machine for archived content"""
        result = {
            "target": target,
            "results": [],
            "error": None
        }
        
        try:
            # Check if target is a URL
            if not target.startswith("http://") and not target.startswith("https://"):
                target = f"https://{target}"
            
            # Query Wayback Machine
            url = f"https://web.archive.org/cdx/search/cdx?url={target}&output=json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Process results
                    if data and len(data) > 1:  # Skip header row
                        for row in data[1:]:
                            if len(row) >= 4:
                                timestamp = row[1]
                                original_url = row[2]
                                archived_url = f"https://web.archive.org/web/{timestamp}id_/{original_url}"
                                
                                result["results"].append({
                                    "source": "wayback_machine",
                                    "timestamp": timestamp,
                                    "original_url": original_url,
                                    "archived_url": archived_url,
                                    "status_code": row[4] if len(row) > 4 else None
                                })
        except Exception as e:
            result["error"] = str(e)
            console.print(f"[yellow]Warning: Wayback Machine check failed: {e}[/yellow]")
        
        return result
    
    async def check_google_cache(self, target: str) -> Dict[str, Any]:
        """Check Google Cache for archived content"""
        result = {
            "target": target,
            "url": None,
            "error": None
        }
        
        try:
            # Check if target is a URL
            if not target.startswith("http://") and not target.startswith("https://"):
                target = f"https://{target}"
            
            # Query Google Cache
            url = f"https://webcache.googleusercontent.com/search?q=cache:{target}"
            
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status == 200:
                    result["url"] = url
                    result["status"] = "available"
                elif response.status == 404:
                    result["status"] = "not_available"
        except Exception as e:
            result["error"] = str(e)
            console.print(f"[yellow]Warning: Google Cache check failed: {e}[/yellow]")
        
        return result
    
    async def check_archive_today(self, target: str) -> Dict[str, Any]:
        """Check Archive.today for archived content"""
        result = {
            "target": target,
            "results": [],
            "error": None
        }
        
        try:
            # Check if target is a URL
            if not target.startswith("http://") and not target.startswith("https://"):
                target = f"https://{target}"
            
            # Query Archive.today
            url = f"https://archive.today/{target}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    result["results"].append({
                        "source": "archive_today",
                        "url": url,
                        "status": "available"
                    })
                elif response.status == 404:
                    result["status"] = "not_available"
        except Exception as e:
            result["error"] = str(e)
            console.print(f"[yellow]Warning: Archive.today check failed: {e}[/yellow]")
        
        return result
    
    async def check_social_archives(self, target: str) -> Dict[str, Any]:
        """Check social media specific archives"""
        result = {
            "target": target,
            "results": [],
            "error": None
        }
        
        try:
            # Determine if this is a social media URL
            social_platforms = [
                ("twitter.com", "unddit", "https://unddit.com/r/{}"),
                ("reddit.com", "unddit", "https://unddit.com/r/{}"),
                ("reddit.com", "reveddit", "https://www.reveddit.com/r/{}"),
                ("reddit.com", "snew", "https://snew.github.io/r/{}"),
            ]
            
            for platform, archive_name, archive_url_template in social_platforms:
                if platform in target:
                    # Extract subreddit or username
                    parts = target.split("/")
                    for part in parts:
                        if part and not part.startswith("http") and not part.startswith("www"):
                            archive_url = archive_url_template.format(part)
                            result["results"].append({
                                "source": archive_name,
                                "url": archive_url,
                                "target": part
                            })
        except Exception as e:
            result["error"] = str(e)
            console.print(f"[yellow]Warning: Social archives check failed: {e}[/yellow]")
        
        return result
    
    def analyze_recovery_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze recovery data"""
        analysis = {
            "target": data["target"],
            "total_results": len(data["results"]),
            "wayback_count": len(data["wayback_machine"].get("results", [])),
            "google_cache_available": data["google_cache"].get("url") is not None,
            "archive_today_count": len(data["archive_today"].get("results", [])),
            "social_archive_count": len(data["social_archives"].get("results", [])),
            "oldest_snapshot": None,
            "newest_snapshot": None,
            "has_content": False,
            "recommendations": []
        }
        
        # Extract timestamps from Wayback Machine
        wayback_results = data["wayback_machine"].get("results", [])
        if wayback_results:
            timestamps = []
            for result in wayback_results:
                try:
                    timestamp = result.get("timestamp")
                    if timestamp:
                        timestamps.append(timestamp)
                except:
                    pass
            
            if timestamps:
                analysis["oldest_snapshot"] = min(timestamps)
                analysis["newest_snapshot"] = max(timestamps)
        
        # Check if we have content
        if analysis["total_results"] > 0:
            analysis["has_content"] = True
        
        # Generate recommendations
        if analysis["has_content"]:
            analysis["recommendations"].append(
                f"FOUND: {analysis['total_results']} archived versions available"
            )
        else:
            analysis["recommendations"].append(
                "No archived content found"
            )
        
        if analysis["wayback_count"] > 0:
            analysis["recommendations"].append(
                f"WAYBACK: {analysis['wayback_count']} snapshots in Wayback Machine"
            )
        
        if analysis["google_cache_available"]:
            analysis["recommendations"].append(
                "GOOGLE CACHE: Content available in Google Cache"
            )
        
        if analysis["archive_today_count"] > 0:
            analysis["recommendations"].append(
                f"ARCHIVE.TODAY: {analysis['archive_today_count']} snapshots available"
            )
        
        if analysis["social_archive_count"] > 0:
            analysis["recommendations"].append(
                f"SOCIAL ARCHIVES: {analysis['social_archive_count']} social archive links"
            )
        
        if analysis["oldest_snapshot"] and analysis["newest_snapshot"]:
            analysis["recommendations"].append(
                f"HISTORY: Content archived from {analysis['oldest_snapshot']} to {analysis['newest_snapshot']}"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's a URL
        url_pattern = r"^https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9._-]*)*$"
        if re.match(url_pattern, target):
            return TargetType.URL
        
        # Check if it's a username
        username_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,30}[a-zA-Z0-9]$"
        if re.match(username_pattern, target):
            return TargetType.USERNAME
        
        return None


# Module instance
deleted_content_recovery_module = DeletedContentRecoveryModule
