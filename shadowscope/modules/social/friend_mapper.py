"""
Friend Mapper Module for SHADOWSCOPE
Maps social connections and friend networks.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import aiohttp
from bs4 import BeautifulSoup
from rich.console import Console

from shadowscope.core import cache, proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class FriendMapperConfig(ModuleConfig):
    """Configuration for friend mapper module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    max_depth: int = 2
    max_connections: int = 100
    scrape_followers: bool = True
    scrape_following: bool = True
    scrape_friends: bool = True

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "twitter_api": "https://api.twitter.com/2",
                "instagram_api": "https://graph.instagram.com",
                "facebook_api": "https://graph.facebook.com",
                "linkedin_api": "https://api.linkedin.com",
            }


class FriendMapperModule(BaseModule):
    """
    Friend Mapper Module
    
    Maps social connections and friend networks.
    Builds graphs of relationships between users.
    """

    MODULE_NAME = "friend_mapper"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Social Engineering"
    MODULE_DESCRIPTION = "Social network mapping and relationship analysis"
    MODULE_TARGET_TYPES = [TargetType.USERNAME, TargetType.EMAIL, TargetType.URL]

    DEFAULT_CONFIG = FriendMapperConfig

    def __init__(self, config: FriendMapperConfig | None = None):
        super().__init__(config or FriendMapperConfig())
        self.session: aiohttp.ClientSession | None = None
        self.platform_urls: dict[str, str] = {}

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

    async def get_platform_urls(self) -> dict[str, str]:
        """Get URLs for all platforms"""
        platform_urls = {
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
            "github": "https://github.com/{}",
            "gitlab": "https://gitlab.com/{}",
            "stackoverflow": "https://stackoverflow.com/users/{}",
        }

        return platform_urls

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the friend mapper module"""
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

            # Extract username and platform
            username, platform = self.parse_target(target)
            if not username:
                result.status = "error"
                result.error = f"Could not extract username from: {target}"
                return result

            # Check cache
            cache_key = f"friend_mapper:{platform}:{username}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Map friends/connections
            network_data = await self.map_network(username, platform)

            # Store in cache
            cache.set(cache_key, network_data, ttl=3600)  # 1 hour

            result.status = "success"
            result.data = network_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    def parse_target(self, target: str) -> tuple:
        """Parse target to extract username and platform"""
        # Check if it's a URL
        if target.startswith("http://") or target.startswith("https://"):
            for platform, url_template in self.platform_urls.items():
                if platform in target:
                    username = target.replace(url_template.format("{}"), "")
                    return username, platform

        # Otherwise, treat as username
        return target, None

    async def map_network(self, username: str, platform: str | None = None) -> dict[str, Any]:
        """Map social network for a user"""
        data = {
            "username": username,
            "platform": platform or "unknown",
            "network": {
                "nodes": [],
                "edges": [],
            },
            "followers": [],
            "following": [],
            "mutual": [],
            "analysis": {}
        }

        # Determine platform if not specified
        if not platform:
            platform = await self.detect_platform(username)
            data["platform"] = platform

        if not platform:
            data["error"] = "Could not determine platform"
            return data

        # Add root node
        data["network"]["nodes"].append({
            "id": username,
            "type": "root",
            "platform": platform,
            "depth": 0
        })

        # Scrape connections based on platform
        if platform == "twitter":
            followers, following = await self.scrape_twitter_connections(username)
        elif platform == "instagram":
            followers, following = await self.scrape_instagram_connections(username)
        elif platform == "linkedin":
            followers, following = await self.scrape_linkedin_connections(username)
        elif platform == "github":
            followers, following = await self.scrape_github_connections(username)
        elif platform == "reddit":
            followers, following = await self.scrape_reddit_connections(username)
        else:
            followers, following = await self.scrape_generic_connections(username, platform)

        # Process followers
        if followers:
            data["followers"] = followers
            for follower in followers:
                data["network"]["nodes"].append({
                    "id": follower,
                    "type": "follower",
                    "platform": platform,
                    "depth": 1
                })
                data["network"]["edges"].append({
                    "source": username,
                    "target": follower,
                    "type": "followed_by"
                })

        # Process following
        if following:
            data["following"] = following
            for followee in following:
                data["network"]["nodes"].append({
                    "id": followee,
                    "type": "following",
                    "platform": platform,
                    "depth": 1
                })
                data["network"]["edges"].append({
                    "source": username,
                    "target": followee,
                    "type": "following"
                })

        # Find mutual connections
        if followers and following:
            data["mutual"] = list(set(followers) & set(following))

            for mutual in data["mutual"]:
                # Update edge type
                for edge in data["network"]["edges"]:
                    if edge["target"] == mutual and edge["type"] == "followed_by":
                        edge["type"] = "mutual"
                    if edge["target"] == mutual and edge["type"] == "following":
                        edge["type"] = "mutual"

        # Analyze the data
        data["analysis"] = self.analyze_network_data(data)

        return data

    async def detect_platform(self, username: str) -> str | None:
        """Detect which platform a username belongs to"""
        if "@" in username:
            return "twitter"
        elif username.startswith("u/") or username.startswith("user/"):
            return "reddit"
        elif len(username) == 40 and all(c in "0123456789abcdef" for c in username):
            return "github"

        return "twitter"

    async def scrape_twitter_connections(self, username: str) -> tuple:
        """Scrape Twitter followers and following"""
        followers = []
        following = []

        try:
            # Scrape followers
            if self.config.scrape_followers:
                followers_url = f"https://twitter.com/{username}/followers"
                followers = await self.scrape_twitter_page(followers_url, "followers")

            # Scrape following
            if self.config.scrape_following:
                following_url = f"https://twitter.com/{username}/following"
                following = await self.scrape_twitter_page(following_url, "following")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape Twitter connections: {e}[/yellow]")

        return followers, following

    async def scrape_instagram_connections(self, username: str) -> tuple:
        """Scrape Instagram followers and following"""
        followers = []
        following = []

        try:
            # Scrape profile page for counts
            profile_url = f"https://instagram.com/{username}"

            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract follower count
                    follower_element = soup.find("meta", {"property": "og:followers"})
                    if follower_element:
                        followers_count = follower_element.get("content", "0")
                        console.print(f"[green]+[/green] Instagram followers: {followers_count}")

                    # Extract following count
                    following_element = soup.find("meta", {"property": "og:following"})
                    if following_element:
                        following_count = following_element.get("content", "0")
                        console.print(f"[green]+[/green] Instagram following: {following_count}")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape Instagram connections: {e}[/yellow]")

        return followers, following

    async def scrape_linkedin_connections(self, username: str) -> tuple:
        """Scrape LinkedIn connections"""
        followers = []
        following = []

        try:
            profile_url = f"https://linkedin.com/in/{username}"

            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract connection count
                    connections_element = soup.find("span", {"class": "t-16 t-black--light t-normal"})
                    if connections_element:
                        connections = connections_element.get_text().strip()
                        console.print(f"[green]+[/green] LinkedIn connections: {connections}")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape LinkedIn connections: {e}[/yellow]")

        return followers, following

    async def scrape_github_connections(self, username: str) -> tuple:
        """Scrape GitHub followers and following"""
        followers = []
        following = []

        try:
            profile_url = f"https://github.com/{username}"

            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract follower count
                    follower_element = soup.find("a", {"href": f"/{username}?tab=followers"})
                    if follower_element:
                        followers_text = follower_element.get_text().strip()
                        followers_count = self.parse_number(followers_text)
                        console.print(f"[green]+[/green] GitHub followers: {followers_count}")

                    # Extract following count
                    following_element = soup.find("a", {"href": f"/{username}?tab=following"})
                    if following_element:
                        following_text = following_element.get_text().strip()
                        following_count = self.parse_number(following_text)
                        console.print(f"[green]+[/green] GitHub following: {following_count}")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape GitHub connections: {e}[/yellow]")

        return followers, following

    async def scrape_reddit_connections(self, username: str) -> tuple:
        """Scrape Reddit followers and following"""
        followers = []
        following = []

        try:
            profile_url = f"https://reddit.com/user/{username}"

            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract karma (Reddit doesn't have explicit followers/following)
                    karma_element = soup.find("div", {"class": "_2TQG7W5OQ2W5q5JJ3s7K4E"})
                    if karma_element:
                        karma = karma_element.get_text().strip()
                        console.print(f"[green]+[/green] Reddit karma: {karma}")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape Reddit connections: {e}[/yellow]")

        return followers, following

    async def scrape_generic_connections(self, username: str, platform: str) -> tuple:
        """Scrape generic connections"""
        followers = []
        following = []

        try:
            url_template = self.platform_urls.get(platform)
            if url_template:
                profile_url = url_template.format(username)

                async with self.session.get(profile_url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, "html.parser")

                        # Try to extract connection counts
                        # This is platform-specific and may not work for all
                        connection_patterns = [
                            r"(\d+[KMB]?)\s+(followers?|connections?|subscribers?)",
                            r"(followers?|connections?|subscribers?):\s+(\d+[KMB]?)",
                        ]

                        for pattern in connection_patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            for match in matches:
                                console.print(f"[green]+[/green] Found connection info: {match}")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape generic connections: {e}[/yellow]")

        return followers, following

    async def scrape_twitter_page(self, url: str, connection_type: str) -> list[str]:
        """Scrape a Twitter connections page"""
        connections = []

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract usernames from the page
                    # This is a simplified extraction
                    username_elements = soup.find_all("a", {"href": re.compile(r"/\w+")})

                    for element in username_elements:
                        href = element.get("href", "")
                        if href.startswith("/"):
                            username = href[1:].split("/")[0]
                            if username and username != "":
                                connections.append(username)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to scrape Twitter {connection_type}: {e}[/yellow]")

        return connections

    def parse_number(self, text: str) -> int | None:
        """Parse number from text (e.g., '1.2K' -> 1200)"""
        text = text.strip().upper()

        if "K" in text:
            num = float(text.replace("K", ""))
            return int(num * 1000)
        elif "M" in text:
            num = float(text.replace("M", ""))
            return int(num * 1000000)
        else:
            try:
                return int(text.replace(",", ""))
            except ValueError:
                return None

    def analyze_network_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze network data"""
        analysis = {
            "username": data["username"],
            "platform": data["platform"],
            "total_nodes": len(data["network"]["nodes"]),
            "total_edges": len(data["network"]["edges"]),
            "follower_count": len(data["followers"]),
            "following_count": len(data["following"]),
            "mutual_count": len(data["mutual"]),
            "follower_following_ratio": 0.0,
            "is_influencer": False,
            "is_social": False,
            "is_isolated": False,
            "recommendations": []
        }

        # Calculate follower/following ratio
        if analysis["following_count"] > 0:
            analysis["follower_following_ratio"] = (
                analysis["follower_count"] / analysis["following_count"]
            )

        # Determine if influencer
        if analysis["follower_count"] > 10000:
            analysis["is_influencer"] = True

        # Determine if social
        if analysis["total_edges"] > 10:
            analysis["is_social"] = True

        # Determine if isolated
        if analysis["total_edges"] == 0:
            analysis["is_isolated"] = True

        # Generate recommendations
        if analysis["is_influencer"]:
            analysis["recommendations"].append(
                f"INFLUENCER: {analysis['follower_count']:,} followers"
            )

        if analysis["is_social"]:
            analysis["recommendations"].append(
                f"SOCIAL: {analysis['total_edges']} connections"
            )

        if analysis["is_isolated"]:
            analysis["recommendations"].append(
                "ISOLATED: No connections found"
            )

        if analysis["mutual_count"] > 0:
            analysis["recommendations"].append(
                f"MUTUAL: {analysis['mutual_count']} mutual connections"
            )

        if analysis["follower_following_ratio"] > 10:
            analysis["recommendations"].append(
                f"POPULAR: Follower/following ratio of {analysis['follower_following_ratio']:.1f}"
            )
        elif analysis["follower_following_ratio"] < 0.1:
            analysis["recommendations"].append(
                "FOLLOWER: Following many more than followers"
            )

        return analysis

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""
        import re

        # Check if it's a URL
        url_pattern = r"^https?://[a-zA-Z0-9.-]+/([a-zA-Z0-9._-]+)"
        if re.match(url_pattern, target):
            return TargetType.URL

        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL

        # Check if it's a username
        username_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,30}[a-zA-Z0-9]$"
        if re.match(username_pattern, target):
            return TargetType.USERNAME

        return None


# Module instance
friend_mapper_module = FriendMapperModule
