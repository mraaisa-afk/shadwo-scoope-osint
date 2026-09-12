"""
Profile Scraper Module for SHADOWSCOPE
Scrapes social media profiles for information.
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
class ProfileScraperConfig(ModuleConfig):
    """Configuration for profile scraper module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    max_concurrent: int = 20
    scrape_bio: bool = True
    scrape_posts: bool = True
    scrape_followers: bool = True
    scrape_following: bool = True
    max_posts: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "twitter_api": "https://api.twitter.com/2",
                "instagram_api": "https://graph.instagram.com",
                "facebook_api": "https://graph.facebook.com",
            }


class ProfileScraperModule(BaseModule):
    """
    Profile Scraper Module
    
    Scrapes social media profiles for information.
    Extracts bio, posts, followers, following, and other profile data.
    """

    MODULE_NAME = "profile_scraper"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Social Engineering"
    MODULE_DESCRIPTION = "Social media profile scraping and data extraction"
    MODULE_TARGET_TYPES = [TargetType.USERNAME, TargetType.EMAIL, TargetType.URL]

    DEFAULT_CONFIG = ProfileScraperConfig

    def __init__(self, config: ProfileScraperConfig | None = None):
        super().__init__(config or ProfileScraperConfig())
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
                proxy=proxy_url,
                headers={"User-Agent": self.config.user_agent}
            )
        else:
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": self.config.user_agent}
            )

        # Initialize platform URLs
        self.platform_urls = await self.get_platform_urls()

    async def get_platform_urls(self) -> dict[str, str]:
        """Get URLs for all platforms"""
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
            "dribbble": "https://dribbble.com/{}",
            "behance": "https://www.behance.net/{}",

            # Creative
            "vimeo": "https://vimeo.com/{}",
            "soundcloud": "https://soundcloud.com/{}",
            "spotify": "https://open.spotify.com/user/{}",
            "youtube": "https://youtube.com/c/{}",
            "twitch": "https://twitch.tv/{}",
        }

        return platform_urls

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the profile scraper module"""
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

            # Extract username and platform if URL
            username, platform = self.parse_target(target)
            if not username:
                result.status = "error"
                result.error = f"Could not extract username from: {target}"
                return result

            # Check cache
            cache_key = f"profile_scraper:{platform}:{username}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Scrape profile
            profile_data = await self.scrape_profile(username, platform)

            # Store in cache
            cache.set(cache_key, profile_data, ttl=3600)  # 1 hour

            result.status = "success"
            result.data = profile_data
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
                    # Extract username from URL
                    username = target.replace(url_template.format("{}"), "")
                    return username, platform

        # Otherwise, treat as username
        return target, None

    async def scrape_profile(self, username: str, platform: str | None = None) -> dict[str, Any]:
        """Scrape profile from a platform"""
        data = {
            "username": username,
            "platform": platform or "unknown",
            "url": None,
            "exists": False,
            "profile": {},
            "bio": None,
            "posts": [],
            "followers": None,
            "following": None,
            "metadata": {},
            "analysis": {}
        }

        # Determine platform if not specified
        if not platform:
            platform = await self.detect_platform(username)
            data["platform"] = platform

        if not platform:
            data["error"] = "Could not determine platform"
            return data

        # Get URL
        url_template = self.platform_urls.get(platform)
        if url_template:
            data["url"] = url_template.format(username)

        # Check if profile exists
        exists = await self.check_profile_exists(username, platform)
        data["exists"] = exists

        if not exists:
            return data

        # Scrape profile based on platform
        if platform == "twitter":
            data["profile"] = await self.scrape_twitter(username)
        elif platform == "instagram":
            data["profile"] = await self.scrape_instagram(username)
        elif platform == "github":
            data["profile"] = await self.scrape_github(username)
        elif platform == "linkedin":
            data["profile"] = await self.scrape_linkedin(username)
        elif platform == "reddit":
            data["profile"] = await self.scrape_reddit(username)
        else:
            data["profile"] = await self.scrape_generic(username, platform)

        # Extract bio if configured
        if self.config.scrape_bio:
            data["bio"] = data["profile"].get("bio") or data["profile"].get("description")

        # Extract followers/following if configured
        if self.config.scrape_followers:
            data["followers"] = data["profile"].get("followers")
            data["following"] = data["profile"].get("following")

        # Scrape posts if configured
        if self.config.scrape_posts:
            data["posts"] = await self.scrape_posts(username, platform)

        # Analyze the data
        data["analysis"] = self.analyze_profile_data(data)

        return data

    async def detect_platform(self, username: str) -> str | None:
        """Detect which platform a username belongs to"""
        # This is a simplified detection
        # In a real implementation, this would check multiple platforms

        # Check common patterns
        if "@" in username:
            return "twitter"
        elif username.startswith("u/") or username.startswith("user/"):
            return "reddit"
        elif len(username) == 40 and all(c in "0123456789abcdef" for c in username):
            return "github"  # GitHub user ID

        # Default to twitter
        return "twitter"

    async def check_profile_exists(self, username: str, platform: str) -> bool:
        """Check if a profile exists on a platform"""
        url_template = self.platform_urls.get(platform)
        if not url_template:
            return False

        url = url_template.format(username)

        try:
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status == 200:
                    return True
                elif response.status == 404:
                    return False
                else:
                    return True  # Assume exists for non-404 status
        except Exception:
            return False

    async def scrape_twitter(self, username: str) -> dict[str, Any]:
        """Scrape Twitter profile"""
        profile = {
            "platform": "twitter",
            "username": username,
            "name": None,
            "bio": None,
            "location": None,
            "url": None,
            "join_date": None,
            "tweets": None,
            "following": None,
            "followers": None,
            "likes": None,
            "verified": False,
            "avatar": None,
            "banner": None
        }

        try:
            url = f"https://twitter.com/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract profile data
                    profile["name"] = self.extract_twitter_name(soup)
                    profile["bio"] = self.extract_twitter_bio(soup)
                    profile["location"] = self.extract_twitter_location(soup)
                    profile["url"] = self.extract_twitter_url(soup)
                    profile["join_date"] = self.extract_twitter_join_date(soup)
                    profile["tweets"] = self.extract_twitter_tweets(soup)
                    profile["following"] = self.extract_twitter_following(soup)
                    profile["followers"] = self.extract_twitter_followers(soup)
                    profile["likes"] = self.extract_twitter_likes(soup)
                    profile["verified"] = self.extract_twitter_verified(soup)
                    profile["avatar"] = self.extract_twitter_avatar(soup)
                    profile["banner"] = self.extract_twitter_banner(soup)
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_instagram(self, username: str) -> dict[str, Any]:
        """Scrape Instagram profile"""
        profile = {
            "platform": "instagram",
            "username": username,
            "name": None,
            "bio": None,
            "url": None,
            "posts": None,
            "followers": None,
            "following": None,
            "verified": False,
            "avatar": None,
            "is_private": False
        }

        try:
            url = f"https://instagram.com/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract profile data
                    profile["name"] = self.extract_instagram_name(soup)
                    profile["bio"] = self.extract_instagram_bio(soup)
                    profile["url"] = self.extract_instagram_url(soup)
                    profile["posts"] = self.extract_instagram_posts(soup)
                    profile["followers"] = self.extract_instagram_followers(soup)
                    profile["following"] = self.extract_instagram_following(soup)
                    profile["verified"] = self.extract_instagram_verified(soup)
                    profile["avatar"] = self.extract_instagram_avatar(soup)
                    profile["is_private"] = self.extract_instagram_private(soup)
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_github(self, username: str) -> dict[str, Any]:
        """Scrape GitHub profile"""
        profile = {
            "platform": "github",
            "username": username,
            "name": None,
            "bio": None,
            "url": None,
            "location": None,
            "join_date": None,
            "repositories": None,
            "followers": None,
            "following": None,
            "avatar": None,
            "blog": None,
            "company": None,
            "email": None
        }

        try:
            url = f"https://github.com/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract profile data
                    profile["name"] = self.extract_github_name(soup)
                    profile["bio"] = self.extract_github_bio(soup)
                    profile["url"] = self.extract_github_url(soup)
                    profile["location"] = self.extract_github_location(soup)
                    profile["join_date"] = self.extract_github_join_date(soup)
                    profile["repositories"] = self.extract_github_repositories(soup)
                    profile["followers"] = self.extract_github_followers(soup)
                    profile["following"] = self.extract_github_following(soup)
                    profile["avatar"] = self.extract_github_avatar(soup)
                    profile["blog"] = self.extract_github_blog(soup)
                    profile["company"] = self.extract_github_company(soup)
                    profile["email"] = self.extract_github_email(soup)
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_linkedin(self, username: str) -> dict[str, Any]:
        """Scrape LinkedIn profile"""
        profile = {
            "platform": "linkedin",
            "username": username,
            "name": None,
            "headline": None,
            "location": None,
            "current_position": None,
            "past_positions": [],
            "education": [],
            "skills": [],
            "connections": None,
            "avatar": None
        }

        try:
            url = f"https://linkedin.com/in/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract profile data
                    profile["name"] = self.extract_linkedin_name(soup)
                    profile["headline"] = self.extract_linkedin_headline(soup)
                    profile["location"] = self.extract_linkedin_location(soup)
                    profile["current_position"] = self.extract_linkedin_current_position(soup)
                    profile["past_positions"] = self.extract_linkedin_past_positions(soup)
                    profile["education"] = self.extract_linkedin_education(soup)
                    profile["skills"] = self.extract_linkedin_skills(soup)
                    profile["connections"] = self.extract_linkedin_connections(soup)
                    profile["avatar"] = self.extract_linkedin_avatar(soup)
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_reddit(self, username: str) -> dict[str, Any]:
        """Scrape Reddit profile"""
        profile = {
            "platform": "reddit",
            "username": username,
            "name": None,
            "karma": None,
            "cake_day": None,
            "join_date": None,
            "subreddits": [],
            "avatar": None,
            "banner": None
        }

        try:
            url = f"https://reddit.com/user/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract profile data
                    profile["name"] = self.extract_reddit_name(soup)
                    profile["karma"] = self.extract_reddit_karma(soup)
                    profile["cake_day"] = self.extract_reddit_cake_day(soup)
                    profile["join_date"] = self.extract_reddit_join_date(soup)
                    profile["subreddits"] = self.extract_reddit_subreddits(soup)
                    profile["avatar"] = self.extract_reddit_avatar(soup)
                    profile["banner"] = self.extract_reddit_banner(soup)
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_generic(self, username: str, platform: str) -> dict[str, Any]:
        """Scrape generic profile"""
        profile = {
            "platform": platform,
            "username": username,
            "name": None,
            "bio": None,
            "url": None,
            "join_date": None,
            "content": None
        }

        try:
            url_template = self.platform_urls.get(platform)
            if url_template:
                url = url_template.format(username)

                async with self.session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, "html.parser")

                        # Extract basic profile data
                        profile["name"] = self.extract_generic_name(soup)
                        profile["bio"] = self.extract_generic_bio(soup)
                        profile["url"] = url
                        profile["content"] = str(soup.get_text()[:1000])  # First 1000 chars
        except Exception as e:
            profile["error"] = str(e)

        return profile

    async def scrape_posts(self, username: str, platform: str) -> list[dict[str, Any]]:
        """Scrape recent posts from a profile"""
        posts = []

        try:
            if platform == "twitter":
                posts = await self.scrape_twitter_posts(username)
            elif platform == "instagram":
                posts = await self.scrape_instagram_posts(username)
            elif platform == "reddit":
                posts = await self.scrape_reddit_posts(username)
            elif platform == "github":
                posts = await self.scrape_github_repos(username)
        except Exception as e:
            posts = [{"error": str(e)}]

        return posts[:self.config.max_posts]

    async def scrape_twitter_posts(self, username: str) -> list[dict[str, Any]]:
        """Scrape Twitter posts"""
        posts = []

        try:
            url = f"https://twitter.com/{username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract tweets
                    tweets = soup.find_all("div", {"data-testid": "tweet"})

                    for tweet in tweets:
                        posts.append({
                            "text": self.extract_tweet_text(tweet),
                            "timestamp": self.extract_tweet_timestamp(tweet),
                            "likes": self.extract_tweet_likes(tweet),
                            "retweets": self.extract_tweet_retweets(tweet),
                            "replies": self.extract_tweet_replies(tweet)
                        })
        except Exception as e:
            posts = [{"error": str(e)}]

        return posts

    # Extractors for Twitter
    def extract_twitter_name(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("span", {"class": "ProfileHeaderCard-name"})
        return element.get_text().strip() if element else None

    def extract_twitter_bio(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("p", {"class": "ProfileHeaderCard-bio"})
        return element.get_text().strip() if element else None

    def extract_twitter_location(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("span", {"class": "ProfileHeaderCard-location"})
        return element.get_text().strip() if element else None

    def extract_twitter_url(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("a", {"class": "ProfileHeaderCard-url"})
        return element["href"] if element else None

    def extract_twitter_join_date(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("span", {"class": "ProfileHeaderCard-joinDate"})
        return element.get_text().strip() if element else None

    def extract_twitter_tweets(self, soup: BeautifulSoup) -> int | None:
        element = soup.find("span", {"class": "ProfileNav-value", "data-nav": "tweets"})
        if element:
            text = element.get_text().strip()
            return self.parse_number(text)
        return None

    def extract_twitter_following(self, soup: BeautifulSoup) -> int | None:
        element = soup.find("span", {"class": "ProfileNav-value", "data-nav": "following"})
        if element:
            text = element.get_text().strip()
            return self.parse_number(text)
        return None

    def extract_twitter_followers(self, soup: BeautifulSoup) -> int | None:
        element = soup.find("span", {"class": "ProfileNav-value", "data-nav": "followers"})
        if element:
            text = element.get_text().strip()
            return self.parse_number(text)
        return None

    def extract_twitter_likes(self, soup: BeautifulSoup) -> int | None:
        element = soup.find("span", {"class": "ProfileNav-value", "data-nav": "favorites"})
        if element:
            text = element.get_text().strip()
            return self.parse_number(text)
        return None

    def extract_twitter_verified(self, soup: BeautifulSoup) -> bool:
        element = soup.find("i", {"class": "Icon--verified"})
        return element is not None

    def extract_twitter_avatar(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("img", {"class": "ProfileAvatar-image"})
        return element["src"] if element else None

    def extract_twitter_banner(self, soup: BeautifulSoup) -> str | None:
        element = soup.find("div", {"class": "ProfileCanopy-headerBg"})
        if element:
            return element["style"].split("url('")[1].split("')")[0] if "url('" in element.get("style", "") else None
        return None

    # Helper methods
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

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""

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

    def analyze_profile_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze profile data"""
        analysis = {
            "username": data["username"],
            "platform": data["platform"],
            "exists": data["exists"],
            "has_bio": data["bio"] is not None,
            "bio_length": len(data["bio"]) if data["bio"] else 0,
            "has_followers": data["followers"] is not None,
            "followers_count": data["followers"] or 0,
            "has_following": data["following"] is not None,
            "following_count": data["following"] or 0,
            "posts_count": len(data["posts"]),
            "is_active": False,
            "is_influencer": False,
            "is_private": data["profile"].get("is_private", False),
            "recommendations": []
        }

        # Check if active
        if analysis["posts_count"] > 0:
            analysis["is_active"] = True

        # Check if influencer (arbitrary threshold)
        if analysis["followers_count"] > 10000:
            analysis["is_influencer"] = True

        # Generate recommendations
        if not data["exists"]:
            analysis["recommendations"].append(
                "Profile does not exist or is not accessible"
            )
        else:
            if analysis["is_private"]:
                analysis["recommendations"].append(
                    "Profile is private - limited information available"
                )

            if analysis["is_active"]:
                analysis["recommendations"].append(
                    f"ACTIVE: Profile has {analysis['posts_count']} posts"
                )
            else:
                analysis["recommendations"].append(
                    "Profile appears to be inactive"
                )

            if analysis["is_influencer"]:
                analysis["recommendations"].append(
                    f"INFLUENCER: Profile has {analysis['followers_count']:,} followers"
                )

            if analysis["has_bio"]:
                analysis["recommendations"].append(
                    f"BIO: {analysis['bio_length']} character bio"
                )

        return analysis


# Module instance
profile_scraper_module = ProfileScraperModule
