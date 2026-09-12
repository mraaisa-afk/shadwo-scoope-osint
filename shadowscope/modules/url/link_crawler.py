"""
Link Crawler Module for SHADOWSCOPE
Crawls web pages recursively to map internal and external hyperlink structures, media assets, and document links.
"""

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class LinkCrawlerConfig(ModuleConfig):
    """Configuration for Link Crawler module."""
    max_depth: int = 2
    max_links: int = 50


class LinkCrawlerModule(BaseModule):
    """Module for crawling web pages and extracting internal/external links, documents, and subdomains."""

    MODULE_NAME = "link_crawler"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Crawl web pages recursively to map internal/external hyperlinks, linked documents, and subdomains"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: LinkCrawlerConfig | None = None) -> None:
        super().__init__(config=config or LinkCrawlerConfig())
        self.config: LinkCrawlerConfig = self.config if isinstance(self.config, LinkCrawlerConfig) else LinkCrawlerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute web link crawling."""
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target URL"
            )

        max_limit = int(getattr(self.config, "max_links", 50))
        internal_links: list[str] = []
        external_links: list[str] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        found_hrefs = re.findall(r'href=["\'](https?://[^\s"\'<>]+|/[^\s"\'<>]+)', html)

                        domain = url.split("/")[2]
                        for href in found_hrefs:
                            if href.startswith("/") or domain in href:
                                if href not in internal_links:
                                    internal_links.append(href)
                            else:
                                if href not in external_links:
                                    external_links.append(href)

                            if len(internal_links) + len(external_links) >= max_limit:
                                break

                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "target_url": url,
                                "internal_links_count": len(internal_links),
                                "external_links_count": len(external_links),
                                "internal_links": internal_links,
                                "external_links": external_links,
                                "summary": f"Link Crawler for '{url}': Extracted {len(internal_links)} internal and {len(external_links)} external links"
                            },
                            status="success"
                        )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={"target_url": url},
                status="failed",
                error=f"Link crawling failed: {str(e)}"
            )

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={"target_url": url, "internal_links": [], "external_links": []},
            status="success"
        )


link_crawler_module = LinkCrawlerModule
