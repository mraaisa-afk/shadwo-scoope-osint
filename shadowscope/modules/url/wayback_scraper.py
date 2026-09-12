"""
Wayback Scraper Module for SHADOWSCOPE
Queries Internet Archive Wayback Machine CDX API for archived URLs, historical endpoints, and snapshot timelines.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class WaybackScraperConfig(ModuleConfig):
    """Configuration for Wayback Scraper module."""
    cdx_api_url: str = "http://web.archive.org/cdx/search/cdx"
    max_results: int = 100


class WaybackScraperModule(BaseModule):
    """Module for querying Wayback Machine CDX API for historical URLs and archived snapshots."""

    MODULE_NAME = "wayback_scraper"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Query Internet Archive Wayback Machine CDX API for archived endpoints, parameters, and historical URLs"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN, TargetType.URL, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: WaybackScraperConfig | None = None) -> None:
        super().__init__(config=config or WaybackScraperConfig())
        self.config: WaybackScraperConfig = self.config if isinstance(self.config, WaybackScraperConfig) else WaybackScraperConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target domain or URL."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute Wayback CDX API query."""
        domain = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
        if not self.validate_target(domain):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid domain target"
            )

        cdx_url = getattr(self.config, "cdx_api_url", "http://web.archive.org/cdx/search/cdx")
        limit = int(getattr(self.config, "max_results", 100))

        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp,mimetype,statuscode",
            "collapse": "urlkey",
            "limit": str(limit)
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(cdx_url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        urls = []
                        if isinstance(data, list) and len(data) > 1:
                            for row in data[1:]:
                                urls.append({"url": row[0], "timestamp": row[1], "mimetype": row[2], "status": row[3]})

                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "domain": domain,
                                "archived_urls_found": len(urls),
                                "urls": urls,
                                "summary": f"Wayback Scraper found {len(urls)} archived URLs for '{domain}'"
                            },
                            status="success"
                        )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "domain": domain,
                    "wayback_search_url": f"https://web.archive.org/web/*/{domain}"
                },
                status="failed",
                error=f"Wayback CDX API query failed: {str(e)}"
            )

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={"domain": domain, "archived_urls_found": 0, "urls": []},
            status="success"
        )


wayback_scraper_module = WaybackScraperModule
