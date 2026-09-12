"""
FireHOL Module for SHADOWSCOPE
Checks target IP addresses against FireHOL IP lists, blocklists, and threat intelligence feeds.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Popular FireHOL IP feeds for lookup
FIREHOL_FEEDS: dict[str, str] = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "botscout": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset",
    "alienvault": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset"
}


@dataclass
class FireholConfig(ModuleConfig):
    """Configuration for FireHOL module."""
    feeds: dict[str, str] = None

    def __post_init__(self):
        if self.feeds is None:
            self.feeds = FIREHOL_FEEDS.copy()


class FireholModule(BaseModule):
    """Module for cross-referencing IP addresses against FireHOL reputation blocklists and IP sets."""

    MODULE_NAME = "firehol"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "threat"
    MODULE_DESCRIPTION = "Cross-reference target IP addresses against FireHOL threat intelligence blocklists and IP sets"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: FireholConfig | None = None) -> None:
        super().__init__(config=config or FireholConfig())
        self.config: FireholConfig = self.config if isinstance(self.config, FireholConfig) else FireholConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target IP address string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute FireHOL IP blocklist search."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target IP string"
            )

        feeds_to_check = getattr(self.config, "feeds", FIREHOL_FEEDS) or FIREHOL_FEEDS
        matched_feeds: list[str] = []
        checked_feeds_count = 0

        try:
            async with aiohttp.ClientSession() as session:
                for feed_name, feed_url in feeds_to_check.items():
                    try:
                        async with session.get(feed_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                checked_feeds_count += 1
                                content = await resp.text()
                                if cleaned_target in content:
                                    matched_feeds.append(feed_name)
                    except Exception:
                        pass
        except Exception:
            pass

        is_listed = len(matched_feeds) > 0

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "ip": cleaned_target,
                "is_listed": is_listed,
                "matched_blocklists": matched_feeds,
                "feeds_checked": checked_feeds_count,
                "total_feeds_available": len(feeds_to_check),
                "firehol_repo_url": "https://github.com/firehol/blocklist-ipsets",
                "summary": f"FireHOL IP check for {cleaned_target}: Listed in {len(matched_feeds)} blocklists ({', '.join(matched_feeds) if matched_feeds else 'Clean'})"
            },
            status="success"
        )


firehol_module = FireholModule
