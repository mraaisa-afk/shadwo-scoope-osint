"""
ThreatFox Module for SHADOWSCOPE
Queries ThreatFox API (by abuse.ch) for Indicator of Compromise (IoC) records (hashes, IPs, domains, malware names).
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class ThreatFoxConfig(ModuleConfig):
    """Configuration for ThreatFox module."""
    api_url: str = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxModule(BaseModule):
    """Module for searching ThreatFox IoC database by abuse.ch for hashes, IPs, domains, and URLs."""

    MODULE_NAME = "threat_fox"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "threat"
    MODULE_DESCRIPTION = "Search ThreatFox database by abuse.ch for Indicators of Compromise (hashes, IPs, domains, malware families)"
    MODULE_TARGET_TYPES = [
        TargetType.IP,
        TargetType.DOMAIN,
        TargetType.MD5,
        TargetType.SHA1,
        TargetType.SHA256,
        TargetType.URL,
        TargetType.UNKNOWN,
    ]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: ThreatFoxConfig | None = None) -> None:
        super().__init__(config=config or ThreatFoxConfig())
        self.config: ThreatFoxConfig = self.config if isinstance(self.config, ThreatFoxConfig) else ThreatFoxConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute ThreatFox API search."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        api_url = getattr(self.config, "api_url", "https://threatfox-api.abuse.ch/api/v1/")

        # Determine search payload type
        if len(cleaned_target) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in cleaned_target):
            payload = {"query": "search_hash", "hash": cleaned_target}
        else:
            payload = {"query": "search_ioc", "search_term": cleaned_target}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        json_resp = await resp.json()
                        query_status = json_resp.get("query_status", "unknown")
                        data_items = json_resp.get("data", [])

                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "target": cleaned_target,
                                "query_status": query_status,
                                "iocs_found": len(data_items) if isinstance(data_items, list) else 0,
                                "iocs": data_items,
                                "summary": f"ThreatFox search for '{cleaned_target}': {query_status} ({len(data_items) if isinstance(data_items, list) else 0} records)"
                            },
                            status="success"
                        )
                    else:
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={"target": cleaned_target},
                            status="failed",
                            error=f"ThreatFox API returned HTTP {resp.status}"
                        )
        except Exception as e:
            # Provide structured response on error/offline
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "target": cleaned_target,
                    "web_lookup_url": f"https://threatfox.abuse.ch/browse.php?search={cleaned_target}"
                },
                status="failed",
                error=f"ThreatFox request failed: {str(e)}"
            )


threat_fox_module = ThreatFoxModule
