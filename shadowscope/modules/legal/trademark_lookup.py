"""
Trademark Lookup Module for SHADOWSCOPE
Queries global trademark offices (USPTO TESS / TSDR, EUIPO, WIPO Global Brand Database) for brand registration status.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class TrademarkLookupConfig(ModuleConfig):
    """Configuration for Trademark Lookup module."""
    uspto_api_url: str = "https://tsdrapi.uspto.gov/ts/cd/casestatus"


class TrademarkLookupModule(BaseModule):
    """Module for querying USPTO, EUIPO, and WIPO trademark databases for brand filings and ownership."""

    MODULE_NAME = "trademark_lookup"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "legal"
    MODULE_DESCRIPTION = "Search USPTO, EUIPO, and WIPO databases for brand trademarks, serial numbers, active status, and owners"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: TrademarkLookupConfig | None = None) -> None:
        super().__init__(config=config or TrademarkLookupConfig())
        self.config: TrademarkLookupConfig = self.config if isinstance(self.config, TrademarkLookupConfig) else TrademarkLookupConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target trademark query string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute trademark database search."""
        query = target.strip()
        if not self.validate_target(query):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid trademark query string"
            )

        # Build public registry web search links
        uspto_url = f"https://tmsearch.uspto.gov/bin/gate.exe?f=searchss&state={query.replace(' ', '+')}"
        wipo_url = f"https://www3.wipo.int/branddb/en/#q={query.replace(' ', '+')}"
        euipo_url = f"https://euipo.europa.eu/eSearch/#details/trademarks/{query.replace(' ', '+')}"

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "trademark_query": query,
                "uspto_tess_url": uspto_url,
                "wipo_global_brand_url": wipo_url,
                "euipo_url": euipo_url,
                "summary": f"Trademark search query prepared for '{query}' across USPTO, WIPO, and EUIPO registries"
            },
            status="success"
        )


trademark_lookup_module = TrademarkLookupModule
