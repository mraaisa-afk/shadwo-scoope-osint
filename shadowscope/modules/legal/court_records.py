"""
Court Records Module for SHADOWSCOPE
Searches judicial dockets, court records repositories (RECAP / CourtListener, PACER), and litigation archives.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class CourtRecordsConfig(ModuleConfig):
    """Configuration for Court Records module."""
    api_url: str = "https://www.courtlistener.com/api/rest/v3/dockets/"


class CourtRecordsModule(BaseModule):
    """Module for searching judicial dockets, court opinions, and litigation records."""

    MODULE_NAME = "court_records"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "legal"
    MODULE_DESCRIPTION = "Search public court records, judicial dockets (CourtListener RECAP), and legal proceedings archives"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: CourtRecordsConfig | None = None) -> None:
        super().__init__(config=config or CourtRecordsConfig())
        self.config: CourtRecordsConfig = self.config if isinstance(self.config, CourtRecordsConfig) else CourtRecordsConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target name or docket number string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute court record docket search."""
        query = target.strip()
        if not self.validate_target(query):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid court records search target"
            )

        api_url = getattr(self.config, "api_url", "https://www.courtlistener.com/api/rest/v3/dockets/")

        try:
            async with aiohttp.ClientSession() as session:
                params = {"q": query}
                async with session.get(api_url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results_list = data.get("results", [])
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "query": query,
                                "dockets_found": len(results_list),
                                "dockets": results_list,
                                "summary": f"Court Records search for '{query}': {len(results_list)} docket(s) retrieved"
                            },
                            status="success"
                        )
        except Exception:
            pass

        # Direct search portal URL
        web_search_url = f"https://www.courtlistener.com/?q={query.replace(' ', '+')}"
        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "query": query,
                "courtlistener_url": web_search_url,
                "summary": f"Court Records portal link generated for '{query}'"
            },
            status="success"
        )


court_records_module = CourtRecordsModule
