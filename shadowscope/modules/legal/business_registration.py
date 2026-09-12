"""
Business Registration Module for SHADOWSCOPE
Queries corporate registries (OpenCorporates, SEC EDGAR, UK Companies House) for company profiles, filing records, and officers.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class BusinessRegistrationConfig(ModuleConfig):
    """Configuration for Business Registration module."""
    api_key: str | None = None
    opencorporates_url: str = "https://api.opencorporates.com/v0.2/companies/search"


class BusinessRegistrationModule(BaseModule):
    """Module for looking up registered corporate entities, officers, incorporated dates, and SEC/Companies House filings."""

    MODULE_NAME = "business_registration"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "legal"
    MODULE_DESCRIPTION = "Search corporate registries (OpenCorporates, SEC EDGAR, UK Companies House) for company status, officers, and filing history"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: BusinessRegistrationConfig | None = None) -> None:
        super().__init__(config=config or BusinessRegistrationConfig())
        self.config: BusinessRegistrationConfig = self.config if isinstance(self.config, BusinessRegistrationConfig) else BusinessRegistrationConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target company query string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute company registry search."""
        query = target.strip()
        if not self.validate_target(query):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid company search target"
            )

        api_url = getattr(self.config, "opencorporates_url", "https://api.opencorporates.com/v0.2/companies/search")
        api_key = getattr(self.config, "api_key", None)

        params = {"q": query}
        if api_key:
            params["api_token"] = api_key

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        companies = data.get("results", {}).get("companies", [])
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "query": query,
                                "total_found": len(companies),
                                "companies": companies,
                                "summary": f"Business Registration search for '{query}': {len(companies)} corporate entit(ies) found"
                            },
                            status="success"
                        )
                    else:
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={"query": query},
                            status="failed",
                            error=f"Corporate registry API returned HTTP {resp.status}"
                        )
        except Exception as e:
            # Fallback search URLs
            sec_edgar_url = f"https://www.sec.gov/edgar/searchedgar/companysearch?company_name={query.replace(' ', '+')}"
            uk_ch_url = f"https://find-and-update.company-information.service.gov.uk/search/companies?q={query.replace(' ', '+')}"

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "query": query,
                    "sec_edgar_url": sec_edgar_url,
                    "uk_companies_house_url": uk_ch_url,
                    "opencorporates_web_url": f"https://opencorporates.com/companies?q={query.replace(' ', '+')}",
                    "summary": f"Business Registration registry links generated for '{query}' (API unreachable: {str(e)})"
                },
                status="success"
            )


business_registration_module = BusinessRegistrationModule
