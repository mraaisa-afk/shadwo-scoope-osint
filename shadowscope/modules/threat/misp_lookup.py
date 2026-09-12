"""
MISP Lookup Module for SHADOWSCOPE
Queries MISP (Malware Information Sharing Platform) REST APIs for attribute & IoC correlations.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class MispLookupConfig(ModuleConfig):
    """Configuration for MISP Lookup module."""
    misp_url: str | None = None
    api_key: str | None = None


class MispLookupModule(BaseModule):
    """Module for querying MISP threat intelligence instances for attribute matching and event correlations."""

    MODULE_NAME = "misp_lookup"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "threat"
    MODULE_DESCRIPTION = "Query MISP threat intelligence instances for attribute matching, threat events, and malware tags"
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

    def __init__(self, config: MispLookupConfig | None = None) -> None:
        super().__init__(config=config or MispLookupConfig())
        self.config: MispLookupConfig = self.config if isinstance(self.config, MispLookupConfig) else MispLookupConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute MISP attribute lookup query."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        misp_url = getattr(self.config, "misp_url", None)
        api_key = getattr(self.config, "api_key", None)

        if misp_url and api_key:
            endpoint = f"{misp_url.rstrip('/')}/attributes/restSearch"
            headers = {
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            body = {"returnFormat": "json", "value": cleaned_target}

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(endpoint, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            res_data = await resp.json()
                            attrs = res_data.get("response", {}).get("Attribute", [])
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={
                                    "target": cleaned_target,
                                    "misp_url": misp_url,
                                    "attributes_found": len(attrs),
                                    "attributes": attrs,
                                    "summary": f"MISP query found {len(attrs)} attributes for '{cleaned_target}'"
                                },
                                status="success"
                            )
                        else:
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={"target": cleaned_target},
                                status="failed",
                                error=f"MISP instance returned HTTP {resp.status}"
                            )
            except Exception as e:
                return ModuleResult(
                    target=target,
                    module=self.MODULE_NAME,
                    data={"target": cleaned_target},
                    status="failed",
                    error=f"MISP request failed: {str(e)}"
                )

        # Fallback when MISP instance URL or API key is not configured
        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target": cleaned_target,
                "misp_configured": False,
                "community_misp_instances": [
                    "https://misp.circl.lu",
                    "https://misp.cisa.gov"
                ],
                "sample_query": f"POST /attributes/restSearch with body: {{'value': '{cleaned_target}'}}",
                "summary": f"MISP query prepared for '{cleaned_target}' (No MISP URL/API Key configured)"
            },
            status="success"
        )


misp_lookup_module = MispLookupModule
