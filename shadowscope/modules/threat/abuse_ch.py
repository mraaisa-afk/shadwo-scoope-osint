"""
abuse.ch Module for SHADOWSCOPE
Queries abuse.ch threat platforms (URLhaus, MalwareBazaar, Feodo Tracker, YARAify) for malicious URL and malware threat data.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class AbuseChConfig(ModuleConfig):
    """Configuration for abuse.ch aggregator module."""
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/"
    bazaar_url: str = "https://mb-api.abuse.ch/api/v1/"


class AbuseChModule(BaseModule):
    """Module for querying abuse.ch platforms (URLhaus & MalwareBazaar) for malicious URLs, domains, and malware payloads."""

    MODULE_NAME = "abuse_ch"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "threat"
    MODULE_DESCRIPTION = "Query abuse.ch platforms (URLhaus, MalwareBazaar) for malicious URLs, domain hosts, and malware file samples"
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

    def __init__(self, config: AbuseChConfig | None = None) -> None:
        super().__init__(config=config or AbuseChConfig())
        self.config: AbuseChConfig = self.config if isinstance(self.config, AbuseChConfig) else AbuseChConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute abuse.ch multi-service lookup."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        urlhaus_api = getattr(self.config, "urlhaus_url", "https://urlhaus-api.abuse.ch/v1/")
        bazaar_api = getattr(self.config, "bazaar_url", "https://mb-api.abuse.ch/api/v1/")

        results: dict[str, Any] = {
            "target": cleaned_target,
            "urlhaus": None,
            "malware_bazaar": None
        }

        # Query URLhaus (Host or URL search)
        try:
            async with aiohttp.ClientSession() as session:
                urlhaus_payload = {"host": cleaned_target} if not cleaned_target.startswith("http") else {"url": cleaned_target}
                endpoint = f"{urlhaus_api.rstrip('/')}/host/" if not cleaned_target.startswith("http") else f"{urlhaus_api.rstrip('/')}/url/"

                async with session.post(endpoint, data=urlhaus_payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        results["urlhaus"] = await resp.json()
        except Exception:
            results["urlhaus"] = {"query_status": "error_or_offline"}

        # Query MalwareBazaar if target looks like a hash
        if len(cleaned_target) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in cleaned_target):
            try:
                async with aiohttp.ClientSession() as session:
                    bazaar_payload = {"query": "get_info", "hash": cleaned_target}
                    async with session.post(bazaar_api, data=bazaar_payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status == 200:
                            results["malware_bazaar"] = await resp.json()
            except Exception:
                results["malware_bazaar"] = {"query_status": "error_or_offline"}

        urlhaus_status = results.get("urlhaus", {}).get("query_status", "no_data") if isinstance(results.get("urlhaus"), dict) else "no_data"
        bazaar_status = results.get("malware_bazaar", {}).get("query_status", "no_data") if isinstance(results.get("malware_bazaar"), dict) else "no_data"

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target": cleaned_target,
                "services": results,
                "summary": f"abuse.ch lookup for '{cleaned_target}' -> URLhaus: {urlhaus_status}, MalwareBazaar: {bazaar_status}"
            },
            status="success"
        )


abuse_ch_module = AbuseChModule
