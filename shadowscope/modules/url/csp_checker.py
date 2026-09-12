"""
CSP Checker Module for SHADOWSCOPE
Analyzes Content Security Policy (CSP) headers on web targets to identify bypass vectors and subdomains.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class CspCheckerConfig(ModuleConfig):
    """Configuration for CSP Checker module."""
    check_bypass: bool = True


class CspCheckerModule(BaseModule):
    """Module for fetching and evaluating Content Security Policy (CSP) directives and domain allowlists."""

    MODULE_NAME = "csp_checker"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Analyze Content Security Policy (CSP) headers for allowed script domains, wildcard entries, and bypass risks"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: CspCheckerConfig | None = None) -> None:
        super().__init__(config=config or CspCheckerConfig())
        self.config: CspCheckerConfig = self.config if isinstance(self.config, CspCheckerConfig) else CspCheckerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute CSP header inspection."""
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid URL target"
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = resp.headers
                    csp_header = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only")

                    if csp_header:
                        directives = [d.strip() for d in csp_header.split(";") if d.strip()]
                        has_unsafe_inline = "'unsafe-inline'" in csp_header
                        has_unsafe_eval = "'unsafe-eval'" in csp_header
                        has_wildcard = "*" in csp_header

                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "url": url,
                                "csp_present": True,
                                "raw_csp": csp_header,
                                "directives_count": len(directives),
                                "directives": directives,
                                "has_unsafe_inline": has_unsafe_inline,
                                "has_unsafe_eval": has_unsafe_eval,
                                "has_wildcard": has_wildcard,
                                "summary": f"CSP present on '{url}': {len(directives)} directives (unsafe-inline: {has_unsafe_inline}, unsafe-eval: {has_unsafe_eval})"
                            },
                            status="success"
                        )
                    else:
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "url": url,
                                "csp_present": False,
                                "summary": f"No Content-Security-Policy header detected on '{url}'"
                            },
                            status="success"
                        )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={"url": url},
                status="failed",
                error=f"CSP check failed: {str(e)}"
            )


csp_checker_module = CspCheckerModule
