"""
JS Analyzer Module for SHADOWSCOPE
Scrapes JavaScript files from target URLs to discover API endpoints, secret tokens, AWS keys, and internal URLs.
"""

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class JsAnalyzerConfig(ModuleConfig):
    """Configuration for JS Analyzer module."""
    extract_endpoints: bool = True


class JsAnalyzerModule(BaseModule):
    """Module for fetching and analyzing JavaScript assets for endpoints, API keys, and hardcoded secrets."""

    MODULE_NAME = "js_analyzer"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Analyze JavaScript files and bundles for API endpoints, hardcoded API keys, JWT tokens, and internal paths"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: JsAnalyzerConfig | None = None) -> None:
        super().__init__(config=config or JsAnalyzerConfig())
        self.config: JsAnalyzerConfig = self.config if isinstance(self.config, JsAnalyzerConfig) else JsAnalyzerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL or JS file path."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute JS content analysis."""
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

        endpoints: list[str] = []
        secrets: list[dict[str, str]] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()

                        # Extract relative/absolute API paths
                        found_paths = re.findall(r'["\'](/api/v\d+/[a-zA-Z0-9_/-]+|/v1/[a-zA-Z0-9_/-]+|/graphql)["\']', text)
                        endpoints = sorted(list(set(found_paths)))

                        # Check for API key patterns
                        if "AKIA" in text:
                            aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', text)
                            for k in set(aws_keys):
                                secrets.append({"type": "AWS Access Key", "value": k})

                        if "eyJ" in text:
                            jwts = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', text)
                            for j in set(jwts[:3]):
                                secrets.append({"type": "JWT Token", "value": j})

                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "url": url,
                                "endpoints_discovered": endpoints,
                                "secrets_discovered": secrets,
                                "summary": f"JS Analyzer for '{url}': Discovered {len(endpoints)} API endpoint(s) and {len(secrets)} potential secret(s)"
                            },
                            status="success"
                        )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={"url": url},
                status="failed",
                error=f"JS analysis failed: {str(e)}"
            )

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={"url": url, "endpoints_discovered": [], "secrets_discovered": []},
            status="success"
        )


js_analyzer_module = JsAnalyzerModule
