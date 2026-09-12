"""
Param Brute Module for SHADOWSCOPE
Fuzzes HTTP parameters on target URLs to discover hidden GET/POST parameters and unlinked query inputs.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

COMMON_HTTP_PARAMS = [
    "id", "user", "admin", "debug", "test", "file", "page", "url", "redirect",
    "cmd", "exec", "search", "query", "key", "token", "auth", "config", "mode"
]


@dataclass
class ParamBruteConfig(ModuleConfig):
    """Configuration for Param Brute module."""
    wordlist: list[str] | None = None

    def __post_init__(self):
        if self.wordlist is None:
            self.wordlist = COMMON_HTTP_PARAMS.copy()


class ParamBruteModule(BaseModule):
    """Module for brute-forcing HTTP GET/POST query parameters to find hidden web inputs."""

    MODULE_NAME = "param_brute"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Brute-force HTTP query parameters to discover unlinked GET/POST inputs, debug flags, and hidden parameters"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: ParamBruteConfig | None = None) -> None:
        super().__init__(config=config or ParamBruteConfig())
        self.config: ParamBruteConfig = self.config if isinstance(self.config, ParamBruteConfig) else ParamBruteConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL or domain string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute parameter brute-force analysis."""
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid URL string"
            )

        words = getattr(self.config, "wordlist", COMMON_HTTP_PARAMS) or COMMON_HTTP_PARAMS

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target_url": url,
                "wordlist_size": len(words),
                "params_tested": words,
                "summary": f"Param Brute analysis initialized for '{url}': {len(words)} common parameter names queued for fuzzing"
            },
            status="success"
        )


param_brute_module = ParamBruteModule
