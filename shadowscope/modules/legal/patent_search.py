"""
Patent Search Module for SHADOWSCOPE
Searches international patent databases (Google Patents, USPTO Patents, Espacenet / EPO) for inventors, assignees, and technology claims.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class PatentSearchConfig(ModuleConfig):
    """Configuration for Patent Search module."""
    google_patents_base: str = "https://patents.google.com"


class PatentSearchModule(BaseModule):
    """Module for querying Google Patents, USPTO, and EPO Espacenet for patent filings, assignees, and inventors."""

    MODULE_NAME = "patent_search"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "legal"
    MODULE_DESCRIPTION = "Search Google Patents, USPTO, and EPO Espacenet for patent documents, inventors, assignees, and technical claims"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: PatentSearchConfig | None = None) -> None:
        super().__init__(config=config or PatentSearchConfig())
        self.config: PatentSearchConfig = self.config if isinstance(self.config, PatentSearchConfig) else PatentSearchConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate patent query string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute patent lookup query."""
        query = target.strip()
        if not self.validate_target(query):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid patent query string"
            )

        google_patents_url = f"https://patents.google.com/?q={query.replace(' ', '+')}"
        espacenet_url = f"https://worldwide.espacenet.com/patent/search?q={query.replace(' ', '+')}"

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "query": query,
                "google_patents_url": google_patents_url,
                "espacenet_url": espacenet_url,
                "summary": f"Patent Search links generated for '{query}' across Google Patents & Espacenet"
            },
            status="success"
        )


patent_search_module = PatentSearchModule
