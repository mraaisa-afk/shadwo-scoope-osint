"""
SWIFT / BIC Code Module for SHADOWSCOPE
Decodes SWIFT / BIC codes into institution name, country, location city, and branch office.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Common SWIFT/BIC code directory catalog
SWIFT_CATALOG: dict[str, dict[str, str]] = {
    "BOFAUS3N": {"bank": "Bank of America", "city": "New York", "country": "United States", "branch": "Primary Head Office"},
    "CHASUS33": {"bank": "JPMorgan Chase Bank", "city": "New York", "country": "United States", "branch": "Head Office"},
    "CITIUS33": {"bank": "Citibank N.A.", "city": "New York", "country": "United States", "branch": "Head Office"},
    "HSBCGB2L": {"bank": "HSBC Bank plc", "city": "London", "country": "United Kingdom", "branch": "Head Office"},
    "BARCGB22": {"bank": "Barclays Bank UK PLC", "city": "London", "country": "United Kingdom", "branch": "Head Office"},
    "DBACDEFF": {"bank": "Deutsche Bank AG", "city": "Frankfurt am Main", "country": "Germany", "branch": "Head Office"},
    "BNPAFRPP": {"bank": "BNP Paribas", "city": "Paris", "country": "France", "branch": "Head Office"},
    "SCBLBDDD": {"bank": "Standard Chartered Bank", "city": "Dhaka", "country": "Bangladesh", "branch": "Bangladesh Head Office"},
    "HSBCBDDH": {"bank": "HSBC Bangladesh", "city": "Dhaka", "country": "Bangladesh", "branch": "Main Branch"},
}


@dataclass
class SwiftCodeConfig(ModuleConfig):
    """Configuration for SWIFT Code module."""
    include_branch_details: bool = True


class SwiftCodeModule(BaseModule):
    """Module for decoding and verifying 8-11 character SWIFT/BIC banking codes."""

    MODULE_NAME = "swift_code"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "financial"
    MODULE_DESCRIPTION = "Decode 8-11 character SWIFT/BIC bank codes to identify financial institution, country, city, and branch office"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: SwiftCodeConfig | None = None) -> None:
        super().__init__(config=config or SwiftCodeConfig())
        self.config: SwiftCodeConfig = self.config if isinstance(self.config, SwiftCodeConfig) else SwiftCodeConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate string format for 8 or 11 character SWIFT/BIC candidate."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip().upper()
        return len(cleaned) in (8, 11) and cleaned.isalnum()

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute SWIFT code decoding."""
        code = target.strip().upper()
        if not self.validate_target(code):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid SWIFT code length (must be 8 or 11 alphanumeric characters)"
            )

        bank_code = code[:4]
        country_code = code[4:6]
        location_code = code[6:8]
        branch_code = code[8:11] if len(code) == 11 else "XXX (Primary)"

        # Check local catalog
        match_8 = code[:8]
        catalog_entry = SWIFT_CATALOG.get(code) or SWIFT_CATALOG.get(match_8)

        bank_name = catalog_entry["bank"] if catalog_entry else f"Bank Code '{bank_code}'"
        city_name = catalog_entry["city"] if catalog_entry else f"Location Code '{location_code}'"
        country_name = catalog_entry["country"] if catalog_entry else country_code
        branch_desc = catalog_entry["branch"] if catalog_entry else branch_code

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "swift_code": code,
                "bank_code": bank_code,
                "country_code": country_code,
                "location_code": location_code,
                "branch_code": branch_code,
                "bank_name": bank_name,
                "city": city_name,
                "country": country_name,
                "branch": branch_desc,
                "in_catalog": catalog_entry is not None,
                "summary": f"SWIFT Code {code}: {bank_name}, {city_name}, {country_name} ({branch_desc})"
            },
            status="success"
        )


swift_code_module = SwiftCodeModule
