"""
Property Records Module for SHADOWSCOPE
Analyzes physical addresses for cadastral, county GIS, and property assessor query generation.
"""

import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class PropertyRecordsConfig(ModuleConfig):
    """Configuration for Property Records module."""
    default_country: str = "US"


class PropertyRecordsModule(BaseModule):
    """Module for parsing physical addresses and generating county GIS and property assessor search parameters."""

    MODULE_NAME = "property_records"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "physical"
    MODULE_DESCRIPTION = "Parse physical addresses to generate county GIS, tax assessor, and cadastral search queries"
    MODULE_TARGET_TYPES = [TargetType.ADDRESS, TargetType.COORDINATES, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: PropertyRecordsConfig | None = None) -> None:
        super().__init__(config=config or PropertyRecordsConfig())
        self.config: PropertyRecordsConfig = self.config if isinstance(self.config, PropertyRecordsConfig) else PropertyRecordsConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target address or coordinates string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _parse_address_components(address: str) -> dict[str, Any]:
        """Parse address string into basic components (number, street, city, state, zip)."""
        components: dict[str, Any] = {
            "street_number": None,
            "street_name": None,
            "city": None,
            "state": None,
            "zip_code": None,
            "raw_address": address
        }

        # Match ZIP code
        zip_match = re.search(r"\b(\d{5}(-\d{4})?)\b", address)
        if zip_match:
            components["zip_code"] = zip_match.group(1)

        # Match street number & name
        num_match = re.match(r"^(\d+[A-Za-z]?)\s+(.+)", address.strip())
        if num_match:
            components["street_number"] = num_match.group(1)
            remainder = num_match.group(2)
            parts = [p.strip() for p in remainder.split(",")]
            if parts:
                components["street_name"] = parts[0]
            if len(parts) > 1:
                components["city"] = parts[1]
            if len(parts) > 2:
                state_part = parts[2].strip()
                state_match = re.search(r"\b([A-Z]{2})\b", state_part)
                if state_match:
                    components["state"] = state_match.group(1)
                else:
                    components["state"] = state_part

        return components

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute property record query generation."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target address string"
            )

        parsed = self._parse_address_components(cleaned_target)

        # Search links
        query_encoded = cleaned_target.replace(" ", "+")
        search_links = {
            "county_assessor_search": f"https://www.google.com/search?q={query_encoded}+property+tax+assessor+records",
            "county_gis_map_search": f"https://www.google.com/search?q={query_encoded}+county+GIS+parcel+map",
            "realtor_property_info": f"https://www.realtor.com/realestateandhomes-search/{query_encoded}",
            "zillow_property_info": f"https://www.zillow.com/homes/{query_encoded}_rb/",
            "redfin_property_info": f"https://www.redfin.com/stingray/do/query-location?location={query_encoded}",
        }

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target_address": cleaned_target,
                "parsed_components": parsed,
                "search_queries": {
                    "assessor_query": f"{cleaned_target} property tax assessor",
                    "deed_query": f"{cleaned_target} property deed records owner",
                    "gis_parcel_query": f"{cleaned_target} GIS parcel number",
                },
                "resource_links": search_links,
                "summary": f"Property records queries generated for: {cleaned_target}"
            },
            status="success"
        )


property_records_module = PropertyRecordsModule
