"""
License Plate Module for SHADOWSCOPE
Analyzes vehicle license plate formats and generates state/jurisdiction vehicle record search queries.
"""

import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class LicensePlateConfig(ModuleConfig):
    """Configuration for License Plate module."""
    default_state: str = "US"


class LicensePlateModule(BaseModule):
    """Module for analyzing license plate formats, detecting jurisdiction patterns, and generating lookup links."""

    MODULE_NAME = "license_plate"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "transport"
    MODULE_DESCRIPTION = "Analyze vehicle license plate patterns, detect jurisdiction formats, and generate registry queries"
    MODULE_TARGET_TYPES = [TargetType.LICENSE_PLATE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: LicensePlateConfig | None = None) -> None:
        super().__init__(config=config or LicensePlateConfig())
        self.config: LicensePlateConfig = self.config if isinstance(self.config, LicensePlateConfig) else LicensePlateConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate license plate string (2 to 8 alphanumeric chars, spaces/dashes allowed)."""
        if not target or not isinstance(target, str):
            return False
        cleaned = re.sub(r"[\s-]", "", target.strip().upper())
        return bool(re.match(r"^[A-Z0-9]{2,8}$", cleaned))

    @staticmethod
    def _detect_format_pattern(plate: str) -> str:
        """Detect pattern format (e.g. 1ABC234, ABC-1234, UK AB12 CDE, etc.)."""
        p = plate.upper().strip()
        if re.match(r"^\d[A-Z]{3}\d{3}$", p):
            return "US California Standard (1ABC123)"
        if re.match(r"^[A-Z]{3}\d{4}$", p):
            return "US Standard (ABC1234)"
        if re.match(r"^[A-Z]{3}\d{3}$", p):
            return "US/CAN Standard (ABC123)"
        if re.match(r"^[A-Z]{2}\d{2}[A-Z]{3}$", p):
            return "UK Standard (AB12 CDE)"
        if re.match(r"^[A-Z]{2}\d{3}[A-Z]{2}$", p):
            return "EU Standard (AB123CD)"
        return "General Alphanumeric"

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute license plate query generation."""
        raw_target = target.strip().upper()
        plate_clean = re.sub(r"[\s-]", "", raw_target)

        if not self.validate_target(plate_clean):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Invalid license plate string: '{target}' (must be 2-8 alphanumeric chars)"
            )

        pattern = self._detect_format_pattern(plate_clean)

        # Public lookup search URLs
        query_encoded = plate_clean.replace(" ", "+")
        search_links = {
            "faxvin_plate_lookup": f"https://www.faxvin.com/license-plate-lookup/result?plate={query_encoded}",
            "findbyplate_lookup": f"https://findbyplate.com/US/{query_encoded}/",
            "vehiclehistory_lookup": f"https://www.vehiclehistory.com/license-plate-search?plate={query_encoded}",
            "uk_gov_vehicle_check": "https://www.gov.uk/get-vehicle-information-from-dvla" if "UK" in pattern else None,
        }

        # Filter out None links
        search_links = {k: v for k, v in search_links.items() if v}

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "raw_plate": raw_target,
                "normalized_plate": plate_clean,
                "detected_pattern": pattern,
                "character_count": len(plate_clean),
                "lookup_queries": {
                    "general_search": f"license plate {plate_clean} vehicle owner",
                    "vin_from_plate": f"convert license plate {plate_clean} to VIN",
                },
                "search_links": search_links,
                "summary": f"License plate format '{plate_clean}' analyzed: {pattern}"
            },
            status="success"
        )


license_plate_module = LicensePlateModule
