"""
Ship Tracker Module for SHADOWSCOPE
Tracks maritime vessels via IMO numbers, MMSI IDs, and AIS vessel tracking providers.
"""

import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class ShipTrackerConfig(ModuleConfig):
    """Configuration for Ship Tracker module."""
    verify_imo_checksum: bool = True


class ShipTrackerModule(BaseModule):
    """Module for tracking maritime ships, verifying IMO/MMSI identifiers, and generating AIS links."""

    MODULE_NAME = "ship_tracker"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "transport"
    MODULE_DESCRIPTION = "Track maritime vessels by IMO, MMSI, or vessel name and verify IMO checksums"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: ShipTrackerConfig | None = None) -> None:
        super().__init__(config=config or ShipTrackerConfig())
        self.config: ShipTrackerConfig = self.config if isinstance(self.config, ShipTrackerConfig) else ShipTrackerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target vessel IMO, MMSI, or name."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) >= 3

    @staticmethod
    def _verify_imo_checksum(imo_str: str) -> bool:
        """Verify 7-digit IMO number checksum digit."""
        digits_only = re.sub(r"\D", "", imo_str)
        if len(digits_only) != 7:
            return False
        try:
            d = [int(c) for c in digits_only]
            calc_check = (7 * d[0] + 6 * d[1] + 5 * d[2] + 4 * d[3] + 3 * d[4] + 2 * d[5]) % 10
            return calc_check == d[6]
        except Exception:
            return False

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute ship tracking query."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Invalid vessel identifier: '{target}'"
            )

        digits_only = re.sub(r"\D", "", cleaned_target)
        is_imo = len(digits_only) == 7 and (cleaned_target.upper().startswith("IMO") or digits_only == cleaned_target)
        is_mmsi = len(digits_only) == 9 and digits_only == cleaned_target

        imo_valid = self._verify_imo_checksum(digits_only) if is_imo else None

        query_param = digits_only if (is_imo or is_mmsi) else cleaned_target

        tracking_links = {
            "vesselfinder": f"https://www.vesselfinder.com/vessels?name={query_param}",
            "marinetraffic": f"https://www.marinetraffic.com/en/ais/details/ships/search:{query_param}",
            "myshiptracking": f"https://www.myshiptracking.com/vessels?name={query_param}",
            "fleetmon": f"https://www.fleetmon.com/vessels/?search={query_param}",
        }

        # MID (Maritime Identification Digits) country code parsing for MMSI
        mid_country = None
        if is_mmsi and len(digits_only) == 9:
            mid = digits_only[:3]
            # Sample MID mappings
            mid_map = {
                "366": "United States", "367": "United States", "368": "United States", "369": "United States",
                "232": "United Kingdom", "233": "United Kingdom", "234": "United Kingdom", "235": "United Kingdom",
                "412": "China", "413": "China", "414": "China",
                "419": "India",
                "405": "Bangladesh",
            }
            mid_country = mid_map.get(mid, f"MID Code {mid}")

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target": cleaned_target,
                "is_imo": is_imo,
                "imo_checksum_valid": imo_valid,
                "is_mmsi": is_mmsi,
                "mmsi_country": mid_country,
                "parsed_identifier": query_param,
                "tracking_providers": tracking_links,
                "summary": f"Vessel tracking analysis for '{cleaned_target}': IMO={is_imo}, MMSI={is_mmsi}"
            },
            status="success"
        )


ship_tracker_module = ShipTrackerModule
