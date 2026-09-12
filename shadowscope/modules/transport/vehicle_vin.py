"""
Vehicle VIN Module for SHADOWSCOPE
Decodes 17-character Vehicle Identification Numbers (VIN), verifies check digits, and queries NHTSA VPIC API.
"""

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class VehicleVinConfig(ModuleConfig):
    """Configuration for Vehicle VIN module."""
    nhtsa_api_url: str = "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin"


class VehicleVinModule(BaseModule):
    """Module for decoding VIN numbers, verifying check digits, and querying NHTSA vehicle specs."""

    MODULE_NAME = "vehicle_vin"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "transport"
    MODULE_DESCRIPTION = "Decode 17-character Vehicle Identification Numbers (VIN), verify check digits, and fetch NHTSA vehicle specs"
    MODULE_TARGET_TYPES = [TargetType.VIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: VehicleVinConfig | None = None) -> None:
        super().__init__(config=config or VehicleVinConfig())
        self.config: VehicleVinConfig = self.config if isinstance(self.config, VehicleVinConfig) else VehicleVinConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate 17-character VIN format (excluding I, O, Q)."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip().upper()
        return bool(re.match(r"^[A-HJ-NPR-Z0-9]{17}$", cleaned))

    @staticmethod
    def _verify_vin_check_digit(vin: str) -> tuple[bool, str, str]:
        """Verify position 9 VIN check digit per North American / ISO 3779 standard."""
        vin = vin.upper()
        if len(vin) != 17:
            return False, "", ""

        values = {
            'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
            'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9, 'S': 2,
            'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
            '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9
        }

        weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

        total = 0
        try:
            for i in range(17):
                char = vin[i]
                if char not in values:
                    return False, vin[8], "Invalid character"
                total += values[char] * weights[i]

            remainder = total % 11
            expected = "X" if remainder == 10 else str(remainder)
            actual = vin[8]

            return (expected == actual), actual, expected
        except Exception as e:
            return False, vin[8] if len(vin) > 8 else "", str(e)

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute VIN decoding query."""
        vin = target.strip().upper()
        if not self.validate_target(vin):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Invalid 17-character VIN format: '{target}' (must be 17 chars, no I/O/Q)"
            )

        is_valid_check, actual_check, expected_check = self._verify_vin_check_digit(vin)

        # Basic WMI (World Manufacturer Identifier) country lookup
        wmi = vin[:3]
        country_code = vin[0]
        country_map = {
            "1": "United States", "4": "United States", "5": "United States",
            "2": "Canada", "3": "Mexico",
            "J": "Japan", "K": "South Korea", "S": "United Kingdom",
            "W": "Germany", "Z": "Italy", "L": "China"
        }
        origin_country = country_map.get(country_code, "International")

        # Query NHTSA VPIC API
        api_base = getattr(self.config, "nhtsa_api_url", "https://vpic.nhtsa.dot.gov/api/vehicles/decodevin")
        api_url = f"{api_base}/{vin}?format=json"

        nhtsa_data: dict[str, Any] = {}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        json_resp = await resp.json()
                        results = json_resp.get("Results", [])
                        for item in results:
                            val = item.get("Value")
                            variable = item.get("Variable")
                            if val and variable:
                                nhtsa_data[variable] = val

            make = nhtsa_data.get("Make")
            model = nhtsa_data.get("Model")
            model_year = nhtsa_data.get("Model Year")
            vehicle_type = nhtsa_data.get("Vehicle Type")
            plant_country = nhtsa_data.get("Plant Country") or origin_country

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "vin": vin,
                    "wmi": wmi,
                    "check_digit_valid": is_valid_check,
                    "actual_check_digit": actual_check,
                    "expected_check_digit": expected_check,
                    "make": make,
                    "model": model,
                    "model_year": model_year,
                    "vehicle_type": vehicle_type,
                    "plant_country": plant_country,
                    "nhtsa_specs": nhtsa_data,
                    "summary": f"VIN Decoded: {model_year or ''} {make or ''} {model or ''} ({plant_country or origin_country})"
                },
                status="success"
            )

        except Exception:
            # Fallback if API unavailable
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "vin": vin,
                    "wmi": wmi,
                    "check_digit_valid": is_valid_check,
                    "origin_country": origin_country,
                    "offline_fallback": True,
                    "summary": f"VIN Analysis for '{vin}': Check digit valid={is_valid_check}, WMI Country={origin_country}"
                },
                status="success"
            )


vehicle_vin_module = VehicleVinModule
