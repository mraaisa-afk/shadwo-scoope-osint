"""
IBAN Lookup Module for SHADOWSCOPE
Validates International Bank Account Numbers (IBAN), checks MOD 97 checksums, and parses bank/country metadata.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Country code to IBAN length mapping
IBAN_LENGTHS: dict[str, int] = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16, "BA": 20,
    "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24, "DK": 18, "DO": 28,
    "EE": 20, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23, "GR": 27,
    "GL": 18, "GT": 28, "HU": 28, "IS": 26, "IE": 22, "IL": 23, "IT": 27, "JO": 30,
    "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20,
    "MK": 19, "MT": 31, "MR": 27, "MU": 30, "MD": 24, "MC": 27, "ME": 22, "NL": 18,
    "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "LC": 32,
    "SM": 27, "SA": 24, "RS": 22, "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21,
    "TN": 24, "TR": 26, "UA": 29, "AE": 23, "GB": 22, "VG": 24
}


@dataclass
class IbanLookupConfig(ModuleConfig):
    """Configuration for IBAN Lookup module."""
    strict_checksum: bool = True


class IbanLookupModule(BaseModule):
    """Module for parsing and validating International Bank Account Numbers (IBAN)."""

    MODULE_NAME = "iban_lookup"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "financial"
    MODULE_DESCRIPTION = "Validate IBAN bank account numbers, perform ISO 13616 MOD-97 check digit verification, and parse country codes"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: IbanLookupConfig | None = None) -> None:
        super().__init__(config=config or IbanLookupConfig())
        self.config: IbanLookupConfig = self.config if isinstance(self.config, IbanLookupConfig) else IbanLookupConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate string length for IBAN candidate."""
        if not target or not isinstance(target, str):
            return False
        cleaned = "".join(c for c in target if c.isalnum())
        return 14 <= len(cleaned) <= 34

    @staticmethod
    def _verify_mod97(iban: str) -> bool:
        """Perform MOD-97-10 checksum validation (ISO 7064 / ISO 13616)."""
        rearranged = iban[4:] + iban[:4]
        numeric_str = ""
        for char in rearranged:
            if char.isdigit():
                numeric_str += char
            elif char.isalpha():
                numeric_str += str(ord(char.upper()) - 55)
            else:
                return False
        try:
            return int(numeric_str) % 97 == 1
        except ValueError:
            return False

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute IBAN validation and extraction."""
        iban_clean = "".join(c.upper() for c in target if c.isalnum())

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid IBAN candidate string"
            )

        country_code = iban_clean[:2]
        check_digits = iban_clean[2:4]
        bban = iban_clean[4:]

        expected_length = IBAN_LENGTHS.get(country_code)
        length_valid = expected_length is not None and len(iban_clean) == expected_length
        checksum_valid = self._verify_mod97(iban_clean)

        is_valid = bool(length_valid and checksum_valid)

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "iban": iban_clean,
                "country_code": country_code,
                "check_digits": check_digits,
                "bban": bban,
                "is_valid": is_valid,
                "checksum_valid": checksum_valid,
                "length_valid": length_valid,
                "expected_length": expected_length,
                "summary": f"IBAN {iban_clean} -> Valid: {is_valid} (Country: {country_code}, Checksum MOD97: {checksum_valid})"
            },
            status="success"
        )


iban_lookup_module = IbanLookupModule
