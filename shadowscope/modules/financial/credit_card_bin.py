"""
Credit Card BIN Module for SHADOWSCOPE
Queries Issuer Identification Number (IIN / BIN) database for payment card brand, issuing bank, country, and card type.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Local fallback database for common BIN ranges
COMMON_BIN_DB: dict[str, dict[str, str]] = {
    "400000": {"brand": "Visa", "type": "Credit", "level": "Classic", "bank": "Chase", "country": "United States", "country_code": "US"},
    "414720": {"brand": "Visa", "type": "Credit", "level": "Signature", "bank": "Capital One", "country": "United States", "country_code": "US"},
    "510000": {"brand": "MasterCard", "type": "Credit", "level": "Standard", "bank": "Citibank", "country": "United States", "country_code": "US"},
    "520000": {"brand": "MasterCard", "type": "Debit", "level": "World", "bank": "HSBC", "country": "United Kingdom", "country_code": "GB"},
    "371449": {"brand": "American Express", "type": "Credit", "level": "Platinum", "bank": "American Express", "country": "United States", "country_code": "US"},
    "601100": {"brand": "Discover", "type": "Credit", "level": "Standard", "bank": "Discover Bank", "country": "United States", "country_code": "US"},
}


@dataclass
class CreditCardBinConfig(ModuleConfig):
    """Configuration for Credit Card BIN module."""
    api_url: str = "https://lookup.binlist.net"


class CreditCardBinModule(BaseModule):
    """Module for looking up payment card Issuer Identification Numbers (BIN / IIN)."""

    MODULE_NAME = "credit_card_bin"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "financial"
    MODULE_DESCRIPTION = "Lookup payment card Bank Identification Numbers (BIN / IIN) for issuing bank, card brand, level, and country"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: CreditCardBinConfig | None = None) -> None:
        super().__init__(config=config or CreditCardBinConfig())
        self.config: CreditCardBinConfig = self.config if isinstance(self.config, CreditCardBinConfig) else CreditCardBinConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate BIN target string (must contain at least 6 digits)."""
        if not target or not isinstance(target, str):
            return False
        digits = "".join(c for c in target if c.isdigit())
        return len(digits) >= 6

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute BIN lookup query."""
        digits = "".join(c for c in target if c.isdigit())
        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid BIN target: require at least 6 digits"
            )

        bin_number = digits[:6]
        base_url = getattr(self.config, "api_url", "https://lookup.binlist.net")

        # Try API lookup
        try:
            headers = {"Accept-Version": "3"}
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{base_url.rstrip('/')}/{bin_number}", headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        api_data = await resp.json()
                        return ModuleResult(
                            target=target,
                            module=self.MODULE_NAME,
                            data={
                                "bin": bin_number,
                                "scheme": api_data.get("scheme"),
                                "type": api_data.get("type"),
                                "brand": api_data.get("brand"),
                                "bank": api_data.get("bank", {}).get("name"),
                                "country": api_data.get("country", {}).get("name"),
                                "country_code": api_data.get("country", {}).get("alpha2"),
                                "raw": api_data,
                                "summary": f"BIN {bin_number}: {api_data.get('scheme', 'Unknown').upper()} {api_data.get('type', '')} issued by {api_data.get('bank', {}).get('name', 'Unknown')} ({api_data.get('country', {}).get('name', '')})"
                            },
                            status="success"
                        )
        except Exception:
            pass

        # Fallback to local BIN table
        fallback_data = COMMON_BIN_DB.get(bin_number)
        if not fallback_data:
            # Infer scheme from first digit
            first_digit = bin_number[0]
            schemes = {"4": "Visa", "5": "MasterCard", "3": "American Express", "6": "Discover / UnionPay"}
            scheme_name = schemes.get(first_digit, "Unknown")
            fallback_data = {
                "brand": scheme_name,
                "type": "Credit/Debit",
                "level": "Unknown",
                "bank": "Unlisted Issuer",
                "country": "Unknown",
                "country_code": "??"
            }

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "bin": bin_number,
                "scheme": fallback_data.get("brand"),
                "type": fallback_data.get("type"),
                "level": fallback_data.get("level"),
                "bank": fallback_data.get("bank"),
                "country": fallback_data.get("country"),
                "country_code": fallback_data.get("country_code"),
                "summary": f"BIN {bin_number}: {fallback_data.get('brand')} ({fallback_data.get('bank')}, {fallback_data.get('country')})"
            },
            status="success"
        )


credit_card_bin_module = CreditCardBinModule
