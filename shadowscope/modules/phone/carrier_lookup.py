"""
Carrier Lookup Module for SHADOWSCOPE

Parses phone numbers into E.164, resolves the country via the ITU
calling-code table, refines NANPA/Bangladesh allocations offline, and
optionally queries a carrier-lookup API when credentials are configured.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

# ITU-T E.164 country calling codes (code -> country/region).
CALLING_CODES: dict[str, str] = {
    "1": "United States/Canada/Caribbean (NANPA)",
    "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France",
    "34": "Spain", "39": "Italy", "40": "Romania", "41": "Switzerland",
    "43": "Austria", "44": "United Kingdom", "45": "Denmark",
    "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany",
    "51": "Peru", "52": "Mexico", "53": "Cuba", "54": "Argentina",
    "55": "Brazil", "56": "Chile", "57": "Colombia", "58": "Venezuela",
    "60": "Malaysia", "61": "Australia", "62": "Indonesia",
    "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam",
    "86": "China", "90": "Turkey", "91": "India", "92": "Pakistan",
    "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar", "98": "Iran",
    "212": "Morocco", "213": "Algeria", "216": "Tunisia", "218": "Libya",
    "220": "Gambia", "221": "Senegal", "222": "Mauritania", "223": "Mali",
    "224": "Guinea", "225": "Ivory Coast", "226": "Burkina Faso",
    "227": "Niger", "228": "Togo", "229": "Benin", "230": "Mauritius",
    "231": "Liberia", "232": "Sierra Leone", "233": "Ghana",
    "234": "Nigeria", "235": "Chad", "236": "Central African Republic",
    "237": "Cameroon", "238": "Cape Verde", "239": "Sao Tome and Principe",
    "240": "Equatorial Guinea", "241": "Gabon", "242": "Congo",
    "243": "DR Congo", "244": "Angola", "245": "Guinea-Bissau",
    "246": "Diego Garcia", "248": "Seychelles", "249": "Sudan",
    "250": "Rwanda", "251": "Ethiopia", "252": "Somalia", "253": "Djibouti",
    "254": "Kenya", "255": "Tanzania", "256": "Uganda", "257": "Burundi",
    "258": "Mozambique", "260": "Zambia", "261": "Madagascar",
    "262": "Reunion/Mayotte", "263": "Zimbabwe", "264": "Namibia",
    "265": "Malawi", "266": "Lesotho", "267": "Botswana", "268": "Eswatini",
    "269": "Comoros", "290": "Saint Helena", "291": "Eritrea",
    "297": "Aruba", "298": "Faroe Islands", "299": "Greenland",
    "350": "Gibraltar", "351": "Portugal", "352": "Luxembourg",
    "353": "Ireland", "354": "Iceland", "355": "Albania", "356": "Malta",
    "357": "Cyprus", "358": "Finland", "359": "Bulgaria",
    "370": "Lithuania", "371": "Latvia", "372": "Estonia", "373": "Moldova",
    "374": "Armenia", "375": "Belarus", "376": "Andorra", "377": "Monaco",
    "378": "San Marino", "380": "Ukraine", "381": "Serbia",
    "382": "Montenegro", "383": "Kosovo", "385": "Croatia", "386": "Slovenia",
    "387": "Bosnia and Herzegovina", "389": "North Macedonia",
    "420": "Czech Republic", "421": "Slovakia", "423": "Liechtenstein",
    "500": "Falkland Islands", "501": "Belize", "502": "Guatemala",
    "503": "El Salvador", "504": "Honduras", "505": "Nicaragua",
    "506": "Costa Rica", "507": "Panama",
    "508": "Saint Pierre and Miquelon", "509": "Haiti",
    "590": "Guadeloupe", "591": "Bolivia", "592": "Guyana",
    "593": "Ecuador", "594": "French Guiana", "595": "Paraguay",
    "596": "Martinique", "597": "Suriname", "598": "Uruguay",
    "599": "Curacao", "670": "East Timor", "672": "Norfolk Island",
    "673": "Brunei", "674": "Nauru", "675": "Papua New Guinea",
    "676": "Tonga", "677": "Solomon Islands", "678": "Vanuatu",
    "679": "Fiji", "680": "Palau", "681": "Wallis and Futuna",
    "682": "Cook Islands", "683": "Niue", "685": "Samoa", "686": "Kiribati",
    "687": "New Caledonia", "688": "Tuvalu", "689": "French Polynesia",
    "690": "Tokelau", "691": "Micronesia", "692": "Marshall Islands",
    "850": "North Korea", "852": "Hong Kong", "853": "Macau",
    "855": "Cambodia", "856": "Laos", "880": "Bangladesh", "886": "Taiwan",
    "960": "Maldives", "961": "Lebanon", "962": "Jordan", "963": "Syria",
    "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia", "967": "Yemen",
    "968": "Oman", "970": "Palestine", "971": "UAE", "972": "Israel",
    "973": "Bahrain", "974": "Qatar", "975": "Bhutan", "976": "Mongolia",
    "977": "Nepal", "992": "Tajikistan", "993": "Turkmenistan",
    "994": "Azerbaijan", "995": "Georgia", "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}

# Major NANPA area codes (area -> city/region). Curated subset.
NANPA_AREA_CODES: dict[str, str] = {
    "201": "New Jersey", "202": "Washington DC", "203": "Connecticut",
    "206": "Seattle", "212": "New York City", "213": "Los Angeles",
    "214": "Dallas", "215": "Philadelphia", "216": "Cleveland",
    "305": "Miami", "312": "Chicago", "313": "Detroit", "404": "Atlanta",
    "415": "San Francisco", "416": "Toronto", "503": "Portland",
    "514": "Montreal", "604": "Vancouver", "617": "Boston",
    "702": "Las Vegas", "703": "N. Virginia", "713": "Houston",
    "718": "New York City", "808": "Hawaii", "876": "Jamaica",
    "787": "Puerto Rico", "907": "Alaska", "917": "New York City",
}

# Bangladesh mobile operator prefixes (BTRC allocations; MNP may vary).
BD_OPERATOR_PREFIXES: dict[str, str] = {
    "013": "Grameenphone", "017": "Grameenphone",
    "014": "Banglalink", "019": "Banglalink",
    "015": "Teletalk", "016": "Airtel", "018": "Robi",
}


@dataclass
class CarrierLookupConfig(ModuleConfig):
    """Configuration for carrier lookup."""

    default_region: str = "BD"
    query_api: bool = False
    api_url: str = ""
    api_key: str = ""
    request_timeout: int = 15
    extra_tables: dict[str, dict[str, str]] = field(default_factory=dict)


class CarrierLookupModule(BaseModule):
    """Resolve carrier/country information for a phone number."""

    MODULE_NAME = "carrier_lookup"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Phone OSINT"
    MODULE_DESCRIPTION = "Carrier and country lookup for phone numbers"
    MODULE_TARGET_TYPES = [TargetType.PHONE]

    def __init__(self, config: CarrierLookupConfig | None = None):
        super().__init__(config or CarrierLookupConfig())
        self.session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)

    async def cleanup(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        digits = re.sub(r"\D", "", target)
        return 7 <= len(digits) <= 15

    def normalize_e164(self, target: str) -> str:
        """Normalize a number to E.164-ish ``+<digits>`` form."""
        text = target.strip().replace(" ", "").replace("-", "")
        text = text.replace("(", "").replace(")", "")
        if text.startswith("00"):
            text = "+" + text[2:]
        if not text.startswith("+"):
            text = "+" + text
        return text

    def split_calling_code(self, e164: str) -> dict[str, str]:
        """Longest-prefix match of the country calling code."""
        digits = e164.lstrip("+")
        for length in (4, 3, 2, 1):
            code = digits[:length]
            if code in CALLING_CODES:
                return {
                    "calling_code": code,
                    "country": CALLING_CODES[code],
                    "national_number": digits[length:],
                }
        return {"calling_code": "", "country": "Unknown", "national_number": digits}

    def refine_nanpa(self, national: str) -> dict[str, str]:
        """Refine a NANPA national number via area code."""
        area = national[:3]
        info: dict[str, str] = {"area_code": area}
        if area in NANPA_AREA_CODES:
            info["region"] = NANPA_AREA_CODES[area]
        else:
            info["region"] = "Unknown NANPA area"
        if len(national) == 10:
            info["format"] = f"+1 ({area}) {national[3:6]}-{national[6:]}"
        return info

    def refine_bangladesh(self, national: str) -> dict[str, str]:
        """Refine a Bangladeshi national number via operator prefix."""
        info: dict[str, str] = {}
        trunk = "0" + national if not national.startswith("0") else national
        prefix = trunk[:3]
        info["national_format"] = trunk
        info["operator_prefix"] = prefix
        if prefix in BD_OPERATOR_PREFIXES:
            info["likely_operator"] = BD_OPERATOR_PREFIXES[prefix]
            info["operator_note"] = "BTRC allocation; number portability may vary"
        else:
            info["likely_operator"] = "Unknown"
        return info

    async def query_api_lookup(
        self, e164: str
    ) -> dict[str, Any]:
        """Query an external lookup API when configured."""
        if not (self.config.query_api and self.config.api_url):
            return {"queried": False, "reason": "no API configured"}
        if self.session is None:
            await self.initialize()
        assert self.session is not None
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        try:
            async with self.session.get(
                self.config.api_url,
                params={"number": e164},
                headers=headers,
            ) as response:
                payload: Any = await response.json()
                return {"queried": True, "status": response.status, "data": payload}
        except Exception as exc:
            return {"queried": True, "status": 0, "error": str(exc)}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute carrier lookup on a phone-number target."""
        del options
        started = datetime.now().isoformat()
        if not self.validate_target(target):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid phone number format",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        e164 = self.normalize_e164(target)
        split = self.split_calling_code(e164)
        data: dict[str, Any] = {
            "input": target,
            "e164": e164,
            "calling_code": split["calling_code"],
            "country": split["country"],
            "national_number": split["national_number"],
            "refinement": {},
            "api": {"queried": False},
        }
        if split["calling_code"] == "1":
            data["refinement"] = self.refine_nanpa(split["national_number"])
        elif split["calling_code"] == "880":
            data["refinement"] = self.refine_bangladesh(split["national_number"])
        if self.config.query_api:
            await self.initialize()
            try:
                data["api"] = await self.query_api_lookup(e164)
            finally:
                await self.cleanup()
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
carrier_lookup_module = CarrierLookupModule
