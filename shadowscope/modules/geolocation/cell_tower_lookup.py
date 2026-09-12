"""
Cell Tower Lookup Module for SHADOWSCOPE

Parses cell identifiers (MCC-MNC-LAC-CID CGI/ECGI forms), resolves the
country from a curated ITU MCC table plus bundled major operators,
estimates positions from multi-cell sightings via least-squares
trilateration, and can query OpenCellID when an API key is configured.
"""

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

# Curated ITU MCC subset (MCC -> country). High-confidence entries;
# extend via operator_file or the OpenCellID hook for full coverage.
MCC_COUNTRIES: dict[str, str] = {
    "202": "Greece", "204": "Netherlands", "206": "Belgium",
    "208": "France", "214": "Spain", "216": "Hungary", "219": "Croatia",
    "220": "Serbia", "222": "Italy", "226": "Romania", "230": "Czechia",
    "231": "Slovakia", "234": "United Kingdom", "235": "United Kingdom",
    "238": "Denmark", "240": "Sweden", "242": "Norway", "244": "Finland",
    "250": "Russia", "255": "Ukraine", "257": "Belarus", "259": "Moldova",
    "260": "Poland", "262": "Germany", "268": "Portugal",
    "270": "Luxembourg", "272": "Ireland", "274": "Iceland",
    "276": "Albania", "278": "Malta", "280": "Cyprus",
    "293": "Slovenia", "302": "Canada", "310": "United States",
    "311": "United States", "312": "United States", "313": "United States",
    "314": "United States", "315": "United States", "316": "United States",
    "330": "Puerto Rico", "334": "Mexico", "338": "Jamaica",
    "401": "Kazakhstan", "404": "India", "405": "India", "406": "India",
    "410": "Pakistan", "412": "Afghanistan", "413": "Sri Lanka",
    "414": "Myanmar", "415": "Lebanon", "416": "Jordan", "417": "Syria",
    "418": "Iraq", "419": "Kuwait", "420": "Saudi Arabia", "421": "Yemen",
    "422": "Oman", "423": "Palestine", "424": "UAE", "425": "Israel",
    "426": "Bahrain", "427": "Qatar", "429": "Nepal", "430": "UAE",
    "432": "Iran", "434": "Uzbekistan", "437": "Kyrgyzstan",
    "438": "Turkmenistan", "440": "Japan", "441": "Japan",
    "450": "South Korea", "455": "Macau", "460": "China", "466": "Taiwan",
    "470": "Bangladesh", "502": "Malaysia", "505": "Australia",
    "510": "Indonesia", "515": "Philippines", "520": "Thailand",
    "525": "Singapore", "528": "Brunei", "530": "New Zealand",
    "542": "Fiji", "557": "Solomon Islands", "559": "American Samoa",
    "560": "Samoa", "602": "Egypt", "603": "Algeria", "604": "Morocco",
    "605": "Tunisia", "606": "Libya", "607": "Gambia", "608": "Senegal",
    "609": "Mauritania", "610": "Mali", "611": "Guinea",
    "612": "Ivory Coast", "617": "Mauritius", "619": "Sierra Leone",
    "620": "Ghana", "621": "Nigeria", "622": "Chad", "624": "Cameroon",
    "628": "Gabon", "630": "DR Congo", "631": "Angola", "634": "Sudan",
    "639": "Kenya", "640": "Tanzania", "641": "Uganda",
    "643": "Mozambique", "645": "Zambia", "646": "Madagascar",
    "647": "Reunion", "648": "Zimbabwe", "649": "Namibia", "650": "Malawi",
    "651": "Lesotho", "652": "Botswana", "653": "Eswatini",
    "655": "South Africa", "657": "Eritrea", "659": "South Sudan",
    "702": "Belize", "704": "Guatemala", "706": "El Salvador",
    "708": "Honduras", "710": "Nicaragua", "712": "Costa Rica",
    "714": "Panama", "716": "Peru", "722": "Argentina", "724": "Brazil",
    "730": "Chile", "732": "Colombia", "734": "Venezuela", "740": "Ecuador",
    "744": "Paraguay", "746": "Suriname", "747": "Trinidad and Tobago",
    "748": "Uruguay", "901": "International Networks",
}

# Well-known operators ("MCC-MNC" -> operator). Portability may vary.
OPERATORS: dict[str, str] = {
    "470-01": "Grameenphone (BD)", "470-02": "Robi (BD)",
    "470-03": "Banglalink (BD)", "470-04": "Teletalk (BD)",
    "470-06": "Airtel (BD)",
    "310-260": "T-Mobile (US)", "310-410": "AT&T (US)",
    "311-480": "Verizon (US)", "310-120": "Sprint/T-Mobile (US)",
    "234-10": "O2 (UK)", "234-15": "Vodafone (UK)",
    "234-20": "Three (UK)", "234-30": "EE (UK)", "234-33": "Orange/EE (UK)",
    "262-01": "Telekom (DE)", "262-02": "Vodafone (DE)",
    "262-03": "O2/Telefonica (DE)",
    "404-10": "Airtel (IN)", "404-11": "Vodafone Idea (IN)",
    "405-874": "Jio (IN)",
}

CELL_FORMS = [
    re.compile(r"^\s*(\d{3})\s*[-:.,\s]\s*(\d{2,3})\s*[-:.,\s]\s*"
               r"(\d{1,5})\s*[-:.,\s]\s*(\d{1,9})\s*$"),
    re.compile(r"MCC\s*=\s*(\d{3}).*?MNC\s*=\s*(\d{2,3}).*?"
               r"(?:LAC|TAC)\s*=\s*(\d{1,5}).*?(?:CID|CI|ECI)\s*=\s*"
               r"(\d{1,9})", re.IGNORECASE | re.DOTALL),
]


@dataclass
class CellTowerLookupConfig(ModuleConfig):
    """Configuration for cell-tower lookup."""

    opencellid_key: str = ""
    opencellid_url: str = "https://opencellid.org/cell/get"
    request_timeout: int = 20
    extra_operators: dict[str, str] = field(default_factory=dict)


class CellTowerLookupModule(BaseModule):
    """Look up cell towers and estimate positions."""

    MODULE_NAME = "cell_tower_lookup"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Geolocation"
    MODULE_DESCRIPTION = "Cell tower parsing, lookup and trilateration"
    MODULE_TARGET_TYPES = [TargetType.CELL_TOWER]

    def __init__(self, config: CellTowerLookupConfig | None = None):
        super().__init__(config or CellTowerLookupConfig())

    def parse_cell(self, text: str) -> dict[str, int] | None:
        """Parse MCC/MNC/LAC/CID from supported notations."""
        for pattern in CELL_FORMS:
            match = pattern.match(text or "")
            if match:
                mcc, mnc, lac, cid = (int(g) for g in match.groups())
                if 1 <= lac <= 65535 and 0 <= cid <= 268435455:
                    return {"mcc": mcc, "mnc": mnc, "lac": lac,
                            "cid": cid}
        return None

    def validate_target(self, target: str) -> bool:
        return self.parse_cell(target or "") is not None

    def resolve_cell(self, cell: dict[str, int]) -> dict[str, Any]:
        """Resolve country/operator and radio-technology hints."""
        mcc = str(cell["mcc"]).zfill(3)
        operators = dict(OPERATORS)
        operators.update(self.config.extra_operators)
        key = f"{mcc}-{cell['mnc']}"
        cid = cell["cid"]
        tech = "GSM (16-bit CID)" if cid <= 65535 else \
            "UMTS/LTE (28-bit CID)"
        info: dict[str, Any] = {
            "mcc": mcc, "mnc": cell["mnc"], "lac": cell["lac"],
            "cid": cid, "cgi": f"{mcc}-{cell['mnc']}-{cell['lac']}-{cid}",
            "country": MCC_COUNTRIES.get(mcc, "Unknown"),
            "operator": operators.get(key, "Unknown"),
            "technology_hint": tech,
        }
        if cid > 65535:
            info["lte_enb"] = cid >> 8
            info["lte_sector"] = cid & 0xFF
        return info

    @staticmethod
    def trilaterate(
        points: list[tuple[float, float, float]]
    ) -> dict[str, Any]:
        """Least-squares position from (lat, lon, dist_km) fixes.

        Gauss-Newton iteration on locally equirectangular projection.
        Honest math: needs 3+ distinct fixes to converge well.
        """
        if len(points) < 3:
            return {"estimated": False,
                    "reason": "need at least 3 fixes"}
        ref_lat = sum(p[0] for p in points) / len(points)
        ref_lon = sum(p[1] for p in points) / len(points)
        kx = 111.32 * math.cos(math.radians(ref_lat))
        ky = 110.57
        loc = [( (p[1] - ref_lon) * kx, (p[0] - ref_lat) * ky, p[2])
               for p in points]
        x = sum(p[0] for p in loc) / len(loc)
        y = sum(p[1] for p in loc) / len(loc)
        for _ in range(50):
            jx = jy = 0.0
            gx = gy = 0.0
            for (px, py, dist) in loc:
                dx, dy = x - px, y - py
                pred = math.hypot(dx, dy) or 1e-9
                residual = pred - dist
                ux, uy = dx / pred, dy / pred
                jx += ux * ux
                jy += uy * uy
                gx += ux * residual
                gy += uy * residual
            step_x = gx / (jx or 1e-9)
            step_y = gy / (jy or 1e-9)
            x -= step_x
            y -= step_y
            if math.hypot(step_x, step_y) < 1e-6:
                break
        residuals = [abs(math.hypot(x - px, y - py) - d)
                     for px, py, d in loc]
        return {"estimated": True,
                "lat": round(ref_lat + y / ky, 6),
                "lon": round(ref_lon + x / kx, 6),
                "rmse_km": round(
                    math.sqrt(sum(r * r for r in residuals)
                              / len(residuals)), 4),
                "fixes": len(points)}

    async def query_opencellid(self, cell: dict[str, int]) -> dict[str, Any]:
        """Query OpenCellID when an API key is configured."""
        if not self.config.opencellid_key:
            return {"queried": False, "reason": "no OpenCellID key"}
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        params = {"key": self.config.opencellid_key, "format": "json",
                  "mcc": cell["mcc"], "mnc": cell["mnc"],
                  "lac": cell["lac"], "cellid": cell["cid"]}
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.config.opencellid_url,
                                       params=params) as response:
                    payload = await response.json()
                    return {"queried": True, "status": response.status,
                            "data": payload}
        except Exception as exc:
            return {"queried": True, "error": str(exc)}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute cell-tower lookup on a cell identifier."""
        started = datetime.now().isoformat()
        cell = self.parse_cell(target or "")
        if not cell:
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed",
                error="Unparseable cell (need MCC-MNC-LAC-CID)",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        data: dict[str, Any] = {
            "cell": self.resolve_cell(cell),
            "opencellid": await self.query_opencellid(cell),
            "position": {"estimated": False,
                         "reason": "no fixes provided"},
        }
        fixes = (options or {}).get("fixes", [])
        if fixes:
            triples = [(float(f[0]), float(f[1]), float(f[2]))
                       for f in fixes if len(f) >= 3]
            data["position"] = self.trilaterate(triples)
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
cell_tower_lookup_module = CellTowerLookupModule
