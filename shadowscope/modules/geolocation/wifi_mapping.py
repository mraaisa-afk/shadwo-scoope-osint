"""
Wi-Fi Mapping Module for SHADOWSCOPE

Maps Wi-Fi access points: validates BSSIDs, resolves vendors from a
bundled IEEE OUI subset (extensible via a manuf-format file), estimates
positions from multi-AP sightings with weighted centroids, and can
query the WiGLE API when credentials are configured.
"""

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Bundled IEEE OUI subset (OUI -> vendor). Curated well-known
# assignments; load a full manuf file via oui_file for coverage.
OUI_VENDORS: dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "005056": "VMware",
    "080027": "PCS/VirtualBox", "00155D": "Microsoft Hyper-V",
    "001A11": "Google", "3C5AB4": "Google/Nest", "F88FCA": "Google",
    "001B63": "Apple", "001EC2": "Apple", "0021E9": "Apple",
    "002500": "Apple", "60FB42": "Apple", "8C7B9D": "Apple",
    "001E52": "Cisco", "0021A0": "Cisco", "58AC78": "Cisco",
    "001422": "Dell", "0026B9": "Dell", "B8AC6F": "Dell",
    "001CC8": "Microsoft", "7CED8D": "Microsoft",
    "00215A": "Intel", "001B77": "Intel", "F8F21E": "Intel",
    "001E67": "Huawei", "002559": "Huawei", "48AD08": "Huawei",
    "C83A35": "Xiaomi", "F0B429": "Xiaomi", "64CC2E": "Xiaomi",
    "001A8F": "Samsung", "002566": "Samsung", "78D6F0": "Samsung",
    "A402B9": "Samsung", "9C65B2": "LG", "C8F733": "LG",
    "001D0F": "TP-Link", "3C7C3F": "TP-Link", "B09575": "TP-Link",
    "9CADEF": "D-Link", "001B11": "D-Link", "1C7EC5": "D-Link",
    "0026F2": "Netgear", "A06391": "Netgear", "9C3DCF": "Netgear",
    "002618": "Ubiquiti", "0418D6": "Ubiquiti", "B4FBE4": "Ubiquiti",
    "001B54": "Ubiquiti", "24A43C": "Ubiquiti",
    "000B86": "Aruba", "24DE48": "Aruba", "6CF37F": "Aruba",
    "0012F0": "Ruckus", "2C5D93": "Ruckus", "C0C520": "Ruckus",
    "00037F": "Atheros", "001374": "Atheros", "04CE14": "Atheros",
    "9C2A70": "Amazon", "A002DC": "Amazon", "F0D2F1": "Amazon",
    "FCFBFB": "Amazon", "68A8E1": "Amazon/Eero",
    "0017C4": "Quanta", "3CDFFF": "Quanta",
    "00248C": "Asus", "1C872C": "Asus", "AC9E17": "Asus",
    "0013E8": "Intel Corporate", "001DE1": "Intel Corporate",
}


@dataclass
class WifiMappingConfig(ModuleConfig):
    """Configuration for Wi-Fi mapping."""

    oui_file: str = ""
    wigle_user: str = ""
    wigle_key: str = ""
    wigle_url: str = "https://api.wigle.net/api/v2/network/search"
    request_timeout: int = 20
    extra_ouis: dict[str, str] = field(default_factory=dict)


class WifiMappingModule(BaseModule):
    """Map Wi-Fi access points by BSSID."""

    MODULE_NAME = "wifi_mapping"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Geolocation"
    MODULE_DESCRIPTION = "Wi-Fi AP mapping, OUI and position estimates"
    MODULE_TARGET_TYPES = [TargetType.BSSID]

    def __init__(self, config: WifiMappingConfig | None = None):
        super().__init__(config or WifiMappingConfig())
        self._ouis: dict[str, str] = {}
        self._ouis_loaded = False

    def validate_target(self, target: str) -> bool:
        return bool(BSSID_RE.match((target or "").strip()))

    def normalize(self, target: str) -> str:
        return (target or "").strip().upper()

    def load_ouis(self) -> dict[str, str]:
        """Load OUI table: bundled subset + manuf file + extras."""
        if self._ouis_loaded:
            return self._ouis
        self._ouis_loaded = True
        table = dict(OUI_VENDORS)
        if self.config.oui_file:
            try:
                for line in Path(self.config.oui_file).expanduser() \
                        .read_text(errors="replace").splitlines():
                    match = re.match(
                        r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
                        r"\s+(\S.*\S)\s*$", line)
                    if match:
                        oui = match.group(1).replace(":", "").upper()
                        table.setdefault(oui, match.group(2).strip())
            except Exception as exc:
                console.print(f"[yellow]OUI file unreadable: {exc}[/yellow]")
        for oui, vendor in self.config.extra_ouis.items():
            table[oui.replace(":", "").upper()] = vendor
        self._ouis = table
        return table

    def vendor_lookup(self, bssid: str) -> dict[str, Any]:
        """Resolve the vendor for a BSSID OUI."""
        table = self.load_ouis()
        oui = bssid.replace(":", "")[:6].upper()
        vendor = table.get(oui, "")
        first_octet = int(bssid.split(":")[0], 16)
        return {
            "bssid": bssid, "oui": oui,
            "vendor": vendor or "Unknown",
            "locally_administered": bool(first_octet & 0x02),
            "multicast_bit": bool(first_octet & 0x01),
            "table_entries": len(table),
        }

    @staticmethod
    def weighted_centroid(
        sightings: list[tuple[float, float, float]]
    ) -> dict[str, Any]:
        """Position estimate from (lat, lon, rssi_dbm) sightings.

        Stronger (less negative) RSSI weighs more via 1/(|rssi|).
        """
        if not sightings:
            return {"estimated": False, "reason": "no sightings"}
        weights = [1.0 / max(1.0, abs(s[2])) for s in sightings]
        total = sum(weights)
        lat = sum(s[0] * w for s, w in zip(sightings, weights)) / total
        lon = sum(s[1] * w for s, w in zip(sightings, weights)) / total
        spread = max(
            math.hypot(s[0] - lat, s[1] - lon) for s in sightings) \
            * 111.0  # degrees -> ~km
        return {"estimated": True, "lat": lat, "lon": lon,
                "spread_km": round(spread, 4),
                "sightings": len(sightings)}

    async def query_wigle(self, bssid: str) -> dict[str, Any]:
        """Query WiGLE for a BSSID when credentials are configured."""
        if not (self.config.wigle_user and self.config.wigle_key):
            return {"queried": False, "reason": "no WiGLE credentials"}
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        auth = aiohttp.BasicAuth(self.config.wigle_user, self.config.wigle_key)
        try:
            async with aiohttp.ClientSession(timeout=timeout,
                                             auth=auth) as session:
                async with session.get(
                        self.config.wigle_url,
                        params={"netid": bssid}) as response:
                    payload = await response.json()
                    return {"queried": True, "status": response.status,
                            "results": (payload.get("results")
                                        or [])[:5],
                            "total": payload.get("totalResults")}
        except Exception as exc:
            return {"queried": True, "error": str(exc)}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute Wi-Fi mapping on a BSSID."""
        started = datetime.now().isoformat()
        text = (target or "").strip()
        if not self.validate_target(text):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid BSSID (need AA:BB:CC:DD:EE:FF)",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        bssid = self.normalize(text)
        data: dict[str, Any] = {
            "vendor": self.vendor_lookup(bssid),
            "wigle": await self.query_wigle(bssid),
            "position": {"estimated": False,
                         "reason": "no sightings provided"},
        }
        sightings = (options or {}).get("sightings", [])
        if sightings:
            triples = [(float(s[0]), float(s[1]), float(s[2]))
                       for s in sightings if len(s) >= 3]
            data["position"] = self.weighted_centroid(triples)
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
wifi_mapping_module = WifiMappingModule
