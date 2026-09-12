"""
Geocoder Module for SHADOWSCOPE
Performs forward and reverse geocoding via OpenStreetMap Nominatim API.
"""

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class GeocoderConfig(ModuleConfig):
    """Configuration for Geocoder module."""
    user_agent: str = "SHADOWSCOPE-OSINT-Framework/1.0"
    nominatim_url: str = "https://nominatim.openstreetmap.org"


class GeocoderModule(BaseModule):
    """Module for forward and reverse geocoding of physical addresses and coordinates."""

    MODULE_NAME = "geocoder"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "physical"
    MODULE_DESCRIPTION = "Forward and reverse geocoding of physical addresses and GPS coordinates using OpenStreetMap Nominatim"
    MODULE_TARGET_TYPES = [TargetType.COORDINATES, TargetType.ADDRESS, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: GeocoderConfig | None = None) -> None:
        super().__init__(config=config or GeocoderConfig())
        self.config: GeocoderConfig = self.config if isinstance(self.config, GeocoderConfig) else GeocoderConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target address or coordinates string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _parse_coordinates(target: str) -> tuple[float, float] | None:
        """Parse lat, lon from string if present."""
        match = re.match(r"^-?\d{1,3}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?$", target.strip())
        if match:
            try:
                parts = [p.strip() for p in target.split(",")]
                lat = float(parts[0])
                lon = float(parts[1])
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    return lat, lon
            except ValueError:
                pass
        return None

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute geocoding query."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target: empty string"
            )

        coords = self._parse_coordinates(cleaned_target)
        is_reverse = coords is not None

        headers = {"User-Agent": getattr(self.config, "user_agent", "SHADOWSCOPE-OSINT-Framework/1.0")}
        base_url = getattr(self.config, "nominatim_url", "https://nominatim.openstreetmap.org")

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                if is_reverse and coords:
                    lat, lon = coords
                    url = f"{base_url}/reverse?format=json&lat={lat}&lon={lon}&addressdetails=1"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            address = data.get("address", {})
                            display_name = data.get("display_name", "")
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={
                                    "target": target,
                                    "query_type": "reverse",
                                    "latitude": lat,
                                    "longitude": lon,
                                    "display_name": display_name,
                                    "address": address,
                                    "osm_id": data.get("osm_id"),
                                    "osm_type": data.get("osm_type"),
                                    "boundingbox": data.get("boundingbox"),
                                    "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                                },
                                status="success"
                            )
                        else:
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={
                                    "target": target,
                                    "query_type": "reverse",
                                    "latitude": lat,
                                    "longitude": lon,
                                    "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                                },
                                status="partial",
                                error=f"Nominatim API HTTP {resp.status}"
                            )
                else:
                    # Forward geocoding query
                    url = f"{base_url}/search?format=json&q={aiohttp.helpers.quote(cleaned_target)}&addressdetails=1&limit=5"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            results = await resp.json()
                            if results and isinstance(results, list):
                                top = results[0]
                                lat = float(top.get("lat", 0))
                                lon = float(top.get("lon", 0))
                                return ModuleResult(
                                    target=target,
                                    module=self.MODULE_NAME,
                                    data={
                                        "target": target,
                                        "query_type": "forward",
                                        "latitude": lat,
                                        "longitude": lon,
                                        "display_name": top.get("display_name", ""),
                                        "address": top.get("address", {}),
                                        "confidence": top.get("importance", 0),
                                        "all_results": results,
                                        "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                                    },
                                    status="success"
                                )
                            else:
                                return ModuleResult(
                                    target=target,
                                    module=self.MODULE_NAME,
                                    data={"target": target, "query_type": "forward", "results_found": 0},
                                    status="failed",
                                    error=f"No geocoding results found for address: '{cleaned_target}'"
                                )
                        else:
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={"target": target, "query_type": "forward"},
                                status="failed",
                                error=f"Nominatim API HTTP {resp.status}"
                            )

        except Exception as e:
            # Fallback for offline / network failure
            if is_reverse and coords:
                lat, lon = coords
                return ModuleResult(
                    target=target,
                    module=self.MODULE_NAME,
                    data={
                        "target": target,
                        "query_type": "reverse",
                        "latitude": lat,
                        "longitude": lon,
                        "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                        "offline_fallback": True,
                    },
                    status="success"
                )
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Geocoding request failed: {str(e)}"
            )


geocoder_module = GeocoderModule
