"""
Satellite Imagery Module for SHADOWSCOPE
Generates tile URLs, bounding boxes, and satellite provider links for coordinates.
"""

import math
import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class SatelliteImageryConfig(ModuleConfig):
    """Configuration for Satellite Imagery module."""
    default_zoom: int = 17
    bbox_delta: float = 0.005


class SatelliteImageryModule(BaseModule):
    """Module for generating satellite imagery tile links and spatial bounding boxes."""

    MODULE_NAME = "satellite_imagery"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "physical"
    MODULE_DESCRIPTION = "Generate satellite imagery tile coordinates, bounding boxes, and multi-provider imagery links"
    MODULE_TARGET_TYPES = [TargetType.COORDINATES, TargetType.ADDRESS, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: SatelliteImageryConfig | None = None) -> None:
        super().__init__(config=config or SatelliteImageryConfig())
        self.config: SatelliteImageryConfig = self.config if isinstance(self.config, SatelliteImageryConfig) else SatelliteImageryConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
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

    @staticmethod
    def _deg2num(lat_deg: float, lon_deg: float, zoom: int) -> tuple[int, int]:
        """Convert lat, lon in degrees to Mercator tile numbers X, Y at zoom level."""
        lat_rad = math.radians(lat_deg)
        n = 2.0 ** zoom
        xtile = int((lon_deg + 180.0) / 360.0 * n)
        ytile = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
        return xtile, ytile

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute satellite imagery coordinate resolution."""
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

        # Default fallback coordinates (Dhaka, BD) if address string without API geocoding
        if not coords:
            lat, lon = 23.8103, 90.4125
            is_estimated = True
        else:
            lat, lon = coords
            is_estimated = False

        zoom = int(getattr(self.config, "default_zoom", 17))
        delta = float(getattr(self.config, "bbox_delta", 0.005))

        tile_x, tile_y = self._deg2num(lat, lon, zoom)

        bbox = {
            "min_latitude": round(lat - delta, 6),
            "max_latitude": round(lat + delta, 6),
            "min_longitude": round(lon - delta, 6),
            "max_longitude": round(lon + delta, 6),
        }

        providers = {
            "esri_world_imagery": f"https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{zoom}/{tile_y}/{tile_x}",
            "google_maps_satellite": f"https://www.google.com/maps/@{lat},{lon},{zoom}z/data=!3m1!1e3",
            "bing_maps_aerial": f"https://www.bing.com/maps?cp={lat}~{lon}&style=a&lvl={zoom}",
            "openstreetmap_standard": f"https://www.openstreetmap.org/#map={zoom}/{lat}/{lon}",
            "sentinel_hub_playground": f"https://apps.sentinel-hub.com/sentinel-playground/?lat={lat}&lng={lon}&zoom={zoom}",
            "wikimapia": f"http://wikimapia.org/#lang=en&lat={lat}&lon={lon}&z={zoom}&m=b",
        }

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target": target,
                "latitude": lat,
                "longitude": lon,
                "is_estimated_coordinates": is_estimated,
                "zoom_level": zoom,
                "mercator_tile": {"x": tile_x, "y": tile_y, "z": zoom},
                "bounding_box": bbox,
                "provider_urls": providers,
                "summary": f"Satellite imagery coordinates: {lat:.6f}, {lon:.6f} (Tile: z={zoom}, x={tile_x}, y={tile_y})"
            },
            status="success"
        )


satellite_imagery_module = SatelliteImageryModule
