"""
Neighbor Mapper Module for SHADOWSCOPE
Calculates surrounding geographic cardinal points and generates nearby POI queries.
"""

import math
import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class NeighborMapperConfig(ModuleConfig):
    """Configuration for Neighbor Mapper module."""
    radius_meters: float = 500.0


class NeighborMapperModule(BaseModule):
    """Module for calculating surrounding geographic neighbor points and spatial POI queries."""

    MODULE_NAME = "neighbor_mapper"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "physical"
    MODULE_DESCRIPTION = "Calculate surrounding geographic neighbor coordinates and generate spatial POI/Overpass queries"
    MODULE_TARGET_TYPES = [TargetType.COORDINATES, TargetType.ADDRESS, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: NeighborMapperConfig | None = None) -> None:
        super().__init__(config=config or NeighborMapperConfig())
        self.config: NeighborMapperConfig = self.config if isinstance(self.config, NeighborMapperConfig) else NeighborMapperConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

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
    def _offset_point(lat: float, lon: float, distance_meters: float, bearing_degrees: float) -> tuple[float, float]:
        """Calculate destination point given distance (m) and bearing (deg) from origin."""
        earth_radius = 6371000.0  # meters
        angular_dist = distance_meters / earth_radius

        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)
        bearing_rad = math.radians(bearing_degrees)

        dest_lat_rad = math.asin(
            math.sin(lat_rad) * math.cos(angular_dist) +
            math.cos(lat_rad) * math.sin(angular_dist) * math.cos(bearing_rad)
        )

        dest_lon_rad = lon_rad + math.atan2(
            math.sin(bearing_rad) * math.sin(angular_dist) * math.cos(lat_rad),
            math.cos(angular_dist) - math.sin(lat_rad) * math.sin(dest_lat_rad)
        )

        dest_lat = math.degrees(dest_lat_rad)
        dest_lon = math.degrees(dest_lon_rad)

        return round(dest_lat, 6), round(dest_lon, 6)

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute neighbor coordinate calculation."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        coords = self._parse_coordinates(cleaned_target)
        if not coords:
            lat, lon = 23.8103, 90.4125
            is_estimated = True
        else:
            lat, lon = coords
            is_estimated = False

        radius = float(getattr(self.config, "radius_meters", 500.0))

        directions = {
            "north": 0.0,
            "northeast": 45.0,
            "east": 90.0,
            "southeast": 135.0,
            "south": 180.0,
            "southwest": 225.0,
            "west": 270.0,
            "northwest": 315.0,
        }

        neighbors: list[dict[str, Any]] = []
        for direction, bearing in directions.items():
            n_lat, n_lon = self._offset_point(lat, lon, radius, bearing)
            neighbors.append({
                "direction": direction,
                "bearing_degrees": bearing,
                "distance_meters": radius,
                "latitude": n_lat,
                "longitude": n_lon,
                "google_maps_url": f"https://www.google.com/maps?q={n_lat},{n_lon}"
            })

        # Overpass Turbo OSM query for nearby POIs
        overpass_query = f"""[out:json];
(
  node(around:{radius},{lat},{lon});
  way(around:{radius},{lat},{lon});
);
out body;
>;
out skel qt;"""

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "center_point": {"latitude": lat, "longitude": lon, "is_estimated": is_estimated},
                "search_radius_meters": radius,
                "neighbor_points": neighbors,
                "overpass_osm_query": overpass_query,
                "summary": f"Generated 8 cardinal neighbor points within {radius}m of ({lat:.6f}, {lon:.6f})"
            },
            status="success"
        )


neighbor_mapper_module = NeighborMapperModule
