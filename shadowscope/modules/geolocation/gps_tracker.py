"""
GPS Tracker Module for SHADOWSCOPE

Fully offline coordinate-trail analysis: parses decimal degrees,
DMS and GPX tracks, then computes haversine distances, per-leg
speeds, impossible-travel anomalies, bounding boxes, centroids and
optional geofence containment.
"""

import math
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

EARTH_KM = 6371.0088

DMS_RE = re.compile(
    r"(?P<lat_d>\d{1,3})[°d\s]+(?P<lat_m>\d{1,2})['m\s]+"
    r"(?P<lat_s>\d{1,2}(?:\.\d+)?)[\"s\s]*(?P<lat_h>[NS])"
    r"[,;\s]+"
    r"(?P<lon_d>\d{1,3})[°d\s]+(?P<lon_m>\d{1,2})['m\s]+"
    r"(?P<lon_s>\d{1,2}(?:\.\d+)?)[\"s\s]*(?P<lon_h>[EW])",
    re.IGNORECASE,
)
DD_RE = re.compile(
    r"(?P<lat>-?\d{1,3}(?:\.\d+)?)\s*[,;]\s*(?P<lon>-?\d{1,3}(?:\.\d+)?)")


def haversine_km(left: tuple[float, float],
                 right: tuple[float, float]) -> float:
    """Great-circle distance in kilometres (haversine, real math)."""
    lat1, lon1 = math.radians(left[0]), math.radians(left[1])
    lat2, lon2 = math.radians(right[0]), math.radians(right[1])
    delta_lat, delta_lon = lat2 - lat1, lon2 - lon1
    inner = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) \
        * math.sin(delta_lon / 2) ** 2
    return 2 * EARTH_KM * math.asin(math.sqrt(inner))


def dms_to_dd(degrees: float, minutes: float, seconds: float,
              hemisphere: str) -> float:
    value = abs(degrees) + minutes / 60 + seconds / 3600
    return -value if hemisphere.upper() in ("S", "W") else value


@dataclass
class GpsTrackerConfig(ModuleConfig):
    """Configuration for GPS trail analysis."""

    max_points: int = 5000
    speed_anomaly_kmh: float = 1000.0
    geofence_lat: float | None = None
    geofence_lon: float | None = None
    geofence_radius_km: float = 1.0


class GpsTrackerModule(BaseModule):
    """Analyze GPS coordinate trails offline."""

    MODULE_NAME = "gps_tracker"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Geolocation"
    MODULE_DESCRIPTION = "GPS trail parsing and movement analysis"
    MODULE_TARGET_TYPES = [TargetType.COORDINATES, TargetType.URL]

    def __init__(self, config: GpsTrackerConfig | None = None):
        super().__init__(config or GpsTrackerConfig())

    def parse_points(self, text: str) -> list[tuple[float, float]]:
        """Parse DD / DMS / GPX points from free text."""
        points: list[tuple[float, float]] = []
        cleaned = (text or "").strip()
        if "<gpx" in cleaned.lower():
            points.extend(self.parse_gpx(cleaned))
        for match in DMS_RE.finditer(cleaned):
            lat = dms_to_dd(float(match.group("lat_d")),
                            float(match.group("lat_m")),
                            float(match.group("lat_s")),
                            match.group("lat_h"))
            lon = dms_to_dd(float(match.group("lon_d")),
                            float(match.group("lon_m")),
                            float(match.group("lon_s")),
                            match.group("lon_h"))
            points.append((lat, lon))
        stripped = DMS_RE.sub(" ", cleaned)
        for match in DD_RE.finditer(stripped):
            lat, lon = float(match.group("lat")), float(match.group("lon"))
            if abs(lat) <= 90 and abs(lon) <= 180:
                points.append((lat, lon))
        seen = set()
        ordered = []
        for point in points:
            key = (round(point[0], 6), round(point[1], 6))
            if key not in seen:
                seen.add(key)
                ordered.append(point)
        return ordered[:self.config.max_points]

    def parse_gpx(self, text: str) -> list[tuple[float, float]]:
        """Parse trkpt/rtept/wpt elements from a GPX document."""
        points: list[tuple[float, float]] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return points
        for elem in root.iter():
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag in ("trkpt", "rtept", "wpt"):
                try:
                    lat = float(elem.attrib.get("lat", "nan"))
                    lon = float(elem.attrib.get("lon", "nan"))
                except ValueError:
                    continue
                if abs(lat) <= 90 and abs(lon) <= 180:
                    points.append((lat, lon))
        return points

    def validate_target(self, target: str) -> bool:
        return bool(self.parse_points(target or ""))

    def analyze_trail(
        self, points: list[tuple[float, float]]
    ) -> dict[str, Any]:
        """Compute distances, speeds, anomalies and bounds."""
        legs = []
        total_km = 0.0
        anomalies = []
        for index in range(1, len(points)):
            dist = haversine_km(points[index - 1], points[index])
            total_km += dist
            legs.append({"from": index - 1, "to": index,
                         "km": round(dist, 4)})
        # Without timestamps, flag only physically absurd single jumps
        # against the configured anomaly threshold per assumed hour.
        for leg in legs:
            if leg["km"] > self.config.speed_anomaly_kmh:
                anomalies.append({
                    "leg": {"from": leg["from"], "to": leg["to"]},
                    "km": leg["km"],
                    "note": "jump exceeds anomaly threshold for one hour",
                })
        lats = [p[0] for p in points]
        lons = [p[1] for p in points]
        result: dict[str, Any] = {
            "point_count": len(points),
            "total_km": round(total_km, 4),
            "legs": legs[:50],
            "legs_truncated": len(legs) > 50,
            "anomalies": anomalies,
            "bbox": {"min_lat": min(lats), "max_lat": max(lats),
                     "min_lon": min(lons), "max_lon": max(lons)},
            "centroid": {"lat": sum(lats) / len(lats),
                         "lon": sum(lons) / len(lons)},
        }
        if self.config.geofence_lat is not None \
                and self.config.geofence_lon is not None:
            center = (self.config.geofence_lat, self.config.geofence_lon)
            inside = [i for i, p in enumerate(points)
                      if haversine_km(center, p)
                      <= self.config.geofence_radius_km]
            result["geofence"] = {
                "center": {"lat": center[0], "lon": center[1]},
                "radius_km": self.config.geofence_radius_km,
                "inside_idx": inside,
                "inside_count": len(inside),
            }
        return result

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute trail analysis on coordinate input."""
        del options
        started = datetime.now().isoformat()
        points = self.parse_points(target or "")
        if not points:
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed",
                error="No coordinates found (need DD, DMS or GPX)",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        data = self.analyze_trail(points)
        data["points"] = [{"lat": p[0], "lon": p[1]} for p in points[:100]]
        data["points_truncated"] = len(points) > 100
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
gps_tracker_module = GpsTrackerModule
