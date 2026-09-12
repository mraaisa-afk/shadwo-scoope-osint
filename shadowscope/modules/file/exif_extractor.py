"""
EXIF Extractor Module for SHADOWSCOPE
Extracts EXIF metadata and GPS coordinates from image files using Pillow.
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class ExifExtractorConfig(ModuleConfig):
    """Configuration for EXIF Extractor module."""
    extract_gps: bool = True
    decode_values: bool = True


class ExifExtractorModule(BaseModule):
    """Module for extracting EXIF metadata and GPS information from images."""

    MODULE_NAME = "exif_extractor"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "file"
    MODULE_DESCRIPTION = "Extract EXIF metadata and GPS coordinates from image files using Pillow"
    MODULE_TARGET_TYPES = [TargetType.FILE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["Pillow"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: ExifExtractorConfig | None = None) -> None:
        super().__init__(config=config or ExifExtractorConfig())
        self.config: ExifExtractorConfig = self.config if isinstance(self.config, ExifExtractorConfig) else ExifExtractorConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target file path string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _convert_value(val: Any) -> Any:
        """Recursively convert Pillow EXIF values to JSON-serializable types."""
        if isinstance(val, bytes):
            try:
                return val.decode("utf-8", errors="replace")
            except Exception:
                return val.hex()
        elif isinstance(val, (int, float, str, bool)) or val is None:
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                return str(val)
            return val
        elif isinstance(val, (tuple, list)):
            return [ExifExtractorModule._convert_value(v) for v in val]
        elif isinstance(val, dict):
            return {str(k): ExifExtractorModule._convert_value(v) for k, v in val.items()}
        elif hasattr(val, "numerator") and hasattr(val, "denominator"):
            try:
                den = float(val.denominator)
                if den != 0:
                    return float(val.numerator) / den
                return 0.0
            except Exception:
                return str(val)
        return str(val)

    @staticmethod
    def _convert_dms_to_decimal(dms: Any, ref: str) -> float | None:
        """Convert GPS degrees, minutes, seconds tuple to decimal degrees."""
        try:
            d = ExifExtractorModule._convert_value(dms[0])
            m = ExifExtractorModule._convert_value(dms[1])
            s = ExifExtractorModule._convert_value(dms[2])
            deg = float(d) + (float(m) / 60.0) + (float(s) / 3600.0)
            if ref in ["S", "W", "s", "w"]:
                deg = -deg
            return round(deg, 6)
        except Exception:
            return None

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute EXIF extraction on target file."""
        file_path = Path(target.strip())
        if not file_path.is_file():
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"File not found: {target}"
            )

        try:
            with Image.open(file_path) as img:
                format_name = img.format
                width, height = img.size
                mode = img.mode

                exif_data: dict[str, Any] = {}
                gps_data: dict[str, Any] = {}

                # Get EXIF data if available
                raw_exif = None
                if hasattr(img, "_getexif") and callable(img._getexif):
                    raw_exif = img._getexif()

                if raw_exif:
                    for tag_id, value in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))

                        if tag_name == "GPSInfo" and isinstance(value, dict):
                            raw_gps = value
                            for gps_tag_id, gps_val in raw_gps.items():
                                gps_tag_name = ExifTags.GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                                gps_data[gps_tag_name] = self._convert_value(gps_val)
                        else:
                            exif_data[tag_name] = self._convert_value(value)

                # Process GPS coordinates if present
                lat_decimal = None
                lon_decimal = None
                maps_link = None

                if gps_data and "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
                    lat_ref = str(gps_data.get("GPSLatitudeRef", "N"))
                    lon_ref = str(gps_data.get("GPSLongitudeRef", "E"))
                    lat_decimal = self._convert_dms_to_decimal(gps_data["GPSLatitude"], lat_ref)
                    lon_decimal = self._convert_dms_to_decimal(gps_data["GPSLongitude"], lon_ref)

                    if lat_decimal is not None and lon_decimal is not None:
                        gps_data["latitude_decimal"] = lat_decimal
                        gps_data["longitude_decimal"] = lon_decimal
                        maps_link = f"https://www.google.com/maps?q={lat_decimal},{lon_decimal}"
                        gps_data["google_maps_url"] = maps_link

                return ModuleResult(
                    target=target,
                    module=self.MODULE_NAME,
                    data={
                        "file_path": str(file_path),
                        "file_size": file_path.stat().st_size,
                        "format": format_name,
                        "dimensions": {"width": width, "height": height},
                        "mode": mode,
                        "has_exif": bool(exif_data),
                        "has_gps": bool(gps_data and lat_decimal is not None),
                        "exif": exif_data,
                        "gps": gps_data,
                        "coordinates": f"{lat_decimal}, {lon_decimal}" if lat_decimal is not None else None,
                        "google_maps_url": maps_link,
                    },
                    status="success"
                )

        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Failed to process image EXIF: {str(e)}"
            )


exif_extractor_module = ExifExtractorModule
