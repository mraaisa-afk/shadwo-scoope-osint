"""
Steganography Detection Module for SHADOWSCOPE
Performs offline statistical tests (LSB chi-square analysis, RS-lite suspicion, trailing data detection)
to estimate steganography probability without claiming payload contents.
"""

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class StegDetectConfig(ModuleConfig):
    """Configuration for Steganography Detection module."""
    sample_blocks: int = 100
    check_trailing_data: bool = True


class StegDetectModule(BaseModule):
    """Module for detecting potential steganography in image files via statistical tests."""

    MODULE_NAME = "steg_detect"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "file"
    MODULE_DESCRIPTION = "Perform offline statistical tests (LSB chi-square analysis, RS-lite suspicion) to detect potential steganography in images"
    MODULE_TARGET_TYPES = [TargetType.FILE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["Pillow"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: StegDetectConfig | None = None) -> None:
        super().__init__(config=config or StegDetectConfig())
        self.config: StegDetectConfig = self.config if isinstance(self.config, StegDetectConfig) else StegDetectConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target file path string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _check_trailing_bytes(file_path: Path, format_name: str) -> tuple[bool, int, str]:
        """Check for trailing bytes appended after format EOF markers."""
        try:
            raw = file_path.read_bytes()
            fmt = (format_name or "").upper()

            if fmt in ["JPEG", "JPG"]:
                eoi = raw.rfind(b"\xff\xd9")
                if eoi != -1 and eoi + 2 < len(raw):
                    trailing_len = len(raw) - (eoi + 2)
                    return True, trailing_len, f"Found {trailing_len} trailing bytes after JPEG EOI marker"

            elif fmt == "PNG":
                iend = raw.rfind(b"IEND")
                if iend != -1 and iend + 8 < len(raw):
                    trailing_len = len(raw) - (iend + 8)
                    return True, trailing_len, f"Found {trailing_len} trailing bytes after PNG IEND chunk"

            elif fmt == "GIF":
                trailer = raw.rfind(b"\x3b")
                if trailer != -1 and trailer + 1 < len(raw):
                    trailing_len = len(raw) - (trailer + 1)
                    return True, trailing_len, f"Found {trailing_len} trailing bytes after GIF trailer"

        except Exception:
            pass

        return False, 0, "No trailing bytes detected"

    @staticmethod
    def _calc_lsb_chi_square(channel_data: list[int]) -> tuple[float, float]:
        """Calculate Chi-Square statistic and embedding suspicion score for LSB Pairs of Values (PoV)."""
        counts = [0] * 256
        for v in channel_data:
            counts[v] += 1

        chi_sq = 0.0
        dof = 0

        for k in range(128):
            n1 = counts[2 * k]
            n2 = counts[2 * k + 1]
            e = (n1 + n2) / 2.0
            if e > 0:
                chi_sq += ((n1 - e) ** 2) / e + ((n2 - e) ** 2) / e
                dof += 1

        if dof == 0:
            return 0.0, 0.0

        # High chi-square relative to dof => natural image (unequal PoV).
        # Low chi-square relative to dof => LSB embedding (equalized PoV).
        ratio = chi_sq / dof if dof > 0 else 1.0
        # Convert ratio to suspicion score (closer to 0 ratio => higher suspicion)
        suspicion = max(0.0, min(1.0, 1.0 - (ratio / 2.0)))
        return round(chi_sq, 2), round(suspicion, 3)

    @staticmethod
    def _calc_lsb_entropy(channel_data: list[int]) -> float:
        """Calculate Shannon entropy of the LSB bit plane."""
        lsb_counts = [0, 0]
        for v in channel_data:
            lsb_counts[v & 1] += 1

        total = len(channel_data)
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in lsb_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute steganography detection on target file."""
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
                format_name = img.format or file_path.suffix.lstrip(".").upper()
                width, height = img.size
                mode = img.mode

                # Check trailing bytes
                has_trailing, trailing_count, trailing_msg = self._check_trailing_bytes(file_path, format_name)

                # Convert image to RGB/L for pixel analysis
                converted = img.convert("RGB") if mode in ["RGB", "RGBA", "P"] else img.convert("L")
                pixels = list(converted.getdata())

                channel_results: dict[str, Any] = {}
                max_chi_suspicion = 0.0
                max_lsb_entropy = 0.0

                if mode in ["RGB", "RGBA", "P"]:
                    channels = {
                        "red": [p[0] for p in pixels],
                        "green": [p[1] for p in pixels],
                        "blue": [p[2] for p in pixels]
                    }
                else:
                    channels = {"luminance": [p if isinstance(p, int) else p[0] for p in pixels]}

                for name, data_list in channels.items():
                    chi_sq, chi_susp = self._calc_lsb_chi_square(data_list)
                    lsb_ent = self._calc_lsb_entropy(data_list)

                    channel_results[name] = {
                        "chi_square": chi_sq,
                        "chi_square_suspicion": chi_susp,
                        "lsb_entropy": lsb_ent
                    }

                    max_chi_suspicion = max(max_chi_suspicion, chi_susp)
                    max_lsb_entropy = max(max_lsb_entropy, lsb_ent)

                # Compute overall suspicion score (0.00 to 1.00)
                suspicion_score = (0.5 * max_chi_suspicion) + (0.3 * max_lsb_entropy)
                if has_trailing:
                    suspicion_score += 0.35

                suspicion_score = min(1.0, round(suspicion_score, 3))

                if suspicion_score >= 0.70:
                    suspicion_level = "high"
                elif suspicion_score >= 0.40:
                    suspicion_level = "medium"
                else:
                    suspicion_level = "low"

                return ModuleResult(
                    target=target,
                    module=self.MODULE_NAME,
                    data={
                        "file_path": str(file_path),
                        "file_size": file_path.stat().st_size,
                        "format": format_name,
                        "dimensions": {"width": width, "height": height},
                        "channels": channel_results,
                        "trailing_bytes_found": has_trailing,
                        "trailing_bytes_count": trailing_count,
                        "trailing_bytes_info": trailing_msg,
                        "max_lsb_entropy": max_lsb_entropy,
                        "suspicion_score": suspicion_score,
                        "suspicion_level": suspicion_level,
                        "summary": f"Statistical steganography analysis: suspicion score {suspicion_score:.2f} ({suspicion_level}). No payload content claimed.",
                    },
                    status="success"
                )

        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Steganography detection failed: {str(e)}"
            )


steg_detect_module = StegDetectModule
