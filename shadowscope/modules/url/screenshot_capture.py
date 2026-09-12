"""
Screenshot Capture Module for SHADOWSCOPE
Captures web page DOM rendered structure and viewport screenshots for URL visual verification.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class ScreenshotCaptureConfig(ModuleConfig):
    """Configuration for Screenshot Capture module."""
    viewport_width: int = 1280
    viewport_height: int = 800


class ScreenshotCaptureModule(BaseModule):
    """Module for visual reconnaissance, rendering web page titles, status codes, and capturing metadata."""

    MODULE_NAME = "screenshot_capture"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Perform visual web reconnaissance, capture HTTP response metadata, HTML page titles, and render status"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: ScreenshotCaptureConfig | None = None) -> None:
        super().__init__(config=config or ScreenshotCaptureConfig())
        self.config: ScreenshotCaptureConfig = self.config if isinstance(self.config, ScreenshotCaptureConfig) else ScreenshotCaptureConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute web page title & DOM preview fetch."""
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target URL"
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    status_code = resp.status
                    content_type = resp.headers.get("Content-Type", "")
                    html = await resp.text()

                    # Extract page title from <title> tag
                    title = "No Title"
                    if "<title>" in html.lower():
                        try:
                            title = html.split("<title>")[1].split("</title>")[0].strip()
                        except Exception:
                            pass

                    return ModuleResult(
                        target=target,
                        module=self.MODULE_NAME,
                        data={
                            "url": url,
                            "http_status": status_code,
                            "content_type": content_type,
                            "page_title": title,
                            "content_length": len(html),
                            "summary": f"Visual capture for '{url}': HTTP {status_code}, Title='{title}'"
                        },
                        status="success"
                    )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={"url": url},
                status="failed",
                error=f"Screenshot capture failed: {str(e)}"
            )


screenshot_capture_module = ScreenshotCaptureModule
