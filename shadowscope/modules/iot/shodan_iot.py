"""
Shodan IoT Module for SHADOWSCOPE
Searches Shodan for IoT devices, industrial control systems (ICS/SCADA), and embedded hardware exposures.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class ShodanIotConfig(ModuleConfig):
    """Configuration for Shodan IoT module."""
    api_key: str | None = None
    api_url: str = "https://api.shodan.io"


class ShodanIotModule(BaseModule):
    """Module for querying Shodan for IoT devices, webcams, ICS/SCADA, and exposed services."""

    MODULE_NAME = "shodan_iot"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "iot"
    MODULE_DESCRIPTION = "Search Shodan for IoT devices, webcams, RTSP streams, and industrial control systems (ICS/SCADA)"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: ShodanIotConfig | None = None) -> None:
        super().__init__(config=config or ShodanIotConfig())
        self.config: ShodanIotConfig = self.config if isinstance(self.config, ShodanIotConfig) else ShodanIotConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute Shodan IoT search query."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        api_key = getattr(self.config, "api_key", None)
        base_url = getattr(self.config, "api_url", "https://api.shodan.io")

        # Typical IoT query filters
        iot_tags = ["camera", "webcam", "scada", "ics", "modbus", "mqtt", "rtsp", "dvr", "router"]
        detected_iot_type = next((tag for tag in iot_tags if tag in cleaned_target.lower()), "general_device")

        if api_key:
            try:
                async with aiohttp.ClientSession() as session:
                    # Check if IP or query
                    if "." in cleaned_target and not any(c.isalpha() for c in cleaned_target.replace(".", "")):
                        url = f"{base_url}/shodan/host/{cleaned_target}?key={api_key}"
                    else:
                        url = f"{base_url}/shodan/host/search?key={api_key}&query={aiohttp.helpers.quote(cleaned_target)}"

                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={
                                    "target": cleaned_target,
                                    "device_category": detected_iot_type,
                                    "shodan_data": data,
                                    "summary": f"Shodan IoT data retrieved for '{cleaned_target}'"
                                },
                                status="success"
                            )
                        else:
                            return ModuleResult(
                                target=target,
                                module=self.MODULE_NAME,
                                data={"target": cleaned_target, "device_category": detected_iot_type},
                                status="failed",
                                error=f"Shodan API returned HTTP {resp.status}"
                            )
            except Exception as e:
                return ModuleResult(
                    target=target,
                    module=self.MODULE_NAME,
                    data={"target": cleaned_target, "device_category": detected_iot_type},
                    status="failed",
                    error=f"Shodan API request failed: {str(e)}"
                )

        # Honest fallback when API key is not configured
        shodan_search_url = f"https://www.shodan.io/search?query={cleaned_target.replace(' ', '+')}"
        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "target": cleaned_target,
                "device_category": detected_iot_type,
                "api_key_configured": False,
                "web_search_url": shodan_search_url,
                "suggested_dorks": [
                    f"has_screenshot:true {cleaned_target}",
                    f"port:1883 {cleaned_target}",
                    f"port:554 {cleaned_target}",
                    f"product:\"MQTT\" {cleaned_target}"
                ],
                "summary": f"Shodan IoT web search links generated for '{cleaned_target}' (No API key provided)"
            },
            status="success"
        )


shodan_iot_module = ShodanIotModule
