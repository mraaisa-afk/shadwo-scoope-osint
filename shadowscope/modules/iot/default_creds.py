"""
Default Credentials Module for SHADOWSCOPE
Looks up known factory default credentials for IoT devices, routers, IP cameras, switches, and gateways.
"""

from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Curated IoT Default Credentials Database
DEFAULT_CREDS_DB: list[dict[str, str]] = [
    {"vendor": "Cisco", "model": "Router / Switch", "username": "admin", "password": "cisco", "protocol": "HTTP/SSH"},
    {"vendor": "Cisco", "model": "Small Business", "username": "cisco", "password": "cisco", "protocol": "HTTP"},
    {"vendor": "Hikvision", "model": "IP Camera / DVR", "username": "admin", "password": "12345", "protocol": "HTTP/RTSP"},
    {"vendor": "Dahua", "model": "IP Camera / NVR", "username": "admin", "password": "admin", "protocol": "HTTP/RTSP"},
    {"vendor": "D-Link", "model": "DIR Series Router", "username": "admin", "password": "", "protocol": "HTTP"},
    {"vendor": "TP-Link", "model": "Archer / WR Series", "username": "admin", "password": "admin", "protocol": "HTTP"},
    {"vendor": "MikroTik", "model": "RouterOS", "username": "admin", "password": "", "protocol": "WinBox/SSH/HTTP"},
    {"vendor": "Ubiquiti", "model": "EdgeRouter / UniFi", "username": "ubnt", "password": "ubnt", "protocol": "SSH/HTTP"},
    {"vendor": "Netgear", "model": "Nighthawk / ProSafe", "username": "admin", "password": "password", "protocol": "HTTP"},
    {"vendor": "ASUS", "model": "RT Series Router", "username": "admin", "password": "admin", "protocol": "HTTP"},
    {"vendor": "Zyxel", "model": "Gateway / Switch", "username": "admin", "password": "1234", "protocol": "HTTP/SSH"},
    {"vendor": "Axis", "model": "Network Camera", "username": "root", "password": "pass", "protocol": "HTTP"},
    {"vendor": "Fortinet", "model": "FortiGate", "username": "admin", "password": "", "protocol": "HTTP/SSH"},
    {"vendor": "Raspberry Pi", "model": "Raspberry Pi OS", "username": "pi", "password": "raspberry", "protocol": "SSH"},
    {"vendor": "OpenWrt", "model": "Embedded Linux", "username": "root", "password": "", "protocol": "SSH/LuCI"},
]


@dataclass
class DefaultCredsConfig(ModuleConfig):
    """Configuration for Default Creds module."""
    include_protocols: bool = True


class DefaultCredsModule(BaseModule):
    """Module for looking up factory default credentials for IoT and network hardware."""

    MODULE_NAME = "default_creds"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "iot"
    MODULE_DESCRIPTION = "Lookup factory default usernames and passwords for routers, IP cameras, switches, and embedded hardware"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: DefaultCredsConfig | None = None) -> None:
        super().__init__(config=config or DefaultCredsConfig())
        self.config: DefaultCredsConfig = self.config if isinstance(self.config, DefaultCredsConfig) else DefaultCredsConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute default credential lookup."""
        query = target.strip().lower()
        if not self.validate_target(query):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid query string"
            )

        matches: list[dict[str, str]] = []
        for entry in DEFAULT_CREDS_DB:
            vendor = entry["vendor"].lower()
            model = entry["model"].lower()
            proto = entry["protocol"].lower()

            if query in vendor or query in model or query in proto or query == "all":
                matches.append(entry)

        # If no specific match, return top common default credentials
        if not matches:
            matches = DEFAULT_CREDS_DB[:5]

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "query": target,
                "matches_found": len(matches),
                "credentials": matches,
                "summary": f"Found {len(matches)} default credential entries for '{target}'"
            },
            status="success"
        )


default_creds_module = DefaultCredsModule
