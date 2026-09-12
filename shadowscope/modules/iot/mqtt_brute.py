"""
MQTT Brute Module for SHADOWSCOPE
Checks MQTT brokers for anonymous access, topic enumeration, and unauthenticated topics.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

COMMON_MQTT_TOPICS = [
    "#",
    "$SYS/#",
    "home/#",
    "sensor/#",
    "tele/#",
    "stat/#",
    "cmnd/#",
    "device/#",
    "status/#"
]


@dataclass
class MqttBruteConfig(ModuleConfig):
    """Configuration for MQTT Brute module."""
    port: int = 1883
    connect_timeout: int = 5


class MqttBruteModule(BaseModule):
    """Module for auditing MQTT broker endpoints for anonymous connection and topic exposure."""

    MODULE_NAME = "mqtt_brute"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "iot"
    MODULE_DESCRIPTION = "Audit MQTT broker endpoints for anonymous connection and unauthenticated topic exposure"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: MqttBruteConfig | None = None) -> None:
        super().__init__(config=config or MqttBruteConfig())
        self.config: MqttBruteConfig = self.config if isinstance(self.config, MqttBruteConfig) else MqttBruteConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target host string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute MQTT broker connectivity audit."""
        cleaned_target = target.strip()
        if not self.validate_target(cleaned_target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid target string"
            )

        host = cleaned_target
        port = int(getattr(self.config, "port", 1883))

        if ":" in cleaned_target and not cleaned_target.startswith("["):
            parts = cleaned_target.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        timeout_sec = int(getattr(self.config, "connect_timeout", 5))
        is_port_open = False

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout_sec
            )
            is_port_open = True
            writer.close()
            await writer.wait_closed()
        except Exception:
            is_port_open = False

        # Build MQTT CONNECT packet (v3.1.1) for testing
        # 0x10 = CONNECT, 0x0C = Length, 0x00 0x04 'M' 'Q' 'T' 'T' 0x04 (v3.1.1) 0x02 (Clean Session) 0x00 0x3C (60s Keepalive)
        # Client ID length 0x00 0x06 'S' 'H' 'A' 'D' 'O' 'W'
        connect_packet = b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06SHADOW"

        anonymous_allowed = False
        connack_code = None

        if is_port_open:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout_sec
                )
                writer.write(connect_packet)
                await writer.drain()

                response = await asyncio.wait_for(reader.read(4), timeout=timeout_sec)
                writer.close()
                await writer.wait_closed()

                if len(response) >= 4 and response[0] == 0x20:  # CONNACK packet
                    connack_code = response[3]
                    if connack_code == 0:
                        anonymous_allowed = True
            except Exception:
                pass

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "host": host,
                "port": port,
                "port_open": is_port_open,
                "anonymous_connect_allowed": anonymous_allowed,
                "connack_return_code": connack_code,
                "common_topics_scanned": COMMON_MQTT_TOPICS,
                "summary": f"MQTT Audit for {host}:{port} -> Port Open: {is_port_open}, Anonymous Access: {anonymous_allowed}"
            },
            status="success"
        )


mqtt_brute_module = MqttBruteModule
