"""
Flight Tracker Module for SHADOWSCOPE
Tracks flight numbers, callsigns, and aircraft registrations using OpenSky Network and public aviation APIs.
"""

import re
from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class FlightTrackerConfig(ModuleConfig):
    """Configuration for Flight Tracker module."""
    opensky_api_url: str = "https://opensky-network.org/api/states/all"


class FlightTrackerModule(BaseModule):
    """Module for tracking flights, ICAO callsigns, and aircraft registrations."""

    MODULE_NAME = "flight_tracker"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "transport"
    MODULE_DESCRIPTION = "Track flight numbers, ICAO callsigns, and tail numbers via OpenSky Network and public tracking aggregators"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: FlightTrackerConfig | None = None) -> None:
        super().__init__(config=config or FlightTrackerConfig())
        self.config: FlightTrackerConfig = self.config if isinstance(self.config, FlightTrackerConfig) else FlightTrackerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target flight identifier."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip().upper()
        # Typical flight numbers: e.g. AA123, BA456, N12345, ICAO callsigns 3-8 chars
        return bool(re.match(r"^[A-Z0-9-]{2,10}$", cleaned))

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute flight tracking query."""
        callsign = target.strip().upper()
        if not self.validate_target(callsign):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Invalid flight callsign/registration format: '{target}'"
            )

        # Public flight tracking URLs
        tracking_links = {
            "flightradar24": f"https://www.flightradar24.com/data/flights/{callsign.lower()}",
            "flightaware": f"https://www.flightaware.com/live/flight/{callsign}",
            "radarbox": f"https://www.radarbox.com/data/flights/{callsign}",
            "opensky_network": f"https://opensky-network.org/network/explorer?callsign={callsign}",
            "planespotters": f"https://www.planespotters.net/search?q={callsign}",
        }

        # Query OpenSky Network API
        opensky_url = getattr(self.config, "opensky_api_url", "https://opensky-network.org/api/states/all")
        live_state: dict[str, Any] | None = None

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(opensky_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        states = data.get("states", [])
                        if states:
                            for state in states:
                                if state and len(state) > 1 and str(state[1]).strip().upper() == callsign:
                                    live_state = {
                                        "icao24": state[0],
                                        "callsign": str(state[1]).strip(),
                                        "origin_country": state[2],
                                        "longitude": state[5],
                                        "latitude": state[6],
                                        "altitude_meters": state[7] or state[13],
                                        "on_ground": state[8],
                                        "velocity_m_s": state[9],
                                        "true_track_degrees": state[10],
                                    }
                                    break

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "callsign": callsign,
                    "live_tracking": live_state,
                    "is_airborne": bool(live_state and not live_state.get("on_ground")),
                    "tracking_links": tracking_links,
                    "summary": f"Flight tracking links generated for '{callsign}'" + (f" (Live location: {live_state['latitude']}, {live_state['longitude']})" if live_state else "")
                },
                status="success"
            )

        except Exception:
            # Fallback if network/API is unreachable
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "callsign": callsign,
                    "live_tracking": None,
                    "tracking_links": tracking_links,
                    "summary": f"Flight tracking links generated for '{callsign}' (API offline fallback)"
                },
                status="success"
            )


flight_tracker_module = FlightTrackerModule
