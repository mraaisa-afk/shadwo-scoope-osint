"""
BGP Hijack Detection Module for SHADOWSCOPE
Detects BGP hijacking and route anomalies for IP addresses.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core import cache, proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class BGPHijackConfig(ModuleConfig):
    """Configuration for BGP hijack detection module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 30.0
    use_proxy: bool = True
    max_retries: int = 3
    check_history: bool = True
    history_days: int = 30
    alert_threshold: float = 0.1  # 10% change threshold

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "bgpstream": "https://api.bgpstream.com",
                "bgpview": "https://api.bgpview.io",
                "ripe_stat": "https://stat.ripe.net/data",
                "bgpmon": "https://api.bgpmon.net",
                "bgp_he": "https://bgp.he.net",
            }


class BGPHijackModule(BaseModule):
    """
    BGP Hijack Detection Module
    
    Detects BGP hijacking, route anomalies, and suspicious routing changes.
    Monitors BGP updates and compares with historical data to identify hijacks.
    """

    MODULE_NAME = "bgp_hijack"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "IP/Network"
    MODULE_DESCRIPTION = "BGP hijacking detection and route anomaly analysis"
    MODULE_TARGET_TYPES = [TargetType.IP]

    DEFAULT_CONFIG = BGPHijackConfig

    def __init__(self, config: BGPHijackConfig | None = None):
        super().__init__(config or BGPHijackConfig())
        self.session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the BGP hijack detection module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            # Validate target
            target_type = self.validate_target(target)
            if not target_type:
                result.status = "error"
                result.error = f"Invalid target: {target}"
                return result

            # Check cache
            cache_key = f"bgp_hijack:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Detect BGP hijacks
            hijack_data = await self.detect_hijacks(target)

            # Store in cache
            cache.set(cache_key, hijack_data, ttl=3600)  # 1 hour

            result.status = "success"
            result.data = hijack_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def detect_hijacks(self, ip: str) -> dict[str, Any]:
        """Detect BGP hijacks for an IP address"""
        data = {
            "ip": ip,
            "asn": None,
            "prefix": None,
            "current_routes": [],
            "historical_routes": [],
            "anomalies": [],
            "hijacks": [],
            "analysis": {}
        }

        # Get current ASN and prefix
        asn_info = await self.get_ip_asn(ip)
        if asn_info:
            data["asn"] = asn_info.get("asn")
            data["prefix"] = asn_info.get("prefix")

        # Get current routes
        current_routes = await self.get_current_routes(ip)
        if current_routes:
            data["current_routes"] = current_routes

        # Check history if enabled
        if self.config.check_history:
            historical_routes = await self.get_historical_routes(ip)
            if historical_routes:
                data["historical_routes"] = historical_routes
                # Compare with current routes
                data["anomalies"] = self.detect_route_anomalies(
                    current_routes, historical_routes
                )

        # Check for known hijacks
        hijacks = await self.check_known_hijacks(ip)
        if hijacks:
            data["hijacks"] = hijacks

        # Analyze the data
        data["analysis"] = self.analyze_hijack_data(data)

        return data

    async def get_ip_asn(self, ip: str) -> dict[str, Any] | None:
        """Get ASN information for an IP"""
        # Use BGPView API
        url = f"{self.config.api_endpoints['bgpview']}/ip/{ip}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "data" in data:
                        asn_info = data["data"]
                        return {
                            "asn": asn_info.get("asn"),
                            "prefix": asn_info.get("prefix"),
                            "name": asn_info.get("name"),
                            "description": asn_info.get("description")
                        }
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get ASN info: {e}[/yellow]")

        return None

    async def get_current_routes(self, ip: str) -> list[dict[str, Any]]:
        """Get current BGP routes for an IP"""
        routes = []

        # Try BGPView
        url = f"{self.config.api_endpoints['bgpview']}/ip/{ip}/routes"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "data" in data:
                        for route in data["data"]:
                            routes.append({
                                "prefix": route.get("prefix"),
                                "asn": route.get("asn"),
                                "as_path": route.get("path"),
                                "origin": route.get("origin"),
                                "source": "bgpview"
                            })
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get current routes: {e}[/yellow]")

        return routes

    async def get_historical_routes(self, ip: str) -> list[dict[str, Any]]:
        """Get historical BGP routes for an IP"""
        routes = []

        # Use RIPE Stat API for historical data
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=self.config.history_days)

        url = f"{self.config.api_endpoints['ripe_stat']}/bgplay/data.json?resource={ip}&start={start_date.strftime('%Y-%m-%d')}&end={end_date.strftime('%Y-%m-%d')}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    # Parse RIPE Stat historical data
                    if data and "data" in data:
                        for entry in data["data"]:
                            routes.append({
                                "timestamp": entry.get("timestamp"),
                                "prefix": entry.get("prefix"),
                                "asn": entry.get("asn"),
                                "as_path": entry.get("as_path"),
                                "source": "ripe_stat"
                            })
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to get historical routes: {e}[/yellow]")

        return routes

    async def check_known_hijacks(self, ip: str) -> list[dict[str, Any]]:
        """Check for known BGP hijacks affecting this IP"""
        hijacks = []

        # Check BGPStream for known hijacks
        url = f"{self.config.api_endpoints['bgpstream']}/event/ip/{ip}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "events" in data:
                        for event in data["events"]:
                            hijacks.append({
                                "event_id": event.get("id"),
                                "type": event.get("type"),
                                "prefix": event.get("prefix"),
                                "hijacker_asn": event.get("hijacker_asn"),
                                "victim_asn": event.get("victim_asn"),
                                "start_time": event.get("start_time"),
                                "end_time": event.get("end_time"),
                                "severity": event.get("severity"),
                                "source": "bgpstream"
                            })
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to check known hijacks: {e}[/yellow]")

        return hijacks

    def detect_route_anomalies(self, current_routes: list[dict[str, Any]],
                              historical_routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect anomalies between current and historical routes"""
        anomalies = []

        if not current_routes or not historical_routes:
            return anomalies

        # Build historical AS path patterns
        historical_as_paths = {}
        for route in historical_routes:
            as_path = route.get("as_path", [])
            if as_path:
                path_key = " ".join(str(asn) for asn in as_path)
                if path_key not in historical_as_paths:
                    historical_as_paths[path_key] = 0
                historical_as_paths[path_key] += 1

        # Check current routes against historical patterns
        for route in current_routes:
            as_path = route.get("as_path", [])
            if as_path:
                path_key = " ".join(str(asn) for asn in as_path)

                # Check if this path is new or has changed significantly
                if path_key not in historical_as_paths:
                    anomalies.append({
                        "type": "new_path",
                        "prefix": route.get("prefix"),
                        "as_path": as_path,
                        "severity": "high",
                        "description": "New AS path detected"
                    })
                else:
                    # Check if the path frequency has changed significantly
                    historical_count = historical_as_paths[path_key]
                    total_historical = len(historical_routes)
                    historical_ratio = historical_count / total_historical if total_historical > 0 else 0

                    # If this path was rare historically but is now active
                    if historical_ratio < self.config.alert_threshold:
                        anomalies.append({
                            "type": "rare_path",
                            "prefix": route.get("prefix"),
                            "as_path": as_path,
                            "severity": "medium",
                            "description": f"Rare AS path (historically {historical_ratio:.1%} common)"
                        })

        # Check for ASN changes
        current_asns = set()
        for route in current_routes:
            asn = route.get("asn")
            if asn:
                current_asns.add(asn)

        historical_asns = set()
        for route in historical_routes:
            asn = route.get("asn")
            if asn:
                historical_asns.add(asn)

        # New ASNs in current routes
        new_asns = current_asns - historical_asns
        for asn in new_asns:
            anomalies.append({
                "type": "new_asn",
                "asn": asn,
                "severity": "high",
                "description": f"New ASN {asn} detected in routes"
            })

        # ASNs that disappeared
        lost_asns = historical_asns - current_asns
        for asn in lost_asns:
            anomalies.append({
                "type": "lost_asn",
                "asn": asn,
                "severity": "medium",
                "description": f"ASN {asn} no longer in routes"
            })

        return anomalies

    def analyze_hijack_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze BGP hijack data"""
        analysis = {
            "ip": data["ip"],
            "asn": data["asn"],
            "prefix": data["prefix"],
            "current_routes_count": len(data["current_routes"]),
            "historical_routes_count": len(data["historical_routes"]),
            "anomalies_count": len(data["anomalies"]),
            "hijacks_count": len(data["hijacks"]),
            "is_hijacked": False,
            "is_suspicious": False,
            "threat_level": "low",
            "recommendations": []
        }

        # Check for active hijacks
        if data["hijacks"]:
            analysis["is_hijacked"] = True
            analysis["threat_level"] = "critical"
            analysis["recommendations"].append(
                f"ACTIVE HIJACK: {analysis['hijacks_count']} known hijack(s) detected"
            )

        # Check for anomalies
        if data["anomalies"]:
            analysis["is_suspicious"] = True

            # Count severity levels
            high_anomalies = sum(1 for a in data["anomalies"] if a.get("severity") == "high")
            medium_anomalies = sum(1 for a in data["anomalies"] if a.get("severity") == "medium")

            if high_anomalies > 0:
                analysis["threat_level"] = "high"
                analysis["recommendations"].append(
                    f"HIGH: {high_anomalies} high-severity route anomalies detected"
                )
            elif medium_anomalies > 2:
                analysis["threat_level"] = "medium"
                analysis["recommendations"].append(
                    f"MEDIUM: {medium_anomalies} medium-severity route anomalies detected"
                )
            else:
                analysis["threat_level"] = "low"

        # Check for route changes
        if data["current_routes"] and data["historical_routes"]:
            route_change = abs(
                analysis["current_routes_count"] - analysis["historical_routes_count"]
            )
            if route_change > 5:
                analysis["recommendations"].append(
                    f"Significant route change: {route_change} routes difference"
                )

        # Generate general recommendations
        if analysis["threat_level"] == "low":
            analysis["recommendations"].append(
                "No active hijacks or anomalies detected"
            )

        if not data["current_routes"]:
            analysis["recommendations"].append(
                "No route information available - check connectivity"
            )

        return analysis

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""
        import re

        # Check if it's an IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            return TargetType.IP

        return None


# Module instance
bgp_hijack_module = BGPHijackModule
