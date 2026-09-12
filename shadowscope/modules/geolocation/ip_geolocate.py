"""
IP Geolocation Module for SHADOWSCOPE

Classifies IP addresses offline (private, reserved, CGNAT, multicast,
loopback via stdlib ipaddress), resolves ASN/owner through the public
Team Cymru DNS service (no key needed), and optionally enriches with
city/ISP data from the keyless ip-api.com endpoint.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
import dns.resolver
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class IpGeolocateConfig(ModuleConfig):
    """Configuration for IP geolocation."""

    nameservers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dns_timeout: float = 8.0
    enrich_http: bool = True
    enrich_url: str = "http://ip-api.com/json/{ip}"
    enrich_fields: str = "status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
    request_timeout: int = 15


class IpGeolocateModule(BaseModule):
    """Geolocate and classify IP addresses."""

    MODULE_NAME = "ip_geolocate"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Geolocation"
    MODULE_DESCRIPTION = "IP geolocation, ASN and network classification"
    MODULE_TARGET_TYPES = [TargetType.IP, TargetType.IPV6]

    def __init__(self, config: IpGeolocateConfig | None = None):
        super().__init__(config or IpGeolocateConfig())

    def validate_target(self, target: str) -> bool:
        try:
            ipaddress.ip_address((target or "").strip())
            return True
        except ValueError:
            return False

    def classify(self, ip: Any) -> dict[str, Any]:
        """Offline classification via stdlib ipaddress."""
        text = str(ip)
        info: dict[str, Any] = {
            "address": text,
            "version": ip.version,
            "is_private": ip.is_private,
            "is_global": ip.is_global,
            "is_reserved": ip.is_reserved,
            "is_loopback": ip.is_loopback,
            "is_multicast": ip.is_multicast,
            "is_link_local": ip.is_link_local,
        }
        if ip.version == 4:
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            info["is_carrier_nat"] = ip in cgnat
            info["reverse_dns"] = ".".join(reversed(text.split("."))) \
                + ".in-addr.arpa"
        else:
            info["is_carrier_nat"] = False
            info["reverse_dns"] = ip.reverse_pointer
        routable = bool(ip.is_global and not ip.is_reserved)
        info["globally_routable"] = routable
        return info

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(self.config.nameservers)
        resolver.lifetime = self.config.dns_timeout
        return resolver

    def cymru_asn(self, ip: Any) -> dict[str, Any]:
        """Resolve origin ASN + BGP prefix via Team Cymru DNS."""
        if ip.version == 4:
            query = ".".join(reversed(str(ip).split("."))) \
                + ".origin.asn.cymru.com"
        else:
            query = ip.reverse_pointer.replace("ip6.arpa",
                                               "origin6.asn.cymru.com")
        try:
            answers = self._resolver().resolve(query, "TXT")
            raw = [r.to_text().strip('"') for r in answers]
        except Exception as exc:
            return {"queried": query, "records": [],
                    "error": f"{type(exc).__name__}: {exc}"}
        entries = []
        for line in raw:
            parts = [p.strip().strip('"') for p in line.split("|")]
            if len(parts) >= 3:
                entries.append({"asn": parts[0], "prefix": parts[1],
                                "country": parts[2]})
        return {"queried": query, "records": entries}

    def cymru_asname(self, asn: str) -> dict[str, Any]:
        """Resolve an AS name via Team Cymru DNS."""
        number = asn.strip().upper().removeprefix("AS")
        if not number.isdigit():
            return {"asn": asn, "name": "", "error": "not numeric"}
        query = f"AS{number}.asn.cymru.com"
        try:
            answers = self._resolver().resolve(query, "TXT")
            raw = [r.to_text().strip('"') for r in answers]
        except Exception as exc:
            return {"asn": asn, "name": "",
                    "error": f"{type(exc).__name__}: {exc}"}
        names = [line.split("|")[-1].strip().strip('"') for line in raw]
        return {"asn": f"AS{number}", "name": names[0] if names else ""}

    async def enrich(self, ip_text: str) -> dict[str, Any]:
        """Enrich with the keyless ip-api.com endpoint."""
        if not self.config.enrich_http:
            return {"queried": False, "reason": "HTTP enrichment disabled"}
        url = self.config.enrich_url.format(ip=ip_text)
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                        url, params={"fields": self.config.enrich_fields}
                ) as response:
                    payload = await response.json()
                    return {"queried": True, "status": response.status,
                            "data": payload}
        except Exception as exc:
            return {"queried": True, "error": str(exc)}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute geolocation on an IP address."""
        del options
        started = datetime.now().isoformat()
        text = (target or "").strip()
        if not self.validate_target(text):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid IP address",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        ip = ipaddress.ip_address(text)
        info = self.classify(ip)
        asn_info: dict[str, Any] = {"skipped": "not globally routable"}
        enrichment: dict[str, Any] = {"queried": False,
                                      "reason": "not globally routable"}
        if info["globally_routable"]:
            asn_info = self.cymru_asn(ip)
            records = asn_info.get("records", [])
            if records:
                asn_info["as_names"] = [
                    self.cymru_asname(r["asn"]) for r in records[:3]]
            enrichment = await self.enrich(text)
        data: dict[str, Any] = {
            "classification": info,
            "asn": asn_info,
            "enrichment": enrichment,
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
ip_geolocate_module = IpGeolocateModule
