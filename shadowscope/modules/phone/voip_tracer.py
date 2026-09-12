"""
VoIP Tracer Module for SHADOWSCOPE

Traces VoIP exposure of a phone number with real ENUM (RFC 6116)
lookups: the E.164 number is mapped into e164.arpa and queried for
NAPTR records that may reveal SIP/H.323 URIs. Optional SIP OPTIONS
probing is supported but disabled by default.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import dns.resolver
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

# National VoIP/IPTSP ranges (calling_code, regex, label).
VOIP_RANGES: list[Any] = [
    ("880", r"^96", "Bangladesh IPTSP series"),
    ("1", r"^5", "NANPA 5XX personal/follow-me"),
    ("44", r"^56", "UK VoIP (Ofcom 056)"),
    ("49", r"^32", "Germany VoIP (032)"),
    ("33", r"^9", "France VoIP (09)"),
    ("39", r"^55", "Italy VoIP (055)"),
    ("34", r"^51", "Spain VoIP nomadic"),
    ("81", r"^50", "Japan IP telephony (050)"),
    ("82", r"^70", "South Korea VoIP (070)"),
    ("61", r"^14", "Australia VoIP range"),
]


@dataclass
class VoipTracerConfig(ModuleConfig):
    """Configuration for VoIP tracing."""

    enum_suffix: str = "e164.arpa"
    nameservers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    dns_timeout: float = 8.0
    sip_probe: bool = False
    sip_probe_timeout: float = 5.0


class VoipTracerModule(BaseModule):
    """Trace VoIP/ENUM exposure of a phone number."""

    MODULE_NAME = "voip_tracer"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Phone OSINT"
    MODULE_DESCRIPTION = "ENUM and VoIP exposure tracing for numbers"
    MODULE_TARGET_TYPES = [TargetType.PHONE]

    def __init__(self, config: VoipTracerConfig | None = None):
        super().__init__(config or VoipTracerConfig())

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        digits = re.sub(r"\D", "", target)
        return 7 <= len(digits) <= 15

    def normalize(self, target: str) -> str:
        text = target.strip().replace(" ", "").replace("-", "")
        text = text.replace("(", "").replace(")", "")
        if text.startswith("00"):
            text = "+" + text[2:]
        return text if text.startswith("+") else "+" + text

    def enum_domain(self, e164: str) -> str:
        """Map E.164 to its ENUM domain (RFC 6116)."""
        digits = re.sub(r"\D", "", e164)
        nibbles = ".".join(reversed(digits))
        return f"{nibbles}.{self.config.enum_suffix}"

    def query_enum(self, domain: str) -> dict[str, Any]:
        """Query NAPTR records for an ENUM domain."""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(self.config.nameservers)
        resolver.lifetime = self.config.dns_timeout
        records: list[dict[str, Any]] = []
        try:
            answers = resolver.resolve(domain, "NAPTR")
        except dns.resolver.NXDOMAIN:
            return {"domain": domain, "records": [],
                    "note": "no ENUM delegation (NXDOMAIN)"}
        except Exception as exc:
            return {"domain": domain, "records": [],
                    "error": f"{type(exc).__name__}: {exc}"}
        for record in answers:
            regexp = record.regexp.decode("utf-8", "replace") \
                if isinstance(record.regexp, bytes) else str(record.regexp)
            records.append({
                "order": int(record.order),
                "preference": int(record.preference),
                "flags": str(record.flags.decode() if isinstance(
                    record.flags, bytes) else record.flags),
                "service": str(record.service.decode() if isinstance(
                    record.service, bytes) else record.service),
                "regexp": regexp,
                "replacement": str(record.replacement),
            })
        records.sort(key=lambda r: (r["order"], r["preference"]))
        return {"domain": domain, "records": records}

    def match_voip_range(self, e164: str) -> dict[str, Any]:
        """Match the number against known VoIP ranges."""
        from shadowscope.modules.phone.carrier_lookup import CALLING_CODES
        digits = e164.lstrip("+")
        code, national = "", digits
        for length in (4, 3, 2, 1):
            if digits[:length] in CALLING_CODES:
                code, national = digits[:length], digits[length:]
                break
        matches = [
            {"calling_code": c, "label": label}
            for c, pattern, label in VOIP_RANGES
            if c == code and re.match(pattern, national)
        ]
        return {"calling_code": code, "national_number": national,
                "voip_range_match": bool(matches), "matches": matches}

    async def sip_options_probe(self, uri: str) -> dict[str, Any]:
        """Send a SIP OPTIONS probe (opt-in, may be intrusive)."""
        import socket
        host = uri.split("@")[-1].split(">")[0].split(";")[0].strip()
        if ":" in host and not host.startswith("["):
            host_part, _, port_part = host.partition(":")
            port = int(port_part) if port_part.isdigit() else 5060
            host = host_part
        else:
            port = 5060
        message = (
            f"OPTIONS sip:{host} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP shadowscope:5060;branch=z9hG4bK1\r\n"
            "Max-Forwards: 1\r\n"
            f"To: <{uri}>\r\n"
            "From: <sip:shadowscope@localhost>;tag=1\r\n"
            "Call-ID: shadowscope-probe\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.sip_probe_timeout)
        try:
            sock.sendto(message.encode(), (host, port))
            payload, _ = sock.recvfrom(4096)
            first = payload.decode("utf-8", "replace").splitlines()
            return {"uri": uri, "reachable": True,
                    "response": first[0] if first else ""}
        except Exception as exc:
            return {"uri": uri, "reachable": False, "error": str(exc)}
        finally:
            sock.close()

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute VoIP tracing on a phone number."""
        del options
        started = datetime.now().isoformat()
        if not self.validate_target(target):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid phone number format",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        e164 = self.normalize(target)
        enum = self.query_enum(self.enum_domain(e164))
        plan = self.match_voip_range(e164)
        probes: list[dict[str, Any]] = []
        if self.config.sip_probe:
            for record in enum.get("records", []):
                regexp = record.get("regexp", "")
                match = re.search(r"sips?:[^!\s]+", regexp)
                if match:
                    probes.append(await self.sip_options_probe(match.group(0)))
        data: dict[str, Any] = {
            "input": target,
            "e164": e164,
            "enum": enum,
            "numbering_plan": plan,
            "sip_probes": probes,
            "voip_exposed": bool(enum.get("records")) or bool(
                plan.get("voip_range_match")),
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
voip_tracer_module = VoipTracerModule
