"""
SIM Swap Check Module for SHADOWSCOPE

Computes transparent SIM-swap / account-takeover risk signals for a
phone number: numbering-plan analysis (premium, VoIP, personal ranges),
portability exposure by country, and an optional HLR lookup API hook.
Definitive SIM state always requires carrier/HLR data; offline results
are risk indicators, never verdicts.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

# Numbering-plan ranges with elevated takeover/abuse relevance.
# (calling_code, prefix_regex, label, risk_points, note)
SENSITIVE_RANGES: list[Any] = [
    ("1", r"^900", "NANPA premium-rate", 25, "premium billing range"),
    ("1", r"^8(00|33|44|55|66|77|88)", "NANPA toll-free", 10,
     "often forwarded, weak identity binding"),
    ("1", r"^5", "NANPA personal/loc-based", 15,
     "one-number follow-me services live here"),
    ("44", r"^70", "UK personal numbering", 30,
     "070 numbers are a known fraud/SIM-swap vector"),
    ("44", r"^7", "UK mobile", 10, "standard mobile range"),
    ("44", r"^80", "UK freephone", 10, "forwarded range"),
    ("44", r"^90", "UK premium-rate", 20, "premium billing range"),
    ("880", r"^96", "BD IPTSP/VoIP", 25,
     "096-series IP telephony, non-SIM identity"),
]

# Countries with live mobile number portability (curated subset).
MNP_COUNTRIES = {
    "1", "44", "880", "91", "92", "61", "65", "60", "49", "33", "39",
    "34", "31", "46", "47", "48", "81", "82", "86", "90", "353",
    "351", "352", "354",
}


@dataclass
class SimSwapCheckConfig(ModuleConfig):
    """Configuration for SIM-swap checks."""

    hlr_api_url: str = ""
    hlr_api_key: str = ""
    request_timeout: int = 15
    high_risk_threshold: int = 50


class SimSwapCheckModule(BaseModule):
    """Assess SIM-swap risk signals for a phone number."""

    MODULE_NAME = "sim_swap_check"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Phone OSINT"
    MODULE_DESCRIPTION = "SIM-swap and takeover risk signal analysis"
    MODULE_TARGET_TYPES = [TargetType.PHONE]

    def __init__(self, config: SimSwapCheckConfig | None = None):
        super().__init__(config or SimSwapCheckConfig())
        self.session: aiohttp.ClientSession | None = None

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

    def split_code(self, e164: str) -> dict[str, str]:
        from shadowscope.modules.phone.carrier_lookup import CALLING_CODES
        digits = e164.lstrip("+")
        for length in (4, 3, 2, 1):
            if digits[:length] in CALLING_CODES:
                return {"code": digits[:length],
                        "national": digits[length:]}
        return {"code": "", "national": digits}

    def analyze_plan(self, code: str, national: str) -> dict[str, Any]:
        """Match the national number against sensitive ranges."""
        signals: list[dict[str, Any]] = []
        score = 0
        for range_code, pattern, label, points, note in SENSITIVE_RANGES:
            if range_code == code and re.match(pattern, national):
                signals.append({"range": label, "points": points,
                                "note": note})
                score += points
        portable = code in MNP_COUNTRIES
        if portable:
            signals.append({"range": "MNP market", "points": 10,
                            "note": "number can be ported between carriers"})
            score += 10
        return {"signals": signals, "plan_score": score,
                "portability_exposed": portable}

    async def query_hlr(self, e164: str) -> dict[str, Any]:
        """Query an HLR lookup API when configured."""
        if not self.config.hlr_api_url:
            return {"queried": False,
                    "reason": "no HLR API configured"}
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        headers = {"Accept": "application/json"}
        if self.config.hlr_api_key:
            headers["Authorization"] = f"Bearer {self.config.hlr_api_key}"
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    self.config.hlr_api_url,
                    params={"number": e164}, headers=headers,
                ) as response:
                    payload: Any = await response.json()
                    return {"queried": True, "status": response.status,
                            "data": payload}
        except Exception as exc:
            return {"queried": True, "status": 0, "error": str(exc)}

    def verdict(self, score: int) -> str:
        if score >= self.config.high_risk_threshold:
            return "high"
        if score >= 20:
            return "medium"
        return "low"

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute SIM-swap risk analysis on a phone number."""
        del options
        started = datetime.now().isoformat()
        if not self.validate_target(target):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid phone number format",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        e164 = self.normalize(target)
        split = self.split_code(e164)
        plan = self.analyze_plan(split["code"], split["national"])
        hlr = await self.query_hlr(e164)
        score = int(plan["plan_score"])
        data: dict[str, Any] = {
            "input": target,
            "e164": e164,
            "calling_code": split["code"],
            "national_number": split["national"],
            "signals": plan["signals"],
            "risk_score": score,
            "risk_level": self.verdict(score),
            "hlr": hlr,
            "disclaimer": "Offline signals only; confirm SIM state via "
                          "carrier/HLR data before acting.",
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
sim_swap_check_module = SimSwapCheckModule
