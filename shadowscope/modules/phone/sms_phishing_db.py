"""
SMS Phishing Database Module for SHADOWSCOPE

Offline smishing analyzer: extracts URLs from a message, detects
shorteners, IDN homographs and lookalike domains (Levenshtein), and
scores urgency/lure language with a transparent, documented rubric.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

URL_RE = re.compile(r"https?://[^\s\"'<>]+|(?:www\.)[^\s\"'<>]+", re.IGNORECASE)

# Well-known URL shorteners abused in smishing.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "s.id",
    "shorturl.at", "tiny.cc", "lnkiy.in",
}

# Urgency / lure phrases with weights (EN + common BD romaji/Bangla).
LURE_PHRASES: list[Any] = [
    ("urgent", 8), ("immediately", 8), ("verify now", 10),
    ("account suspended", 12), ("account locked", 12),
    ("suspended", 8), ("locked", 6), ("expire", 6), ("expiring", 6),
    ("otp", 8), ("one-time password", 8), ("pin", 6),
    ("confirm your", 8), ("update your", 6), ("click here", 6),
    ("click the link", 6), ("limited time", 6), ("act now", 6),
    ("prize", 8), ("winner", 8), ("lottery", 8), ("reward", 6),
    ("bkash", 6), ("nagad", 6), ("rocket", 5), ("upay", 5),
    ("বিকাশ", 6), ("নগদ", 6), ("জরুরি", 8), ("যাচাই", 8),
    ("সাসপেন্ড", 8), ("পুরস্কার", 8),
]

# High-value brands frequently impersonated (lookalike baseline).
WATCH_BRANDS = [
    "bkash", "nagad", "rocket", "upay", "paypal", "apple", "google",
    "facebook", "amazon", "microsoft", "netflix", "bank", "grameenphone",
    "robi", "banglalink", "airtel", "teletalk",
]


@dataclass
class SmsPhishingDbConfig(ModuleConfig):
    """Configuration for SMS phishing analysis."""

    high_risk_threshold: int = 40
    lookalike_max_distance: int = 2
    extra_lures: list[str] = field(default_factory=list)
    extra_brands: list[str] = field(default_factory=list)


class SmsPhishingDbModule(BaseModule):
    """Analyze an SMS/message for smishing indicators."""

    MODULE_NAME = "sms_phishing_db"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Phone OSINT"
    MODULE_DESCRIPTION = "Offline SMS phishing (smishing) analysis"
    MODULE_TARGET_TYPES = [TargetType.PHONE]

    def __init__(self, config: SmsPhishingDbConfig | None = None):
        super().__init__(config or SmsPhishingDbConfig())

    def validate_target(self, target: str) -> bool:
        return bool(target and target.strip())

    @staticmethod
    def levenshtein(left: str, right: str) -> int:
        """Classic dynamic-programming edit distance."""
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)
        prev = list(range(len(right) + 1))
        for i, char_l in enumerate(left, 1):
            curr = [i]
            for j, char_r in enumerate(right, 1):
                cost = 0 if char_l == char_r else 1
                curr.append(min(prev[j] + 1, curr[j - 1] + 1,
                                prev[j - 1] + cost))
            prev = curr
        return prev[-1]

    def extract_urls(self, text: str) -> list[str]:
        return [m.group(0).rstrip(".,;!?)") for m in URL_RE.finditer(text)]

    def analyze_url(self, url: str) -> dict[str, Any]:
        """Score a single URL for phishing indicators."""
        findings: list[str] = []
        score = 0
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        flags: dict[str, Any] = {"url": url, "host": host}
        if host in SHORTENERS:
            findings.append("url shortener")
            score += 15
        try:
            ascii_host = host.encode("idna").decode("ascii")
            if ascii_host != host or ascii_host.startswith("xn--"):
                findings.append("IDN/homograph host")
                score += 20
        except Exception:
            findings.append("unparseable host")
            score += 10
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append("bare IP host")
            score += 15
        if "@" in url:
            findings.append("'@' in URL (credential confusion)")
            score += 15
        if parsed.port and parsed.port not in (80, 443):
            findings.append(f"unusual port {parsed.port}")
            score += 8
        brands = WATCH_BRANDS + list(self.config.extra_brands)
        base = host.split(".")[0] if host else ""
        for brand in brands:
            if not brand or brand in host:
                continue
            distance = self.levenshtein(base, brand.lower())
            if 0 < distance <= self.config.lookalike_max_distance:
                findings.append(f"lookalike of '{brand}' (d={distance})")
                score += 18
                break
        flags["findings"] = findings
        flags["score"] = score
        return flags

    def analyze_lures(self, text: str) -> dict[str, Any]:
        """Score urgency/lure language in the message."""
        lowered = text.lower()
        hits: list[dict[str, Any]] = []
        score = 0
        phrases = list(LURE_PHRASES) + [(p, 6) for p in self.config.extra_lures]
        for phrase, weight in phrases:
            if phrase.lower() in lowered:
                hits.append({"phrase": phrase, "weight": weight})
                score += weight
        return {"hits": hits, "score": score}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute smishing analysis on a message."""
        del options
        started = datetime.now().isoformat()
        if not self.validate_target(target):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Empty message",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        urls = [self.analyze_url(u) for u in self.extract_urls(target)]
        lures = self.analyze_lures(target)
        total = sum(u["score"] for u in urls) + int(lures["score"])
        level = "high" if total >= self.config.high_risk_threshold \
            else ("medium" if total >= 15 else "low")
        data: dict[str, Any] = {
            "input_length": len(target),
            "urls": urls,
            "lures": lures,
            "risk_score": total,
            "risk_level": level,
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
sms_phishing_db_module = SmsPhishingDbModule
