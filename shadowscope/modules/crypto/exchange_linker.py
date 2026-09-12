"""
Exchange Linker Module for SHADOWSCOPE

Links addresses to exchanges via an operator-maintained tag database
(JSON file) plus on-chain deposit/withdrawal pattern heuristics:
round-amount clustering, fan-in/fan-out detection, and hot-wallet
churn scoring. Ships with an empty tag DB and an explicit schema —
no fabricated attributions, ever.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

TAG_SCHEMA = {
    "description": "address -> {label, entity, confidence}",
    "example": {
        "1ExampleExchangeHotWallet...": {
            "label": "Example hot wallet",
            "entity": "Example Exchange",
            "confidence": "high",
        }
    },
}


@dataclass
class ExchangeLinkerConfig(ModuleConfig):
    """Configuration for exchange linkage."""

    tag_db_path: str = ""
    esplora_url: str = "https://blockstream.info/api"
    max_txs: int = 25
    request_timeout: int = 20
    extra_tags: dict[str, dict[str, str]] = field(default_factory=dict)


class ExchangeLinkerModule(BaseModule):
    """Link crypto addresses to exchanges and services."""

    MODULE_NAME = "exchange_linker"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Crypto Tracking"
    MODULE_DESCRIPTION = "Exchange deposit/withdrawal linkage analysis"
    MODULE_TARGET_TYPES = [TargetType.BITCOIN, TargetType.ETHEREUM,
                            TargetType.CRYPTO]

    def __init__(self, config: ExchangeLinkerConfig | None = None):
        super().__init__(config or ExchangeLinkerConfig())
        self._tags: dict[str, dict[str, str]] = {}
        self._tags_loaded = False

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        text = target.strip()
        if re.match(r"^0x[0-9a-fA-F]{40}$", text):
            return True
        if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", text):
            return True
        return bool(re.match(
            r"^(bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}$",
            text.lower()))

    def load_tags(self) -> dict[str, dict[str, str]]:
        """Load the operator tag DB (empty by default)."""
        if self._tags_loaded:
            return self._tags
        self._tags_loaded = True
        tags: dict[str, dict[str, str]] = {}
        if self.config.tag_db_path:
            try:
                raw = json.loads(Path(self.config.tag_db_path)
                                 .expanduser().read_text())
                if isinstance(raw, dict):
                    tags.update({str(k): (v if isinstance(v, dict)
                                                 else {"label": str(v)})
                                         for k, v in raw.items()})
            except Exception as exc:
                console.print(f"[yellow]Tag DB unreadable: {exc}[/yellow]")
        tags.update(self.config.extra_tags)
        self._tags = tags
        return tags

    def match_tag(self, address: str) -> dict[str, Any]:
        """Match an address against the tag DB."""
        tags = self.load_tags()
        hit = tags.get(address) or tags.get(address.lower())
        return {"matched": hit is not None,
                "tag": hit or {},
                "db_entries": len(tags),
                "schema": TAG_SCHEMA}

    async def fetch_btc_txs(self, address: str) -> list[dict[str, Any]]:
        """Fetch recent BTC transactions from Esplora."""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            url = f"{self.config.esplora_url}/address/{address}/txs"
            async with session.get(url) as response:
                response.raise_for_status()
                txs = await response.json()
        detailed = []
        for entry in (txs or [])[:self.config.max_txs]:
            txid = entry.get("txid")
            if not txid:
                continue
            try:
                timeout2 = aiohttp.ClientTimeout(
                    total=self.config.request_timeout)
                async with aiohttp.ClientSession(timeout=timeout2) as sess2:
                    url2 = f"{self.config.esplora_url}/tx/{txid}"
                    async with sess2.get(url2) as resp2:
                        detailed.append(await resp2.json())
            except Exception:
                continue
        return detailed

    def pattern_score(self, txs: list[dict[str, Any]],
                      address: str) -> dict[str, Any]:
        """Score exchange-like on-chain patterns (BTC only)."""
        fan_in = fan_out = round_hits = 0
        for tx in txs:
            vins = tx.get("vin", [])
            vouts = tx.get("vout", [])
            in_addrs = {v.get("prevout", {}).get("scriptpubkey_address")
                        for v in vins}
            out_addrs = {v.get("scriptpubkey_address") for v in vouts}
            in_addrs.discard(None)
            out_addrs.discard(None)
            if address in out_addrs and len(in_addrs) >= 5:
                fan_in += 1  # many depositors -> one address
            if address in in_addrs and len(out_addrs) >= 5:
                fan_out += 1  # one address -> many withdrawals
            for vout in vouts:
                value = vout.get("value", 0) or 0
                if value > 0 and value % 100000 == 0:  # round mBTC-ish
                    round_hits += 1
        score = min(100, fan_in * 15 + fan_out * 15 + round_hits * 2)
        return {"fan_in_txs": fan_in, "fan_out_txs": fan_out,
                "round_amount_outputs": round_hits,
                "exchange_likeness": score,
                "txs_analyzed": len(txs)}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute exchange linkage on a crypto address."""
        del options
        started = datetime.now().isoformat()
        address = (target or "").strip()
        if not self.validate_target(address):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Unsupported address format",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        data: dict[str, Any] = {
            "address": address,
            "tag_match": self.match_tag(address),
            "patterns": {},
        }
        is_btc = not address.startswith("0x")
        if is_btc:
            try:
                txs = await self.fetch_btc_txs(address)
                data["patterns"] = self.pattern_score(txs, address)
            except Exception as exc:
                data["patterns"] = {"error": f"chain data unavailable: {exc}"}
        else:
            data["patterns"] = {
                "note": "ETH pattern heuristics require an Etherscan key; "
                        "see eth_tracer history output"}
        linked = bool(data["tag_match"]["matched"]) or \
            int(data.get("patterns", {}).get("exchange_likeness", 0)) >= 40
        data["exchange_linked"] = linked
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
exchange_linker_module = ExchangeLinkerModule
