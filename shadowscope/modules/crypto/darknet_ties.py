"""
Darknet Ties Module for SHADOWSCOPE

Screens addresses for darknet-adjacent on-chain behavior using
evidence-only heuristics computed from fetched transactions:
CoinJoin/equal-output detection, peel-chain tracing, mixer-shaped
fan patterns, and screening against an operator-supplied watchlist
(empty by default). Reports evidence with scores, never accusations.
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


@dataclass
class DarknetTiesConfig(ModuleConfig):
    """Configuration for darknet-ties screening."""

    esplora_url: str = "https://blockstream.info/api"
    watchlist_path: str = ""
    extra_watchlist: list[str] = field(default_factory=list)
    max_txs: int = 25
    request_timeout: int = 20
    coinjoin_min_equal_outputs: int = 5


class DarknetTiesModule(BaseModule):
    """Screen addresses for darknet-adjacent on-chain patterns."""

    MODULE_NAME = "darknet_ties"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Crypto Tracking"
    MODULE_DESCRIPTION = "Darknet-adjacent on-chain pattern screening"
    MODULE_TARGET_TYPES = [TargetType.BITCOIN, TargetType.ETHEREUM,
                            TargetType.CRYPTO]

    def __init__(self, config: DarknetTiesConfig | None = None):
        super().__init__(config or DarknetTiesConfig())
        self._watchlist: set[str] = set()
        self._watchlist_loaded = False

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

    def load_watchlist(self) -> set[str]:
        """Load operator watchlist (empty unless configured)."""
        if self._watchlist_loaded:
            return self._watchlist
        self._watchlist_loaded = True
        entries: set[str] = {e.strip() for e in self.config.extra_watchlist
                              if e and e.strip()}
        if self.config.watchlist_path:
            try:
                raw = json.loads(Path(self.config.watchlist_path)
                                 .expanduser().read_text())
                items = raw if isinstance(raw, list) else raw.get("watchlist",
                                                                  [])
                entries.update(str(e).strip() for e in items if str(e).strip())
            except Exception as exc:
                console.print(f"[yellow]Watchlist unreadable: {exc}[/yellow]")
        self._watchlist = entries
        return entries

    async def fetch_btc_txs(self, address: str) -> list[dict[str, Any]]:
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

    def detect_coinjoin(self, tx: dict[str, Any]) -> dict[str, Any]:
        """Equal-output CoinJoin heuristic for one transaction."""
        values = [v.get("value", 0) for v in tx.get("vout", [])]
        counts: dict[int, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        best = max(counts.values()) if counts else 0
        threshold = self.config.coinjoin_min_equal_outputs
        return {"is_coinjoin_like": best >= threshold and
                len(tx.get("vin", [])) >= 3,
                "max_equal_outputs": best,
                "input_count": len(tx.get("vin", []))}

    def detect_peel(self, txs: list[dict[str, Any]],
                    address: str) -> dict[str, Any]:
        """Peel-chain heuristic: 1-in/2-out chains paying change onward."""
        peels = 0
        for tx in txs:
            vins = [v.get("prevout", {}).get("scriptpubkey_address")
                    for v in tx.get("vin", [])]
            vouts = [(v.get("scriptpubkey_address"), v.get("value", 0))
                     for v in tx.get("vout", [])]
            if len(vins) == 1 and len(vouts) == 2 and address in vins \
                    and address not in [a for a, _ in vouts]:
                peels += 1
        return {"peel_like_txs": peels}

    def detect_mixer_shape(self, txs: list[dict[str, Any]]) -> dict[str, Any]:
        """Mixer-shaped fan patterns (many-to-many, split/merge)."""
        splits = merges = 0
        for tx in txs:
            vin_n, vout_n = len(tx.get("vin", [])), len(tx.get("vout", []))
            if vin_n <= 2 and vout_n >= 8:
                splits += 1
            if vin_n >= 8 and vout_n <= 2:
                merges += 1
        return {"split_txs": splits, "merge_txs": merges}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute darknet-ties screening on a crypto address."""
        del options
        started = datetime.now().isoformat()
        address = (target or "").strip()
        if not self.validate_target(address):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Unsupported address format",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        watchlist = self.load_watchlist()
        data: dict[str, Any] = {
            "address": address,
            "watchlist": {
                "entries": len(watchlist),
                "matched": address in watchlist,
            },
            "heuristics": {},
        }
        if address.startswith("0x"):
            data["heuristics"] = {
                "note": "ETH heuristics need Etherscan history; run "
                        "eth_tracer with an API key first"}
        else:
            try:
                txs = await self.fetch_btc_txs(address)
            except Exception as exc:
                data["heuristics"] = {
                    "error": f"chain data unavailable: {exc}"}
                return ModuleResult(
                    target=target, module=self.MODULE_NAME, data=data,
                    status="partial", started_at=started,
                    completed_at=datetime.now().isoformat())
            coinjoins = [t.get("txid") for t in txs
                         if self.detect_coinjoin(t)["is_coinjoin_like"]]
            heuristics = {
                "txs_analyzed": len(txs),
                "coinjoin_like_txs": coinjoins,
                "peel": self.detect_peel(txs, address),
                "mixer_shape": self.detect_mixer_shape(txs),
            }
            score = min(100, len(coinjoins) * 20
                        + heuristics["peel"]["peel_like_txs"] * 10
                        + (heuristics["mixer_shape"]["split_txs"]
                           + heuristics["mixer_shape"]["merge_txs"]) * 10
                        + (40 if data["watchlist"]["matched"] else 0))
            heuristics["obfuscation_score"] = score
            data["heuristics"] = heuristics
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
darknet_ties_module = DarknetTiesModule
