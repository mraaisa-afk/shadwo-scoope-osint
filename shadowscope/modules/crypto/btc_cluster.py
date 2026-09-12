"""
Bitcoin Clustering Module for SHADOWSCOPE

Validates Bitcoin addresses (Base58Check + bech32, pure Python), pulls
on-chain data from the public Blockstream Esplora API (no key needed),
and applies the common-input-ownership heuristic with union-find to
build one-hop address clusters.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def base58check_valid(address: str) -> bool:
    """Validate a legacy Base58Check address (real checksum)."""
    if not re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
        return False
    num = 0
    for char in address:
        num = num * 58 + BASE58_ALPHABET.index(char)
    raw = num.to_bytes(25, "big")
    leading = len(address) - len(address.lstrip("1"))
    payload = b"\x00" * leading + raw.lstrip(b"\x00")
    if len(payload) != 25:
        payload = payload.rjust(25, b"\x00")[-25:]
    body, check = payload[:-4], payload[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == check


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD,
                 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_valid(address: str) -> bool:
    """Validate a bech32/bech32m address (BIP-173/350 checksum)."""
    text = address.lower()
    if text != address.lower() or any(c not in BECH32_CHARSET + "tb1"
                                      for c in text):
        pass
    if not re.match(r"^(bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}$",
                    text):
        return False
    pos = text.rfind("1")
    hrp, data = text[:pos], text[pos + 1:]
    try:
        values = [_bech32_charset_index(c) for c in data]
    except ValueError:
        return False
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values)
    return polymod in (1, 0x2BC830A3)  # bech32 or bech32m


def _bech32_charset_index(char: str) -> int:
    return BECH32_CHARSET.index(char)


class UnionFind:
    """Union-find for clustering co-spent addresses."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        root = self.parent.setdefault(item, item)
        while self.parent[root] != root:
            self.parent[item], root = root, self.parent[root]
            item = root
        return root

    def union(self, *items: str) -> None:
        roots = [self.find(i) for i in items]
        for other in roots[1:]:
            self.parent[other] = roots[0]

    def clusters(self) -> list[set[str]]:
        groups: dict[str, set[str]] = {}
        for item in list(self.parent):
            groups.setdefault(self.find(item), set()).add(item)
        return list(groups.values())


@dataclass
class BtcClusterConfig(ModuleConfig):
    """Configuration for Bitcoin clustering."""

    esplora_url: str = "https://blockstream.info/api"
    max_txs: int = 25
    max_inputs_per_tx: int = 50
    request_timeout: int = 20


class BtcClusterModule(BaseModule):
    """Cluster Bitcoin addresses via common-input ownership."""

    MODULE_NAME = "btc_cluster"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Crypto Tracking"
    MODULE_DESCRIPTION = "Bitcoin address clustering and fund tracing"
    MODULE_TARGET_TYPES = [TargetType.BITCOIN, TargetType.CRYPTO]

    def __init__(self, config: BtcClusterConfig | None = None):
        super().__init__(config or BtcClusterConfig())

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        text = target.strip()
        return base58check_valid(text) or bech32_valid(text)

    def address_format(self, target: str) -> str:
        text = target.strip()
        if text.lower().startswith(("bc1", "tb1")):
            return "bech32"
        if text.startswith("1"):
            return "p2pkh"
        if text.startswith("3"):
            return "p2sh"
        return "unknown"

    async def _get(self, session: aiohttp.ClientSession,
                   path: str) -> Any:
        url = f"{self.config.esplora_url}{path}"
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.json()

    async def fetch_address_data(self, address: str) -> dict[str, Any]:
        """Fetch address summary + recent transactions."""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            info = await self._get(session, f"/address/{address}")
            txs = await self._get(session, f"/address/{address}/txs")
            detailed = []
            for entry in (txs or [])[:self.config.max_txs]:
                txid = entry.get("txid")
                if not txid:
                    continue
                try:
                    detailed.append(await self._get(session, f"/tx/{txid}"))
                except Exception:
                    continue
            return {"info": info, "transactions": detailed,
                    "tx_count": len(txs or [])}

    def cluster_inputs(
        self, transactions: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Apply common-input-ownership clustering to transactions."""
        union = UnionFind()
        co_spends = 0
        for tx in transactions:
            inputs = [vin.get("prevout", {}).get("scriptpubkey_address")
                      for vin in tx.get("vin", [])]
            inputs = [a for a in inputs if a][
                :self.config.max_inputs_per_tx]
            if len(inputs) > 1:
                co_spends += 1
                union.union(*inputs)
        clusters = [sorted(c) for c in union.clusters() if len(c) > 1]
        clusters.sort(key=len, reverse=True)
        return {"co_spend_txs": co_spends,
                "cluster_count": len(clusters),
                "clusters": clusters[:10]}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute clustering on a Bitcoin address."""
        del options
        started = datetime.now().isoformat()
        address = (target or "").strip()
        if not self.validate_target(address):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid Bitcoin address",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        try:
            chain = await self.fetch_address_data(address)
        except Exception as exc:
            return ModuleResult(
                target=target, module=self.MODULE_NAME,
                data={"address": address,
                      "format": self.address_format(address),
                      "error": f"chain data unavailable: {exc}"},
                status="partial", started_at=started,
                completed_at=datetime.now().isoformat(),
            )
        stats = (chain.get("info") or {}).get("chain_stats", {})
        data: dict[str, Any] = {
            "address": address,
            "format": self.address_format(address),
            "funded_txo_sum": stats.get("funded_txo_sum"),
            "spent_txo_sum": stats.get("spent_txo_sum"),
            "tx_count": stats.get("tx_count"),
            "balance_sats": (stats.get("funded_txo_sum", 0)
                              - stats.get("spent_txo_sum", 0)),
            "clustering": self.cluster_inputs(chain.get("transactions", [])),
            "txs_analyzed": len(chain.get("transactions", [])),
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
btc_cluster_module = BtcClusterModule
