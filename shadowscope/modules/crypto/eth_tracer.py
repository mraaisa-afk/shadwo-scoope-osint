"""
Ethereum Tracer Module for SHADOWSCOPE

Validates Ethereum addresses (EIP-55 checksum via pure-Python
Keccak-256), reads live balance/nonce over a public JSON-RPC endpoint
(no key needed), and optionally pulls transaction history from an
Etherscan-compatible API when a key is configured.
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


def keccak_256(data: bytes) -> bytes:
    """Pure-Python Keccak-256 (as used by Ethereum, not NIST SHA3)."""
    # --- Keccak-f[1600] permutation ----------------------------------
    rot = [
        [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
    ]
    rcs = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    mask = 0xFFFFFFFFFFFFFFFF

    def rotl(value: int, shift: int) -> int:
        shift %= 64
        return ((value << shift) | (value >> (64 - shift))) & mask if shift \
            else value & mask

    def keccak_f(state: list[int]) -> None:
        for rnd in range(24):
            # Theta
            cols = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
                    ^ state[x + 20] for x in range(5)]
            for x in range(5):
                temp = cols[(x + 4) % 5] ^ rotl(cols[(x + 1) % 5], 1)
                for y in range(5):
                    state[x + 5 * y] ^= temp
            # Rho + Pi
            nxt = [0] * 25
            for x in range(5):
                for y in range(5):
                    nxt[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(
                        state[x + 5 * y], rot[x][y])
            # Chi
            for y in range(5):
                row = [nxt[5 * y + x] for x in range(5)]
                for x in range(5):
                    state[5 * y + x] = row[x] ^ ((~row[(x + 1) % 5]) & mask
                                                     & row[(x + 2) % 5])
            # Iota
            state[0] ^= rcs[rnd]

    # --- Sponge (rate 1088, suffix 0x01) ------------------------------
    block_size = 136
    state = [0] * 25
    offset = 0
    while offset < len(data):
        block = data[offset:offset + block_size]
        for i in range(0, len(block), 8):
            word = int.from_bytes(block[i:i + 8].ljust(8, b"\x00"),
                                  "little")
            state[i // 8] ^= word
        offset += block_size
        if len(block) == block_size:
            keccak_f(state)
    # Padding (pad10*1 with domain suffix 0x01)
    pad_index = len(data) % block_size
    pad = bytearray(block_size)
    pad[pad_index] = 0x01
    pad[-1] |= 0x80
    if pad_index == block_size - 1:
        pad[pad_index] |= 0x80
    for i in range(0, block_size, 8):
        state[i // 8] ^= int.from_bytes(bytes(pad[i:i + 8]), "little")
    keccak_f(state)
    return b"".join(w.to_bytes(8, "little") for w in state)[:32]


def eip55_checksum(address: str) -> str:
    """Return the EIP-55 checksummed rendering of an address."""
    body = address.lower().replace("0x", "")
    digest = keccak_256(body.encode("ascii")).hex()
    out = ["0x"]
    for i, char in enumerate(body):
        if char in "abcdef" and int(digest[i], 16) >= 8:
            out.append(char.upper())
        else:
            out.append(char)
    return "".join(out)


def eth_address_valid(address: str) -> bool:
    """Validate format and, when mixed-case, the EIP-55 checksum."""
    if not re.match(r"^0x[0-9a-fA-F]{40}$", address or ""):
        return False
    body = address[2:]
    if body == body.lower() or body == body.upper():
        return True  # non-checksummed form
    try:
        return eip55_checksum(address) == address
    except Exception:
        return False


@dataclass
class EthTracerConfig(ModuleConfig):
    """Configuration for Ethereum tracing."""

    rpc_url: str = "https://cloudflare-eth.com"
    etherscan_url: str = "https://api.etherscan.io/api"
    etherscan_key: str = ""
    max_txs: int = 50
    request_timeout: int = 20


class EthTracerModule(BaseModule):
    """Trace Ethereum address activity and funds."""

    MODULE_NAME = "eth_tracer"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Crypto Tracking"
    MODULE_DESCRIPTION = "Ethereum address tracing and fund analysis"
    MODULE_TARGET_TYPES = [TargetType.ETHEREUM, TargetType.CRYPTO]

    def __init__(self, config: EthTracerConfig | None = None):
        super().__init__(config or EthTracerConfig())

    def validate_target(self, target: str) -> bool:
        return eth_address_valid((target or "").strip())

    async def rpc_call(self, session: aiohttp.ClientSession, method: str,
                       params: list[Any]) -> Any:
        async with session.post(
            self.config.rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": method,
                  "params": params},
        ) as response:
            response.raise_for_status()
            payload = await response.json()
            if "error" in payload:
                raise RuntimeError(str(payload["error"]))
            return payload.get("result")

    async def fetch_onchain(self, address: str) -> dict[str, Any]:
        """Fetch balance + nonce from public RPC."""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            balance_hex = await self.rpc_call(
                session, "eth_getBalance", [address, "latest"])
            nonce_hex = await self.rpc_call(
                session, "eth_getTransactionCount", [address, "latest"])
            code = await self.rpc_call(
                session, "eth_getCode", [address, "latest"])
        balance_wei = int(balance_hex, 16)
        return {
            "balance_wei": str(balance_wei),
            "balance_eth": balance_wei / 10 ** 18,
            "nonce": int(nonce_hex, 16),
            "is_contract": code not in (None, "0x", "0x0"),
        }

    async def fetch_history(self, address: str) -> dict[str, Any]:
        """Fetch tx history from Etherscan when a key is configured."""
        if not self.config.etherscan_key:
            return {"queried": False,
                    "reason": "no Etherscan API key configured"}
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        params = {"module": "account", "action": "txlist",
                  "address": address, "sort": "desc",
                  "apikey": self.config.etherscan_key}
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.config.etherscan_url,
                                       params=params) as response:
                    payload = await response.json()
        except Exception as exc:
            return {"queried": True, "error": str(exc)}
        results = payload.get("result", []) or []
        if isinstance(results, str):
            return {"queried": True, "error": results}
        trimmed = results[:self.config.max_txs]
        total_in = sum(int(t.get("value", 0))
                       for t in trimmed
                       if str(t.get("to", "")).lower() == address.lower())
        total_out = sum(int(t.get("value", 0))
                        for t in trimmed
                        if str(t.get("from", "")).lower() == address.lower())
        counterparties = sorted({
            (t.get("to") if str(t.get("from", "")).lower() == address.lower()
             else t.get("from")) or ""
            for t in trimmed
        } - {address, ""})
        return {"queried": True, "tx_count": len(results),
                "txs_analyzed": len(trimmed),
                "total_in_wei": str(total_in),
                "total_out_wei": str(total_out),
                "counterparties": counterparties[:25],
                "sample": trimmed[:5]}

    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ModuleResult:
        """Execute tracing on an Ethereum address."""
        del options
        started = datetime.now().isoformat()
        address = (target or "").strip()
        if not self.validate_target(address):
            return ModuleResult(
                target=target, module=self.MODULE_NAME, data={},
                status="failed", error="Invalid Ethereum address",
                started_at=started, completed_at=datetime.now().isoformat(),
            )
        try:
            checksummed = eip55_checksum(address)
        except Exception:
            checksummed = address.lower()
        try:
            onchain = await self.fetch_onchain(checksummed)
        except Exception as exc:
            return ModuleResult(
                target=target, module=self.MODULE_NAME,
                data={"address": checksummed,
                      "error": f"chain data unavailable: {exc}"},
                status="partial", started_at=started,
                completed_at=datetime.now().isoformat(),
            )
        data: dict[str, Any] = {
            "address": checksummed,
            "onchain": onchain,
            "history": await self.fetch_history(checksummed),
        }
        return ModuleResult(
            target=target, module=self.MODULE_NAME, data=data,
            status="success", started_at=started,
            completed_at=datetime.now().isoformat(),
        )


# Module instance
eth_tracer_module = EthTracerModule
