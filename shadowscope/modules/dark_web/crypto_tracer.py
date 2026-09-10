"""
Crypto Tracer Module for SHADOWSCOPE
Traces cryptocurrency addresses and transactions across blockchains.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import re
import json

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class CryptoTracerConfig(ModuleConfig):
    """Configuration for crypto tracer module"""
    blockchain_explorers: Dict[str, str] = field(default_factory=lambda: {
        "bitcoin": "https://blockstream.info/api",
        "ethereum": "https://api.etherscan.io/api",
        "monero": "https://monero-blockchain-explorer.com/api",
        "litecoin": "https://blockstream.info/litecoin/api",
        "dash": "https://blockexplorer.com/api",
        "zcash": "https://explorer.zcha.in/api"
    })
    api_keys: Dict[str, str] = field(default_factory=dict)
    timeout: float = 120.0
    max_transactions: int = 100
    max_depth: int = 5
    trace_exchanges: bool = True
    trace_mixers: bool = True
    check_darknet_ties: bool = True
    
    def __post_init__(self):
        pass


@dataclass
class TransactionInfo:
    """Information about a cryptocurrency transaction"""
    tx_id: str
    blockchain: str
    from_address: str
    to_address: str
    amount: float
    currency: str
    timestamp: Optional[str] = None
    fee: Optional[float] = None
    confirmation_count: int = 0
    status: str = "confirmed"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "blockchain": self.blockchain,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "amount": self.amount,
            "currency": self.currency,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "confirmation_count": self.confirmation_count,
            "status": self.status
        }


@dataclass
class AddressInfo:
    """Information about a cryptocurrency address"""
    address: str
    blockchain: str
    balance: float = 0.0
    total_received: float = 0.0
    total_sent: float = 0.0
    transaction_count: int = 0
    first_transaction: Optional[str] = None
    last_transaction: Optional[str] = None
    is_mixer: bool = False
    is_exchange: bool = False
    is_darknet_related: bool = False
    labels: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "blockchain": self.blockchain,
            "balance": self.balance,
            "total_received": self.total_received,
            "total_sent": self.total_sent,
            "transaction_count": self.transaction_count,
            "first_transaction": self.first_transaction,
            "last_transaction": self.last_transaction,
            "is_mixer": self.is_mixer,
            "is_exchange": self.is_exchange,
            "is_darknet_related": self.is_darknet_related,
            "labels": self.labels
        }


@dataclass
class ClusterInfo:
    """Information about address clustering"""
    cluster_id: str
    addresses: List[str] = field(default_factory=list)
    total_balance: float = 0.0
    total_transactions: int = 0
    is_exchange: bool = False
    exchange_name: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "addresses": self.addresses,
            "total_balance": self.total_balance,
            "total_transactions": self.total_transactions,
            "is_exchange": self.is_exchange,
            "exchange_name": self.exchange_name
        }


@dataclass
class ExchangeInfo:
    """Information about exchange linkage"""
    exchange_name: str
    deposit_address: str
    withdrawal_address: str
    first_deposit: Optional[str] = None
    last_deposit: Optional[str] = None
    total_deposited: float = 0.0
    total_withdrawn: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "exchange_name": self.exchange_name,
            "deposit_address": self.deposit_address,
            "withdrawal_address": self.withdrawal_address,
            "first_deposit": self.first_deposit,
            "last_deposit": self.last_deposit,
            "total_deposited": self.total_deposited,
            "total_withdrawn": self.total_withdrawn
        }


class CryptoTracerModule(BaseModule):
    """
    Crypto Tracer Module
    
    Traces cryptocurrency addresses and transactions across blockchains.
    Supports Bitcoin, Ethereum, Monero, and other major cryptocurrencies.
    """
    
    MODULE_NAME = "crypto_tracer"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Dark Web"
    MODULE_DESCRIPTION = "Cryptocurrency address tracing and transaction analysis"
    MODULE_TARGET_TYPES = [TargetType.CRYPTO, TargetType.ONION, TargetType.URL]
    
    DEFAULT_CONFIG = CryptoTracerConfig
    
    # Known mixer addresses (placeholder - should be loaded from database)
    KNOWN_MIXERS = {
        "bitcoin": [
            "123...abc",  # Placeholder mixer addresses
            "456...def",
        ],
        "ethereum": [
            "0x123...abc",
            "0x456...def",
        ]
    }
    
    # Known exchange addresses (placeholder)
    KNOWN_EXCHANGES = {
        "bitcoin": {
            "Coinbase": ["1...", "3..."],
            "Binance": ["1...", "3..."],
            "Kraken": ["1...", "3..."],
        },
        "ethereum": {
            "Coinbase": ["0x...", "0x..."],
            "Binance": ["0x...", "0x..."],
        }
    }
    
    # Known darknet market addresses (placeholder)
    KNOWN_DARKNET = {
        "bitcoin": [
            "1...",
            "3...",
        ],
        "monero": [
            "4...",
        ]
    }
    
    def __init__(self, config: Optional[CryptoTracerConfig] = None):
        super().__init__(config or CryptoTracerConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_addresses: set = set()
    
    async def initialize(self) -> None:
        """Initialize the module"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def cleanup(self) -> None:
        """Clean up resources"""
        if self.session:
            await self.session.close()
        self.visited_addresses.clear()
    
    def _detect_blockchain(self, address: str) -> str:
        """Detect blockchain type from address format"""
        address = address.strip()
        
        # Bitcoin (P2PKH: 1..., P2SH: 3..., Bech32: bc1...)
        if re.match(r'^[13][a-km-zA-KM-Z2-7]{25,34}$', address):
            return "bitcoin"
        if re.match(r'^bc1[a-z0-9]{39,59}$', address):
            return "bitcoin"
        
        # Ethereum
        if re.match(r'^0x[a-fA-F0-9]{40}$', address):
            return "ethereum"
        
        # Monero
        if re.match(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', address):
            return "monero"
        
        # Litecoin
        if re.match(r'^[LM3][a-km-zA-KM-Z2-7]{26,33}$', address):
            return "litecoin"
        
        # Dash
        if re.match(r'^X[1-9A-HJ-NP-Za-km-z]{33}$', address):
            return "dash"
        
        # Zcash
        if re.match(r'^t1[ac-hj-np-zAC-HJ-NP-Z1-9]{33,34}$', address):
            return "zcash"
        if re.match(r'^t3[ac-hj-np-zAC-HJ-NP-Z1-9]{33,34}$', address):
            return "zcash"
        
        return "unknown"
    
    async def _fetch_address_info(self, address: str, blockchain: str) -> Optional[AddressInfo]:
        """Fetch address information from blockchain explorer API"""
        try:
            base_url = self.config.blockchain_explorers.get(blockchain, "")
            if not base_url:
                console.print(f"[yellow]No explorer configured for blockchain: {blockchain}[/yellow]")
                return None
            
            # Try different API endpoints based on blockchain
            if blockchain == "bitcoin":
                # Blockstream API
                url = f"{base_url}/address/{address}"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        info = AddressInfo(
                            address=address,
                            blockchain=blockchain,
                            balance=data.get("chain_stats", {}).get("funded_txo_sum", 0) / 100000000,
                            total_received=data.get("chain_stats", {}).get("funded_txo_sum", 0) / 100000000,
                            total_sent=data.get("chain_stats", {}).get("spent_txo_sum", 0) / 100000000,
                            transaction_count=data.get("chain_stats", {}).get("tx_count", 0),
                            first_transaction=data.get("address", {}).get("first_seen", None),
                            last_transaction=data.get("address", {}).get("last_seen", None)
                        )
                        return info
            
            elif blockchain == "ethereum":
                # Etherscan API
                api_key = self.config.api_keys.get("etherscan", "")
                url = f"{base_url}?module=account&action=balance&address={address}&tag=latest"
                if api_key:
                    url += f"&apikey={api_key}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "1":
                            balance_wei = int(data.get("result", "0"))
                            balance_eth = balance_wei / 1000000000000000000
                            
                            # Get transaction count
                            tx_url = f"{base_url}?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest"
                            if api_key:
                                tx_url += f"&apikey={api_key}"
                            
                            async with self.session.get(tx_url) as tx_response:
                                if tx_response.status == 200:
                                    tx_data = await tx_response.json()
                                    tx_count = int(tx_data.get("result", "0x0"), 16)
                            
                            info = AddressInfo(
                                address=address,
                                blockchain=blockchain,
                                balance=balance_eth,
                                transaction_count=tx_count
                            )
                            return info
            
            elif blockchain == "monero":
                # Monero explorer
                url = f"{base_url}/address/{address}"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        info = AddressInfo(
                            address=address,
                            blockchain=blockchain,
                            balance=data.get("balance", 0) / 1000000000000,
                            total_received=data.get("total_received", 0) / 1000000000000,
                            total_sent=data.get("total_sent", 0) / 1000000000000,
                            transaction_count=data.get("tx_count", 0)
                        )
                        return info
            
            console.print(f"[yellow]Unsupported blockchain or API format: {blockchain}[/yellow]")
            return None
            
        except aiohttp.ClientError as e:
            console.print(f"[red]Error fetching address info: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            return None
    
    async def _fetch_transactions(self, address: str, blockchain: str, limit: int = 50) -> List[TransactionInfo]:
        """Fetch recent transactions for an address"""
        transactions = []
        try:
            base_url = self.config.blockchain_explorers.get(blockchain, "")
            if not base_url:
                return transactions
            
            if blockchain == "bitcoin":
                url = f"{base_url}/address/{address}/txs"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for tx in data[:limit]:
                            # Parse Bitcoin transaction
                            inputs = tx.get("vin", [])
                            outputs = tx.get("vout", [])
                            
                            for inp in inputs:
                                input_addr = inp.get("prevout", {}).get("scriptpubkey_address", "")
                                for out in outputs:
                                    output_addr = out.get("scriptpubkey_address", "")
                                    amount = out.get("value", 0) / 100000000
                                    
                                    transactions.append(TransactionInfo(
                                        tx_id=tx.get("txid", ""),
                                        blockchain=blockchain,
                                        from_address=input_addr,
                                        to_address=output_addr,
                                        amount=amount,
                                        currency="BTC",
                                        timestamp=tx.get("status", {}).get("block_time", None),
                                        fee=tx.get("fee", 0) / 100000000,
                                        confirmation_count=tx.get("status", {}).get("confirmations", 0)
                                    ))
            
            elif blockchain == "ethereum":
                api_key = self.config.api_keys.get("etherscan", "")
                url = f"{base_url}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={api_key}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "1":
                            for tx in data.get("result", [])[:limit]:
                                transactions.append(TransactionInfo(
                                    tx_id=tx.get("hash", ""),
                                    blockchain=blockchain,
                                    from_address=tx.get("from", ""),
                                    to_address=tx.get("to", ""),
                                    amount=int(tx.get("value", "0")) / 1000000000000000000,
                                    currency="ETH",
                                    timestamp=datetime.fromtimestamp(int(tx.get("timeStamp", "0"))).isoformat(),
                                    fee=int(tx.get("txfee", "0")) / 1000000000000000000,
                                    confirmation_count=int(tx.get("confirmations", "0"))
                                ))
            
        except Exception as e:
            console.print(f"[red]Error fetching transactions: {e}[/red]")
        
        return transactions
    
    def _check_mixer(self, address: str, blockchain: str) -> bool:
        """Check if address is a known mixer"""
        mixers = self.KNOWN_MIXERS.get(blockchain, [])
        return address in mixers
    
    def _check_exchange(self, address: str, blockchain: str) -> Optional[str]:
        """Check if address belongs to a known exchange"""
        exchanges = self.KNOWN_EXCHANGES.get(blockchain, {})
        for exchange_name, addresses in exchanges.items():
            if address in addresses:
                return exchange_name
        return None
    
    def _check_darknet(self, address: str, blockchain: str) -> bool:
        """Check if address is known to be associated with darknet markets"""
        darknet = self.KNOWN_DARKNET.get(blockchain, [])
        return address in darknet
    
    async def _trace_address(self, address: str, depth: int = 0) -> Dict[str, Any]:
        """Trace a cryptocurrency address and its transactions"""
        if depth > self.config.max_depth or address in self.visited_addresses:
            return {}
        
        self.visited_addresses.add(address)
        blockchain = self._detect_blockchain(address)
        
        if blockchain == "unknown":
            return {}
        
        results = {}
        
        # Get address info
        address_info = await self._fetch_address_info(address, blockchain)
        if address_info:
            results["address"] = address_info.to_dict()
            
            # Check for mixer/exchange/darknet associations
            address_info.is_mixer = self._check_mixer(address, blockchain)
            exchange_name = self._check_exchange(address, blockchain)
            if exchange_name:
                address_info.is_exchange = True
                address_info.labels.append(exchange_name)
            address_info.is_darknet_related = self._check_darknet(address, blockchain)
            
            # Get transactions
            if self.config.max_transactions > 0:
                transactions = await self._fetch_transactions(address, blockchain, self.config.max_transactions)
                results["transactions"] = [t.to_dict() for t in transactions]
                
                # Trace connected addresses
                if depth < self.config.max_depth:
                    connected_addresses = set()
                    for tx in transactions:
                        if tx.from_address and tx.from_address != address:
                            connected_addresses.add(tx.from_address)
                        if tx.to_address and tx.to_address != address:
                            connected_addresses.add(tx.to_address)
                    
                    traced_connections = []
                    for connected_addr in list(connected_addresses)[:10]:
                        if connected_addr not in self.visited_addresses:
                            connection_result = await self._trace_address(connected_addr, depth + 1)
                            if connection_result:
                                traced_connections.append({
                                    "address": connected_addr,
                                    "data": connection_result
                                })
                    
                    if traced_connections:
                        results["connections"] = traced_connections
        
        return results
    
    async def _extract_crypto_addresses(self, text: str) -> List[str]:
        """Extract cryptocurrency addresses from text"""
        addresses = []
        
        # Bitcoin addresses
        btc_pattern = r'\b([13][a-km-zA-KM-Z2-7]{25,34}|bc1[a-z0-9]{39,59})\b'
        addresses.extend(re.findall(btc_pattern, text))
        
        # Ethereum addresses
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        addresses.extend(re.findall(eth_pattern, text))
        
        # Monero addresses
        xmr_pattern = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        addresses.extend(re.findall(xmr_pattern, text))
        
        # Litecoin addresses
        ltc_pattern = r'\b[LM3][a-km-zA-KM-Z2-7]{26,33}\b'
        addresses.extend(re.findall(ltc_pattern, text))
        
        # Dash addresses
        dash_pattern = r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b'
        addresses.extend(re.findall(dash_pattern, text))
        
        return list(set(addresses))
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the crypto tracer module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )
        
        try:
            options = options or {}
            depth = options.get('depth', 0)
            
            console.print(f"[blue]Tracing cryptocurrency target: {target}[/blue]")
            
            # Check if target is a cryptocurrency address
            blockchain = self._detect_blockchain(target)
            
            if blockchain != "unknown":
                trace_result = await self._trace_address(target, depth)
                
                if trace_result:
                    result.status = "success"
                    result.data = trace_result
                    address_info = trace_result.get("address", {})
                    result.summary = f"Traced {blockchain} address: balance={address_info.get('balance', 0)}, tx_count={address_info.get('transaction_count', 0)}"
                else:
                    result.status = "partial"
                    result.error = f"Could not trace address: {target}"
            else:
                # Try to extract addresses from text (e.g., onion page content)
                addresses = await self._extract_crypto_addresses(target)
                if addresses:
                    traced_addresses = []
                    for addr in addresses[:5]:  # Limit to 5 addresses
                        trace_result = await self._trace_address(addr, depth)
                        if trace_result:
                            traced_addresses.append({
                                "address": addr,
                                "data": trace_result
                            })
                    
                    if traced_addresses:
                        result.status = "success"
                        result.data = {
                            "extracted_addresses": addresses,
                            "traced_addresses": traced_addresses
                        }
                        result.summary = f"Found and traced {len(addresses)} cryptocurrency addresses"
                    else:
                        result.status = "partial"
                        result.error = f"Extracted {len(addresses)} addresses but could not trace any"
                else:
                    result.status = "failed"
                    result.error = f"No cryptocurrency address detected in target: {target}"
                    
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            console.print(f"[red]Error tracing cryptocurrency: {e}[/red]")
        
        result.end_time = datetime.utcnow()
        return result
    
    async def execute_batch(self, targets: List[str], options: Optional[Dict[str, Any]] = None) -> List[ModuleResult]:
        """Execute on multiple targets"""
        results = []
        for target in targets:
            result = await self.execute(target, options)
            results.append(result)
            self.visited_addresses.clear()  # Reset for each batch item
        return results


# Module instance
crypto_tracer_module = CryptoTracerModule()
