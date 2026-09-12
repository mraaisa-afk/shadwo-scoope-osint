"""
Transaction Tracer Module for SHADOWSCOPE
Traces financial transaction IDs, wire transfer logs, payment gateway receipts, and currency flow patterns.
"""

import re
from dataclasses import dataclass
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

TRANSACTION_PATTERNS = [
    {"type": "Stripe Charge / Payment Intent", "pattern": r"^ch_[a-zA-Z0-9]{24}$|^pi_[a-zA-Z0-9]{24}$"},
    {"type": "PayPal Transaction ID", "pattern": r"^[0-9A-Z]{17}$"},
    {"type": "Square Payment ID", "pattern": r"^[a-zA-Z0-9]{24}$"},
    {"type": "Fedwire / Wire Reference", "pattern": r"^\d{4}[0-9A-Z]{12}$"},
    {"type": "Crypto TxHash (EVM / BTC)", "pattern": r"^0x[a-fA-F0-9]{64}$|^[a-fA-F0-9]{64}$"},
]


@dataclass
class TransactionTracerConfig(ModuleConfig):
    """Configuration for Transaction Tracer module."""
    analyze_network_flow: bool = True


class TransactionTracerModule(BaseModule):
    """Module for identifying, parsing, and tracing payment transaction identifiers and wire transfer receipts."""

    MODULE_NAME = "transaction_tracer"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "financial"
    MODULE_DESCRIPTION = "Identify payment gateway IDs (Stripe, PayPal, Square), wire reference numbers, and transaction logs"
    MODULE_TARGET_TYPES = [TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: TransactionTracerConfig | None = None) -> None:
        super().__init__(config=config or TransactionTracerConfig())
        self.config: TransactionTracerConfig = self.config if isinstance(self.config, TransactionTracerConfig) else TransactionTracerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate transaction string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute transaction pattern classification and analysis."""
        tx_id = target.strip()
        if not self.validate_target(tx_id):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid transaction ID string"
            )

        detected_types: list[str] = []
        for pat in TRANSACTION_PATTERNS:
            if re.match(pat["pattern"], tx_id):
                detected_types.append(pat["type"])

        if not detected_types:
            detected_types.append("Generic Payment / Wire Transaction Reference")

        return ModuleResult(
            target=target,
            module=self.MODULE_NAME,
            data={
                "transaction_id": tx_id,
                "length": len(tx_id),
                "detected_types": detected_types,
                "primary_type": detected_types[0],
                "summary": f"Transaction Tracer: Identified '{tx_id}' as {detected_types[0]}"
            },
            status="success"
        )


transaction_tracer_module = TransactionTracerModule
