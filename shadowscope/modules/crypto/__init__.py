"""
Crypto Tracking Modules for SHADOWSCOPE
"""

from .btc_cluster import btc_cluster_module
from .darknet_ties import darknet_ties_module
from .eth_tracer import eth_tracer_module
from .exchange_linker import exchange_linker_module

# Module registry
MODULES = {
    "btc_cluster": btc_cluster_module,
    "eth_tracer": eth_tracer_module,
    "exchange_linker": exchange_linker_module,
    "darknet_ties": darknet_ties_module,
}

# Export all modules
btc_cluster = btc_cluster_module
eth_tracer = eth_tracer_module
exchange_linker = exchange_linker_module
darknet_ties = darknet_ties_module

__all__ = [
    "btc_cluster", "eth_tracer", "exchange_linker",
    "darknet_ties",
    "MODULES"
]
