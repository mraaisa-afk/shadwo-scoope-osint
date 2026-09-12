"""
IP/Network Modules for SHADOWSCOPE
"""

from .asn_lookup import asn_lookup_module
from .bgp_hijack import bgp_hijack_module
from .censys_query import censys_query_module
from .port_knocking import port_knocking_module
from .shodan_scan import shodan_scan_module

# Module registry
MODULES = {
    "shodan_scan": shodan_scan_module,
    "censys_query": censys_query_module,
    "asn_lookup": asn_lookup_module,
    "bgp_hijack": bgp_hijack_module,
    "port_knocking": port_knocking_module,
}

# Export all modules
shodan_scan = shodan_scan_module
censys_query = censys_query_module
asn_lookup = asn_lookup_module
bgp_hijack = bgp_hijack_module
port_knocking = port_knocking_module

__all__ = [
    "shodan_scan", "censys_query", "asn_lookup",
    "bgp_hijack", "port_knocking",
    "MODULES"
]
