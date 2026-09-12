"""
SHADOWSCOPE Modules Package
Contains all module implementations organized by category
"""

# Import module categories (only categories that exist on disk are
# imported here; extend this list as new categories are implemented).
from .domain import *
from .ip import *
from .email import *
from .social import *
from .dark_web import *
from .phone import *
from .crypto import *
from .geolocation import *

__all__ = [
    # Domain modules
    "dns_brute", "whois_historical", "dnssec_check", "subdomain_takeover", "cert_transparency",

    # IP modules
    "shodan_scan", "censys_query", "asn_lookup", "bgp_hijack", "port_knocking",

    # Email modules
    "breach_lookup", "spf_analyzer", "header_forensics", "alias_hunter", "disposable_check",

    # Social modules
    "username_sherlock", "profile_scraper", "friend_mapper", "deleted_content_recovery",

    # Dark Web modules
    "onion_resolver", "i2p_crawler", "marketplace_scraper", "pgp_fingerprint", "crypto_tracer",

    # Phone OSINT modules
    "carrier_lookup", "sim_swap_check", "voip_tracer", "sms_phishing_db",

    # Crypto Tracking modules
    "btc_cluster", "eth_tracer", "exchange_linker", "darknet_ties",

    # Geolocation modules
    "ip_geolocate", "gps_tracker", "wifi_mapping", "cell_tower_lookup",
]
