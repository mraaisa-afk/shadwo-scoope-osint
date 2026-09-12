"""
SHADOWSCOPE Modules Package
Contains all module implementations organized by category
"""

from .crypto import (
    btc_cluster,
    darknet_ties,
    eth_tracer,
    exchange_linker,
)
from .dark_web import (
    crypto_tracer,
    i2p_crawler,
    marketplace_scraper,
    onion_resolver,
    pgp_fingerprint,
)
from .domain import (
    cert_transparency,
    dns_brute,
    dnssec_check,
    subdomain_takeover,
    whois_historical,
)
from .email import (
    alias_hunter,
    breach_lookup,
    disposable_check,
    header_forensics,
    spf_analyzer,
)
from .file import (
    exif_extractor,
    office_macro_analysis,
    pdf_metadata,
    steg_detect,
)
from .geolocation import (
    cell_tower_lookup,
    gps_tracker,
    ip_geolocate,
    wifi_mapping,
)
from .ip import (
    asn_lookup,
    bgp_hijack,
    censys_query,
    port_knocking,
    shodan_scan,
)
from .phone import (
    carrier_lookup,
    sim_swap_check,
    sms_phishing_db,
    voip_tracer,
)
from .social import (
    deleted_content_recovery,
    friend_mapper,
    profile_scraper,
    username_sherlock,
)

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

    # File OSINT modules
    "exif_extractor", "pdf_metadata", "steg_detect", "office_macro_analysis",
]
