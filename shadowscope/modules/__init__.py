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
from .financial import (
    credit_card_bin,
    iban_lookup,
    swift_code,
    transaction_tracer,
)
from .geolocation import (
    cell_tower_lookup,
    gps_tracker,
    ip_geolocate,
    wifi_mapping,
)
from .iot import (
    default_creds,
    firmware_scanner,
    mqtt_brute,
    shodan_iot,
)
from .ip import (
    asn_lookup,
    bgp_hijack,
    censys_query,
    port_knocking,
    shodan_scan,
)
from .legal import (
    business_registration,
    court_records,
    patent_search,
    trademark_lookup,
)
from .malware import (
    hybrid_analysis,
    malware_family_identifier,
    virus_total,
    yara_scan,
)
from .phone import (
    carrier_lookup,
    sim_swap_check,
    sms_phishing_db,
    voip_tracer,
)
from .physical import (
    geocoder,
    neighbor_mapper,
    property_records,
    satellite_imagery,
)
from .social import (
    deleted_content_recovery,
    friend_mapper,
    profile_scraper,
    username_sherlock,
)
from .threat import (
    abuse_ch,
    firehol,
    misp_lookup,
    threat_fox,
)
from .transport import (
    flight_tracker,
    license_plate,
    ship_tracker,
    vehicle_vin,
)
from .url import (
    csp_checker,
    js_analyzer,
    link_crawler,
    param_brute,
    screenshot_capture,
    wayback_scraper,
    web_fingerprint,
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

    # Physical Intelligence modules
    "geocoder", "satellite_imagery", "property_records", "neighbor_mapper",

    # Transport Intelligence modules
    "flight_tracker", "ship_tracker", "vehicle_vin", "license_plate",

    # IoT OSINT modules
    "shodan_iot", "default_creds", "firmware_scanner", "mqtt_brute",

    # Threat Intelligence modules
    "threat_fox", "misp_lookup", "abuse_ch", "firehol",

    # Malware Analysis modules
    "virus_total", "hybrid_analysis", "yara_scan", "malware_family_identifier",

    # Financial Recon modules
    "credit_card_bin", "iban_lookup", "swift_code", "transaction_tracer",

    # Legal & Corporate OSINT modules
    "business_registration", "court_records", "trademark_lookup", "patent_search",

    # URL Reconnaissance modules
    "wayback_scraper", "param_brute", "js_analyzer", "csp_checker", "web_fingerprint", "screenshot_capture", "link_crawler",
]
