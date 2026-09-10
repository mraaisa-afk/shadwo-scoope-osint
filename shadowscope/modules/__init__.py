"""
SHADOWSCOPE Modules Package
Contains all module implementations organized by category
"""

# Import module categories
from .domain import *
from .ip import *
from .email import *
from .social import *
from .darkweb import *
from .file import *
from .phone import *
from .crypto import *
from .physical import *
from .iot import *
from .malware import *
from .threat import *
from .geolocation import *
from .financial import *
from .legal import *
from .transport import *

__all__ = [
    # Domain modules
    "dns_brute", "whois_historical", "dnssec_check", "subdomain_takeover", "cert_transparency",
    
    # IP modules
    "shodan_scan", "censys_query", "asn_lookup", "bgp_hijack", "port_knocking",
    
    # Email modules
    "breach_lookup", "spf_analyzer", "header_forensics", "alias_hunter", "disposable_check",
    
    # Social modules
    "username_sherlock", "profile_scraper", "friend_mapper", "deleted_content_recovery",
    
    # Darkweb modules
    "onion_resolver", "i2p_crawler", "marketplace_scraper", "pgp_fingerprint", "crypto_tracer",
    
    # File modules
    "exif_extractor", "pdf_metadata", "steg_detect", "office_macro_analysis",
    
    # Phone modules
    "carrier_lookup", "sim_swap_check", "voip_tracer", "sms_phishing_db",
    
    # Crypto modules
    "btc_cluster", "eth_tracer", "exchange_linker", "darknet_ties",
    
    # Physical modules
    "geocoder", "satellite_imagery", "property_records", "neighbor_mapper",
    
    # IoT modules
    "shodan_iot", "default_creds", "firmware_scanner", "mqtt_brute",
    
    # Malware modules
    "virus_total", "hybrid_analysis", "yara_scan", "malware_family_identifier",
    
    # Threat modules
    "threat_fox", "misp_lookup", "abuse_ch", "firehol",
    
    # Geolocation modules
    "ip_geolocate", "gps_tracker", "wifi_mapping", "cell_tower_lookup",
    
    # Financial modules
    "credit_card_bin", "iban_lookup", "swift_code", "transaction_tracer",
    
    # Legal modules
    "business_registration", "court_records", "trademark_lookup", "patent_search",
    
    # Transport modules
    "flight_tracker", "ship_tracker", "vehicle_vin", "license_plate",
]
