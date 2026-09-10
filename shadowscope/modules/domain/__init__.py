"""
Domain Recon Modules for SHADOWSCOPE
"""

from .dns_brute import dns_brute_module
from .whois_historical import whois_historical_module
from .dnssec_check import dnssec_check_module
from .subdomain_takeover import subdomain_takeover_module
from .cert_transparency import cert_transparency_module

# Module registry
MODULES = {
    "dns_brute": dns_brute_module,
    "whois_historical": whois_historical_module,
    "dnssec_check": dnssec_check_module,
    "subdomain_takeover": subdomain_takeover_module,
    "cert_transparency": cert_transparency_module,
}

# Export all modules
dns_brute = dns_brute_module
whois_historical = whois_historical_module
dnssec_check = dnssec_check_module
subdomain_takeover = subdomain_takeover_module
cert_transparency = cert_transparency_module

__all__ = [
    "dns_brute", "whois_historical", "dnssec_check", 
    "subdomain_takeover", "cert_transparency",
    "MODULES"
]
