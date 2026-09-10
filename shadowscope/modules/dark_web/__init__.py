"""
Dark Web Modules for SHADOWSCOPE
"""

from .onion_resolver import onion_resolver_module
from .i2p_crawler import i2p_crawler_module
from .marketplace_scraper import marketplace_scraper_module
from .pgp_fingerprint import pgp_fingerprint_module
from .crypto_tracer import crypto_tracer_module

# Module registry
MODULES = {
    "onion_resolver": onion_resolver_module,
    "i2p_crawler": i2p_crawler_module,
    "marketplace_scraper": marketplace_scraper_module,
    "pgp_fingerprint": pgp_fingerprint_module,
    "crypto_tracer": crypto_tracer_module,
}

# Export all modules
onion_resolver = onion_resolver_module
i2p_crawler = i2p_crawler_module
marketplace_scraper = marketplace_scraper_module
pgp_fingerprint = pgp_fingerprint_module
crypto_tracer = crypto_tracer_module

__all__ = [
    "onion_resolver", "i2p_crawler", "marketplace_scraper",
    "pgp_fingerprint", "crypto_tracer",
    "MODULES"
]
