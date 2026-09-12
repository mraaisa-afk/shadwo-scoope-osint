"""
Phone OSINT Modules for SHADOWSCOPE
"""

from .carrier_lookup import carrier_lookup_module
from .sim_swap_check import sim_swap_check_module
from .sms_phishing_db import sms_phishing_db_module
from .voip_tracer import voip_tracer_module

# Module registry
MODULES = {
    "carrier_lookup": carrier_lookup_module,
    "sim_swap_check": sim_swap_check_module,
    "voip_tracer": voip_tracer_module,
    "sms_phishing_db": sms_phishing_db_module,
}

# Export all modules
carrier_lookup = carrier_lookup_module
sim_swap_check = sim_swap_check_module
voip_tracer = voip_tracer_module
sms_phishing_db = sms_phishing_db_module

__all__ = [
    "carrier_lookup", "sim_swap_check", "voip_tracer",
    "sms_phishing_db",
    "MODULES"
]
