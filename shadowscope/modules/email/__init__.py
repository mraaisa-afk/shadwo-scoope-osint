"""
Email OSINT Modules for SHADOWSCOPE
"""

from .alias_hunter import alias_hunter_module
from .breach_lookup import breach_lookup_module
from .disposable_check import disposable_check_module
from .header_forensics import header_forensics_module
from .spf_analyzer import spf_analyzer_module

# Module registry
MODULES = {
    "breach_lookup": breach_lookup_module,
    "spf_analyzer": spf_analyzer_module,
    "header_forensics": header_forensics_module,
    "alias_hunter": alias_hunter_module,
    "disposable_check": disposable_check_module,
}

# Export all modules
breach_lookup = breach_lookup_module
spf_analyzer = spf_analyzer_module
header_forensics = header_forensics_module
alias_hunter = alias_hunter_module
disposable_check = disposable_check_module

__all__ = [
    "breach_lookup", "spf_analyzer", "header_forensics",
    "alias_hunter", "disposable_check",
    "MODULES"
]
