"""
Legal & Corporate OSINT Modules for SHADOWSCOPE
Includes Business Registration, Court Records, Trademark Lookup, and Patent Search.
"""

from shadowscope.modules.legal.business_registration import business_registration_module
from shadowscope.modules.legal.court_records import court_records_module
from shadowscope.modules.legal.patent_search import patent_search_module
from shadowscope.modules.legal.trademark_lookup import trademark_lookup_module

__all__ = [
    "business_registration_module",
    "court_records_module",
    "trademark_lookup_module",
    "patent_search_module",
]
