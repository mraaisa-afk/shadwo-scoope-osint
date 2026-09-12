"""
Threat Intelligence OSINT Modules for SHADOWSCOPE
Includes ThreatFox, MISP Lookup, abuse.ch, and FireHOL Threat Feeds.
"""

from shadowscope.modules.threat.abuse_ch import abuse_ch_module
from shadowscope.modules.threat.firehol import firehol_module
from shadowscope.modules.threat.misp_lookup import misp_lookup_module
from shadowscope.modules.threat.threat_fox import threat_fox_module

__all__ = [
    "threat_fox_module",
    "misp_lookup_module",
    "abuse_ch_module",
    "firehol_module",
]
