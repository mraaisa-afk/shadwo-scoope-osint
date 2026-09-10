"""
SHADOWSCOPE Assets Package
Contains wordlists, templates, and other static assets
"""

# Wordlists
from .wordlists import (
    DNS_WORDLIST,
    SUBDOMAIN_WORDLIST,
    USERNAME_WORDLIST,
    PASSWORD_WORDLIST,
    COMMON_PORTS,
    USER_AGENTS
)

__all__ = [
    "DNS_WORDLIST",
    "SUBDOMAIN_WORDLIST", 
    "USERNAME_WORDLIST",
    "PASSWORD_WORDLIST",
    "COMMON_PORTS",
    "USER_AGENTS"
]
