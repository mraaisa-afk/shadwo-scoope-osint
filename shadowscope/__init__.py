"""
SHADOWSCOPE - A Modular OSINT Framework

A comprehensive, extensible framework for deep reconnaissance, data correlation,
and iterative target expansion. Designed for elite operators who demand stealth,
scalability, and brutality in their investigations.
"""

__version__ = "1.0.0"
__author__ = "SHADOWSCOPE Team"
__license__ = "GPL-3.0"

# Import core components
from .core import (
    config,
    storage,
    targets,
    modules,
    sandbox,
    proxy,
    cache
)

# Import CLI
from .cli import app

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "config",
    "storage",
    "targets",
    "modules",
    "sandbox",
    "proxy",
    "cache",
    "app"
]
