"""
SHADOWSCOPE Core Framework
A modular, extensible OSINT framework for deep reconnaissance and data correlation.
"""

__version__ = "1.0.0"
__author__ = "SHADOWSCOPE Team"
__license__ = "GPL-3.0"

from .config import Config
from .storage import Storage
from .targets import TargetManager
from .modules import ModuleManager
from .sandbox import SandboxManager
from .proxy import ProxyManager
from .cache import CacheManager

# Initialize core components
config = Config()
storage = Storage()
targets = TargetManager()
modules = ModuleManager()
sandbox = SandboxManager()
proxy = ProxyManager()
cache = CacheManager()

__all__ = [
    "config",
    "storage", 
    "targets",
    "modules",
    "sandbox",
    "proxy",
    "cache",
    "__version__",
    "__author__",
    "__license__"
]
