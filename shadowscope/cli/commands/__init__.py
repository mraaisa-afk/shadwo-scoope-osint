"""
Command Groups for SHADOWSCOPE CLI
"""

# Core commands (always available)
from . import (
    target_commands,
    module_commands,
    scope_commands,
    config_commands,
    storage_commands
)

# Optional commands (may not be available)
try:
    from . import proxy_commands
except ImportError:
    proxy_commands = None

try:
    from . import sandbox_commands
except ImportError:
    sandbox_commands = None

try:
    from . import tui_commands
except ImportError:
    tui_commands = None

__all__ = [
    "target_commands",
    "module_commands",
    "scope_commands",
    "config_commands",
    "storage_commands"
]

# Add optional commands if available
if proxy_commands:
    __all__.append("proxy_commands")
if sandbox_commands:
    __all__.append("sandbox_commands")
if tui_commands:
    __all__.append("tui_commands")
