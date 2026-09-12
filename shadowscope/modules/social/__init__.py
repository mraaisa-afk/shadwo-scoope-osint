"""
Social OSINT Modules for SHADOWSCOPE
"""

from .deleted_content_recovery import deleted_content_recovery_module
from .friend_mapper import friend_mapper_module
from .profile_scraper import profile_scraper_module
from .username_sherlock import username_sherlock_module

# Module registry
MODULES = {
    "username_sherlock": username_sherlock_module,
    "profile_scraper": profile_scraper_module,
    "friend_mapper": friend_mapper_module,
    "deleted_content_recovery": deleted_content_recovery_module,
}

# Export all modules
username_sherlock = username_sherlock_module
profile_scraper = profile_scraper_module
friend_mapper = friend_mapper_module
deleted_content_recovery = deleted_content_recovery_module

__all__ = [
    "username_sherlock", "profile_scraper", "friend_mapper",
    "deleted_content_recovery",
    "MODULES"
]
