"""
Geolocation Modules for SHADOWSCOPE
"""

from .cell_tower_lookup import cell_tower_lookup_module
from .gps_tracker import gps_tracker_module
from .ip_geolocate import ip_geolocate_module
from .wifi_mapping import wifi_mapping_module

# Module registry
MODULES = {
    "ip_geolocate": ip_geolocate_module,
    "gps_tracker": gps_tracker_module,
    "wifi_mapping": wifi_mapping_module,
    "cell_tower_lookup": cell_tower_lookup_module,
}

# Export all modules
ip_geolocate = ip_geolocate_module
gps_tracker = gps_tracker_module
wifi_mapping = wifi_mapping_module
cell_tower_lookup = cell_tower_lookup_module

__all__ = [
    "ip_geolocate", "gps_tracker", "wifi_mapping",
    "cell_tower_lookup",
    "MODULES"
]
