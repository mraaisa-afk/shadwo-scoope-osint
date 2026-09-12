"""
Unit Tests for the SHADOWSCOPE Module System.

Guards the contract every built-in module must honor: importable,
instantiable with zero args, exposing run()/get_metadata(), and
advertising honest JSON-serializable metadata. Fully offline — no
module is executed here.
"""

import importlib
import json
from pathlib import Path

import pytest

from shadowscope.core.modules import (
    BaseModule,
    ModuleConfig,
    ModuleManager,
    ModuleMetadata,
)
from shadowscope.core.targets import TargetType

MODULES_ROOT = Path(__file__).resolve().parents[2] / "modules"

EXPECTED_MODULES = {
    # Pre-existing categories
    "domain": ["dns_brute", "whois_historical", "dnssec_check",
               "subdomain_takeover", "cert_transparency"],
    "ip": ["shodan_scan", "censys_query", "asn_lookup", "bgp_hijack",
           "port_knocking"],
    "email": ["breach_lookup", "spf_analyzer", "header_forensics",
              "alias_hunter", "disposable_check"],
    "social": ["username_sherlock", "profile_scraper", "friend_mapper",
               "deleted_content_recovery"],
    "dark_web": ["onion_resolver", "i2p_crawler", "marketplace_scraper",
                 "pgp_fingerprint", "crypto_tracer"],
    # Batch 1 categories
    "phone": ["carrier_lookup", "sim_swap_check", "voip_tracer",
              "sms_phishing_db"],
    "crypto": ["btc_cluster", "eth_tracer", "exchange_linker",
               "darknet_ties"],
    "geolocation": ["ip_geolocate", "gps_tracker", "wifi_mapping",
                    "cell_tower_lookup"],
    "file": ["exif_extractor", "pdf_metadata", "steg_detect",
             "office_macro_analysis"],
    # Batch 2 categories
    "physical": ["geocoder", "satellite_imagery", "property_records",
                 "neighbor_mapper"],
    "transport": ["flight_tracker", "ship_tracker", "vehicle_vin",
                  "license_plate"],
    # Batch 3 categories
    "iot": ["shodan_iot", "default_creds", "firmware_scanner",
            "mqtt_brute"],
    "threat": ["threat_fox", "misp_lookup", "abuse_ch",
               "firehol"],
}

# Offline validate_target spot checks for modules:
# (category, module, good_target, bad_target)
VALIDATE_CASES = [
    ("phone", "carrier_lookup", "+8801712345678", "not-a-number"),
    ("phone", "sim_swap_check", "+14155552671", "12"),
    ("phone", "voip_tracer", "+442071234567", "xyz"),
    ("phone", "sms_phishing_db", "Your OTP is 1234. Verify now!", "   "),
    ("crypto", "btc_cluster", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
     "not-an-address"),
    ("crypto", "eth_tracer", "0x0000000000000000000000000000000000000000",
     "0xZZZ"),
    ("crypto", "exchange_linker", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
     "???"),
    ("crypto", "darknet_ties", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", ""),
    ("geolocation", "ip_geolocate", "8.8.8.8", "999.1.1.1"),
    ("geolocation", "gps_tracker", "23.8103, 90.4125", "hello world"),
    ("geolocation", "wifi_mapping", "00:1A:11:22:33:44", "not-a-bssid"),
    ("geolocation", "cell_tower_lookup", "470-01-1234-56789", "abc"),
    ("file", "exif_extractor", "sample.jpg", ""),
    ("file", "pdf_metadata", "document.pdf", "   "),
    ("file", "steg_detect", "image.png", ""),
    ("file", "office_macro_analysis", "document.docm", ""),
    ("physical", "geocoder", "23.8103, 90.4125", ""),
    ("physical", "satellite_imagery", "23.8103, 90.4125", ""),
    ("physical", "property_records", "123 Main St, New York, NY", ""),
    ("physical", "neighbor_mapper", "23.8103, 90.4125", ""),
    ("transport", "flight_tracker", "AA123", ""),
    ("transport", "ship_tracker", "9314412", ""),
    ("transport", "vehicle_vin", "1HGCR2F83HA000000", ""),
    ("transport", "license_plate", "1ABC123", ""),
    ("iot", "shodan_iot", "camera", ""),
    ("iot", "default_creds", "cisco", ""),
    ("iot", "firmware_scanner", "firmware.bin", ""),
    ("iot", "mqtt_brute", "127.0.0.1", ""),
    ("threat", "threat_fox", "8.8.8.8", ""),
    ("threat", "misp_lookup", "example.com", ""),
    ("threat", "abuse_ch", "http://example.com/malware.exe", ""),
    ("threat", "firehol", "1.1.1.1", ""),
]


def iter_module_files():
    for category, names in EXPECTED_MODULES.items():
        for name in names:
            yield category, name


def load_module_class(category, name):
    module = importlib.import_module(f"shadowscope.modules.{category}.{name}")
    classes = [obj for obj in vars(module).values()
               if isinstance(obj, type)
               and issubclass(obj, BaseModule) and obj is not BaseModule]
    assert classes, f"{category}.{name} defines no BaseModule subclass"
    return classes[0]


def test_target_type_enum_values():
    assert TargetType.DOMAIN == "domain"
    assert TargetType.PHONE == "phone"
    assert TargetType.BITCOIN == "bitcoin"
    assert TargetType.COORDINATES == "coordinates"
    assert TargetType.BSSID == "bssid"
    assert TargetType.CELL_TOWER == "cell_tower"
    assert TargetType.FILE == "file"
    assert TargetType("phone") is TargetType.PHONE
    assert TargetType("file") is TargetType.FILE


def test_module_config_dict_roundtrip():
    config = ModuleConfig.from_dict({"timeout": 60, "bogus": 1})
    assert config.timeout == 60
    assert not hasattr(config, "bogus")
    assert config.to_dict()["timeout"] == 60


@pytest.mark.parametrize("category,name", list(iter_module_files()))
def test_module_importable_with_metadata(category, name):
    path = MODULES_ROOT / category / f"{name}.py"
    assert path.exists(), f"missing file: {path}"
    cls = load_module_class(category, name)
    # Zero-arg construction (executor requirement)
    instance = cls()
    assert isinstance(instance.config, ModuleConfig)
    # Executor interface
    assert callable(getattr(instance, "run", None))
    assert callable(getattr(cls, "get_metadata", None))
    metadata = cls.get_metadata()
    assert metadata["name"] == name
    assert metadata["category"]
    assert isinstance(metadata["target_types"], list)
    # Must survive JSON + ModuleMetadata round-trips
    ModuleMetadata.from_dict(json.loads(json.dumps(metadata)))


@pytest.mark.parametrize("category,name,good,bad", VALIDATE_CASES)
def test_module_validate_target(category, name, good, bad):
    cls = load_module_class(category, name)
    instance = cls()
    assert instance.validate_target(good) is True
    assert instance.validate_target(bad) is False


def test_discovery_finds_all_builtin_modules():
    manager = ModuleManager()
    found = manager._discover_package_modules()
    expected = sum(len(v) for v in EXPECTED_MODULES.values())
    missing = [n for names in EXPECTED_MODULES.values() for n in names
               if n not in found]
    assert not missing, f"undiscovered modules: {missing}"
    assert len(found) >= expected


def test_loader_resolves_category_module():
    manager = ModuleManager()
    module = manager.loader.load_module_from_package("carrier_lookup")
    assert module is not None
    cls = manager.executor._get_module_class(module)
    assert cls is not None and issubclass(cls, BaseModule)
    assert cls.get_metadata()["name"] == "carrier_lookup"


def test_target_autodetect_new_types():
    from shadowscope.core.targets import Target
    assert Target("470-01-1234-56789").target_type == "cell_tower"
    assert Target("+8801712345678").target_type == "phone"
    assert Target("23.8103, 90.4125").target_type == "coordinates"
    assert Target("00:1A:11:22:33:44").target_type == "bssid"
    assert Target("sample.jpg").target_type == "file"
    assert Target("document.pdf").target_type == "file"
    bc1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert Target(bc1).target_type == "bitcoin"


@pytest.mark.asyncio
async def test_auto_registration_and_no_sandbox():
    manager = ModuleManager()
    # exif_extractor built-in module
    metadata = manager.get_module("exif_extractor")
    assert metadata is not None
    assert metadata.name == "exif_extractor"

    # Verify auto-registration into storage
    stored = manager.storage.get_module("exif_extractor")
    assert stored is not None
    assert stored.name == "exif_extractor"

    # Test executor execution with no_sandbox flag
    res = await manager.executor.execute("exif_extractor", "nonexistent.jpg", no_sandbox=True)
    assert res.status == "failed"
    assert "File not found" in res.error
