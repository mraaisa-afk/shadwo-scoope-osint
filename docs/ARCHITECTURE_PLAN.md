# SHADOWSCOPE OSINT Framework - Architecture Plan & Gap Roadmap

## 1. Architecture Overview

SHADOWSCOPE is a modular OSINT (Open Source Intelligence) framework designed for deep reconnaissance and intelligence gathering.

### Core Components
- **Core Runtime (`shadowscope.core`)**:
  - `modules.py`: `BaseModule`, `ModuleConfig`, `ModuleResult`, `ModuleMetadata`, `ModuleLoader`, `ModuleExecutor`, `ModuleManager`
  - `targets.py`: `Target`, `TargetType`, `TargetManager`
  - `storage.py`: SQLite persistence layer, target & result management, module registration (`ModuleInfo`)
  - `config.py`: Global configuration, section management (API, proxy, sandbox, storage, etc.)
  - `sandbox.py`, `proxy.py`, `cache.py`: Core isolation and network services

- **Module Subsystem (`shadowscope.modules`)**:
  - Organized by category subpackages (`shadowscope.modules.<category>.<name>`)
  - Standardized module interface inheriting from `BaseModule`
  - Dataclass configurations inheriting from `ModuleConfig`

- **CLI & TUI (`shadowscope.cli`, `shadowscope.tui`)**:
  - Typer-based CLI interface for managing targets, modules, scope, and storage
  - Textual-based terminal UI

---

## 2. Verified Gap Inventory

### Current State (36 Built-in Modules across 8 Categories)
1. **domain** (5): `cert_transparency`, `dns_brute`, `dnssec_check`, `subdomain_takeover`, `whois_historical`
2. **ip** (5): `asn_lookup`, `bgp_hijack`, `censys_query`, `port_knocking`, `shodan_scan`
3. **email** (5): `alias_hunter`, `breach_lookup`, `disposable_check`, `header_forensics`, `spf_analyzer`
4. **social** (4): `deleted_content_recovery`, `friend_mapper`, `profile_scraper`, `username_sherlock`
5. **dark_web** (5): `crypto_tracer`, `i2p_crawler`, `marketplace_scraper`, `onion_resolver`, `pgp_fingerprint`
6. **phone** (4): `carrier_lookup`, `sim_swap_check`, `sms_phishing_db`, `voip_tracer`
7. **crypto** (4): `btc_cluster`, `darknet_ties`, `eth_tracer`, `exchange_linker`
8. **geolocation** (4): `cell_tower_lookup`, `gps_tracker`, `ip_geolocate`, `wifi_mapping`

### Missing Modules (32 Modules across 8 New Categories + 7 URL Recon)
- **file** (4): `exif_extractor`, `pdf_metadata`, `steg_detect`, `office_macro_analysis` *(Batch 1)*
- **physical** (4): `geocoder`, `satellite_imagery`, `property_records`, `neighbor_mapper`
- **iot** (4): `shodan_iot`, `default_creds`, `firmware_scanner`, `mqtt_brute`
- **malware** (4): `virus_total`, `hybrid_analysis`, `yara_scan`, `malware_family_identifier`
- **threat** (4): `threat_fox`, `misp_lookup`, `abuse_ch`, `firehol`
- **financial** (4): `credit_card_bin`, `iban_lookup`, `swift_code`, `transaction_tracer`
- **legal** (4): `business_registration`, `court_records`, `trademark_lookup`, `patent_search`
- **transport** (4): `flight_tracker`, `ship_tracker`, `vehicle_vin`, `license_plate`
- **url** (7 proposed): `wayback_scraper`, `param_brute`, `js_analyzer`, `csp_checker`, `web_fingerprint`, `screenshot_capture`, `link_crawler`

### Existing Module Partials & Stubs
- `username_sherlock`: Claims 500+ sites in metadata description, contains 56 platforms in implementation with minor duplicates.
- `crypto_tracer`: Uses placeholder simulated data.
- `onion_resolver`: Uses placeholder HSDirs lookup logic.
- `pgp_fingerprint`: Stubbed key validation logic.
- `alias_hunter`: Simulated API response for email permutation testing.

### Framework Gaps Roadmap
- **P0 (Immediate Framework Repairs)**:
  - First-run auto-registration of discovered package built-in modules into storage so `module run` works without manual `module install`.
  - Wire ignored `module run --no-sandbox` flag through CLI and `ModuleExecutor` to execution.
- **P1 (Execution & Export Improvements)**:
  - `chain --parallel` flag support
  - Execution pause/resume capability
  - CSV/HTML report export formatting
- **P2 (Security & Extensibility)**:
  - PGP-signed module manifests and signatures
  - Hot-reloading of modules without CLI restart
  - Per-module venv/binary dependency isolation
- **P3 (Enterprise Storage & Security)**:
  - PostgreSQL backend support
  - SQLCipher encrypted database support
  - Shadowsocks proxy support
  - Desktop / webhook alerting system

---

## 3. Implementation Roadmap: Batch Strategy

### Batch 1 (Current Scope)
- **Category**: `shadowscope/modules/file/`
- **Modules**:
  1. `exif_extractor`: Extract EXIF metadata via Pillow, decode GPS coordinates & device info.
  2. `pdf_metadata`: Catalog info, page count, embedded files, and JS action scan via `pypdf`.
  3. `steg_detect`: Offline statistical tests (LSB chi-square analysis, RS-lite suspicion scoring).
  4. `office_macro_analysis`: OLE stream walk via `olefile`, VBA macro keyword and entropy detection.
- **Framework Fixes**:
  1. Auto-registration of discovered package modules during execution and listing.
  2. Wiring `--no-sandbox` flag through `module run` CLI command to `ModuleExecutor.execute`.
- **Testing**:
  - Extend unit test suites in `tests/unit/test_modules.py`.
  - Offline-only test execution and discovery assertions.

### Future Batches (To be executed sequentially)
- **Batch 2**: Physical & Transport Intelligence
- **Batch 3**: IoT & Threat Intelligence
- **Batch 4**: Malware Analysis & Financial Recon
- **Batch 5**: Legal & URL Reconnaissance
- **Batch 6**: Core Framework P1/P2 Enhancements

---

## 4. Module Design Contract

Every module in SHADOWSCOPE must strictly adhere to the following contract:
1. `MODULE_*` class attributes (`MODULE_NAME`, `MODULE_VERSION`, `MODULE_AUTHOR`, `MODULE_CATEGORY`, `MODULE_DESCRIPTION`, `MODULE_TARGET_TYPES`, `MODULE_DEPENDENCIES`, `MODULE_TIMEOUT`).
2. Custom config class inheriting from `ModuleConfig` (e.g. `ExifExtractorConfig(ModuleConfig)`).
3. `__init__(self, config=None)` zero-arg default instantiation.
4. `validate_target(self, target: str) -> bool` method.
5. `async execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult` method.
6. Module alias at module bottom: `<name>_module = <Class>`.
7. Category subpackage `__init__.py` exposing the module class.
8. `shadowscope/modules/__init__.py` entry and `__all__` list entry.
9. Registration in unit tests (`EXPECTED_MODULES` and `VALIDATE_CASES`).
