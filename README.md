# SHADOWSCOPE 🎯

> **A Modular, Extensible OSINT Framework for Deep Reconnaissance, Data Correlation, and Iterative Target Expansion**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-red.svg)](https://opensource.org/licenses/GPL-3.0)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## ⚡ **OVERVIEW**

SHADOWSCOPE is a **next-generation OSINT framework** designed for **elite operators** who demand **stealth, scalability, and brutality** in their investigations. Built from the ground up for **deep reconnaissance**, **data correlation**, and **iterative target expansion**, SHADOWSCOPE provides a **modular, extensible, and sandboxed** environment for conducting comprehensive intelligence operations.

### **🎯 Core Philosophy**

- **No Attribution** - All requests are anonymized, logs sanitized, errors silent
- **No Limits** - Scales to 10,000+ targets and 100+ concurrent modules
- **No Apologies** - A tool for professionals, by professionals
- **Zero Trust** - Every module runs in isolated sandboxes by default

---

## 🚀 **FEATURES**

### **🎯 Comprehensive Target Coverage**

| Category | Target Types | Modules |
|----------|-------------|---------|
| **Network** | Domains, Subdomains, IPs, URLs | DNS, WHOIS, Port Scanning |
| **Identity** | Emails, Usernames, Phone Numbers | Breach Lookup, Social Search |
| **Dark Web** | Onion, I2P, Cryptocurrency | Marketplace Scraping, Threat Actor Tracking |
| **Files** | Documents, Images, Binaries | Metadata Extraction, Steganography |
| **Physical** | Addresses, VINs, License Plates | Geocoding, Property Records |
| **IoT** | Devices, Cameras, Routers | Shodan Integration, Firmware Analysis |
| **Threat** | Malware, CVEs, Indicators | VT Analysis, Threat Intelligence |

### **🔧 Modular Architecture**

- **Plug-and-Play Modules** - Add new capabilities without touching core code
- **Hot-Reloading** - Develop modules without restarting the application
- **Sandboxed Execution** - Docker, Firejail, or gVisor isolation
- **Registry-Backed** - Private and community module repositories
- **Versioned & Signed** - PGP-signed modules for authenticity verification

### **💾 Storage & Encryption**

- **SQLite (Default)** - Portable, zero-configuration database
- **PostgreSQL (Optional)** - For large-scale investigations
- **Full Database Encryption** - SQLCipher for SQLite, TDE for PostgreSQL
- **Field-Level Encryption** - Sensitive data (emails, IPs, PII) encrypted at rest
- **Automated Backups** - Encrypted, scheduled database backups

### **🌐 Anonymity & Stealth**

- **Proxy Rotation** - HTTP, HTTPS, SOCKS5 with failover
- **Tor Integration** - Native support with circuit management
- **User-Agent Spoofing** - Randomized from real browser fingerprints
- **DNS over HTTPS** - Cloudflare, Google, Quad9 support
- **CAPTCHA Bypass** - 2Captcha, Anti-Captcha, DeathByCaptcha integration
- **Rate Limiting** - Configurable delays to avoid detection

### **🎨 Professional CLI**

- **Rich Terminal Output** - Colorized tables, progress bars, syntax highlighting
- **Autocompletion** - Command, target, and module name completion
- **Interactive Tables** - Sortable, filterable, paginated results
- **Multi-Tab Interface** - Scope, Results, Modules, Logs tabs (TUI mode)
- **Export Formats** - JSON, CSV, HTML, and custom formats

---

## 📦 **INSTALLATION**

### **🐍 pip (Recommended)**

```bash
# Clone the repository
git clone https://github.com/mraaisa-afk/shadwo-scoope-osint.git
cd shadwo-scoope-osint

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### **🐳 Docker**

```bash
# Build the image
docker build -t shadowscope .

# Run interactively
docker run -it --rm shadowscope

# Run with volume for persistence
docker run -it --rm -v ~/.shadowscope:/root/.shadowscope shadowscope
```

### **📦 Pre-built Binaries**

Binaries for Windows, Linux, and macOS will be available in the [Releases](https://github.com/mraaisa-afk/shadwo-scoope-osint/releases) section.

---

## 🎯 **QUICK START**

### **1. Initialize Configuration**

```bash
shadowscope config init
```

Follow the interactive prompts to configure API keys and proxy settings.

### **2. Add Targets to Scope**

```bash
# Add a single target
shadowscope target add example.com

# Add with type and tags
shadowscope target add admin@example.com --type email --tag victim,high-priority

# Bulk import from file
shadowscope target add_bulk targets.txt

# Import from CSV/JSON
shadowscope target import_file targets.csv
```

### **3. Discover Available Modules**

```bash
# List all available modules
shadowscope module list

# List by category
shadowscope module list --category recon

# List by target type
shadowscope module list --target-type domain

# Show module details
shadowscope module show dns_brute
```

### **4. Run Modules**

```bash
# Run a single module on a target
shadowscope module run dns_brute example.com

# Run on all targets in scope
shadowscope module run dns_brute --all

# Run on targets with specific tag
shadowscope module run dns_brute --tag high-priority

# Run with custom configuration
shadowscope module run shodan_scan --all --config '{"api_key": "YOUR_KEY"}'
```

### **5. Chain Modules Together**

```bash
# Run multiple modules in sequence
shadowscope module chain dns_brute whois_historical cert_transparency subdomain_takeover --all

# With parallel execution
shadowscope module chain dns_brute shodan_scan --all --parallel 5
```

### **6. Review Results**

```bash
# Show all results
shadowscope storage search "example.com"

# Filter by module
shadowscope storage search "example.com" --module dns_brute

# Export results
shadowscope storage export results.json

# Show statistics
shadowscope storage stats
```

---

## 📚 **DOCUMENTATION**

- **[Getting Started](docs/guides/getting-started.md)** - Installation and basic usage
- **[Configuration Guide](docs/guides/configuration.md)** - Detailed configuration options
- **[Module Development](docs/guides/module-development.md)** - Creating custom modules
- **[API Reference](docs/api/README.md)** - Python API documentation
- **[Examples](docs/examples/)** - Practical usage examples

---

## 🏗️ **ARCHITECTURE**

```
shadowscope/
├── core/                          # Core framework components
│   ├── __init__.py               # Package initialization
│   ├── config.py                 # Configuration management
│   ├── storage.py                # Database storage layer
│   ├── targets.py                # Target management
│   ├── modules.py                # Module system
│   ├── sandbox.py                # Sandbox execution
│   ├── proxy.py                  # Proxy & anonymity
│   └── cache.py                  # Caching system
│
├── modules/                      # OSINT modules (organized by category)
│   ├── domain/                   # Domain reconnaissance
│   │   ├── dns_brute.py          # DNS brute-forcing
│   │   ├── whois_historical.py    # Historical WHOIS
│   │   └── ...
│   ├── ip/                       # IP/Network reconnaissance
│   │   ├── shodan_scan.py        # Shodan integration
│   │   └── ...
│   ├── email/                    # Email OSINT
│   │   ├── breach_lookup.py      # Breach database lookup
│   │   └── ...
│   └── ...                       # Other categories
│
├── cli/                          # Command-line interface
│   ├── __init__.py
│   ├── app.py                    # Main CLI application
│   └── commands/                 # Command groups
│       ├── target_commands.py
│       ├── module_commands.py
│       └── ...
│
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests
│   └── integration/              # Integration tests
│
├── docs/                         # Documentation
│   ├── api/                      # API documentation
│   ├── guides/                   # User guides
│   └── examples/                 # Usage examples
│
├── scripts/                      # Utility scripts
│   └── setup.py                  # Installation script
│
├── config/                       # Configuration templates
│   └── default.yaml              # Default configuration
│
└── assets/                       # Static assets
    └── user_agents.txt           # User agent list
```

---

## 🔧 **MODULE DEVELOPMENT**

### **Creating a Custom Module**

1. **Create module directory:**
```bash
mkdir -p shadowscope/modules/custom/my_module
cd shadowscope/modules/custom/my_module
```

2. **Create `manifest.yaml`:**
```yaml
name: my_module
version: 1.0.0
author: Your Name
description: My custom OSINT module
category: recon
target_types: [domain, ip]
dependencies: [requests, beautifulsoup4]
is_async: true
is_sandboxed: true
timeout: 300
config_schema:
  api_key:
    type: string
    required: false
    description: API key for external service
```

3. **Create `__init__.py`:**
```python
from .my_module import MyModule

__all__ = ["MyModule"]
```

4. **Create `my_module.py`:**
```python
from shadowscope.core.modules import BaseModule

class MyModule(BaseModule):
    """My custom OSINT module"""
    
    def __init__(self, config=None):
        super().__init__(config)
        self.name = "my_module"
        self.version = "1.0.0"
    
    async def run(self, target):
        """Execute the module on a target"""
        # Your OSINT logic here
        results = {
            "target": target,
            "data": {"found": True},
            "sources": ["my_module"]
        }
        return results
    
    @classmethod
    def get_metadata(cls):
        return {
            "name": "my_module",
            "version": "1.0.0",
            "author": "Your Name",
            "description": "My custom OSINT module",
            "category": "recon",
            "target_types": ["domain", "ip"]
        }
```

5. **Install the module:**
```bash
shadowscope module install my_module --source local
```

---

## 🛡️ **STEALTH & OPSEC**

### **Built-in Protections**

- **No Hardcoded Credentials** - All API keys stored encrypted in config
- **Request Anonymization** - All outbound requests use proxies/Tor by default
- **User-Agent Rotation** - Randomized from 100+ real browser fingerprints
- **Rate Limiting** - Configurable delays between requests (default: 5 req/s)
- **Error Handling** - Silent failures, automatic retries with exponential backoff
- **Log Sanitization** - Sensitive data automatically redacted from logs
- **Network Restrictions** - Blocked domains and IP ranges in sandbox

### **Recommended Usage Patterns**

```bash
# Always use proxies
shadowscope proxy add http://proxy1:8080
shadowscope proxy add socks5://proxy2:1080

# Enable Tor for maximum anonymity
shadowscope config enable proxy tor

# Use DNS over HTTPS
shadowscope config set dns_over_https true --provider cloudflare

# Rotate identities periodically
shadowscope proxy change_tor_identity

# Disable modules that might be detected
shadowscope module disable suspicious_module
```

---

## 📊 **PERFORMANCE**

### **Scalability**

- **10,000+ Targets** - Optimized for large-scale investigations
- **100+ Concurrent Modules** - Parallel execution with configurable limits
- **Batch Processing** - Process thousands of targets efficiently
- **Caching** - Redis, disk, or memory caching for API responses

### **Optimization Features**

```bash
# Increase concurrency
shadowscope config set performance max_concurrency 20

# Enable caching
shadowscope config set performance cache enabled true
shadowscope config set performance cache backend redis

# Adjust rate limits
shadowscope config set performance rate_limit requests_per_second 10
shadowscope config set performance rate_limit burst_size 50
```

---

## 🤝 **CONTRIBUTING**

### **Reporting Issues**

1. Check existing issues to avoid duplicates
2. Provide detailed reproduction steps
3. Include relevant logs (sanitized)
4. Specify OS, Python version, and dependencies

### **Submitting Pull Requests**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow existing code style (Black, isort)
4. Add tests for new functionality
5. Update documentation
6. Submit PR with clear description

### **Module Submission**

1. Create a module following the [Module Development Guide](docs/guides/module-development.md)
2. Test thoroughly with various target types
3. Add to the community registry (TBD)
4. Submit PR for official inclusion

---

## 📜 **LICENSE**

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ **DISCLAIMER**

> **This tool is for authorized security professionals and researchers only.**

- **Legal Compliance**: Ensure all activities comply with applicable laws and regulations
- **Authorization**: Only investigate targets you have explicit permission to test
- **Ethical Use**: Do not use for malicious purposes or unauthorized access
- **No Warranty**: This software is provided "as is" without warranty of any kind
- **No Liability**: The authors are not responsible for any misuse of this tool

---

## 📞 **CONTACT**

- **GitHub**: [mraaisa-afk/shadwo-scoope-osint](https://github.com/mraaisa-afk/shadwo-scoope-osint)
- **Issues**: [GitHub Issues](https://github.com/mraaisa-afk/shadwo-scoope-osint/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mraaisa-afk/shadwo-scoope-osint/discussions)

---

<p align="center">
  <strong>SHADOWSCOPE</strong> - No Attribution. No Limits. No Apologies.
</p>
