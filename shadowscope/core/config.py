"""
Configuration Management for SHADOWSCOPE
Handles all configuration with encryption support for sensitive data.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
import base64
import hashlib
import getpass
from rich.console import Console

console = Console()


@dataclass
class APIConfig:
    """Configuration for external API services"""
    shodan: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    censys: Dict[str, str] = field(default_factory=lambda: {"api_id": "", "api_secret": "", "enabled": "false"})
    zoomeye: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    hunter: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    clearbit: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    hibp: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    virustotal: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    google_maps: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "enabled": "false"})
    twitter: Dict[str, str] = field(default_factory=lambda: {"api_key": "", "api_secret": "", "bearer_token": "", "enabled": "false"})
    telegram: Dict[str, str] = field(default_factory=lambda: {"api_id": "", "api_hash": "", "enabled": "false"})
    tor: Dict[str, str] = field(default_factory=lambda: {"control_port": "9051", "password": "", "enabled": "false"})


@dataclass
class ProxyConfig:
    """Proxy configuration for anonymity"""
    http: List[str] = field(default_factory=list)
    https: List[str] = field(default_factory=list)
    socks5: List[str] = field(default_factory=list)
    tor: Dict[str, str] = field(default_factory=lambda: {"enabled": "false", "port": "9050"})
    rotation: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": "false",
        "interval": 60,
        "randomize": "true"
    })
    user_agents: List[str] = field(default_factory=list)


@dataclass
class SandboxConfig:
    """Sandbox configuration for module isolation"""
    enabled: bool = True
    backend: str = "docker"  # docker, gvisor, firejail
    timeout: int = 300  # seconds
    cpu_limit: str = "1.0"  # CPU cores
    memory_limit: str = "512m"  # Memory
    network_restrictions: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8"
    ])
    blocked_domains: List[str] = field(default_factory=lambda: [
        "google.com",
        "facebook.com",
        "twitter.com",
        "microsoft.com"
    ])


@dataclass
class StorageConfig:
    """Storage configuration"""
    backend: str = "sqlite"  # sqlite, postgres
    path: str = "~/.shadowscope/data/shadowscope.db"
    encryption: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": "true",
        "algorithm": "aes-256-cbc"
    })
    backup: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": "true",
        "interval": "24h",
        "retention": 7
    })


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: str = "~/.shadowscope/logs/shadowscope.log"
    sanitize: bool = True
    encrypt: bool = True
    max_size: int = 10  # MB
    max_files: int = 5


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    max_concurrency: int = 10
    rate_limit: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": "true",
        "requests_per_second": 5,
        "burst_size": 20
    })
    cache: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": "true",
        "backend": "diskcache",  # diskcache, redis
        "ttl": 3600  # seconds
    })


@dataclass
class Config:
    """Main configuration class"""
    api: APIConfig = field(default_factory=APIConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    
    _encryption_key: Optional[bytes] = None
    _config_path: Path = field(default_factory=lambda: Path("~/.shadowscope/config.yaml").expanduser())
    
    def __post_init__(self):
        """Initialize configuration"""
        self._ensure_config_dir()
        self._load_or_create()
        self._load_encryption_key()
    
    def _ensure_config_dir(self):
        """Ensure configuration directory exists"""
        config_dir = self._config_path.parent
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Create other necessary directories
        for dir_path in [
            Path("~/.shadowscope/data").expanduser(),
            Path("~/.shadowscope/logs").expanduser(),
            Path("~/.shadowscope/modules").expanduser(),
            Path("~/.shadowscope/cache").expanduser(),
            Path("~/.shadowscope/backups").expanduser()
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def _load_or_create(self):
        """Load existing config or create default"""
        if self._config_path.exists():
            self._load_config()
        else:
            self._create_default_config()
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            with open(self._config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update configuration from loaded data
            if config_data:
                for section in ['api', 'proxy', 'sandbox', 'storage', 'logging', 'performance']:
                    if section in config_data:
                        section_config = getattr(self, section, None)
                        if section_config is not None and hasattr(section_config, '__dataclass_fields__'):
                            # Update dataclass fields
                            for key, value in config_data[section].items():
                                if hasattr(section_config, key):
                                    setattr(section_config, key, value)
                        elif isinstance(section_config, dict):
                            section_config.update(config_data[section])
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            'api': {
                'shodan': {'api_key': '', 'enabled': False},
                'censys': {'api_id': '', 'api_secret': '', 'enabled': False},
                'zoomeye': {'api_key': '', 'enabled': False},
                'hunter': {'api_key': '', 'enabled': False},
                'clearbit': {'api_key': '', 'enabled': False},
                'hibp': {'api_key': '', 'enabled': False},
                'virustotal': {'api_key': '', 'enabled': False},
                'google_maps': {'api_key': '', 'enabled': False},
                'twitter': {'api_key': '', 'api_secret': '', 'bearer_token': '', 'enabled': False},
                'telegram': {'api_id': '', 'api_hash': '', 'enabled': False},
                'tor': {'control_port': 9051, 'password': '', 'enabled': False}
            },
            'proxy': {
                'http': [],
                'https': [],
                'socks5': [],
                'tor': {'enabled': False, 'port': 9050},
                'rotation': {'enabled': False, 'interval': 60, 'randomize': True},
                'user_agents': []
            },
            'sandbox': {
                'enabled': True,
                'backend': 'docker',
                'timeout': 300,
                'cpu_limit': '1.0',
                'memory_limit': '512m',
                'network_restrictions': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'],
                'blocked_domains': ['google.com', 'facebook.com', 'twitter.com', 'microsoft.com']
            },
            'storage': {
                'backend': 'sqlite',
                'path': '~/.shadowscope/data/shadowscope.db',
                'encryption': {'enabled': True, 'algorithm': 'aes-256-cbc'},
                'backup': {'enabled': True, 'interval': '24h', 'retention': 7}
            },
            'logging': {
                'level': 'INFO',
                'file': '~/.shadowscope/logs/shadowscope.log',
                'sanitize': True,
                'encrypt': True,
                'max_size': 10,
                'max_files': 5
            },
            'performance': {
                'max_concurrency': 10,
                'rate_limit': {'enabled': True, 'requests_per_second': 5, 'burst_size': 20},
                'cache': {'enabled': True, 'backend': 'diskcache', 'ttl': 3600}
            }
        }
        
        with open(self._config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
    
    def _load_encryption_key(self):
        """Load or create encryption key"""
        key_path = Path("~/.shadowscope/.encryption_key").expanduser()
        
        if key_path.exists():
            with open(key_path, 'rb') as f:
                self._encryption_key = f.read()
        else:
            # In non-interactive environments (CI, scripts), auto-generate a random key
            import sys
            if sys.stdin.isatty():
                passphrase = getpass.getpass("Enter encryption passphrase (leave empty to generate random): ")
            else:
                passphrase = ""
            
            if not passphrase:
                self._encryption_key = Fernet.generate_key()
            else:
                # Derive key from passphrase
                salt = os.urandom(16)
                kdf = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000)
                self._encryption_key = base64.urlsafe_b64encode(kdf)
            
            # Save key
            key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(self._encryption_key)
    
    def save(self):
        """Save current configuration to file"""
        config_data = {
            'api': {
                'shodan': {'api_key': self.api.shodan.get('api_key', ''), 'enabled': self.api.shodan.get('enabled', False)},
                'censys': {'api_id': self.api.censys.get('api_id', ''), 'api_secret': self.api.censys.get('api_secret', ''), 'enabled': self.api.censys.get('enabled', False)},
                'zoomeye': {'api_key': self.api.zoomeye.get('api_key', ''), 'enabled': self.api.zoomeye.get('enabled', False)},
                'hunter': {'api_key': self.api.hunter.get('api_key', ''), 'enabled': self.api.hunter.get('enabled', False)},
                'clearbit': {'api_key': self.api.clearbit.get('api_key', ''), 'enabled': self.api.clearbit.get('enabled', False)},
                'hibp': {'api_key': self.api.hibp.get('api_key', ''), 'enabled': self.api.hibp.get('enabled', False)},
                'virustotal': {'api_key': self.api.virustotal.get('api_key', ''), 'enabled': self.api.virustotal.get('enabled', False)},
                'google_maps': {'api_key': self.api.google_maps.get('api_key', ''), 'enabled': self.api.google_maps.get('enabled', False)},
                'twitter': {
                    'api_key': self.api.twitter.get('api_key', ''),
                    'api_secret': self.api.twitter.get('api_secret', ''),
                    'bearer_token': self.api.twitter.get('bearer_token', ''),
                    'enabled': self.api.twitter.get('enabled', False)
                },
                'telegram': {
                    'api_id': self.api.telegram.get('api_id', ''),
                    'api_hash': self.api.telegram.get('api_hash', ''),
                    'enabled': self.api.telegram.get('enabled', False)
                },
                'tor': {
                    'control_port': self.api.tor.get('control_port', 9051),
                    'password': self.api.tor.get('password', ''),
                    'enabled': self.api.tor.get('enabled', False)
                }
            },
            'proxy': {
                'http': self.proxy.http,
                'https': self.proxy.https,
                'socks5': self.proxy.socks5,
                'tor': self.proxy.tor,
                'rotation': self.proxy.rotation,
                'user_agents': self.proxy.user_agents
            },
            'sandbox': {
                'enabled': self.sandbox.enabled,
                'backend': self.sandbox.backend,
                'timeout': self.sandbox.timeout,
                'cpu_limit': self.sandbox.cpu_limit,
                'memory_limit': self.sandbox.memory_limit,
                'network_restrictions': self.sandbox.network_restrictions,
                'blocked_domains': self.sandbox.blocked_domains
            },
            'storage': {
                'backend': self.storage.backend,
                'path': str(self.storage.path),
                'encryption': self.storage.encryption,
                'backup': self.storage.backup
            },
            'logging': {
                'level': self.logging.level,
                'file': str(self.logging.file),
                'sanitize': self.logging.sanitize,
                'encrypt': self.logging.encrypt,
                'max_size': self.logging.max_size,
                'max_files': self.logging.max_files
            },
            'performance': {
                'max_concurrency': self.performance.max_concurrency,
                'rate_limit': self.performance.rate_limit,
                'cache': self.performance.cache
            }
        }
        
        with open(self._config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt a sensitive value"""
        if not self._encryption_key:
            return value
        
        fernet = Fernet(self._encryption_key)
        encrypted = fernet.encrypt(value.encode())
        return encrypted.decode()
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt an encrypted value"""
        if not self._encryption_key:
            return encrypted_value
        
        fernet = Fernet(self._encryption_key)
        decrypted = fernet.decrypt(encrypted_value.encode())
        return decrypted.decode()
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        api_config = getattr(self.api, service, None)
        if api_config and isinstance(api_config, dict):
            key = api_config.get('api_key') or api_config.get('api_secret')
            if key and key.startswith('gAAAA'):
                return self.decrypt_value(key)
            return key
        return None
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a service"""
        api_config = getattr(self.api, service, None)
        if api_config and isinstance(api_config, dict):
            if 'api_key' in api_config:
                api_config['api_key'] = self.encrypt_value(key)
            elif 'api_secret' in api_config:
                api_config['api_secret'] = self.encrypt_value(key)
        self.save()


# Global config instance
config = Config()
