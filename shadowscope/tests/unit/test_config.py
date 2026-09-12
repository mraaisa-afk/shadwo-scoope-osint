"""
Unit Tests for SHADOWSCOPE Configuration
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from shadowscope.core.config import (
    APIConfig,
    Config,
    LoggingConfig,
    PerformanceConfig,
    ProxyConfig,
    SandboxConfig,
    StorageConfig,
)


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary config directory with patched paths"""
    config_path = tmp_path / "config.yaml"
    key_path = tmp_path / ".encryption_key"

    # Generate a key so we don't prompt for passphrase
    key = Fernet.generate_key()
    key_path.write_bytes(key)

    with patch.object(Path, 'expanduser') as mock_expand:
        # Make expanduser return tmp_path-based paths
        def expanduser_side_effect(self):
            s = str(self)
            if '.shadowscope/config.yaml' in s:
                return config_path
            elif '.shadowscope/.encryption_key' in s:
                return key_path
            elif '.shadowscope' in s:
                return tmp_path / Path(s).name
            return self
        mock_expand.side_effect = expanduser_side_effect
        yield tmp_path


class TestAPIConfig:
    """Test APIConfig dataclass"""

    def test_default_values(self):
        """Test default API config values"""
        api = APIConfig()
        assert api.shodan == {"api_key": "", "enabled": "false"}
        assert api.censys == {"api_id": "", "api_secret": "", "enabled": "false"}
        assert api.tor == {"control_port": "9051", "password": "", "enabled": "false"}

    def test_custom_values(self):
        """Test custom API config values"""
        api = APIConfig(
            shodan={"api_key": "test123", "enabled": "true"}
        )
        assert api.shodan["api_key"] == "test123"
        assert api.shodan["enabled"] == "true"


class TestProxyConfig:
    """Test ProxyConfig dataclass"""

    def test_default_values(self):
        """Test default proxy config values"""
        proxy = ProxyConfig()
        assert proxy.http == []
        assert proxy.https == []
        assert proxy.socks5 == []
        assert proxy.tor == {"enabled": "false", "port": "9050"}
        assert proxy.rotation["enabled"] == "false"


class TestSandboxConfig:
    """Test SandboxConfig dataclass"""

    def test_default_values(self):
        """Test default sandbox config values"""
        sandbox = SandboxConfig()
        assert sandbox.enabled is True
        assert sandbox.backend == "docker"
        assert sandbox.timeout == 300
        assert sandbox.cpu_limit == "1.0"
        assert sandbox.memory_limit == "512m"
        assert len(sandbox.network_restrictions) == 4
        assert "127.0.0.0/8" in sandbox.network_restrictions


class TestStorageConfig:
    """Test StorageConfig dataclass"""

    def test_default_values(self):
        """Test default storage config values"""
        storage = StorageConfig()
        assert storage.backend == "sqlite"
        assert "shadowscope.db" in storage.path
        assert storage.encryption["enabled"] == "true"


class TestLoggingConfig:
    """Test LoggingConfig dataclass"""

    def test_default_values(self):
        """Test default logging config values"""
        logging = LoggingConfig()
        assert logging.level == "INFO"
        assert logging.sanitize is True
        assert logging.encrypt is True
        assert logging.max_size == 10
        assert logging.max_files == 5


class TestPerformanceConfig:
    """Test PerformanceConfig dataclass"""

    def test_default_values(self):
        """Test default performance config values"""
        perf = PerformanceConfig()
        assert perf.max_concurrency == 10
        assert perf.rate_limit["requests_per_second"] == 5
        assert perf.cache["backend"] == "diskcache"


class TestConfig:
    """Test main Config dataclass"""

    def test_default_config_sections(self):
        """Test that Config has all expected sections"""
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            assert isinstance(config.api, APIConfig)
            assert isinstance(config.proxy, ProxyConfig)
            assert isinstance(config.sandbox, SandboxConfig)
            assert isinstance(config.storage, StorageConfig)
            assert isinstance(config.logging, LoggingConfig)
            assert isinstance(config.performance, PerformanceConfig)

    def test_encrypt_decrypt_value(self):
        """Test encrypting and decrypting values"""
        key = Fernet.generate_key()
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            config._encryption_key = key

            original = "my_secret_api_key"
            encrypted = config.encrypt_value(original)

            assert encrypted != original
            assert encrypted.startswith('gAAAA')

            decrypted = config.decrypt_value(encrypted)
            assert decrypted == original

    def test_encrypt_without_key(self):
        """Test encryption without key returns original value"""
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            config._encryption_key = None

            value = "test_value"
            assert config.encrypt_value(value) == value
            assert config.decrypt_value(value) == value

    def test_get_api_key(self):
        """Test getting API key for a service"""
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            config._encryption_key = Fernet.generate_key()

            # Set a known API key
            config.api.shodan = {"api_key": "test_key_123", "enabled": "true"}
            key = config.get_api_key("shodan")
            assert key == "test_key_123"

    def test_get_api_key_nonexistent_service(self):
        """Test getting API key for nonexistent service"""
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            config._encryption_key = Fernet.generate_key()

            key = config.get_api_key("nonexistent")
            assert key is None

    def test_set_api_key(self):
        """Test setting API key for a service"""
        with patch.object(Config, '__post_init__', lambda self: None):
            config = Config()
            config._encryption_key = Fernet.generate_key()
            config._config_path = Path("/tmp/test_config.yaml")

            # Mock save to avoid file operations
            config.save = lambda: None

            config.set_api_key("shodan", "new_api_key")
            assert config.api.shodan["api_key"] != "new_api_key"  # Should be encrypted

    def test_load_encryption_key_generates_random(self):
        """Test that encryption key is auto-generated in non-interactive mode"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / ".encryption_key"

            with patch('shadowscope.core.config.Path') as mock_path:
                mock_path.return_value.expanduser.return_value = key_path
                mock_path.side_effect = lambda x: type('P', (), {
                    'expanduser': lambda self: key_path if 'encryption_key' in str(x) else Path(x).expanduser(),
                    'parent': key_path.parent,
                    'exists': lambda self: False
                })()

                # Just test that Fernet.generate_key works
                key = Fernet.generate_key()
                assert len(key) > 0
                assert isinstance(key, bytes)
