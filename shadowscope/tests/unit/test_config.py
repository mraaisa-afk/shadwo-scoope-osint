"""
Unit Tests for SHADOWSCOPE Configuration
"""

import pytest
import tempfile
import os
from pathlib import Path

from shadowscope.core.config import Config, ConfigError


@pytest.fixture
def temp_config_file():
    """Create a temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""
core:
  name: "SHADOWSCOPE"
  version: "1.0.0"
  environment: "test"
  debug: true
  verbose: false

storage:
  backend: "sqlite"
  sqlite:
    database: "test.db"
""")
        f.flush()
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        config_path.write_text("""
core:
  name: "SHADOWSCOPE"
  version: "1.0.0"
""")
        yield tmpdir


class TestConfig:
    """Test configuration management"""
    
    def test_load_config(self, temp_config_file):
        """Test loading configuration from file"""
        config = Config.load_from_file(temp_config_file)
        assert config is not None
        assert config.core.name == "SHADOWSCOPE"
        assert config.core.version == "1.0.0"
        assert config.core.environment == "test"
        assert config.core.debug is True
    
    def test_default_config(self):
        """Test default configuration values"""
        config = Config()
        assert config.core.name == "SHADOWSCOPE"
        assert config.core.version == "1.0.0"
        assert config.core.environment == "development"
        assert config.storage.backend == "sqlite"
    
    def test_save_config(self, temp_config_dir):
        """Test saving configuration to file"""
        config = Config()
        config.core.environment = "test"
        
        config_path = Path(temp_config_dir) / "test_config.yaml"
        config.save_to_file(str(config_path))
        
        assert config_path.exists()
        
        # Verify saved config
        saved_config = Config.load_from_file(str(config_path))
        assert saved_config.core.environment == "test"
    
    def test_get_nested_value(self, temp_config_file):
        """Test getting nested configuration values"""
        config = Config.load_from_file(temp_config_file)
        
        assert config.get("core.name") == "SHADOWSCOPE"
        assert config.get("core.debug") is True
        assert config.get("storage.backend") == "sqlite"
        assert config.get("storage.sqlite.database") == "test.db"
    
    def test_set_nested_value(self, temp_config_file):
        """Test setting nested configuration values"""
        config = Config.load_from_file(temp_config_file)
        
        config.set("core.debug", False)
        assert config.core.debug is False
        
        config.set("storage.sqlite.wal_mode", True)
        assert config.storage.sqlite.wal_mode is True
    
    def test_merge_config(self):
        """Test merging configurations"""
        config1 = Config()
        config1.core.environment = "development"
        
        config2 = Config()
        config2.core.environment = "production"
        config2.storage.backend = "postgresql"
        
        config1.merge(config2)
        
        assert config1.core.environment == "production"
        assert config1.storage.backend == "postgresql"
    
    def test_validate_config(self):
        """Test configuration validation"""
        config = Config()
        
        # Valid config should not raise
        config.validate()
        
        # Test with invalid storage backend
        config.storage.backend = "invalid"
        with pytest.raises(ConfigError):
            config.validate()
    
    def test_encrypt_decrypt(self, temp_config_dir):
        """Test encryption/decryption of sensitive values"""
        config = Config()
        passphrase = "test_passphrase_123"
        
        # Test encryption
        encrypted = config.encrypt_value("secret_value", passphrase)
        assert encrypted != "secret_value"
        
        # Test decryption
        decrypted = config.decrypt_value(encrypted, passphrase)
        assert decrypted == "secret_value"
    
    def test_environment_variables(self, monkeypatch):
        """Test environment variable substitution"""
        monkeypatch.setenv("SHADOWSCOPE_DB_PATH", "/tmp/test.db")
        
        config = Config()
        config.storage.sqlite.database = "$SHADOWSCOPE_DB_PATH"
        
        resolved = config.resolve_environment_vars()
        assert resolved.storage.sqlite.database == "/tmp/test.db"


class TestConfigSingleton:
    """Test configuration singleton pattern"""
    
    def test_singleton_instance(self):
        """Test that Config returns the same instance"""
        config1 = Config.get_instance()
        config2 = Config.get_instance()
        
        assert config1 is config2
    
    def test_singleton_initialization(self):
        """Test singleton initialization"""
        config = Config.get_instance()
        assert config is not None
        assert isinstance(config, Config)


class TestConfigEncryption:
    """Test configuration encryption features"""
    
    def test_generate_encryption_key(self):
        """Test generating encryption key from passphrase"""
        config = Config()
        passphrase = "my_secure_passphrase"
        
        key = config.generate_encryption_key(passphrase)
        assert key is not None
        assert len(key) == 32  # AES-256 key
    
    def test_encrypt_api_keys(self, temp_config_dir):
        """Test encrypting API keys"""
        config = Config()
        config.api_keys.shodan = "test_api_key"
        passphrase = "test_passphrase"
        
        config.encrypt_api_keys(passphrase)
        
        # The key should be encrypted
        assert config.api_keys.shodan != "test_api_key"
        
        # Should be able to decrypt
        decrypted = config.decrypt_value(config.api_keys.shodan, passphrase)
        assert decrypted == "test_api_key"
    
    def test_decrypt_api_keys(self, temp_config_dir):
        """Test decrypting API keys"""
        config = Config()
        passphrase = "test_passphrase"
        
        # Manually encrypt a value
        encrypted = config.encrypt_value("secret_key", passphrase)
        config.api_keys.shodan = encrypted
        
        # Decrypt all
        config.decrypt_api_keys(passphrase)
        
        assert config.api_keys.shodan == "secret_key"
