"""
Unit Tests for SHADOWSCOPE Target Management
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from shadowscope.core.targets import (
    Target, TargetType, TargetManager, TargetError,
    detect_target_type, validate_target, normalize_target
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def target_manager(temp_db):
    """Create a target manager with temporary storage"""
    manager = TargetManager()
    manager.storage.set_database(temp_db)
    manager.storage.initialize()
    return manager


class TestTarget:
    """Test Target dataclass"""
    
    def test_create_target(self):
        """Test creating a target"""
        target = Target(
            value="example.com",
            target_type=TargetType.DOMAIN,
            tags=["test", "example"],
            metadata={"source": "manual"}
        )
        
        assert target.value == "example.com"
        assert target.target_type == TargetType.DOMAIN
        assert target.tags == ["test", "example"]
        assert target.metadata == {"source": "manual"}
        assert target.status == "pending"
        assert target.added_at is not None
    
    def test_target_to_dict(self):
        """Test converting target to dictionary"""
        target = Target(
            value="example.com",
            target_type=TargetType.DOMAIN,
            tags=["test"],
            metadata={"key": "value"}
        )
        
        data = target.to_dict()
        
        assert data["value"] == "example.com"
        assert data["target_type"] == TargetType.DOMAIN
        assert data["tags"] == ["test"]
        assert data["metadata"] == {"key": "value"}
        assert "id" in data
        assert "added_at" in data
    
    def test_target_from_dict(self):
        """Test creating target from dictionary"""
        data = {
            "value": "test.com",
            "target_type": "domain",
            "tags": ["tag1", "tag2"],
            "metadata": {"key": "value"},
            "status": "active"
        }
        
        target = Target.from_dict(data)
        
        assert target.value == "test.com"
        assert target.target_type == TargetType.DOMAIN
        assert target.tags == ["tag1", "tag2"]
        assert target.metadata == {"key": "value"}
        assert target.status == "active"
    
    def test_target_equality(self):
        """Test target equality comparison"""
        target1 = Target(value="example.com", target_type=TargetType.DOMAIN)
        target2 = Target(value="example.com", target_type=TargetType.DOMAIN)
        target3 = Target(value="example.org", target_type=TargetType.DOMAIN)
        
        assert target1 == target2
        assert target1 != target3
    
    def test_target_hash(self):
        """Test target hashing"""
        target1 = Target(value="example.com", target_type=TargetType.DOMAIN)
        target2 = Target(value="example.com", target_type=TargetType.DOMAIN)
        
        # Should be hashable and equal targets should have same hash
        assert hash(target1) == hash(target2)


class TestTargetTypeDetection:
    """Test target type detection"""
    
    def test_detect_domain(self):
        """Test detecting domain targets"""
        assert detect_target_type("example.com") == TargetType.DOMAIN
        assert detect_target_type("sub.example.com") == TargetType.DOMAIN
        assert detect_target_type("example.co.uk") == TargetType.DOMAIN
    
    def test_detect_ip(self):
        """Test detecting IP targets"""
        assert detect_target_type("192.168.1.1") == TargetType.IP
        assert detect_target_type("8.8.8.8") == TargetType.IP
        assert detect_target_type("127.0.0.1") == TargetType.IP
    
    def test_detect_email(self):
        """Test detecting email targets"""
        assert detect_target_type("user@example.com") == TargetType.EMAIL
        assert detect_target_type("john.doe@company.org") == TargetType.EMAIL
    
    def test_detect_url(self):
        """Test detecting URL targets"""
        assert detect_target_type("https://example.com") == TargetType.URL
        assert detect_target_type("http://example.com/path") == TargetType.URL
        assert detect_target_type("https://example.com?query=value") == TargetType.URL
    
    def test_detect_phone(self):
        """Test detecting phone targets"""
        assert detect_target_type("+1234567890") == TargetType.PHONE
        assert detect_target_type("123-456-7890") == TargetType.PHONE
        assert detect_target_type("(123) 456-7890") == TargetType.PHONE
    
    def test_detect_username(self):
        """Test detecting username targets"""
        assert detect_target_type("johndoe") == TargetType.USERNAME
        assert detect_target_type("user123") == TargetType.USERNAME
    
    def test_detect_unknown(self):
        """Test detecting unknown targets"""
        assert detect_target_type("random_string") == TargetType.UNKNOWN


class TestTargetValidation:
    """Test target validation"""
    
    def test_validate_domain(self):
        """Test validating domain targets"""
        assert validate_target("example.com", TargetType.DOMAIN) is True
        assert validate_target("sub.example.com", TargetType.DOMAIN) is True
        assert validate_target("example.co.uk", TargetType.DOMAIN) is True
        
        # Invalid domains
        assert validate_target("example", TargetType.DOMAIN) is False
        assert validate_target("-example.com", TargetType.DOMAIN) is False
        assert validate_target("example..com", TargetType.DOMAIN) is False
    
    def test_validate_ip(self):
        """Test validating IP targets"""
        assert validate_target("192.168.1.1", TargetType.IP) is True
        assert validate_target("8.8.8.8", TargetType.IP) is True
        
        # Invalid IPs
        assert validate_target("256.168.1.1", TargetType.IP) is False
        assert validate_target("192.168.1", TargetType.IP) is False
    
    def test_validate_email(self):
        """Test validating email targets"""
        assert validate_target("user@example.com", TargetType.EMAIL) is True
        assert validate_target("john.doe@company.org", TargetType.EMAIL) is True
        
        # Invalid emails
        assert validate_target("user@.com", TargetType.EMAIL) is False
        assert validate_target("@example.com", TargetType.EMAIL) is False
    
    def test_validate_url(self):
        """Test validating URL targets"""
        assert validate_target("https://example.com", TargetType.URL) is True
        assert validate_target("http://example.com/path", TargetType.URL) is True
        
        # Invalid URLs
        assert validate_target("example.com", TargetType.URL) is False
        assert validate_target("://example.com", TargetType.URL) is False


class TestTargetNormalization:
    """Test target normalization"""
    
    def test_normalize_domain(self):
        """Test normalizing domain targets"""
        assert normalize_target("Example.COM") == "example.com"
        assert normalize_target("  example.com  ") == "example.com"
        assert normalize_target("http://example.com") == "example.com"
        assert normalize_target("https://example.com") == "example.com"
        assert normalize_target("www.example.com") == "example.com"
    
    def test_normalize_ip(self):
        """Test normalizing IP targets"""
        assert normalize_target("192.168.1.1") == "192.168.1.1"
        assert normalize_target("  192.168.1.1  ") == "192.168.1.1"
    
    def test_normalize_email(self):
        """Test normalizing email targets"""
        assert normalize_target("User@Example.COM") == "user@example.com"
        assert normalize_target("  user@example.com  ") == "user@example.com"
    
    def test_normalize_url(self):
        """Test normalizing URL targets"""
        assert normalize_target("https://example.com/path") == "https://example.com/path"
        assert normalize_target("HTTP://EXAMPLE.COM/PATH") == "http://example.com/path"


class TestTargetManager:
    """Test TargetManager class"""
    
    def test_add_target(self, target_manager):
        """Test adding a target"""
        target = target_manager.add("example.com")
        
        assert target is not None
        assert target.value == "example.com"
        assert target.target_type == TargetType.DOMAIN
        assert target.id is not None
    
    def test_add_duplicate_target(self, target_manager):
        """Test adding duplicate targets"""
        target1 = target_manager.add("example.com")
        target2 = target_manager.add("example.com")
        
        # Should return the same target
        assert target1 == target2
    
    def test_add_with_tags(self, target_manager):
        """Test adding target with tags"""
        target = target_manager.add("example.com", tags=["test", "example"])
        
        assert "test" in target.tags
        assert "example" in target.tags
    
    def test_add_with_metadata(self, target_manager):
        """Test adding target with metadata"""
        metadata = {"source": "api", "priority": "high"}
        target = target_manager.add("example.com", metadata=metadata)
        
        assert target.metadata == metadata
    
    def test_add_bulk(self, target_manager):
        """Test adding multiple targets at once"""
        targets = ["example.com", "test.org", "192.168.1.1"]
        results = target_manager.add_bulk(targets)
        
        assert len(results) == 3
        
        types = [t.target_type for t in results]
        assert TargetType.DOMAIN in types
        assert TargetType.IP in types
    
    def test_get_target(self, target_manager):
        """Test getting a target by ID"""
        target = target_manager.add("example.com")
        
        retrieved = target_manager.get(target.id)
        
        assert retrieved == target
    
    def test_get_all(self, target_manager):
        """Test getting all targets"""
        target_manager.add("example.com")
        target_manager.add("test.org")
        
        all_targets = target_manager.get_all()
        
        assert len(all_targets) == 2
    
    def test_remove_target(self, target_manager):
        """Test removing a target"""
        target = target_manager.add("example.com")
        
        success = target_manager.remove(target.id)
        
        assert success is True
        assert target_manager.get(target.id) is None
    
    def test_update_target(self, target_manager):
        """Test updating a target"""
        target = target_manager.add("example.com", tags=["old"])
        
        updated = target_manager.update(
            target.id,
            tags=["new", "updated"],
            status="active"
        )
        
        assert updated.tags == ["new", "updated"]
        assert updated.status == "active"
    
    def test_search_targets(self, target_manager):
        """Test searching targets"""
        target_manager.add("example.com", tags=["test"])
        target_manager.add("test.org", tags=["example"])
        target_manager.add("example.net", tags=["test", "example"])
        
        # Search by tag
        results = target_manager.search(tags=["test"])
        assert len(results) == 2
        
        # Search by type
        results = target_manager.search(target_type=TargetType.DOMAIN)
        assert len(results) == 3
        
        # Search by value
        results = target_manager.search(value="example")
        assert len(results) == 2
    
    def test_clear_all(self, target_manager):
        """Test clearing all targets"""
        target_manager.add("example.com")
        target_manager.add("test.org")
        
        count = target_manager.clear_all()
        
        assert count == 2
        assert len(target_manager.get_all()) == 0
    
    def test_export_targets(self, target_manager, temp_config_dir):
        """Test exporting targets"""
        target_manager.add("example.com", tags=["test"])
        target_manager.add("test.org")
        
        output_path = Path(temp_config_dir) / "export.json"
        count = target_manager.export_targets(str(output_path))
        
        assert count == 2
        assert output_path.exists()
    
    def test_import_targets(self, target_manager, temp_config_dir):
        """Test importing targets"""
        # First create an export file
        target_manager.add("example.com", tags=["test"])
        output_path = Path(temp_config_dir) / "import.json"
        target_manager.export_targets(str(output_path))
        
        # Clear and import
        target_manager.clear_all()
        count = target_manager.import_targets(str(output_path))
        
        assert count == 1
        assert len(target_manager.get_all()) == 1


class TestTargetManagerTags:
    """Test tag management in TargetManager"""
    
    def test_add_tags(self, target_manager):
        """Test adding tags to a target"""
        target = target_manager.add("example.com")
        
        updated = target_manager.add_tags(target.id, ["new", "tag"])
        
        assert "new" in updated.tags
        assert "tag" in updated.tags
    
    def test_remove_tags(self, target_manager):
        """Test removing tags from a target"""
        target = target_manager.add("example.com", tags=["test", "example", "remove"])
        
        updated = target_manager.remove_tags(target.id, ["remove"])
        
        assert "remove" not in updated.tags
        assert "test" in updated.tags
    
    def test_get_by_tag(self, target_manager):
        """Test getting targets by tag"""
        target_manager.add("example.com", tags=["test"])
        target_manager.add("test.org", tags=["test", "example"])
        target_manager.add("other.com", tags=["other"])
        
        results = target_manager.get_by_tag("test")
        
        assert len(results) == 2


class TestTargetManagerStats:
    """Test statistics in TargetManager"""
    
    def test_get_stats(self, target_manager):
        """Test getting target statistics"""
        target_manager.add("example.com", tags=["test"])
        target_manager.add("test.org", tags=["test"])
        target_manager.add("192.168.1.1", tags=["network"])
        
        stats = target_manager.get_stats()
        
        assert stats.total == 3
        assert stats.by_type[TargetType.DOMAIN] == 2
        assert stats.by_type[TargetType.IP] == 1
        assert stats.by_tag["test"] == 2
        assert stats.by_tag["network"] == 1
