"""
Unit Tests for SHADOWSCOPE Target Management
"""

import pytest
import json
from pathlib import Path
from datetime import datetime

from shadowscope.core.targets import Target, TargetManager


class TestTarget:
    """Test Target dataclass"""
    
    def test_create_target(self):
        """Test creating a target"""
        target = Target(
            value="example.com",
            target_type="domain",
            tags=["test", "example"],
            metadata={"source": "manual"}
        )
        
        assert target.value == "example.com"
        assert target.target_type == "domain"
        assert target.tags == ["test", "example"]
        assert target.metadata == {"source": "manual"}
        assert target.status == "pending"
        assert target.added_at is not None
    
    def test_target_auto_detect_type_domain(self):
        """Test auto-detecting domain type"""
        target = Target(value="example.com")
        assert target.target_type == "domain"
    
    def test_target_auto_detect_type_ip(self):
        """Test auto-detecting IP type"""
        target = Target(value="192.168.1.1")
        assert target.target_type == "ip"
    
    def test_target_auto_detect_type_email(self):
        """Test auto-detecting email type"""
        target = Target(value="user@example.com")
        assert target.target_type == "email"
    
    def test_target_auto_detect_type_url(self):
        """Test auto-detecting URL type"""
        target = Target(value="https://example.com/path")
        assert target.target_type == "url"
    
    def test_target_auto_detect_type_phone(self):
        """Test auto-detecting phone type"""
        target = Target(value="+123456789012")
        assert target.target_type == "phone"
    
    def test_target_auto_detect_type_username(self):
        """Test auto-detecting username type"""
        target = Target(value="johndoe")
        assert target.target_type == "username"
    
    def test_target_to_dict(self):
        """Test converting target to dictionary"""
        target = Target(
            value="example.com",
            target_type="domain",
            tags=["test"],
            metadata={"key": "value"}
        )
        
        data = target.to_dict()
        
        assert data["value"] == "example.com"
        assert data["target_type"] == "domain"
        assert data["tags"] == ["test"]
        assert data["metadata"] == {"key": "value"}
        assert "id" in data
        assert "added_at" in data
    
    def test_target_equality(self):
        """Test target equality comparison"""
        target1 = Target(value="example.com", target_type="domain")
        target2 = Target(value="example.com", target_type="domain")
        target3 = Target(value="example.org", target_type="domain")
        
        assert target1 == target2
        assert target1 != target3
    
    def test_target_hash(self):
        """Test target hashing"""
        target1 = Target(value="example.com", target_type="domain")
        target2 = Target(value="example.com", target_type="domain")
        
        assert hash(target1) == hash(target2)
    
    def test_target_str(self):
        """Test target string representation"""
        target = Target(value="example.com", target_type="domain")
        assert str(target) == "example.com (domain)"
    
    def test_target_case_insensitive_equality(self):
        """Test that equality is case-insensitive"""
        target1 = Target(value="Example.COM")
        target2 = Target(value="example.com")
        assert target1 == target2


class TestTargetManager:
    """Test TargetManager class"""
    
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up target manager with clean state"""
        self.manager = TargetManager()
        # Clear any existing targets before each test
        self.manager.clear()
        yield
        # Clean up after each test
        self.manager.clear()
    
    def test_add_target(self):
        """Test adding a target"""
        target = self.manager.add("example.com")
        
        assert target is not None
        assert target.value == "example.com"
        assert target.target_type == "domain"
        assert target.id is not None
    
    def test_add_with_tags(self):
        """Test adding target with tags"""
        target = self.manager.add("example.com", tags=["test", "example"])
        
        assert "test" in target.tags
        assert "example" in target.tags
    
    def test_add_with_metadata(self):
        """Test adding target with metadata"""
        metadata = {"source": "api", "priority": "high"}
        target = self.manager.add("example.com", metadata=metadata)
        
        assert target.metadata == metadata
    
    def test_add_bulk(self):
        """Test adding multiple targets at once"""
        targets = ["example.com", "test.org", "192.168.1.1"]
        results = self.manager.add_bulk(targets)
        
        assert len(results) == 3
        
        types = [t.target_type for t in results]
        assert "domain" in types
        assert "ip" in types
    
    def test_get_target(self):
        """Test getting a target"""
        target = self.manager.add("example.com")
        
        retrieved = self.manager.get("example.com")
        
        assert retrieved is not None
        assert retrieved.value == target.value
    
    def test_get_all(self):
        """Test getting all targets"""
        self.manager.add("example.com")
        self.manager.add("test.org")
        
        all_targets = self.manager.get_all()
        
        assert len(all_targets) == 2
    
    def test_remove_target(self):
        """Test removing a target"""
        target = self.manager.add("example.com")
        
        success = self.manager.remove("example.com")
        
        assert success is True
        assert self.manager.get("example.com") is None
    
    def test_update_target(self):
        """Test updating a target"""
        target = self.manager.add("example.com", tags=["old"])
        
        self.manager.update("example.com", tags=["new", "updated"], status="active")
        
        updated = self.manager.get("example.com")
        assert "new" in updated.tags
        assert updated.status == "active"
    
    def test_search_targets(self):
        """Test searching targets"""
        self.manager.add("example.com", tags=["test"])
        self.manager.add("other.org", tags=["misc"])
        self.manager.add("example.net", tags=["test", "example"])
        
        results = self.manager.search("example")
        # "example.com" (value match), "example.net" (value match)
        assert len(results) == 2
    
    def test_clear_all(self):
        """Test clearing all targets"""
        self.manager.add("example.com")
        self.manager.add("test.org")
        
        count = self.manager.clear()
        
        assert count == 2
        assert len(self.manager.get_all()) == 0
    
    def test_count_targets(self):
        """Test counting targets"""
        self.manager.add("example.com")
        self.manager.add("test.org")
        self.manager.add("192.168.1.1")
        
        assert self.manager.count() == 3
        assert self.manager.count(target_type="domain") == 2
        assert self.manager.count(target_type="ip") == 1
    
    def test_tag_targets(self):
        """Test tagging targets"""
        self.manager.add("example.com")
        self.manager.add("test.org")
        
        count = self.manager.tag(["example.com", "test.org"], ["osint", "recon"])
        
        assert count == 2
        
        target = self.manager.get("example.com")
        assert "osint" in target.tags
        assert "recon" in target.tags
    
    def test_untag_targets(self):
        """Test removing tags from targets"""
        self.manager.add("example.com", tags=["osint", "recon", "temp"])
        
        count = self.manager.untag(["example.com"], ["temp"])
        
        assert count == 1
        
        target = self.manager.get("example.com")
        assert "temp" not in target.tags
        assert "osint" in target.tags


class TestTargetManagerExportImport:
    """Test import/export functionality"""
    
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up target manager"""
        self.manager = TargetManager()
        self.manager.clear()
        self.tmp_path = tmp_path
        yield
        self.manager.clear()
    
    def test_export_targets_json(self):
        """Test exporting targets to JSON"""
        self.manager.add("example.com", tags=["test"])
        self.manager.add("test.org")
        
        output_path = self.tmp_path / "export.json"
        self.manager.export_to_file(str(output_path), format="json")
        
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert len(data) == 2
    
    def test_export_targets_text(self):
        """Test exporting targets to text"""
        self.manager.add("example.com", tags=["test"])
        
        output_path = self.tmp_path / "export.txt"
        self.manager.export_to_file(str(output_path), format="text")
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "example.com" in content
    
    def test_import_targets_from_file(self):
        """Test importing targets from a text file"""
        import_file = self.tmp_path / "targets.txt"
        import_file.write_text("example.com\ntest.org\n192.168.1.1\n")
        
        count = self.manager.import_from_file(str(import_file))
        
        assert count == 3
        assert self.manager.count() == 3
    
    def test_import_targets_from_json(self):
        """Test importing targets from JSON"""
        import_file = self.tmp_path / "targets.json"
        import_file.write_text(json.dumps(["example.com", "test.org"]))
        
        count = self.manager.import_from_file(str(import_file))
        
        assert count == 2
        assert self.manager.count() == 2
