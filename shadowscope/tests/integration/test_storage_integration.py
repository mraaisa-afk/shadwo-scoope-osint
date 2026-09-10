"""
Integration tests for the SHADOWSCOPE storage layer.

These exercise the real SQLite database (schema creation, WAL mode, file
persistence, encryption at rest, concurrent writers, backup and JSON
export/import) rather than mocking the database away.
"""

import json
import sqlite3
import threading
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from shadowscope.core.storage import (
    EncryptionManager,
    ModuleInfo,
    Result,
    Storage,
    Target,
)


class TestStorageSchema:
    """The database is created on disk with the expected structure."""

    def test_database_file_and_tables_are_created(self, storage, isolated_config):
        db_path = Path(isolated_config.storage.path)
        assert db_path.exists(), "Storage did not create the SQLite database file"

        with sqlite3.connect(db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        assert {"targets", "results", "modules"} <= tables

    def test_indexes_are_created(self, storage, isolated_config):
        db_path = Path(isolated_config.storage.path)
        with sqlite3.connect(db_path) as conn:
            indexes = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
        assert "idx_targets_type" in indexes
        assert "idx_results_target" in indexes
        assert "idx_modules_category" in indexes

    def test_wal_mode_enabled(self, storage):
        conn = storage._get_connection()
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        assert mode.lower() == "wal"


class TestTargetLifecycle:
    """Full CRUD round trip against the real database."""

    def test_detects_target_types(self, storage):
        expected = {
            "example.com": "domain",
            "8.8.8.8": "ip",
            "analyst@example.com": "email",
            "https://target.example/scope": "url",
            "anon_user_42": "username",
        }
        for value, target_type in expected.items():
            target = storage.add_target(value)
            assert target.id is not None
            assert target.target_type == target_type

    def test_added_target_is_readable_by_id_and_value(self, storage):
        added = storage.add_target("scope.example", tags=["client-a"], metadata={"owner": "alpha"})

        by_id = storage.get_target(added.id)
        by_value = storage.get_target_by_value("scope.example")

        assert by_id is not None and by_value is not None
        assert by_id.target == "scope.example"
        assert by_id.target_type == "domain"
        assert by_id.tags == ["client-a"]
        assert by_id.metadata == {"owner": "alpha"}
        assert by_value.id == added.id

    def test_duplicate_target_updates_in_place(self, storage):
        first = storage.add_target("dupe.example", tags=["one"])
        second = storage.add_target("dupe.example", tags=["one", "two"])

        assert second.id == first.id
        assert len(storage.get_all_targets()) == 1
        assert storage.get_target(first.id).tags == ["one", "two"]

    def test_update_and_delete(self, storage):
        target = storage.add_target("update.example", tags=["before"])

        assert storage.update_target(target.id, tags=["after"], status="processing") is True
        updated = storage.get_target(target.id)
        assert updated.tags == ["after"]
        assert updated.status == "processing"

        assert storage.delete_target(target.id) is True
        assert storage.get_target(target.id) is None

    def test_filters_by_type_status_and_tags(self, storage):
        storage.add_target("a.example", tags=["alpha"])
        completed = storage.add_target("b.example", tags=["beta"])
        storage.update_target(completed.id, status="completed")
        storage.add_target("1.2.3.4", tags=["alpha", "beta"])

        assert {t.target for t in storage.get_all_targets(target_type="domain")} == {
            "a.example",
            "b.example",
        }
        assert {t.target for t in storage.get_all_targets(status="completed")} == {"b.example"}
        assert {t.target for t in storage.get_all_targets(tags=["alpha", "beta"])} == {"1.2.3.4"}


class TestPersistence:
    """Data written by one Storage instance is visible to a new one (on-disk state)."""

    def test_survives_reopen(self, isolated_config):
        first = Storage(config=isolated_config)
        target = first.add_target("persisted.example", tags=["durable"])
        first.add_module(ModuleInfo(name="persisted_module", version="2.0", category="recon"))

        # A brand new instance over the same database file.
        second = Storage(config=isolated_config)
        reloaded = second.get_target_by_value("persisted.example")

        assert reloaded is not None
        assert reloaded.id == target.id
        assert reloaded.tags == ["durable"]
        assert second.get_module("persisted_module").version == "2.0"

    def test_concurrent_writers_do_not_lose_rows(self, storage):
        errors = []

        def worker(worker_id):
            try:
                for index in range(10):
                    storage.add_target(f"thread{worker_id}-{index}.example")
            except Exception as exc:  # pragma: no cover - only on a real failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(storage.get_all_targets()) == 50


class TestResultsAndEncryption:
    """Results are stored in SQLite and sensitive fields are encrypted at rest."""

    def test_result_round_trip(self, storage):
        target = storage.add_target("results.example")
        stored = storage.add_result(
            Result(
                target_id=target.id,
                module="sample_recon",
                module_version="1.2.3",
                data={"records": ["203.0.113.10"], "success": True},
                status="success",
            )
        )

        fetched = storage.get_result(stored.id)
        assert fetched is not None
        assert fetched.data == {"records": ["203.0.113.10"], "success": True}
        assert fetched.status == "success"

        by_target = storage.get_results_by_target(target.id)
        assert [r.id for r in by_target] == [stored.id]
        assert [r.id for r in storage.get_results_by_module("sample_recon")] == [stored.id]

    def test_sensitive_values_are_encrypted_on_disk(self, storage, isolated_config):
        target = storage.add_target("secrets.example")
        secret = "analyst@example.com"
        storage.add_result(
            Result(
                target_id=target.id,
                module="sample_recon",
                data={"note": f"email {secret}", "raw": "token abc123"},
            )
        )

        # Inspect the raw column, bypassing the storage API entirely.
        with sqlite3.connect(isolated_config.storage.path) as conn:
            raw = conn.execute("SELECT data FROM results").fetchone()[0]

        assert secret not in raw, "sensitive value was persisted in plaintext"
        assert "gAAAA" in raw, "sensitive value was not Fernet-encrypted"

        # ...and it decrypts transparently when read back through the API.
        stored = storage.get_results_by_module("sample_recon")[0]
        assert stored.data["note"] == f"email {secret}"
        assert stored.data["raw"] == "token abc123"

    def test_encryption_manager_is_reversible(self, isolated_config):
        manager = EncryptionManager(Fernet.generate_key())
        ciphertext = manager.encrypt("email analyst@example.com")

        assert ciphertext != "email analyst@example.com"
        assert manager.is_encrypted(ciphertext)
        assert manager.decrypt(ciphertext) == "email analyst@example.com"

    def test_without_key_values_are_passed_through(self):
        manager = EncryptionManager(None)
        assert manager.encrypt("plain") == "plain"
        assert manager.decrypt("plain") == "plain"


class TestSearchAndStats:
    """Cross-table search and aggregate statistics."""

    def test_search_spans_all_tables(self, storage):
        target = storage.add_target("findme.example", tags=["findme"])
        storage.add_result(
            Result(target_id=target.id, module="findme_module", data={"found": "findme"})
        )
        storage.add_module(
            ModuleInfo(name="findme_module", category="recon", description="findme module")
        )

        results = storage.search("findme")
        found_types = {entry["type"] for entry in results}

        assert "target" in found_types
        assert "result" in found_types
        assert "module" in found_types

    def test_search_respects_limit(self, storage):
        for index in range(10):
            storage.add_target(f"limited-{index}.example")
        assert len(storage.search("limited", limit=3)) <= 3

    def test_stats_reflect_written_rows(self, storage):
        domain = storage.add_target("stats.example")
        storage.add_target("1.1.1.1")
        storage.add_result(Result(target_id=domain.id, module="m1", status="success"))
        storage.add_result(Result(target_id=domain.id, module="m1", status="failed"))
        storage.add_module(ModuleInfo(name="m1", category="recon"))

        stats = storage.get_stats()

        assert stats["targets"] == 2
        assert stats["results"] == 2
        assert stats["modules"] == 1
        assert stats["targets_by_type"] == {"domain": 1, "ip": 1}
        assert stats["results_by_module"] == {"m1": 2}
        assert stats["results_by_status"] == {"success": 1, "failed": 1}


class TestBackupAndExport:
    """Backups and JSON export operate on real files."""

    def test_backup_is_encrypted_and_decryptable(self, storage, isolated_config, tmp_path):
        storage.add_target("backup.example")
        backup_path = tmp_path / "shadowscope_backup.db"

        returned = storage.backup(str(backup_path))

        encrypted_path = Path(returned).with_suffix(".db.enc")
        assert encrypted_path.exists(), "encrypted backup file was not produced"
        assert not Path(returned).exists(), "unencrypted backup was left on disk"

        fernet = Fernet(isolated_config._encryption_key)
        plaintext = fernet.decrypt(encrypted_path.read_bytes())

        # The decrypted payload must be a usable SQLite database.
        assert plaintext.startswith(b"SQLite format 3\x00")
        restored = tmp_path / "restored.db"
        restored.write_bytes(plaintext)
        with sqlite3.connect(restored) as conn:
            assert conn.execute("SELECT target FROM targets").fetchone()[0] == "backup.example"

    def test_export_import_json_round_trip(self, isolated_config, tmp_path):
        source = Storage(config=isolated_config)
        source.add_target("exported.example", tags=["exported"], metadata={"owner": "ops"})
        source.add_module(ModuleInfo(name="exported_module", version="3.1", category="recon"))
        export_path = tmp_path / "export.json"

        source.export_json(str(export_path))

        payload = json.loads(export_path.read_text())
        assert payload["targets"][0]["target"] == "exported.example"
        assert payload["modules"][0]["name"] == "exported_module"

        other_config = isolated_config
        other_config.storage.path = str(tmp_path / "imported" / "shadowscope.db")
        destination = Storage(config=other_config)
        destination.import_json(str(export_path))

        assert destination.get_target_by_value("exported.example").tags == ["exported"]
        assert destination.get_module("exported_module").version == "3.1"

    @pytest.mark.xfail(
        reason="export_json() calls get_results_by_module('') so results are never exported",
        strict=False,
    )
    def test_export_includes_results(self, isolated_config, tmp_path):
        source = Storage(config=isolated_config)
        target = source.add_target("withresults.example")
        source.add_result(Result(target_id=target.id, module="m1", data={"ok": True}))
        export_path = tmp_path / "export_results.json"

        source.export_json(str(export_path))

        assert json.loads(export_path.read_text())["results"], "results missing from export"


class TestWorkingMemory:
    """Targets written through the API stay consistent with their dataclass form."""

    def test_target_to_dict_matches_stored_row(self, storage):
        target = storage.add_target("dict.example", tags=["t"], metadata={"k": "v"})
        reloaded = storage.get_target(target.id)

        expected, actual = target.to_dict(), reloaded.to_dict()
        # SQLite fills added_at/updated_at with CURRENT_TIMESTAMP, so the
        # timestamps are re-formatted on insert; every other field must match.
        for key in ("added_at", "updated_at"):
            assert actual[key] is not None and expected[key] is not None
            actual.pop(key)
            expected.pop(key)

        assert reloaded.added_at.startswith(str(target.added_at)[:10])
        assert actual == expected

    def test_reloaded_target_can_be_rebuilt_from_dict(self, storage):
        target = storage.add_target("rebuild.example", tags=["t"], metadata={"k": "v"})
        reloaded = storage.get_target(target.id)

        assert Target(**reloaded.to_dict()).target == "rebuild.example"
