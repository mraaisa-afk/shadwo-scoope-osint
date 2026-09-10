"""
Integration tests for the SHADOWSCOPE module pipeline.

These cover the path a real operator-module takes through the framework:

    manifest on disk -> discovery -> import -> class resolution
        -> async execution -> result persisted in SQLite

The sample module used here is generated on disk by the fixtures, so the
loader performs a genuine ``importlib`` import of a real package rather than
importing a mock. No network access is required.
"""

import asyncio
from types import SimpleNamespace

import pytest

from shadowscope.core.modules import ModuleMetadata, ModuleResult
from shadowscope.core.storage import ModuleInfo

from .conftest import write_sample_module


class _MetadataAdapterStorage:
    """
    Delegates to a real Storage but returns module metadata carrying the
    ``is_sandboxed``/``timeout`` attributes that ModuleExecutor.execute() reads.

    ``shadowscope.core.storage.ModuleInfo`` does not define those two fields,
    so the executor cannot consume storage metadata directly (covered by
    ``test_execute_reads_storage_metadata`` below). The adapter only bridges
    that gap; every other call (targets, results) hits the real database.
    """

    def __init__(self, storage):
        self._storage = storage

    def __getattr__(self, item):
        return getattr(self._storage, item)

    def get_module(self, module_name):
        info = self._storage.get_module(module_name)
        if info is None:
            return None
        return SimpleNamespace(
            name=info.name,
            version=info.version,
            enabled=info.enabled,
            is_sandboxed=info.config.get("is_sandboxed", False),
            timeout=info.config.get("timeout", 30),
        )


def register_module(storage, name="sample_recon", enabled=True, is_sandboxed=False):
    """Persist module metadata the way ``module install`` would."""
    return storage.add_module(
        ModuleInfo(
            name=name,
            version="1.2.3",
            author="Integration Tests",
            description="Offline sample module",
            category="recon",
            target_types=["domain", "ip"],
            config={"is_sandboxed": is_sandboxed, "timeout": 30},
            enabled=enabled,
        )
    )


class TestDiscovery:
    """Modules are discovered from real directories on disk."""

    def test_user_module_is_discovered_with_manifest_metadata(self, module_manager):
        write_sample_module(module_manager.modules_dir)

        discovered = module_manager.discover_modules()

        assert "sample_recon" in discovered
        metadata = discovered["sample_recon"]
        assert isinstance(metadata, ModuleMetadata)
        assert metadata.version == "1.2.3"
        assert metadata.category == "recon"
        assert metadata.target_types == ["domain", "ip"]
        assert metadata.enabled is True

    def test_directory_without_manifest_is_ignored(self, module_manager):
        (module_manager.modules_dir / "not_a_module").mkdir()
        (module_manager.modules_dir / "not_a_module" / "stuff.py").write_text("x = 1\n")
        write_sample_module(module_manager.modules_dir)

        discovered = module_manager.discover_modules()

        assert "not_a_module" not in discovered
        assert "sample_recon" in discovered

    def test_manifest_metadata_is_honoured(self, module_manager):
        write_sample_module(module_manager.modules_dir, name="disabled_module", enabled=False)

        discovered = module_manager.discover_modules()

        assert discovered["disabled_module"].enabled is False


class TestLoading:
    """The loader imports the on-disk package and finds its module class."""

    def test_load_module_imports_package(self, module_manager):
        write_sample_module(module_manager.modules_dir)

        module = module_manager.loader.load_module("sample_recon")

        assert module is not None, "loader could not import the module package"
        assert hasattr(module, "SampleReconModule")

    def test_module_class_is_resolved(self, module_manager):
        write_sample_module(module_manager.modules_dir)
        module = module_manager.loader.load_module("sample_recon")

        module_class = module_manager.executor._get_module_class(module)

        assert module_class is not None
        assert module_class.__name__ == "SampleReconModule"
        assert module_class.get_metadata()["version"] == "1.2.3"

    def test_unknown_module_returns_none(self, module_manager):
        assert module_manager.loader.load_module("definitely_not_installed") is None


class TestExecution:
    """Async execution with results written back to storage."""

    async def test_direct_execution_returns_module_data(self, module_manager):
        write_sample_module(module_manager.modules_dir)
        module = module_manager.loader.load_module("sample_recon")
        module_class = module_manager.executor._get_module_class(module)

        result = await module_manager.executor._execute_direct(module_class, "scope.example", None, 30)

        assert result.status == "success"
        assert result.target == "scope.example"
        assert result.data["records"] == ["203.0.113.10"]
        assert result.data["success"] is True

    async def test_execute_persists_result_for_known_target(self, module_manager, storage):
        write_sample_module(module_manager.modules_dir)
        register_module(storage)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)
        target = storage.add_target("scope.example")

        result = await module_manager.executor.execute("sample_recon", "scope.example")

        assert result.status == "success"
        assert result.error is None

        persisted = storage.get_results_by_target(target.id)
        assert len(persisted) == 1
        assert persisted[0].module == "sample_recon"
        assert persisted[0].data["records"] == ["203.0.113.10"]
        assert persisted[0].status == "success"

    async def test_execute_batch_runs_all_targets(self, module_manager, storage):
        write_sample_module(module_manager.modules_dir)
        register_module(storage)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)
        targets = ["one.example", "two.example", "three.example"]
        for value in targets:
            storage.add_target(value)

        results = await module_manager.executor.execute_batch(
            "sample_recon", targets, max_concurrency=2
        )

        assert [r.status for r in results] == ["success"] * 3
        assert {r.target for r in results} == set(targets)
        assert len(storage.get_results_by_module("sample_recon")) == 3

    async def test_execution_honours_timeout(self, module_manager, storage):
        slow_dir = module_manager.modules_dir / "slow_module"
        slow_dir.mkdir()
        (slow_dir / "manifest.yaml").write_text("name: slow_module\nversion: '1.0'\n")
        (slow_dir / "__init__.py").write_text(
            "import asyncio\n"
            "\n"
            "class SlowModule:\n"
            "    @classmethod\n"
            "    def get_metadata(cls):\n"
            "        return {'name': 'slow_module', 'version': '1.0'}\n"
            "\n"
            "    def __init__(self, config=None):\n"
            "        pass\n"
            "\n"
            "    async def run(self, target, config=None):\n"
            "        await asyncio.sleep(5)\n"
            "        return {}\n"
        )
        module = module_manager.loader.load_module("slow_module")
        module_class = module_manager.executor._get_module_class(module)

        with pytest.raises(asyncio.TimeoutError):
            await module_manager.executor._execute_direct(module_class, "slow.example", None, 1)

    async def test_unknown_module_fails_cleanly(self, module_manager):
        result = await module_manager.executor.execute("missing_module", "scope.example")

        assert result.status == "failed"
        assert "not found" in result.error

    async def test_disabled_module_is_not_executed(self, module_manager, storage):
        write_sample_module(module_manager.modules_dir, name="disabled_module")
        register_module(storage, name="disabled_module", enabled=False)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)

        result = await module_manager.executor.execute("disabled_module", "scope.example")

        assert result.status == "failed"
        assert "disabled" in result.error
        assert storage.get_results_by_module("disabled_module") == []

    async def test_sandboxed_module_is_routed_to_sandbox(self, module_manager, storage, monkeypatch):
        """is_sandboxed=True must go through the sandbox backend, not run inline."""
        write_sample_module(module_manager.modules_dir, name="sandboxed_module")
        register_module(storage, name="sandboxed_module", is_sandboxed=True)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)
        module_manager.config.sandbox.enabled = True
        storage.add_target("sandbox.example")

        calls = []

        class _RecordingSandbox:
            async def execute(self, module_name, target, config=None, sandbox_config=None):
                calls.append((module_name, target, sandbox_config))
                return ModuleResult(
                    target=target,
                    module=module_name,
                    data={"executed": "in-sandbox"},
                    status="success",
                )

        monkeypatch.setattr(module_manager.executor, "sandbox", _RecordingSandbox())

        result = await module_manager.executor.execute("sandboxed_module", "sandbox.example")

        assert calls and calls[0][1] == "sandbox.example"
        assert result.data == {"executed": "in-sandbox"}
        assert len(storage.get_results_by_target(storage.get_target_by_value("sandbox.example").id)) == 1

    @pytest.mark.xfail(
        reason=(
            "ModuleExecutor.execute() reads is_sandboxed/timeout from storage.ModuleInfo, "
            "which does not define them, so execution raises AttributeError"
        ),
        strict=False,
        raises=AttributeError,
    )
    async def test_execute_reads_storage_metadata(self, module_manager, storage):
        """Documents the storage-vs-executor metadata contract mismatch."""
        write_sample_module(module_manager.modules_dir)
        register_module(storage)
        module_manager.executor.storage = storage  # raw storage, no adapter

        await module_manager.executor.execute("sample_recon", "scope.example")


class TestResultPersistenceIntegration:
    """Module results land in the same tables the storage layer reads."""

    async def test_result_row_matches_execution_output(self, module_manager, storage):
        write_sample_module(module_manager.modules_dir)
        register_module(storage)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)
        target = storage.add_target("roundtrip.example")

        execution = await module_manager.executor.execute("sample_recon", "roundtrip.example")

        row = storage.get_results_by_target(target.id)[0]
        assert row.target_id == target.id
        assert row.module_version == "1.2.3"
        assert row.data == execution.data
        assert storage.get_stats()["results_by_module"] == {"sample_recon": 1}

    async def test_second_execution_appends_new_result(self, module_manager, storage):
        write_sample_module(module_manager.modules_dir)
        register_module(storage)
        module_manager.executor.storage = _MetadataAdapterStorage(storage)
        target = storage.add_target("repeat.example")

        await module_manager.executor.execute("sample_recon", "repeat.example")
        await module_manager.executor.execute("sample_recon", "repeat.example")

        assert len(storage.get_results_by_target(target.id)) == 2
