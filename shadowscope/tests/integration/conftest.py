"""
Shared fixtures for SHADOWSCOPE integration tests.

These tests exercise the framework against real, on-disk and on-the-wire
components (SQLite files, the filesystem-based module pipeline and, when the
CI service containers are available, Redis and PostgreSQL).

Design rules:
  * No network egress is required - every test that would need it is skipped.
  * Every test that touches an external service skips cleanly when the service
    is not reachable, so the suite can also be run locally without the CI
    postgres/redis containers.
  * Nothing writes outside the pytest tmp_path.
"""

import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from shadowscope.core.config import Config

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def redis_url() -> str:
    """Redis URL used by the CI test job (falls back to the local default)."""
    return os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def postgres_dsn() -> str:
    """PostgreSQL DSN used by the CI test job (falls back to the local default)."""
    return os.environ.get(
        "POSTGRES_DSN",
        "postgresql://shadowscope:shadowscope@localhost:5432/shadowscope_test",
    )


def redis_is_available(url: str) -> bool:
    """Return True when the redis server at *url* answers PING."""
    try:
        import redis  # noqa: F401
    except ImportError:
        return False

    import redis

    try:
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        return bool(client.ping())
    except Exception:
        return False


def postgres_is_available(dsn: str) -> bool:
    """Return True when psycopg2 can connect to *dsn*."""
    try:
        import psycopg2  # noqa: F401
    except ImportError:
        return False

    import psycopg2

    try:
        with psycopg2.connect(dsn, connect_timeout=3):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Configuration / storage fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_config(tmp_path):
    """
    A fully isolated Config that never touches the real ~/.shadowscope.

    ``__post_init__`` is skipped (same technique as the unit tests) so that no
    directories, config files or encryption keys are created in $HOME; the
    storage path is redirected into tmp_path instead.
    """
    with patch.object(Config, "__post_init__", lambda self: None):
        config = Config()

    config._encryption_key = Fernet.generate_key()
    config._config_path = tmp_path / "config.yaml"
    config.storage.path = str(tmp_path / "data" / "shadowscope.db")
    config.storage.encryption = {"enabled": "true", "algorithm": "aes-256-cbc"}
    config.sandbox.enabled = False
    config.performance.cache = {"enabled": "true", "backend": "diskcache", "ttl": 60}
    return config


@pytest.fixture
def storage(isolated_config):
    """A Storage instance backed by a throwaway SQLite database."""
    from shadowscope.core.storage import Storage

    return Storage(config=isolated_config)


# ---------------------------------------------------------------------------
# Service fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def redis_cache():
    """A RedisCache pointing at REDIS_URL, skipped when Redis is unreachable."""
    url = redis_url()
    if not redis_is_available(url):
        pytest.skip(f"Redis is not reachable at {url}")

    from shadowscope.core.cache import RedisCache

    cache = RedisCache(redis_url=url, ttl=60)
    yield cache
    # Only remove the keys this suite created - never FLUSHDB a shared server.
    try:
        client = cache._client
        for key in client.scan_iter(match="shadowscope:itest:*"):
            client.delete(key)
    except Exception:
        pass


@pytest.fixture
def postgres_connection():
    """A psycopg2 connection to POSTGRES_DSN, skipped when unreachable."""
    dsn = postgres_dsn()
    if not postgres_is_available(dsn):
        pytest.skip(f"PostgreSQL is not reachable at {dsn}")

    import psycopg2

    conn = psycopg2.connect(dsn, connect_timeout=3)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Module pipeline fixtures
# ---------------------------------------------------------------------------

# Names of the throwaway modules the tests write to disk. They are evicted from
# sys.modules between tests so each test imports the module it just wrote.
TEST_MODULE_NAMES = (
    "sample_recon",
    "disabled_module",
    "sandboxed_module",
    "slow_module",
)

SAMPLE_MODULE_SOURCE = textwrap.dedent(
    '''
    """A sample SHADOWSCOPE module used by the integration tests."""

    # Importing the installed package from a module that lives outside it is
    # only possible when the package is properly installed (pip install -e .).
    from shadowscope.core.modules import ModuleResult  # noqa: F401


    class SampleReconModule:
        """Trivial module that resolves a target without any network access."""

        VERSION = "1.2.3"
        NAME = "sample_recon"

        def __init__(self, config=None):
            self.config = config
            self.calls = []

        @classmethod
        def get_metadata(cls):
            return {
                "name": "sample_recon",
                "version": cls.VERSION,
                "author": "Integration Tests",
                "description": "Offline sample module",
                "category": "recon",
                "target_types": ["domain", "ip"],
                "dependencies": [],
                "is_async": True,
                "is_sandboxed": False,
                "timeout": 30,
            }

        async def run(self, target, config=None):
            self.calls.append(target)
            return {
                "target": target,
                "records": ["203.0.113.10"],
                "source": "integration-test",
                "success": True,
            }
    '''
).lstrip()


def write_sample_module(modules_dir: Path, name: str = "sample_recon", enabled: bool = True):
    """
    Create a real, importable module package on disk (manifest + __init__.py).

    Returns the module directory. This mirrors the layout of an operator
    installed module in ~/.shadowscope/modules/<name>/.
    """
    module_dir = modules_dir / name
    module_dir.mkdir(parents=True, exist_ok=True)

    (module_dir / "manifest.yaml").write_text(
        textwrap.dedent(
            f"""
            name: {name}
            version: "1.2.3"
            author: Integration Tests
            description: Offline sample module
            category: recon
            target_types: [domain, ip]
            dependencies: []
            enabled: {str(enabled).lower()}
            is_async: true
            is_sandboxed: false
            timeout: 30
            """
        ).lstrip()
    )

    source = SAMPLE_MODULE_SOURCE
    if name != "sample_recon":
        source = source.replace("sample_recon", name)
    (module_dir / "__init__.py").write_text(source)

    return module_dir


@pytest.fixture
def module_manager(tmp_path, isolated_config, storage, monkeypatch):
    """
    The module manager that ``ModuleExecutor.execute()`` actually uses, wired
    to throwaway storage and module directories.

    ModuleExecutor.execute() resolves modules through the process-wide manager
    defined in ``shadowscope.core.modules`` (``from .modules import modules``),
    not through a manager created by the test, so this fixture patches that
    singleton instead. monkeypatch restores every attribute afterwards, which
    matters because the unit tests share the same process.
    """
    import importlib

    modules_module = importlib.import_module("shadowscope.core.modules")
    manager = modules_module.modules

    modules_dir = tmp_path / "user_modules"
    local_dir = tmp_path / "local_modules"
    modules_dir.mkdir(exist_ok=True)
    local_dir.mkdir(exist_ok=True)

    monkeypatch.setattr(manager.loader, "_modules_dir", modules_dir)
    monkeypatch.setattr(manager.loader, "_local_modules_dir", local_dir)
    monkeypatch.setattr(manager, "config", isolated_config)
    monkeypatch.setattr(manager.loader, "config", isolated_config)
    monkeypatch.setattr(manager.executor, "config", isolated_config)

    # Make every storage consumer in the pipeline use the throwaway database.
    monkeypatch.setattr(manager, "storage", storage)
    monkeypatch.setattr(manager.executor, "storage", storage)

    # Never reach out to the remote module registry.
    monkeypatch.setattr(manager, "_discover_registry_modules", lambda: {})
    monkeypatch.setattr(manager.loader, "_fetch_from_registry", lambda name: None)

    # Drop imports cached by previous tests so each test imports the module it
    # actually wrote to disk.
    manager.loader._loaded_modules.clear()
    for name in TEST_MODULE_NAMES:
        sys.modules.pop(name, None)

    manager.modules_dir = modules_dir
    manager.local_modules_dir = local_dir
    yield manager

    manager.loader._loaded_modules.clear()
    for name in TEST_MODULE_NAMES:
        sys.modules.pop(name, None)
