"""
Integration tests for the caching layer.

The disk backend is exercised against a real directory (and a real process
restart simulation), and the Redis backend is exercised against the Redis
service container that the CI test job provisions. Redis tests skip cleanly
when REDIS_URL is not reachable, so the suite still runs locally.
"""

import time

import pytest

from shadowscope.core.cache import CacheManager, DiskCache, MemoryCache, RedisCache


@pytest.fixture
def disk_cache(tmp_path):
    return DiskCache(cache_dir=str(tmp_path / "cache"), ttl=60)


class TestMemoryCache:
    def test_set_get_delete(self):
        cache = MemoryCache(ttl=60)
        assert cache.set("k", {"v": 1}) is True
        assert cache.get("k") == {"v": 1}
        assert cache.delete("k") is True
        assert cache.get("k") is None

    def test_entry_expires(self):
        cache = MemoryCache(ttl=1)
        cache.set("k", "v")
        time.sleep(1.1)
        assert cache.get("k") is None

    def test_hit_miss_stats(self):
        cache = MemoryCache(ttl=60)
        cache.set("hit", "value")
        cache.get("hit")
        cache.get("miss")

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1


class TestDiskCache:
    def test_round_trip_persists_on_disk(self, disk_cache, tmp_path):
        assert disk_cache.set("key", {"nested": [1, 2, 3]}) is True

        assert list((tmp_path / "cache").glob("*.cache")), "no cache file written"

        # A brand new instance reads the value written by the first one.
        reopened = DiskCache(cache_dir=str(tmp_path / "cache"), ttl=60)
        assert reopened.get("key") == {"nested": [1, 2, 3]}

    def test_delete_and_clear(self, disk_cache):
        disk_cache.set("a", 1)
        disk_cache.set("b", 2)

        assert disk_cache.delete("a") is True
        assert disk_cache.get("a") is None
        assert disk_cache.clear() >= 1
        assert disk_cache.get("b") is None

    def test_expired_entries_are_not_served(self, tmp_path):
        cache = DiskCache(cache_dir=str(tmp_path / "ttl"), ttl=1)
        cache.set("soon", "value")

        assert cache.get("soon") == "value"
        time.sleep(1.1)
        assert cache.get("soon") is None

    def test_cache_key_is_hashed_not_raw(self, disk_cache, tmp_path):
        disk_cache.set("../unsafe/key", "value")

        files = list((tmp_path / "cache").glob("*.cache"))
        assert len(files) == 1
        assert ".." not in files[0].name
        assert disk_cache.get("../unsafe/key") == "value"


class TestRedisCache:
    """Requires the CI redis service (skipped when unreachable)."""

    def test_round_trip_against_real_redis(self, redis_cache):
        key = "shadowscope:itest:roundtrip"
        assert redis_cache.set(key, {"records": ["203.0.113.10"], "ok": True}) is True

        assert redis_cache.get(key) == {"records": ["203.0.113.10"], "ok": True}
        assert redis_cache.delete(key) is True
        assert redis_cache.get(key) is None

    def test_values_are_shared_between_clients(self, redis_cache):
        key = "shadowscope:itest:shared"
        redis_cache.set(key, {"shared": True})

        other_client = RedisCache(redis_url=redis_cache._redis_url, ttl=60)
        try:
            assert other_client.get(key) == {"shared": True}
        finally:
            other_client.delete(key)

    def test_ttl_is_applied(self, redis_cache):
        key = "shadowscope:itest:ttl"
        redis_cache.set(key, "value", ttl=1)
        assert redis_cache.get(key) == "value"

        time.sleep(1.5)
        assert redis_cache.get(key) is None

    def test_stats_report_configured_url(self, redis_cache):
        redis_cache.set("shadowscope:itest:stats", 1)
        stats = redis_cache.get_stats()

        assert stats["redis_url"] == redis_cache._redis_url
        assert stats["size"] >= 1
        assert 0 <= stats["hit_rate"] <= 1


class TestCacheManager:
    def test_diskcache_is_the_default_backend(self, isolated_config):
        manager = CacheManager(config=isolated_config)

        assert "diskcache" in manager.get_backends()
        assert manager.get_backend("diskcache") is not None

    def test_manager_uses_configured_redis_backend(self, isolated_config):
        from .conftest import redis_is_available, redis_url

        if not redis_is_available(redis_url()):
            pytest.skip(f"Redis is not reachable at {redis_url()}")

        isolated_config.performance.cache = {
            "enabled": "true",
            "backend": "redis",
            "redis_url": redis_url(),
            "ttl": 60,
        }
        manager = CacheManager(config=isolated_config)

        assert "redis" in manager.get_backends()
        assert manager.set_backend("redis") is True

        key = "shadowscope:itest:manager"
        manager.set(key, {"managed": True})
        assert manager.get(key) == {"managed": True}
        manager.get_backend("redis")._client.delete(key)

    def test_generate_cache_key_is_stable_and_distinct(self, isolated_config):
        manager = CacheManager(config=isolated_config)

        first = manager.generate_cache_key("dns", "example.com", depth=2)
        second = manager.generate_cache_key("dns", "example.com", depth=2)
        third = manager.generate_cache_key("dns", "example.com", depth=3)

        assert first == second
        assert first != third
