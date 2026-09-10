"""
Cache System for SHADOWSCOPE
Handles caching of API responses and module results.
"""

import os
import json
import pickle
import hashlib
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from rich.console import Console
import threading
import time

console = Console()


@dataclass
class CacheItem:
    """A single cache item"""
    key: str
    value: Any
    expires_at: Optional[float] = None  # Unix timestamp
    created_at: float = field(default_factory=lambda: time.time())
    access_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if the cache item has expired"""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "access_count": self.access_count
        }


class MemoryCache:
    """In-memory cache implementation"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self._cache: Dict[str, CacheItem] = {}
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache"""
        with self._lock:
            item = self._cache.get(key)
            if item:
                if not item.is_expired():
                    item.access_count += 1
                    self._hits += 1
                    return item.value
                else:
                    # Remove expired item
                    del self._cache[key]
            
            self._misses += 1
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        with self._lock:
            # Remove oldest items if cache is full
            if len(self._cache) >= self._max_size:
                self._evict()
            
            expires_at = time.time() + (ttl or self._ttl)
            self._cache[key] = CacheItem(
                key=key,
                value=value,
                expires_at=expires_at
            )
            return True
    
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> int:
        """Clear all cache items"""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count
    
    def _evict(self):
        """Evict oldest items from cache"""
        # Remove expired items first
        expired = [k for k, v in self._cache.items() if v.is_expired()]
        for key in expired:
            del self._cache[key]
        
        # If still full, remove oldest
        if len(self._cache) >= self._max_size:
            # Sort by creation time and remove oldest
            sorted_items = sorted(self._cache.items(), key=lambda x: x[1].created_at)
            for key, _ in sorted_items[:10]:  # Remove 10 oldest
                del self._cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0
            }


class DiskCache:
    """Disk-based cache implementation"""
    
    def __init__(self, cache_dir: Optional[str] = None, ttl: int = 3600):
        self._cache_dir = Path(cache_dir or tempfile.mkdtemp(prefix="shadowscope_cache_"))
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
    
    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache key"""
        # Create a safe filename from the key
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self._cache_dir / f"{key_hash}.cache"
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache"""
        with self._lock:
            cache_path = self._get_cache_path(key)
            
            if not cache_path.exists():
                self._misses += 1
                return None
            
            try:
                with open(cache_path, 'rb') as f:
                    item = pickle.load(f)
                
                if isinstance(item, CacheItem):
                    if not item.is_expired():
                        item.access_count += 1
                        self._hits += 1
                        return item.value
                    else:
                        # Remove expired item
                        cache_path.unlink()
                
                self._misses += 1
                return None
                
            except Exception:
                self._misses += 1
                return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        with self._lock:
            cache_path = self._get_cache_path(key)
            
            expires_at = time.time() + (ttl or self._ttl)
            item = CacheItem(
                key=key,
                value=value,
                expires_at=expires_at
            )
            
            try:
                with open(cache_path, 'wb') as f:
                    pickle.dump(item, f)
                return True
            except Exception as e:
                console.print(f"[red]Error writing to cache: {e}[/red]")
                return False
    
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        with self._lock:
            cache_path = self._get_cache_path(key)
            if cache_path.exists():
                cache_path.unlink()
                return True
            return False
    
    def clear(self) -> int:
        """Clear all cache items"""
        with self._lock:
            count = 0
            for cache_file in self._cache_dir.glob("*.cache"):
                cache_file.unlink()
                count += 1
            return count
    
    def cleanup_expired(self) -> int:
        """Remove all expired cache items"""
        with self._lock:
            count = 0
            for cache_file in self._cache_dir.glob("*.cache"):
                try:
                    with open(cache_file, 'rb') as f:
                        item = pickle.load(f)
                    
                    if isinstance(item, CacheItem) and item.is_expired():
                        cache_file.unlink()
                        count += 1
                except Exception:
                    cache_file.unlink()
                    count += 1
            
            return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                "size": len(list(self._cache_dir.glob("*.cache"))),
                "cache_dir": str(self._cache_dir),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0
            }


class RedisCache:
    """Redis-based cache implementation"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0", ttl: int = 3600):
        self._redis_url = redis_url
        self._ttl = ttl
        self._client = None
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis client"""
        try:
            import redis
            self._client = redis.from_url(self._redis_url, decode_responses=True)
            self._client.ping()
            console.print("[green]+[/green] Redis cache initialized")
        except Exception as e:
            console.print(f"[yellow]Redis not available: {e}[/yellow]")
            self._client = None
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache"""
        if not self._client:
            self._misses += 1
            return None
        
        with self._lock:
            try:
                value = self._client.get(key)
                if value is not None:
                    self._hits += 1
                    return json.loads(value)
                
                self._misses += 1
                return None
            except Exception:
                self._misses += 1
                return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        if not self._client:
            return False
        
        with self._lock:
            try:
                ttl_seconds = ttl or self._ttl
                self._client.setex(key, ttl_seconds, json.dumps(value))
                return True
            except Exception as e:
                console.print(f"[red]Error writing to Redis: {e}[/red]")
                return False
    
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        if not self._client:
            return False
        
        with self._lock:
            try:
                return bool(self._client.delete(key))
            except Exception:
                return False
    
    def clear(self) -> int:
        """Clear all cache items"""
        if not self._client:
            return 0
        
        with self._lock:
            try:
                count = self._client.dbsize()
                self._client.flushdb()
                return count
            except Exception:
                return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            if not self._client:
                return {"error": "Redis not available"}
            
            try:
                return {
                    "size": self._client.dbsize(),
                    "redis_url": self._redis_url,
                    "hits": self._hits,
                    "misses": self._misses,
                    "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0
                }
            except Exception:
                return {"error": "Could not get Redis stats"}


class CacheManager:
    """Manages all cache backends"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        
        self.config = config or global_config
        self._backends: Dict[str, Any] = {}
        self._current_backend: Optional[Any] = None
        self._init_backends()
    
    def _init_backends(self):
        """Initialize all cache backends"""
        cache_config = self.config.performance.cache
        backend = cache_config.get('backend', 'diskcache')
        ttl = cache_config.get('ttl', 3600)
        
        # Initialize memory cache
        self._backends["memory"] = MemoryCache(ttl=ttl)
        
        # Initialize disk cache
        cache_dir = Path("~/.shadowscope/cache").expanduser()
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._backends["diskcache"] = DiskCache(cache_dir=str(cache_dir), ttl=ttl)
        
        # Initialize Redis if configured
        if backend == "redis":
            redis_url = cache_config.get('redis_url', 'redis://localhost:6379/0')
            self._backends["redis"] = RedisCache(redis_url=redis_url, ttl=ttl)
        
        # Set current backend
        self._current_backend = self._backends.get(backend)
        
        if not self._current_backend:
            console.print(f"[yellow]Cache backend '{backend}' not available, falling back to diskcache[/yellow]")
            self._current_backend = self._backends.get("diskcache")
    
    def get(self, key: str, backend: Optional[str] = None) -> Optional[Any]:
        """Get a value from cache"""
        cache = self._backends.get(backend) or self._current_backend
        if cache:
            return cache.get(key)
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None, 
            backend: Optional[str] = None) -> bool:
        """Set a value in cache"""
        cache = self._backends.get(backend) or self._current_backend
        if cache:
            return cache.set(key, value, ttl)
        return False
    
    def delete(self, key: str, backend: Optional[str] = None) -> bool:
        """Delete a value from cache"""
        cache = self._backends.get(backend) or self._current_backend
        if cache:
            return cache.delete(key)
        return False
    
    def clear(self, backend: Optional[str] = None) -> int:
        """Clear all cache items"""
        if backend:
            cache = self._backends.get(backend)
            if cache:
                return cache.clear()
        else:
            total = 0
            for name, cache in self._backends.items():
                total += cache.clear()
            return total
        return 0
    
    def get_backend(self, backend: str) -> Optional[Any]:
        """Get a specific cache backend"""
        return self._backends.get(backend)
    
    def set_backend(self, backend: str) -> bool:
        """Set the current cache backend"""
        if backend in self._backends:
            self._current_backend = self._backends[backend]
            console.print(f"[green]+[/green] Switched cache backend to: {backend}")
            return True
        
        console.print(f"[red]Cache backend '{backend}' not available[/red]")
        return False
    
    def get_backends(self) -> List[str]:
        """Get list of available backends"""
        return list(self._backends.keys())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics for all backends"""
        stats = {}
        for name, backend in self._backends.items():
            stats[name] = backend.get_stats()
        return stats
    
    def generate_cache_key(self, *args, **kwargs) -> str:
        """Generate a unique cache key from arguments"""
        # Sort kwargs for consistent key generation
        sorted_kwargs = sorted(kwargs.items())
        
        # Create a string representation
        key_str = f"{args}{sorted_kwargs}"
        
        # Hash the string
        return hashlib.sha256(key_str.encode()).hexdigest()
    
    def cache_function(self, ttl: Optional[int] = None, 
                      backend: Optional[str] = None, 
                      key_func: Optional[callable] = None):
        """Decorator to cache function results"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = self.generate_cache_key(*args, **kwargs)
                
                # Try to get from cache
                cached_result = self.get(cache_key, backend)
                if cached_result is not None:
                    return cached_result
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Store in cache
                if result is not None:
                    self.set(cache_key, result, ttl, backend)
                
                return result
            
            return wrapper
        return decorator
    
    async def cache_async_function(self, ttl: Optional[int] = None, 
                                   backend: Optional[str] = None, 
                                   key_func: Optional[callable] = None):
        """Decorator to cache async function results"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = self.generate_cache_key(*args, **kwargs)
                
                # Try to get from cache
                cached_result = self.get(cache_key, backend)
                if cached_result is not None:
                    return cached_result
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Store in cache
                if result is not None:
                    self.set(cache_key, result, ttl, backend)
                
                return result
            
            return wrapper
        return decorator


# Initialize cache manager
cache = CacheManager()
