"""
NexusRE In-Memory LRU Cache

Caches decompilation results, function lookups, and disassembly
so the AI doesn't re-request the same data from slow backends.
Thread-safe with TTL expiration.
"""
import threading
import time
import logging
from collections import OrderedDict

logger = logging.getLogger("NexusRE")


class CacheEntry:
    __slots__ = ('value', 'expires_at')

    def __init__(self, value, ttl_seconds):
        self.value = value
        self.expires_at = time.time() + ttl_seconds


class LRUCache:
    """Thread-safe LRU cache with TTL expiration."""

    def __init__(self, max_size: int = 500, default_ttl: int = 300):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def get(self, key: str):
        """Get a value from the cache. Returns None if not found or expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if time.time() > entry.expires_at:
                del self._cache[key]
                self._misses += 1
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return entry.value

    def set(self, key: str, value, ttl: int = None):
        """Set a value in the cache with optional custom TTL."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = CacheEntry(value, ttl or self._default_ttl)
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def invalidate(self, key: str):
        """Remove a specific key from the cache."""
        with self._lock:
            self._cache.pop(key, None)

    def invalidate_prefix(self, prefix: str):
        """Remove all keys starting with a prefix (e.g., session invalidation)."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._cache[k]

    def clear(self):
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": f"{(self._hits / total * 100):.1f}%" if total > 0 else "0.0%",
                "ttl_seconds": self._default_ttl
            }


# Global cache instances
decompile_cache = LRUCache(max_size=500, default_ttl=600)   # 10 min TTL for decompilation
function_cache = LRUCache(max_size=1000, default_ttl=300)   # 5 min TTL for function lookups
disasm_cache = LRUCache(max_size=300, default_ttl=600)      # 10 min TTL for disassembly
