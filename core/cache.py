"""
NexusRE In-Memory LRU Cache with SQLite Persistence

Caches decompilation results, function lookups, and disassembly
so the AI doesn't re-request the same data from slow backends.
Thread-safe with TTL expiration and disk persistence.
"""
import threading
import time
import logging
import sqlite3
import json
import os
from collections import OrderedDict

logger = logging.getLogger("NexusRE")

def get_db_path():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root_dir, "nexusre_brain.db")

class CacheEntry:
    __slots__ = ('value', 'expires_at')

    def __init__(self, value, ttl_seconds):
        self.value = value
        self.expires_at = time.time() + ttl_seconds


class LRUCache:
    """Thread-safe LRU cache with TTL expiration and SQLite persistence."""

    def __init__(self, name: str, max_size: int = 500, default_ttl: int = 300):
        self.name = name
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0
        self._db_path = get_db_path()
        
        self._init_db()
        self._load_from_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS persistent_cache (name TEXT, key TEXT, value TEXT, expires_at REAL, PRIMARY KEY (name, key))"
                )
                conn.commit()
        except Exception as e:
            logger.warning(f"[Cache] Failed to initialize DB for {self.name}: {e}")

    def _load_from_db(self):
        try:
            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key, value, expires_at FROM persistent_cache WHERE name=?", (self.name,))
                now = time.time()
                for row in cursor.fetchall():
                    key, val_json, expires_at = row
                    if now < expires_at:
                        try:
                            val = json.loads(val_json)
                            entry = CacheEntry(val, expires_at - now)
                            entry.expires_at = expires_at
                            self._cache[key] = entry
                        except Exception:
                            pass
                # Evict expired rows
                conn.execute("DELETE FROM persistent_cache WHERE name=? AND expires_at <= ?", (self.name, now))
                conn.commit()
        except Exception as e:
            logger.warning(f"[Cache] Failed to load DB for {self.name}: {e}")

    def _save_to_db(self, key: str, value, expires_at: float):
        try:
            with sqlite3.connect(self._db_path) as conn:
                val_json = json.dumps(value)
                conn.execute(
                    "INSERT OR REPLACE INTO persistent_cache (name, key, value, expires_at) VALUES (?, ?, ?, ?)",
                    (self.name, key, val_json, expires_at)
                )
                conn.commit()
        except Exception:
            pass
            
    def _delete_from_db(self, key: str):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("DELETE FROM persistent_cache WHERE name=? AND key=?", (self.name, key))
                conn.commit()
        except Exception:
            pass
            
    def _delete_prefix_db(self, prefix: str):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("DELETE FROM persistent_cache WHERE name=? AND key LIKE ?", (self.name, prefix + "%"))
                conn.commit()
        except Exception:
            pass
            
    def _clear_db(self):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("DELETE FROM persistent_cache WHERE name=?", (self.name,))
                conn.commit()
        except Exception:
            pass

    def get(self, key: str):
        """Get a value from the cache. Returns None if not found or expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if time.time() > entry.expires_at:
                del self._cache[key]
                threading.Thread(target=self._delete_from_db, args=(key,), daemon=True).start()
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
            ttl_val = ttl or self._default_ttl
            entry = CacheEntry(value, ttl_val)
            self._cache[key] = entry
            threading.Thread(target=self._save_to_db, args=(key, value, entry.expires_at), daemon=True).start()
            
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                old_key, _ = self._cache.popitem(last=False)
                threading.Thread(target=self._delete_from_db, args=(old_key,), daemon=True).start()

    def invalidate(self, key: str):
        """Remove a specific key from the cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                threading.Thread(target=self._delete_from_db, args=(key,), daemon=True).start()

    def invalidate_prefix(self, prefix: str):
        """Remove all keys starting with a prefix (e.g., session invalidation)."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._cache[k]
            if keys_to_remove:
                threading.Thread(target=self._delete_prefix_db, args=(prefix,), daemon=True).start()

    def clear(self):
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            threading.Thread(target=self._clear_db, daemon=True).start()

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
decompile_cache = LRUCache(name="decompile", max_size=500, default_ttl=86400)   # 24h TTL for decompilation (now persistent)
function_cache = LRUCache(name="function", max_size=1000, default_ttl=86400)    # 24h TTL for function lookups
disasm_cache = LRUCache(name="disasm", max_size=300, default_ttl=86400)         # 24h TTL for disassembly
