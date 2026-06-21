"""
NexusRE In-Memory LRU Cache with SQLite Persistence

Caches decompilation results, function lookups, and disassembly
so the AI doesn't re-request the same data from slow backends.
Thread-safe with TTL expiration and disk persistence.

DB writes are batched through a single background writer thread
(commit every 100ms or every 50 queued items, whichever first).
"""
import atexit
import threading
import time
import logging
import sqlite3
import json
import os
import queue
from collections import OrderedDict

logger = logging.getLogger("NexusRE")

_BATCH_SIZE = 50
_FLUSH_INTERVAL = 0.1  # seconds


def get_db_path():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root_dir, "nexusre_brain.db")


# ---------------------------------------------------------------------------
# Batched DB writer — one thread, one connection, transactional commits
# ---------------------------------------------------------------------------

class _DbWriter:
    """Single background thread that drains a queue of SQL operations
    and commits them in batches for throughput."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="cache-db-writer")
        self._thread.start()
        atexit.register(self.flush)

    # -- public API ----------------------------------------------------------

    def enqueue(self, sql: str, params: tuple = ()):
        """Queue a single SQL statement + params for batched execution."""
        self._queue.put((sql, params))

    def flush(self):
        """Drain and commit everything still in the queue (called at shutdown)."""
        self._stop.set()
        self._thread.join(timeout=5)
        # Final drain in the calling thread in case the writer exited early
        self._drain_all()

    # -- internals -----------------------------------------------------------

    def _run(self):
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            while not self._stop.is_set():
                batch = self._collect_batch()
                if batch:
                    self._execute_batch(conn, batch)
                else:
                    # Nothing queued — sleep briefly then re-check
                    self._stop.wait(timeout=_FLUSH_INTERVAL)
        finally:
            # Final drain before closing
            batch = self._collect_batch()
            if batch:
                self._execute_batch(conn, batch)
            conn.close()

    def _collect_batch(self) -> list:
        batch = []
        deadline = time.monotonic() + _FLUSH_INTERVAL
        while len(batch) < _BATCH_SIZE:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                item = self._queue.get(timeout=remaining)
                batch.append(item)
            except queue.Empty:
                break
        return batch

    def _execute_batch(self, conn: sqlite3.Connection, batch: list):
        try:
            cur = conn.cursor()
            for sql, params in batch:
                cur.execute(sql, params)
            conn.commit()
        except Exception as e:
            logger.debug("[Cache] DB batch write failed: %s", e)

    def _drain_all(self):
        """Emergency drain — runs on the caller thread at shutdown."""
        items = []
        while True:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if not items:
            return
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            cur = conn.cursor()
            for sql, params in items:
                cur.execute(sql, params)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("[Cache] DB emergency drain failed: %s", e)


# Singleton writer — created lazily on first LRUCache instantiation
_writer: _DbWriter | None = None
_writer_lock = threading.Lock()


def _get_writer(db_path: str) -> _DbWriter:
    global _writer
    if _writer is None:
        with _writer_lock:
            if _writer is None:
                _writer = _DbWriter(db_path)
    return _writer


# ---------------------------------------------------------------------------

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
        self._writer = _get_writer(self._db_path)

        self._init_db()
        self._load_from_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS persistent_cache (name TEXT, key TEXT, value TEXT, expires_at REAL, PRIMARY KEY (name, key))"
                )
                conn.commit()
        except Exception as e:
            logger.warning("[Cache] Failed to initialize DB for %s: %s", self.name, e)

    def _load_from_db(self):
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
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
                        except (json.JSONDecodeError, TypeError) as e:
                            logger.debug("[Cache] Skipping corrupt entry %s/%s: %s", self.name, key, e)
                # Evict expired rows
                conn.execute("DELETE FROM persistent_cache WHERE name=? AND expires_at <= ?", (self.name, now))
                conn.commit()
        except Exception as e:
            logger.warning("[Cache] Failed to load DB for %s: %s", self.name, e)

    # -- DB ops now go through the batched writer ----------------------------

    def _save_to_db(self, key: str, value, expires_at: float):
        try:
            val_json = json.dumps(value)
        except TypeError as e:
            logger.warning("[Cache] Cannot serialize value for key %s/%s: %s", self.name, key, e)
            return
        self._writer.enqueue(
            "INSERT OR REPLACE INTO persistent_cache (name, key, value, expires_at) VALUES (?, ?, ?, ?)",
            (self.name, key, val_json, expires_at),
        )

    def _delete_from_db(self, key: str):
        self._writer.enqueue(
            "DELETE FROM persistent_cache WHERE name=? AND key=?",
            (self.name, key),
        )

    def _delete_prefix_db(self, prefix: str):
        self._writer.enqueue(
            "DELETE FROM persistent_cache WHERE name=? AND key LIKE ?",
            (self.name, prefix + "%"),
        )

    def _clear_db(self):
        self._writer.enqueue(
            "DELETE FROM persistent_cache WHERE name=?",
            (self.name,),
        )

    # -- public API ----------------------------------------------------------

    def get(self, key: str):
        """Get a value from the cache. Returns None if not found or expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if time.time() > entry.expires_at:
                del self._cache[key]
                self._delete_from_db(key)
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
            self._save_to_db(key, value, entry.expires_at)

            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                old_key, _ = self._cache.popitem(last=False)
                self._delete_from_db(old_key)

    def invalidate(self, key: str):
        """Remove a specific key from the cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._delete_from_db(key)

    def invalidate_prefix(self, prefix: str):
        """Remove all keys starting with a prefix (e.g., session invalidation)."""
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._cache[k]
            if keys_to_remove:
                self._delete_prefix_db(prefix)

    def clear(self):
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._clear_db()

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
