import os
import sqlite3
import logging
import time

logger = logging.getLogger("NexusRE")

class BrainMemory:
    """
    A persistent SQLite database to store contextual insights,
    pointer chains, findings, sessions, and request audit logs.
    """
    def __init__(self, db_path="nexusre_brain.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS knowledge (
                        key TEXT PRIMARY KEY,
                        summary TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        backend TEXT NOT NULL,
                        binary_path TEXT NOT NULL,
                        architecture TEXT NOT NULL DEFAULT 'x86_64',
                        backend_url TEXT NOT NULL DEFAULT 'http://127.0.0.1:10101',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_used DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS request_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        tool_name TEXT NOT NULL,
                        args_json TEXT,
                        result_summary TEXT,
                        duration_ms INTEGER,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize Brain DB: {e}")

    # ── Knowledge Storage ──────────────────────────────────────────────────

    def store_knowledge(self, key: str, summary: str) -> bool:
        """Store or overwrite a piece of knowledge by an explicit key."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO knowledge (key, summary, timestamp)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (key, summary))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Memory store error: {e}")
            return False

    def recall_knowledge(self, query: str) -> str:
        """Recall knowledge explicitly by key, or do a fuzzy search if key doesn't match."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # 1. Exact Key Match
                cursor.execute("SELECT key, summary, timestamp FROM knowledge WHERE key = ?", (query,))
                row = cursor.fetchone()
                if row:
                    return f"[Exact Match: {row[0]}]\n{row[1]}\n(Saved: {row[2]})"

                # 2. Fuzzy Search Match
                searchable = f"%{query}%"
                cursor.execute("SELECT key, summary, timestamp FROM knowledge WHERE key LIKE ? OR summary LIKE ?", (searchable, searchable))
                rows = cursor.fetchall()
                if not rows:
                    return f"No memories found matching '{query}'"
                
                results = []
                for idx, r in enumerate(rows):
                    results.append(f"----- Finding {idx+1}: {r[0]} -----\n{r[1]}\n(Saved: {r[2]})")
                
                return "\n".join(results)
        except Exception as e:
            logger.error(f"Memory recall error: {e}")
            return str(e)

    def list_knowledge(self) -> list:
        """Return a list of all stored knowledge keys."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key FROM knowledge")
                return [r[0] for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Memory list error: {e}")
            return []

    # ── Session Persistence ────────────────────────────────────────────────

    def save_session(self, session_id: str, backend: str, binary_path: str,
                     architecture: str, backend_url: str) -> bool:
        """Persist a session to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO sessions
                    (session_id, backend, binary_path, architecture, backend_url, last_used)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (session_id, backend, binary_path, architecture, backend_url))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Session save error: {e}")
            return False

    def load_all_sessions(self) -> list:
        """Load all persisted sessions from the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT session_id, backend, binary_path, architecture, backend_url FROM sessions")
                rows = cursor.fetchall()
                return [
                    {
                        "session_id": r[0],
                        "backend": r[1],
                        "binary_path": r[2],
                        "architecture": r[3],
                        "backend_url": r[4]
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error(f"Session load error: {e}")
            return []

    def delete_session(self, session_id: str) -> bool:
        """Delete a persisted session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Session delete error: {e}")
            return False

    def touch_session(self, session_id: str):
        """Update the last_used timestamp for a session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE sessions SET last_used = CURRENT_TIMESTAMP WHERE session_id = ?", (session_id,))
                conn.commit()
        except Exception:
            pass

    # ── Request Audit Log ──────────────────────────────────────────────────

    def log_request(self, session_id: str, tool_name: str, args: dict,
                    result_summary: str, duration_ms: int) -> bool:
        """Log a tool invocation to the audit trail."""
        try:
            import json
            args_json = json.dumps(args) if args else "{}"
            # Truncate result summary to 500 chars to keep DB lean
            if result_summary and len(result_summary) > 500:
                result_summary = result_summary[:500] + "..."
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO request_log (session_id, tool_name, args_json, result_summary, duration_ms)
                    VALUES (?, ?, ?, ?, ?)
                """, (session_id, tool_name, args_json, result_summary, duration_ms))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Request log error: {e}")
            return False

    def get_request_log(self, limit: int = 50, session_id: str = None) -> list:
        """Retrieve recent request log entries."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if session_id:
                    cursor.execute(
                        "SELECT tool_name, args_json, result_summary, duration_ms, timestamp FROM request_log WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                        (session_id, limit)
                    )
                else:
                    cursor.execute(
                        "SELECT tool_name, args_json, result_summary, duration_ms, timestamp FROM request_log ORDER BY id DESC LIMIT ?",
                        (limit,)
                    )
                rows = cursor.fetchall()
                return [
                    {
                        "tool": r[0],
                        "args": r[1],
                        "result": r[2],
                        "duration_ms": r[3],
                        "timestamp": r[4]
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error(f"Request log read error: {e}")
            return []


brain = BrainMemory()
