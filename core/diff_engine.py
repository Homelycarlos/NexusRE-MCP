"""
NexusRE Live Diff Engine

Tracks every mutation (rename, retype, comment, patch) the AI makes to a binary
in a git-style changelog. Supports undo/rollback of the last N changes.
"""
import sqlite3
import json
import time
import logging

logger = logging.getLogger("NexusRE")

class DiffEngine:
    def __init__(self, db_path="nexusre_brain.db"):
        self.db_path = db_path
        self._init_table()

    def _init_table(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS diff_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        target_address TEXT,
                        old_value TEXT,
                        new_value TEXT,
                        metadata_json TEXT,
                        undone INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"DiffEngine init error: {e}")

    def record(self, session_id: str, action_type: str, target_address: str,
               old_value: str, new_value: str, metadata: dict = None):
        """Record a mutation to the diff log."""
        try:
            meta_json = json.dumps(metadata) if metadata else "{}"
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO diff_log (session_id, action_type, target_address,
                                         old_value, new_value, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session_id, action_type, target_address, old_value, new_value, meta_json))
                conn.commit()
        except Exception as e:
            logger.error(f"Diff record error: {e}")

    def get_history(self, session_id: str = None, limit: int = 50) -> list:
        """Retrieve the diff history, newest first."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if session_id:
                    rows = conn.execute(
                        "SELECT id, session_id, action_type, target_address, old_value, new_value, undone, timestamp "
                        "FROM diff_log WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                        (session_id, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT id, session_id, action_type, target_address, old_value, new_value, undone, timestamp "
                        "FROM diff_log ORDER BY id DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                return [
                    {
                        "id": r[0], "session_id": r[1], "action": r[2],
                        "address": r[3], "old": r[4], "new": r[5],
                        "undone": bool(r[6]), "timestamp": r[7]
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error(f"Diff history error: {e}")
            return []

    def get_last_undoable(self, session_id: str) -> dict:
        """Get the most recent non-undone change for a session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT id, action_type, target_address, old_value, new_value, metadata_json "
                    "FROM diff_log WHERE session_id = ? AND undone = 0 ORDER BY id DESC LIMIT 1",
                    (session_id,)
                ).fetchone()
                if row:
                    return {
                        "id": row[0], "action": row[1], "address": row[2],
                        "old": row[3], "new": row[4],
                        "metadata": json.loads(row[5]) if row[5] else {}
                    }
                return None
        except Exception as e:
            logger.error(f"Diff undo lookup error: {e}")
            return None

    def mark_undone(self, diff_id: int):
        """Mark a diff entry as undone."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE diff_log SET undone = 1 WHERE id = ?", (diff_id,))
                conn.commit()
        except Exception as e:
            logger.error(f"Diff mark undone error: {e}")


diff_engine = DiffEngine()
