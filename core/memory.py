import os
import sqlite3
import logging

logger = logging.getLogger("NexusRE")

class BrainMemory:
    """
    A persistent SQLite database to store contextual insights,
    pointer chains, and findings that survive beyond current chat session windows.
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
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize Brain DB: {e}")

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

brain = BrainMemory()
