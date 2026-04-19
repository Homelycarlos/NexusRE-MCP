"""
NexusRE AI Function Similarity Search

Computes similarity between decompiled functions using text-based cosine similarity.
Stores function fingerprints in the brain DB for cross-session searching.
Falls back to difflib when numpy is not available.
"""
import sqlite3
import json
import hashlib
import re
import logging
from collections import Counter

logger = logging.getLogger("NexusRE")


def _tokenize(code: str) -> list:
    """Tokenize decompiled C code into meaningful tokens, stripping noise."""
    # Remove addresses, hex literals that change between builds
    code = re.sub(r'0x[0-9a-fA-F]+', 'HEXVAL', code)
    # Remove variable names like local_XX, param_X, uVar1
    code = re.sub(r'\b(local|param|uVar|iVar|lVar|bVar|cVar|sVar|pVar|ppVar|auVar)\w+', 'VAR', code)
    # Remove FUN_ addresses
    code = re.sub(r'FUN_[0-9a-fA-F]+', 'FUNC', code)
    # Remove DAT_ addresses
    code = re.sub(r'DAT_[0-9a-fA-F]+', 'DATA', code)
    # Tokenize on non-alphanumeric
    tokens = re.findall(r'[a-zA-Z_]\w*|[^\s\w]', code)
    return tokens


def _cosine_similarity(tokens_a: list, tokens_b: list) -> float:
    """Compute cosine similarity between two token lists."""
    counter_a = Counter(tokens_a)
    counter_b = Counter(tokens_b)
    all_tokens = set(counter_a.keys()) | set(counter_b.keys())
    if not all_tokens:
        return 0.0
    dot = sum(counter_a.get(t, 0) * counter_b.get(t, 0) for t in all_tokens)
    mag_a = sum(v ** 2 for v in counter_a.values()) ** 0.5
    mag_b = sum(v ** 2 for v in counter_b.values()) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class SimilarityEngine:
    def __init__(self, db_path="nexusre_brain.db"):
        self.db_path = db_path
        self._init_table()

    def _init_table(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS function_fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        binary_name TEXT,
                        func_address TEXT NOT NULL,
                        func_name TEXT,
                        tokens_json TEXT NOT NULL,
                        code_hash TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(binary_name, func_address)
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"SimilarityEngine init error: {e}")

    def index_function(self, session_id: str, binary_name: str,
                       func_address: str, func_name: str, decompiled_code: str):
        """Index a function's decompiled code for similarity search."""
        tokens = _tokenize(decompiled_code)
        code_hash = hashlib.sha256(decompiled_code.encode()).hexdigest()[:16]
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO function_fingerprints
                    (session_id, binary_name, func_address, func_name, tokens_json, code_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session_id, binary_name, func_address, func_name,
                      json.dumps(tokens), code_hash))
                conn.commit()
        except Exception as e:
            logger.error(f"Index function error: {e}")

    def find_similar(self, decompiled_code: str, binary_name: str = None,
                     top_k: int = 10, threshold: float = 0.5) -> list:
        """Find functions similar to the given decompiled code."""
        query_tokens = _tokenize(decompiled_code)
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                if binary_name:
                    rows = conn.execute(
                        "SELECT func_address, func_name, tokens_json, binary_name "
                        "FROM function_fingerprints WHERE binary_name = ?",
                        (binary_name,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT func_address, func_name, tokens_json, binary_name "
                        "FROM function_fingerprints"
                    ).fetchall()

                for row in rows:
                    stored_tokens = json.loads(row[2])
                    similarity = _cosine_similarity(query_tokens, stored_tokens)
                    if similarity >= threshold:
                        results.append({
                            "address": row[0],
                            "name": row[1],
                            "binary": row[3],
                            "similarity": round(similarity, 4)
                        })

                results.sort(key=lambda x: x["similarity"], reverse=True)
                return results[:top_k]
        except Exception as e:
            logger.error(f"Similarity search error: {e}")
            return []

    def index_count(self, binary_name: str = None) -> int:
        """Get the number of indexed functions."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if binary_name:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM function_fingerprints WHERE binary_name = ?",
                        (binary_name,)
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) FROM function_fingerprints").fetchone()
                return row[0] if row else 0
        except Exception:
            return 0


similarity_engine = SimilarityEngine()
