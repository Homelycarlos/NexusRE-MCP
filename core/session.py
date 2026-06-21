import os
import time
import logging
import threading
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

logger = logging.getLogger("NexusRE")

SUPPORTED_BACKENDS = [
    "ida", "ghidra", "x64dbg", "binja", "radare2",
    "frida", "cheatengine", "gdb", "kernel", "dma", "exdnspy"
]

DEFAULT_PORTS = {
    "ida": 10101,
    "ghidra": 10102,
    "x64dbg": 10103,
    "binja": 10104,
    "cheatengine": 10105,
    "exdnspy": 10106,
    "radare2": 10107,
    "frida": 10108,
    "gdb": 10109,
    "kernel": 10110,
    "dma": 10111,
}

# Session time-to-live in days, configurable via env
SESSION_TTL_DAYS = int(os.environ.get("NEXUSRE_SESSION_TTL_DAYS", "7"))
_SESSION_TTL_SECS = SESSION_TTL_DAYS * 86400


class SessionState(BaseModel):
    backend: str
    binary_path: str
    architecture: str
    backend_url: str = "http://127.0.0.1:10101"
    created_at: float = 0.0   # epoch — set on create, restored from DB


class SessionManager:
    """
    Session manager with default-session support and SQLite persistence.
    Sessions survive server restarts via the BrainMemory database.
    Thread-safe; all mutations go through _lock.
    """
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}
        self._default_session: Optional[str] = None
        self._lock = threading.Lock()
        self._restore_sessions()

    # -- restore / TTL -------------------------------------------------------

    def _restore_sessions(self):
        """Restore sessions from the brain DB on startup, skipping expired."""
        try:
            from .memory import brain
            saved = brain.load_all_sessions()
            now = time.time()
            restored = 0
            for s in saved:
                created = s.get("created_at", now)
                if now - created > _SESSION_TTL_SECS:
                    logger.debug("[Session] Skipping expired session %s (age %.1f days)",
                                 s["session_id"], (now - created) / 86400)
                    continue
                state = SessionState(
                    backend=s["backend"],
                    binary_path=s["binary_path"],
                    architecture=s["architecture"],
                    backend_url=s["backend_url"],
                    created_at=created,
                )
                with self._lock:
                    self._sessions[s["session_id"]] = state
                restored += 1

            with self._lock:
                if len(self._sessions) == 1:
                    self._default_session = next(iter(self._sessions.keys()))
            if restored:
                logger.info("Restored %d session(s) from brain DB", restored)
        except Exception as e:
            logger.debug("[Session] Could not restore sessions: %s", e)

    def delete_expired_sessions(self) -> int:
        """Purge sessions older than TTL. Returns count deleted."""
        now = time.time()
        expired_ids: list[str] = []
        with self._lock:
            for sid, state in list(self._sessions.items()):
                if now - state.created_at > _SESSION_TTL_SECS:
                    expired_ids.append(sid)
            for sid in expired_ids:
                del self._sessions[sid]
                if self._default_session == sid:
                    self._default_session = None

        for sid in expired_ids:
            try:
                from .memory import brain
                brain.delete_session(sid)
            except Exception as e:
                logger.debug("[Session] Failed to delete expired session %s from DB: %s", sid, e)

        if expired_ids:
            logger.info("[Session] Purged %d expired session(s)", len(expired_ids))
        return len(expired_ids)

    # -- CRUD ----------------------------------------------------------------

    def create_session(self, session_id: str, backend: str, binary_path: str,
                       architecture: str, backend_url: str = "") -> SessionState:
        if backend not in SUPPORTED_BACKENDS:
            raise ValueError(f"Unsupported backend '{backend}'. Must be one of: {', '.join(SUPPORTED_BACKENDS)}")

        # Auto-resolve backend URL from default port map if not provided
        if not backend_url:
            port = DEFAULT_PORTS.get(backend)
            if port is None:
                logger.warning("[Session] No default port for backend '%s'; falling back to 10101", backend)
                port = 10101
            backend_url = f"http://127.0.0.1:{port}"

        state = SessionState(
            backend=backend,
            binary_path=binary_path,
            architecture=architecture,
            backend_url=backend_url,
            created_at=time.time(),
        )

        with self._lock:
            self._sessions[session_id] = state
            # Auto-set as default if it's the only session
            if len(self._sessions) == 1:
                self._default_session = session_id

        # Persist to brain DB
        try:
            from .memory import brain
            brain.save_session(session_id, backend, binary_path, architecture, backend_url)
        except Exception as e:
            logger.warning("[Session] Failed to persist session %s: %s", session_id, e)

        return state

    def get_session(self, session_id: Optional[str] = None) -> Optional[SessionState]:
        with self._lock:
            # If no session_id given, try default
            if not session_id or session_id == "auto":
                if self._default_session:
                    return self._sessions.get(self._default_session)
                # If only one session exists, use it
                if len(self._sessions) == 1:
                    return next(iter(self._sessions.values()))
                return None

        # Touch last_used timestamp
        try:
            from .memory import brain
            brain.touch_session(session_id)
        except Exception as e:
            logger.debug("[Session] Failed to touch session %s: %s", session_id, e)

        with self._lock:
            return self._sessions.get(session_id)

    def resolve_session_id(self, session_id: Optional[str] = None) -> Optional[str]:
        """Resolve 'auto' or None to the actual session ID."""
        with self._lock:
            if not session_id or session_id == "auto":
                if self._default_session:
                    return self._default_session
                if len(self._sessions) == 1:
                    return next(iter(self._sessions.keys()))
                return None
            return session_id

    def set_default(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                self._default_session = session_id
                return True
            return False

    def list_sessions(self) -> List[dict]:
        with self._lock:
            result = []
            for sid, state in self._sessions.items():
                result.append({
                    "session_id": sid,
                    "backend": state.backend,
                    "binary_path": state.binary_path,
                    "architecture": state.architecture,
                    "backend_url": state.backend_url,
                    "is_default": sid == self._default_session,
                    "created_at": state.created_at,
                })
            return result

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id not in self._sessions:
                return False
            del self._sessions[session_id]
            if self._default_session == session_id:
                self._default_session = None

        # Remove from brain DB
        try:
            from .memory import brain
            brain.delete_session(session_id)
        except Exception as e:
            logger.warning("[Session] Failed to delete session %s from DB: %s", session_id, e)

        return True

    def touch_session(self, session_id: str):
        """Update last-used timestamp in the brain DB."""
        try:
            from .memory import brain
            brain.touch_session(session_id)
        except Exception as e:
            logger.debug("[Session] Failed to touch session %s: %s", session_id, e)
