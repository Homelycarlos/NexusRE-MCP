from typing import Dict, Any, Optional, List
from pydantic import BaseModel

SUPPORTED_BACKENDS = [
    "ida", "ghidra", "x64dbg", "binja", "radare2",
    "frida", "cheatengine", "gdb", "kernel", "dma"
]

DEFAULT_PORTS = {
    "ida": 10101,
    "ghidra": 10102,
    "x64dbg": 10103,
    "binja": 10104,
    "cheatengine": 10105,
}

class SessionState(BaseModel):
    backend: str
    binary_path: str
    architecture: str
    backend_url: str = "http://127.0.0.1:10101"

class SessionManager:
    """
    Session manager with default-session support and SQLite persistence.
    Sessions survive server restarts via the BrainMemory database.
    """
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}
        self._default_session: Optional[str] = None
        self._restore_sessions()

    def _restore_sessions(self):
        """Restore sessions from the brain DB on startup."""
        try:
            from .memory import brain
            saved = brain.load_all_sessions()
            for s in saved:
                state = SessionState(
                    backend=s["backend"],
                    binary_path=s["binary_path"],
                    architecture=s["architecture"],
                    backend_url=s["backend_url"]
                )
                self._sessions[s["session_id"]] = state
            if len(self._sessions) == 1:
                self._default_session = next(iter(self._sessions.keys()))
            if saved:
                import logging
                logging.getLogger("NexusRE").info(
                    f"Restored {len(saved)} session(s) from brain DB"
                )
        except Exception:
            pass  # First run or DB not initialized yet

    def create_session(self, session_id: str, backend: str, binary_path: str, architecture: str, backend_url: str = "") -> SessionState:
        if backend not in SUPPORTED_BACKENDS:
            raise ValueError(f"Unsupported backend '{backend}'. Must be one of: {', '.join(SUPPORTED_BACKENDS)}")

        # Auto-resolve backend URL from default port map if not provided
        if not backend_url:
            port = DEFAULT_PORTS.get(backend, 10101)
            backend_url = f"http://127.0.0.1:{port}"

        state = SessionState(
            backend=backend,
            binary_path=binary_path,
            architecture=architecture,
            backend_url=backend_url
        )
        self._sessions[session_id] = state

        # Auto-set as default if it's the only session
        if len(self._sessions) == 1:
            self._default_session = session_id

        # Persist to brain DB
        try:
            from .memory import brain
            brain.save_session(session_id, backend, binary_path, architecture, backend_url)
        except Exception:
            pass

        return state

    def get_session(self, session_id: Optional[str] = None) -> Optional[SessionState]:
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
        except Exception:
            pass

        return self._sessions.get(session_id)

    def resolve_session_id(self, session_id: Optional[str] = None) -> Optional[str]:
        """Resolve 'auto' or None to the actual session ID."""
        if not session_id or session_id == "auto":
            if self._default_session:
                return self._default_session
            if len(self._sessions) == 1:
                return next(iter(self._sessions.keys()))
            return None
        return session_id

    def set_default(self, session_id: str) -> bool:
        if session_id in self._sessions:
            self._default_session = session_id
            return True
        return False

    def list_sessions(self) -> List[dict]:
        result = []
        for sid, state in self._sessions.items():
            result.append({
                "session_id": sid,
                "backend": state.backend,
                "binary_path": state.binary_path,
                "architecture": state.architecture,
                "backend_url": state.backend_url,
                "is_default": sid == self._default_session
            })
        return result

    def delete_session(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            if self._default_session == session_id:
                self._default_session = None

            # Remove from brain DB
            try:
                from .memory import brain
                brain.delete_session(session_id)
            except Exception:
                pass

            return True
        return False
