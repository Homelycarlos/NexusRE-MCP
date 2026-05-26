"""
NexusRE Auto-Session Detection

Probes all known backend ports on startup and automatically creates
sessions for any running tools. Zero configuration required.
"""
import socket
import logging
import time
import threading

logger = logging.getLogger("NexusRE")

DEFAULT_BACKENDS = {
    "ida":          {"port": 10101, "arch": "x86_64"},
    "ghidra":       {"port": 10102, "arch": "x86_64"},
    "x64dbg":       {"port": 10103, "arch": "x86_64"},
    "binja":        {"port": 10104, "arch": "x86_64"},
    "cheatengine":  {"port": 10105, "arch": "x86_64"},
    "exdnspy":      {"port": 10106, "arch": "x86_64"},
}


def probe_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open and accepting connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def detect_running_backends(host: str = "127.0.0.1") -> list[dict]:
    """Probe all known ports and return a list of detected backends."""
    detected = []
    for backend, info in DEFAULT_BACKENDS.items():
        port = info["port"]
        if probe_port(host, port):
            detected.append({
                "backend": backend,
                "port": port,
                "url": f"http://{host}:{port}",
                "arch": info["arch"]
            })
            logger.info(f"[Auto-Session] Detected {backend} on port {port}")
    return detected


def auto_create_sessions(session_manager, host: str = "127.0.0.1") -> list[dict]:
    """
    Detect running backends and auto-create sessions for each.
    Returns list of created session info dicts.
    """
    detected = detect_running_backends(host)
    created = []

    for backend_info in detected:
        backend = backend_info["backend"]
        session_id = f"auto_{backend}"

        # Skip if session already exists
        existing = session_manager.get_session(session_id)
        if existing:
            created.append({
                "session_id": session_id,
                "backend": backend,
                "status": "already_exists",
                "url": backend_info["url"]
            })
            continue

        try:
            session_manager.create_session(
                session_id=session_id,
                backend=backend,
                binary_path="auto-detected",
                architecture=backend_info["arch"]
            )
            created.append({
                "session_id": session_id,
                "backend": backend,
                "status": "created",
                "url": backend_info["url"]
            })
            logger.info(f"[Auto-Session] Created session '{session_id}' for {backend}")
        except Exception as e:
            logger.warning(f"[Auto-Session] Failed to create session for {backend}: {e}")
            created.append({
                "session_id": session_id,
                "backend": backend,
                "status": f"error: {e}",
                "url": backend_info["url"]
            })

    return created


def check_session_health(session_manager, host: str = "127.0.0.1"):
    """Check health of existing auto sessions and clean up dead ones."""
    for state in session_manager.list_sessions():
        sid = state["session_id"]
        if sid.startswith("auto_"):
            backend = state["backend"]
            port = DEFAULT_BACKENDS.get(backend, {}).get("port")
            if port and not probe_port(host, port, timeout=1.0):
                logger.info(f"[Auto-Session] Session {sid} dead, removing.")
                session_manager.delete_session(sid)

def start_background_probe(session_manager, interval: int = 30):
    """Start a background thread that periodically probes for new backends."""
    def _probe_loop():
        while True:
            try:
                check_session_health(session_manager)
                auto_create_sessions(session_manager)
            except Exception as e:
                logger.debug(f"[Auto-Session] Probe loop error: {e}")
            time.sleep(interval)

    thread = threading.Thread(target=_probe_loop, daemon=True, name="NexusRE-AutoSession")
    thread.start()
    logger.info(f"[Auto-Session] Background probe started (every {interval}s)")
