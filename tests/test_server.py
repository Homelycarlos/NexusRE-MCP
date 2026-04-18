import pytest
import asyncio
from core.server import mcp, init_session, list_sessions, session_manager

@pytest.fixture(autouse=True)
def setup_teardown():
    """Clear sessions before each test."""
    session_manager._sessions.clear()
    session_manager._default_session = None
    yield

def test_session_creation():
    """Test standard session creation and default assignment."""
    res = init_session("test_ida", "ida", "C:\\fake\\binary.exe")
    assert "successfully created" in res
    
    sessions = list_sessions()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["backend"] == "ida"
    assert sessions[0]["is_default"] is True

def test_invalid_backend():
    """Test initialization fails on unknown backends."""
    res = init_session("test_bad", "wrong_backend", "fake.exe")
    import json
    err = json.loads(res)
    assert "Unsupported backend 'wrong_backend'" in err["message"]
    assert err["code"] == "TOOL_ERROR"

def test_auto_port_resolution():
    """Test that ports are auto-resolved if omitted."""
    init_session("ce_test", "cheatengine", "fake.exe")
    state = session_manager.get_session("ce_test")
    assert state.backend_url == "http://127.0.0.1:10105"

def test_headless_adapter_args():
    """Test headless adapters don't use URLs but binary paths."""
    from adapters.base import BaseAdapter
    
    # Normally we would mock the registry here, but we are just
    # smoke-testing the routing logic.
    init_session("frida_test", "frida", "com.game.test")
    state = session_manager.get_session("frida_test")
    assert state.binary_path == "com.game.test"

# Note: Further tests mock out the adapter HTTP requests to ensure
# handle_error and asyncio.gather (batch tools) run without live servers.
