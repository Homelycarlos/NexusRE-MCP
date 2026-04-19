"""
NexusRE-MCP Adapter Contract Tests

Tests the full JSON contract between adapters, schemas, and the server
using a mock adapter that returns realistic data.
"""
import pytest
import json
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema, ErrorSchema
)
from core.session import SessionManager, SessionState, SUPPORTED_BACKENDS, DEFAULT_PORTS


# ═══════════════════════════════════════════════════════════════════════════════
# Schema Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemas:
    """Validate that schemas serialize/deserialize correctly."""

    def test_function_schema(self):
        f = FunctionSchema(
            name="main",
            address="0x140001000",
            size=256,
            instructions=["push rbp", "mov rbp, rsp"],
            decompiled="int main() { return 0; }",
            xrefs=["0x140002000"]
        )
        data = f.model_dump()
        assert data["name"] == "main"
        assert data["address"] == "0x140001000"
        assert data["size"] == 256
        assert len(data["instructions"]) == 2

    def test_string_schema(self):
        s = StringSchema(address="0x140005000", value="Hello World")
        data = s.model_dump()
        assert data["value"] == "Hello World"

    def test_xref_schema(self):
        x = XrefSchema(**{"from": "0x1000", "to": "0x2000", "type": "CALL"})
        data = x.model_dump(by_alias=True)
        assert data["from"] == "0x1000"
        assert data["to"] == "0x2000"

    def test_error_schema_no_collision(self):
        """The old ErrorSchema had 'error: bool = True' which collided with
        'error in response' checks. Verify the new schema uses error_message."""
        e = ErrorSchema(error_message="Something broke", error_code="TOOL_ERROR")
        data = e.model_dump()
        # The critical assertion: 'error' key should NOT exist
        assert "error" not in data
        assert data["error_message"] == "Something broke"
        assert data["error_code"] == "TOOL_ERROR"

    def test_instruction_schema(self):
        i = InstructionSchema(
            address="0x1000",
            mnemonic="mov",
            operands="rax, rbx",
            raw_line="0x1000: mov rax, rbx"
        )
        assert i.mnemonic == "mov"
        assert i.operands == "rax, rbx"

    def test_global_var_schema(self):
        g = GlobalVarSchema(address="0x3000", name="g_PlayerCount", size=4, value="0x00000010")
        assert g.name == "g_PlayerCount"
        assert g.size == 4

    def test_segment_schema(self):
        s = SegmentSchema(
            name=".text",
            start_address="0x140001000",
            end_address="0x140100000",
            size=0xFF000,
            permissions="RX"
        )
        assert s.permissions == "RX"

    def test_import_schema(self):
        i = ImportSchema(address="0x140200000", name="CreateFileA", module="kernel32.dll")
        assert i.module == "kernel32.dll"

    def test_export_schema(self):
        e = ExportSchema(address="0x140001000", name="DllMain")
        assert e.name == "DllMain"


# ═══════════════════════════════════════════════════════════════════════════════
# Session Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSessionManager:
    """Test session lifecycle: create, get, default, delete."""

    def _fresh_manager(self):
        """Create a SessionManager that doesn't restore from any existing brain DB."""
        sm = SessionManager()
        sm._sessions.clear()
        sm._default_session = None
        return sm

    def test_create_session(self):
        sm = self._fresh_manager()
        state = sm.create_session("test1", "ida", "test.exe", "x86_64")
        assert state.backend == "ida"
        assert state.backend_url == "http://127.0.0.1:10101"

    def test_auto_default_session(self):
        sm = self._fresh_manager()
        sm.create_session("only_one", "ghidra", "dump.exe", "x86_64")
        session = sm.get_session()  # No ID — should auto-resolve
        assert session is not None
        assert session.backend == "ghidra"

    def test_auto_resolve_session_id(self):
        sm = self._fresh_manager()
        sm.create_session("s1", "ida", "a.exe", "x86_64")
        resolved = sm.resolve_session_id("auto")
        assert resolved == "s1"

    def test_delete_session(self):
        sm = self._fresh_manager()
        sm.create_session("del_me", "x64dbg", "b.exe", "x86_64")
        assert sm.delete_session("del_me") == True
        assert sm.get_session("del_me") is None

    def test_list_sessions(self):
        sm = self._fresh_manager()
        sm.create_session("a", "ida", "a.exe", "x86_64")
        sm.create_session("b", "ghidra", "b.exe", "x86_64")
        sessions = sm.list_sessions()
        assert len(sessions) == 2
        names = [s["session_id"] for s in sessions]
        assert "a" in names
        assert "b" in names

    def test_unsupported_backend_raises(self):
        sm = self._fresh_manager()
        with pytest.raises(ValueError, match="Unsupported backend"):
            sm.create_session("bad", "notepad", "c.exe", "x86_64")

    def test_default_ports(self):
        assert DEFAULT_PORTS["ida"] == 10101
        assert DEFAULT_PORTS["ghidra"] == 10102
        assert DEFAULT_PORTS["x64dbg"] == 10103
        assert DEFAULT_PORTS["binja"] == 10104
        assert DEFAULT_PORTS["cheatengine"] == 10105

    def test_set_default(self):
        sm = self._fresh_manager()
        sm.create_session("s1", "ida", "a.exe", "x86_64")
        sm.create_session("s2", "ghidra", "b.exe", "x86_64")
        sm.set_default("s2")
        session = sm.get_session()
        assert session.backend == "ghidra"


# ═══════════════════════════════════════════════════════════════════════════════
# Brain Memory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBrainMemory:
    """Test knowledge storage, session persistence, and request logging."""

    def _get_brain(self, tmp_path):
        from core.memory import BrainMemory
        return BrainMemory(db_path=str(tmp_path / "test_brain.db"))

    def test_knowledge_store_and_recall(self, tmp_path):
        brain = self._get_brain(tmp_path)
        assert brain.store_knowledge("test_key", "test value") == True
        result = brain.recall_knowledge("test_key")
        assert "test value" in result

    def test_knowledge_fuzzy_search(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.store_knowledge("fortnite_offsets", "UWorld = 0x12345")
        result = brain.recall_knowledge("fortnite")
        assert "UWorld" in result

    def test_session_persistence(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.save_session("s1", "ida", "test.exe", "x86_64", "http://127.0.0.1:10101")
        sessions = brain.load_all_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "s1"
        assert sessions[0]["backend"] == "ida"

    def test_session_delete(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.save_session("s1", "ida", "test.exe", "x86_64", "http://127.0.0.1:10101")
        brain.delete_session("s1")
        sessions = brain.load_all_sessions()
        assert len(sessions) == 0

    def test_request_log(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.log_request("s1", "list_functions", {"limit": 100}, "ok", 42)
        entries = brain.get_request_log(limit=10)
        assert len(entries) == 1
        assert entries[0]["tool"] == "list_functions"
        assert entries[0]["duration_ms"] == 42

    def test_request_log_filter_by_session(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.log_request("s1", "tool_a", {}, "ok", 10)
        brain.log_request("s2", "tool_b", {}, "ok", 20)
        entries = brain.get_request_log(limit=10, session_id="s1")
        assert len(entries) == 1
        assert entries[0]["tool"] == "tool_a"

    def test_knowledge_list(self, tmp_path):
        brain = self._get_brain(tmp_path)
        brain.store_knowledge("k1", "v1")
        brain.store_knowledge("k2", "v2")
        keys = brain.list_knowledge()
        assert "k1" in keys
        assert "k2" in keys


# ═══════════════════════════════════════════════════════════════════════════════
# Adapter Registry Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdapterRegistry:
    """Verify that the adapter auto-discovery system works."""

    def test_adapters_discovered(self):
        from core.server import _ADAPTER_REGISTRY
        # At minimum, ghidra and ida should always be discovered
        assert "ghidra" in _ADAPTER_REGISTRY
        assert "ida" in _ADAPTER_REGISTRY

    def test_adapter_classes_have_init(self):
        from core.server import _ADAPTER_REGISTRY
        for name, cls in _ADAPTER_REGISTRY.items():
            assert hasattr(cls, "__init__"), f"{name} adapter missing __init__"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
