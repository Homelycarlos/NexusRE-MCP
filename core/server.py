import json
import logging
from typing import List, Optional, Any
from mcp.server.fastmcp import FastMCP
from .session import SessionManager
from adapters.ida import IDAAdapter
from adapters.ghidra import GhidraAdapter
from adapters.x64dbg import X64DbgAdapter
from adapters.binja import BinjaAdapter
from adapters.r2 import Radare2Adapter
from adapters.frida import FridaAdapter
from adapters.ce import CheatEngineAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema, ErrorSchema
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NexusRE")

mcp = FastMCP("NexusRE MCP Server")
session_manager = SessionManager()

def get_adapter(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise ValueError(f"Invalid session ID: {session_id}")
    if session.backend == "ida":
        return IDAAdapter(session.backend_url)
    elif session.backend == "ghidra":
        return GhidraAdapter(session.backend_url)
    elif session.backend == "x64dbg":
        return X64DbgAdapter(session.backend_url)
    elif session.backend == "binja":
        return BinjaAdapter(session.backend_url)
    elif session.backend == "radare2":
        return Radare2Adapter(session.binary_path)  # Note: r2 takes physical binary_path instead of URL
    elif session.backend == "frida":
        return FridaAdapter(session.binary_path)    # Frida uses binary_path to store the PID or process name
    elif session.backend == "cheatengine":
        return CheatEngineAdapter()                 # Hardcodes default TCP out to 127.0.0.1:10105
    else:
        raise ValueError(f"Unknown backend {session.backend}")

def handle_error(e: Exception) -> dict:
    logger.error(f"Error executing tool: {e}")
    return ErrorSchema(message=str(e), code="TOOL_ERROR").model_dump()

# ═══════════════════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def init_session(session_id: str, backend: str, binary_path: str, architecture: str, backend_url: str = "http://127.0.0.1:10101") -> str:
    """
    Initialize a new NexusRE session.
    backend must be 'ida' or 'ghidra'.
    """
    try:
        session_manager.create_session(session_id, backend, binary_path, architecture, backend_url)
        return f"Session {session_id} successfully created."
    except Exception as e:
        return json.dumps(handle_error(e))

# ═══════════════════════════════════════════════════════════════════════════════
# Decompilation & Function Listing
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_function(session_id: str, address: str) -> Any:
    """Get complete details for a specific function by address."""
    try:
        adapter = get_adapter(session_id)
        func = await adapter.get_function(address)
        if func:
            return func.model_dump()
        return None
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_current_address(session_id: str) -> Any:
    """Get the user's currently selected address in the UI."""
    try:
        adapter = get_adapter(session_id)
        addr = await adapter.get_current_address()
        return {"address": addr}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_current_function(session_id: str) -> Any:
    """Get the user's currently selected function in the UI."""
    try:
        adapter = get_adapter(session_id)
        addr = await adapter.get_current_function()
        return {"address": addr}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def list_functions(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """List all functions in the current binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        funcs = await adapter.list_functions(offset, limit, filter_str)
        return [f.model_dump() for f in funcs]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def decompile_function(session_id: str, address: str) -> Any:
    """Decompile a function at the given address and return C pseudocode."""
    try:
        adapter = get_adapter(session_id)
        code = await adapter.decompile_function(address)
        return {"decompiled": code}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def disassemble_at(session_id: str, address: str) -> Any:
    """Disassemble the function or block at the given address. Returns structured instruction data."""
    try:
        adapter = get_adapter(session_id)
        instructions = await adapter.disassemble_at(address)
        return [i.model_dump() for i in instructions]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def batch_decompile(session_id: str, addresses: list[str]) -> Any:
    """Batch decompile multiple functions at once."""
    try:
        adapter = get_adapter(session_id)
        codes = await adapter.batch_decompile(addresses)
        return {"results": codes}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def analyze_functions(session_id: str, addresses: list[str]) -> Any:
    """Trigger background analysis on a list of function addresses."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.analyze_functions(addresses)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Cross-References
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_xrefs(session_id: str, address: str) -> Any:
    """Get all cross-references to and from the given address."""
    try:
        adapter = get_adapter(session_id)
        xrefs = await adapter.get_xrefs(address)
        return [x.model_dump(by_alias=True) for x in xrefs]
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Data & Strings
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_strings(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """Extract all defined strings from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        strings = await adapter.get_strings(offset, limit, filter_str)
        return [s.model_dump() for s in strings]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_globals(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """Get global data items (named data labels) from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        globals_list = await adapter.get_globals(offset, limit, filter_str)
        return [g.model_dump() for g in globals_list]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_segments(session_id: str, offset: int = 0, limit: int = 100) -> Any:
    """Get all memory segments (.text, .data, .rdata, etc.) from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        segs = await adapter.get_segments(offset, limit)
        return [s.model_dump() for s in segs]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_imports(session_id: str, offset: int = 0, limit: int = 100) -> Any:
    """Get all imported symbols (DLL imports, external references) with pagination."""
    try:
        adapter = get_adapter(session_id)
        imports = await adapter.get_imports(offset, limit)
        return [i.model_dump() for i in imports]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_exports(session_id: str, offset: int = 0, limit: int = 100) -> Any:
    """Get all exported symbols from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        exports = await adapter.get_exports(offset, limit)
        return [e.model_dump() for e in exports]
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Modification & Refactoring
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def rename_symbol(session_id: str, address: str, name: str) -> Any:
    """Rename a symbol or function at the specified address."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.rename_symbol(address, name)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def set_comment(session_id: str, address: str, comment: str, repeatable: bool = False) -> Any:
    """Set a comment at the given address. Use repeatable=True for comments that propagate to xrefs."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_comment(address, comment, repeatable)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def set_function_type(session_id: str, address: str, signature: str) -> Any:
    """Apply a C function prototype/signature to the function at the given address. Example: 'int __fastcall foo(int a1, char *a2)'"""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_function_type(address, signature)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def rename_local_variable(session_id: str, address: str, old_name: str, new_name: str) -> Any:
    """Rename a local variable within a function's decompiled pseudocode."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.rename_local_variable(address, old_name, new_name)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def set_local_variable_type(session_id: str, address: str, variable_name: str, new_type: str) -> Any:
    """Set the type of a local variable within a function. Example: new_type="char *" """
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_local_variable_type(address, variable_name, new_type)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Binary Patching
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def patch_bytes(session_id: str, address: str, hex_bytes: str) -> Any:
    """Overwrite physical program memory bytes at a given address (e.g. '90 90' for NOP)."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.patch_bytes(address, hex_bytes)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def save_binary(session_id: str, output_path: str) -> Any:
    """Recompile/Save the patched binary back to the file system to keep changes."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.save_binary(output_path)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# AI Context Memory (Persistent Brain)
# ═══════════════════════════════════════════════════════════════════════════════

from .memory import brain

@mcp.tool()
def store_knowledge(key: str, summary: str) -> Any:
    """Permanently save a finding, pointer chain, or context summary about a game or binary to the local SQLite DB."""
    try:
        success = brain.store_knowledge(key, summary)
        return {"success": success, "message": f"Saved under key: {key}"}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
def recall_knowledge(query: str) -> Any:
    """Recall permanent findings across sessions. Leave query blank or 'list' to see all keys."""
    try:
        if query.lower() == "list" or not query:
            return {"keys": brain.list_knowledge()}
        return {"data": brain.recall_knowledge(query)}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Dynamic Tracing / Game Hacking Executions
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def instrument_execution(session_id: str, javascript_code: str) -> Any:
    """[FRIDA Backend Only] Inject dynamic javascript hooks into the intercepted process."""
    try:
        adapter = get_adapter(session_id)
        res = await getattr(adapter, 'instrument_execution')(javascript_code)
        return {"outputs": res}
    except AttributeError:
        return handle_error(Exception("The selected backend does not support dynamic Frida execution hooks."))
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def scan_aob(session_id: str, pattern: str) -> Any:
    """[Cheat Engine Only] Scan memory for an AOB pattern (e.g. '48 8b 05 ?? ?? ?? ??')."""
    try:
        adapter = get_adapter(session_id)
        res = await getattr(adapter, 'scan_aob')(pattern)
        return {"address": res} if res else {"error": "Pattern not found."}
    except AttributeError:
        return handle_error(Exception("The selected backend does not support raw AOB scanning."))
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def read_pointer_chain(session_id: str, base_address: str, offsets: List[str]) -> Any:
    """[Cheat Engine Only] Chase a multi-level pointer. (e.g. ['0x18', '0x20', '0x0'])"""
    try:
        adapter = get_adapter(session_id)
        res = await getattr(adapter, 'read_pointer_chain')(base_address, offsets)
        return {"address": res} if res else {"error": "Invalid Pointer Chain."}
    except AttributeError:
        return handle_error(Exception("The selected backend does not support raw pointer reading."))
    except Exception as e:
        return handle_error(e)
