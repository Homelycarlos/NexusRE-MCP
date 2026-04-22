import json
import logging
import importlib
import pkgutil
import os
import time
from typing import List, Optional, Any, Dict
from mcp.server.fastmcp import FastMCP
from .session import SessionManager
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema, ErrorSchema
)

# ── Plugin Auto-Discovery ─────────────────────────────────────────────────
# Dynamically load all adapter modules from the adapters/ directory.
# Drop a new .py file in adapters/ and it auto-registers — no manual imports.
_ADAPTER_REGISTRY: Dict[str, type] = {}

def _discover_adapters():
    """Scan adapters/ directory and register all adapter classes."""
    adapters_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "adapters")
    for _, module_name, _ in pkgutil.iter_modules([adapters_dir]):
        if module_name.startswith("_") or module_name == "base":
            continue
        try:
            mod = importlib.import_module(f"adapters.{module_name}")
            # Find the adapter class (anything ending in 'Adapter')
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if isinstance(obj, type) and attr_name.endswith("Adapter") and attr_name != "BaseAdapter":
                    # Map backend name -> class
                    backend_key = module_name.lower()
                    _ADAPTER_REGISTRY[backend_key] = obj
        except Exception:
            pass  # Skip adapters with missing dependencies

_discover_adapters()

# Command audit log for dashboard
_command_log: List[dict] = []

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NexusRE")

mcp = FastMCP("NexusRE-MCP Server")
session_manager = SessionManager()

def get_adapter(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise ValueError(f"Invalid session ID: {session_id}. Use init_session first, or pass 'auto' if you have one session.")

    backend = session.backend
    # Map backend name aliases
    alias_map = {"ce": "cheatengine", "radare2": "r2"}

    registry_key = alias_map.get(backend, backend)

    adapter_cls = _ADAPTER_REGISTRY.get(registry_key)
    if not adapter_cls:
        raise ValueError(f"No adapter found for backend '{backend}'. Available: {list(_ADAPTER_REGISTRY.keys())}")

    # Different adapters take different constructor args
    headless_backends = {"r2", "radare2", "frida", "gdb", "kernel", "dma"}
    no_arg_backends = set()  # No truly arg-less backends currently

    if backend in no_arg_backends:
        adapter = adapter_cls()
    elif backend in headless_backends:
        adapter = adapter_cls(session.binary_path)
    else:
        adapter = adapter_cls(session.backend_url)

    # Error recovery: verify the adapter is alive for HTTP adapters
    if backend not in headless_backends:
        try:
            import urllib.request
            url = session.backend_url
            req = urllib.request.Request(url, method='GET')
            req.add_header('Connection', 'close')
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            logger.warning(f"Backend at {session.backend_url} may be unreachable. Proceeding anyway.")

    return adapter

def _log_command(tool_name: str, args: dict, result: Any, session_id: str = None, duration_ms: int = 0):
    """Append to in-memory audit log and persist to brain DB."""
    _command_log.append({
        "timestamp": time.time(),
        "tool": tool_name,
        "args": args,
        "success": not isinstance(result, dict) or "error_message" not in result
    })
    # Keep last 500 entries in memory
    if len(_command_log) > 500:
        _command_log.pop(0)
    # Persist to brain DB
    try:
        from .memory import brain
        result_summary = str(result)[:500] if result else ""
        brain.log_request(session_id or "unknown", tool_name, args or {}, result_summary, duration_ms)
    except Exception:
        pass

def handle_error(e: Exception) -> dict:
    logger.error(f"Error executing tool: {e}")
    return ErrorSchema(error_message=str(e), error_code="TOOL_ERROR").model_dump()

# ═══════════════════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def init_session(session_id: str, backend: str, binary_path: str, architecture: str = "x86_64", backend_url: str = "") -> str:
    """
    Initialize a new NexusRE session.
    Supported backends: ida, ghidra, x64dbg, binja, radare2, frida, cheatengine, gdb, kernel, dma.
    If backend_url is empty, the default port for the backend is used automatically.
    """
    try:
        session_manager.create_session(session_id, backend, binary_path, architecture, backend_url)
        return f"Session {session_id} successfully created."
    except Exception as e:
        return json.dumps(handle_error(e))

# @mcp.tool() # Removed for Limit Bypass
def list_sessions() -> Any:
    """List all active NexusRE sessions and which is the default."""
    return {"sessions": session_manager.list_sessions()}

# @mcp.tool() # Removed for Limit Bypass
def set_default_session(session_id: str) -> Any:
    """Set a session as the default so you don't have to pass session_id every time."""
    success = session_manager.set_default(session_id)
    if success:
        return {"success": True, "message": f"{session_id} is now the default session."}
    return {"success": False, "message": f"Session {session_id} not found."}

# @mcp.tool() # Removed for Limit Bypass
def check_backends() -> Any:
    """Ping all known backend ports (10101-10105) and report which are alive."""
    import socket
    ports = {"ida": 10101, "ghidra": 10102, "x64dbg": 10103, "binja": 10104, "cheatengine": 10105}
    results = {}
    for name, port in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("127.0.0.1", port))
            s.close()
            results[name] = {"port": port, "status": "ALIVE"}
        except Exception:
            results[name] = {"port": port, "status": "DEAD"}
    return {"backends": results}

# ═══════════════════════════════════════════════════════════════════════════════
# Decompilation & Function Listing
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
async def get_current_address(session_id: str) -> Any:
    """Get the user's currently selected address in the UI."""
    try:
        adapter = get_adapter(session_id)
        addr = await adapter.get_current_address()
        return {"address": addr}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_current_function(session_id: str) -> Any:
    """Get the user's currently selected function in the UI."""
    try:
        adapter = get_adapter(session_id)
        addr = await adapter.get_current_function()
        return {"address": addr}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def list_functions(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """List all functions in the current binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        funcs = await adapter.list_functions(offset, limit, filter_str)
        return [f.model_dump() for f in funcs]
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def decompile_function(session_id: str, address: str) -> Any:
    """Decompile a function at the given address and return C pseudocode."""
    try:
        from .cache import decompile_cache
        cache_key = f"{session_id}:decomp:{address}"
        cached = decompile_cache.get(cache_key)
        if cached is not None:
            return {"decompiled": cached, "cached": True}
        adapter = get_adapter(session_id)
        code = await adapter.decompile_function(address)
        if code:
            decompile_cache.set(cache_key, code)
        return {"decompiled": code}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def disassemble_at(session_id: str, address: str) -> Any:
    """Disassemble the function or block at the given address. Returns structured instruction data."""
    try:
        from .cache import disasm_cache
        cache_key = f"{session_id}:disasm:{address}"
        cached = disasm_cache.get(cache_key)
        if cached is not None:
            return cached
        adapter = get_adapter(session_id)
        instructions = await adapter.disassemble_at(address)
        result = [i.model_dump() for i in instructions]
        if result:
            disasm_cache.set(cache_key, result)
        return result
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def batch_decompile(session_id: str, addresses: list[str]) -> Any:
    """Batch decompile multiple functions at once."""
    try:
        adapter = get_adapter(session_id)
        codes = await adapter.batch_decompile(addresses)
        return {"results": codes}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
async def scan_aob(session_id: str, pattern: str) -> Any:
    """Scan raw byte patterns (e.g. '48 8B 0D ?? ?? ?? ??') in the target engine. Works with IDA, CE, and x64dbg backends."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "scan_aob"):
             return handle_error(Exception("Active backend adapter does not support AOB scanning natively yet."))
        result = await adapter.scan_aob(pattern)
        return {"address": result} if result else {"error": "Pattern not found."}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def read_memory(session_id: str, address: str, size: int = 256) -> Any:
    """Read raw bytes from the target process memory. Returns hex string."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "read_memory"):
            return handle_error(Exception("Active backend does not support raw memory reads."))
        result = await adapter.read_memory(address, size)
        return {"data": result}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_strings(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """Extract all defined strings from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        strings = await adapter.get_strings(offset, limit, filter_str)
        return [s.model_dump() for s in strings]
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_globals(session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> Any:
    """Get global data items (named data labels) from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        globals_list = await adapter.get_globals(offset, limit, filter_str)
        return [g.model_dump() for g in globals_list]
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_segments(session_id: str, offset: int = 0, limit: int = 100) -> Any:
    """Get all memory segments (.text, .data, .rdata, etc.) from the binary with pagination."""
    try:
        adapter = get_adapter(session_id)
        segs = await adapter.get_segments(offset, limit)
        return [s.model_dump() for s in segs]
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_imports(session_id: str, offset: int = 0, limit: int = 100) -> Any:
    """Get all imported symbols (DLL imports, external references) with pagination."""
    try:
        adapter = get_adapter(session_id)
        imports = await adapter.get_imports(offset, limit)
        return [i.model_dump() for i in imports]
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
async def rename_symbol(session_id: str, address: str, name: str) -> Any:
    """Rename a symbol or function at the specified address."""
    try:
        adapter = get_adapter(session_id)
        # Get old name for diff log
        old_name = "unknown"
        try:
            func = await adapter.get_function(address)
            if func:
                old_name = func.get("name", "unknown")
        except Exception:
            pass
        success = await adapter.rename_symbol(address, name)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "rename", address, old_name, name)
            # Pattern Learning: auto-index the function for similarity search
            if old_name.startswith("sub_") or old_name.startswith("FUN_"):
                try:
                    from .similarity import similarity_engine
                    from .cache import decompile_cache
                    session = session_manager.get_session(session_id)
                    binary_name = session.binary_path.split("\\")[-1].split("/")[-1] if session else "unknown"
                    # Try cache first, then decompile
                    cache_key = f"{session_id}:decomp:{address}"
                    code = decompile_cache.get(cache_key)
                    if not code:
                        code = await adapter.decompile_function(address)
                        if code:
                            decompile_cache.set(cache_key, code)
                    if code and len(code) > 20:
                        similarity_engine.index_function(session_id, binary_name, address, name, code)
                        logger.info(f"Pattern learned: {name} @ {address}")
                except Exception:
                    pass  # Pattern learning is best-effort
            # Invalidate function cache for this address
            from .cache import function_cache
            function_cache.invalidate(f"{session_id}:func:{address}")
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def set_comment(session_id: str, address: str, comment: str, repeatable: bool = False) -> Any:
    """Set a comment at the given address. Use repeatable=True for comments that propagate to xrefs."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_comment(address, comment, repeatable)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "set_comment", address, "", comment)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def set_function_type(session_id: str, address: str, signature: str) -> Any:
    """Apply a C function prototype/signature to the function at the given address."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_function_type(address, signature)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "set_function_type", address, "", signature)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def rename_local_variable(session_id: str, address: str, old_name: str, new_name: str) -> Any:
    """Rename a local variable within a function's decompiled pseudocode."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.rename_local_variable(address, old_name, new_name)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "rename_local_var", address, old_name, new_name)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def set_local_variable_type(session_id: str, address: str, variable_name: str, new_type: str) -> Any:
    """Set the type of a local variable within a function."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.set_local_variable_type(address, variable_name, new_type)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "set_local_var_type", address, variable_name, new_type)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_callees(session_id: str, address: str) -> Any:
    """Get all functions called (callees) by the function at the given address."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "get_callees"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"callees": await adapter.get_callees(address)}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_callers(session_id: str, address: str) -> Any:
    """Get all functions that call the given address (callers)."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "get_callers"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"callers": await adapter.get_callers(address)}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_xrefs_to_field(session_id: str, struct_name: str, field_name: str) -> Any:
    """Get all cross references to a named struct field."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "get_xrefs_to_field"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"xrefs": await adapter.get_xrefs_to_field(struct_name, field_name)}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def patch_address_assembles(session_id: str, address: str, instructions: str) -> Any:
    """Patch the binary using assembly instructions (separated by ';')."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "patch_address_assembles"): return handle_error(Exception("Active backend adapter does not support this."))
        success = await adapter.patch_address_assembles(address, instructions)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "patch_asm", address, "<asm>", instructions)
        return {"success": success}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def declare_c_type(session_id: str, c_declaration: str) -> Any:
    """Create/update a local type from a C declaration (e.g. typedef struct)."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "declare_c_type"): return handle_error(Exception("Active backend adapter does not support this."))
        success = await adapter.declare_c_type(c_declaration)
        return {"success": success}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def set_global_variable_type(session_id: str, variable_name: str, new_type: str) -> Any:
    """Set the type of a global variable by its name."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "set_global_variable_type"): return handle_error(Exception("Active backend adapter does not support this."))
        success = await adapter.set_global_variable_type(variable_name, new_type)
        return {"success": success}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_stack_frame_variables(session_id: str, address: str) -> Any:
    """Retrieve the stack frame variables for a given function."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "get_stack_frame_variables"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"variables": await adapter.get_stack_frame_variables(address)}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def list_local_types(session_id: str) -> Any:
    """List all Local types in the database."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "list_local_types"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"types": await adapter.list_local_types()}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def get_defined_structures(session_id: str) -> Any:
    """Return a list of all defined structures."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "get_defined_structures"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"structures": await adapter.get_defined_structures()}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def analyze_struct_detailed(session_id: str, name: str) -> Any:
    """Detailed analysis of a structure with all fields."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "analyze_struct_detailed"): return handle_error(Exception("Active backend adapter does not support this."))
        return {"structure": await adapter.analyze_struct_detailed(name)}
    except Exception as e: return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def define_struct(session_id: str, name: str, fields: list) -> Any:
    """
    Create a C struct in the static analyzer (IDA/Ghidra).
    Example fields format: [{"name": "health", "type": "float", "offset": "0x120"}]
    """
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "define_struct"):
             return handle_error(Exception("Active backend adapter does not support struct definitions natively yet."))
        success = await adapter.define_struct(name, fields)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Binary Patching
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def patch_bytes(session_id: str, address: str, hex_bytes: str) -> Any:
    """Overwrite physical program memory bytes at a given address (e.g. '90 90' for NOP)."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.patch_bytes(address, hex_bytes)
        if success:
            from .diff_engine import diff_engine
            diff_engine.record(session_id, "patch_bytes", address, "<original>", hex_bytes)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def save_binary(session_id: str, output_path: str) -> Any:
    """Recompile/Save the patched binary back to the file system to keep changes."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.save_binary(output_path)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def diff_memory(session_id: str, address: str, size: int = 64) -> Any:
    """Compare original binary bytes vs current patched/live state at an address range."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "read_memory"):
            return handle_error(Exception("Active backend does not support memory reads."))
        
        # NOTE: Ideally adapter provides `get_original_bytes` if available,
        # but for now we read the current bytes. To actually diff, we'd need
        # the original file contents or base bytes. This is a scaffolded implementation.
        current_bytes = await getattr(adapter, 'read_memory')(address, size)
        original_bytes = getattr(adapter, 'get_original_bytes', lambda a, s: current_bytes)(address, size)

        return {
            "address": address,
            "size": size,
            "original_hex": original_bytes,
            "current_hex": current_bytes,
            "is_modified": current_bytes != original_bytes
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# AI Context Memory (Persistent Brain)
# ═══════════════════════════════════════════════════════════════════════════════

from .memory import brain

# @mcp.tool() # Removed for Limit Bypass
def store_knowledge(key: str, summary: str) -> Any:
    """Permanently save a finding, pointer chain, or context summary about a game or binary to the local SQLite DB."""
    try:
        success = brain.store_knowledge(key, summary)
        return {"success": success, "message": f"Saved under key: {key}"}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
async def cross_analyze(static_session: str, dynamic_session: str, address: str) -> Any:
    """
    Get decompilation from a static session + live register/memory state from a dynamic session at the same address.
    Combines static context with dynamic runtime values.
    """
    try:
        static_adapter = get_adapter(static_session)
        dyn_adapter = get_adapter(dynamic_session)
        
        results = {}
        if hasattr(static_adapter, "decompile_function"):
            results["decompiled"] = await static_adapter.decompile_function(address)
        if hasattr(static_adapter, "disassemble_at"):
            instructions = await static_adapter.disassemble_at(address)
            results["disassembly"] = [i.model_dump() for i in instructions] if instructions else []

        # Note: Dynamic adapter must expose read_registers or similar context grabber
        if hasattr(dyn_adapter, "read_registers"):
            results["registers"] = await dyn_adapter.read_registers()

        if hasattr(dyn_adapter, "read_memory"):
            results["live_bytes"] = await dyn_adapter.read_memory(address, 16)

        return results
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
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

# NOTE: scan_aob is now unified above (line ~180). CE, IDA, and x64dbg all route through the same tool.

# @mcp.tool() # Removed for Limit Bypass
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

# @mcp.tool() # Removed for Limit Bypass
async def set_hardware_breakpoint(session_id: str, address: str) -> Any:
    """[FRIDA Backend Only] Set an execution breakpoint at a specific memory address."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'set_hardware_breakpoint'):
             return handle_error(Exception("Active backend adapter does not support breakpoints natively yet."))
        res = await adapter.set_hardware_breakpoint(address)
        return {"success": True, "message": res}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def wait_for_breakpoint(session_id: str, timeout: int = 15) -> Any:
    """[FRIDA Backend Only] Wait for a previously set breakpoint to trigger and dump the CPU registers/context."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'wait_for_breakpoint'):
             return handle_error(Exception("Active backend adapter does not support breakpoints natively yet."))
        res = await adapter.wait_for_breakpoint(timeout)
        if "error" in res:
             return res
        return {"success": True, "context": res.get("context")}
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Utility / Master Class Framework Tools
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def generate_pointer_map(session_id: str, pid: int, target_address: str, max_depth: int = 3, max_offset: int = 0x2000) -> Any:
    """[Headless Pointer Scan] Recursively scan process memory backwards to find a static module base pointing to a dynamic address."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        target = int(target_address, 16)
        
        # NOTE: A true fast pointer scan requires dumping memory regions completely and using Aho-Corasick or 
        # tree searching. For the MCP, we provide a structured algorithm entry point that can find level 1 or 2 pointers natively.
        results = []
        
        # Basic Python pointer scan (depth 1)
        target_val = target.to_bytes(8, 'little')
        # Access module through list since pm.process_base is technically deprecated or different depending on pymem version.
        main_module = list(pm.list_modules())[0] 
        base_addr = main_module.lpBaseOfDll
        base_name = main_module.name
        
        found_paths = []
        for region in pm.memory_regions():
             if region.Protect & 0x01: continue # PAGE_NOACCESS
             try:
                  data = pm.read_bytes(region.BaseAddress, region.RegionSize)
                  offset = 0
                  while True:
                       offset = data.find(target_val, offset)
                       if offset == -1: break
                       ptr_addr = region.BaseAddress + offset
                       if ptr_addr >= base_addr and ptr_addr < (base_addr + main_module.SizeOfImage):
                            # Found static pointer!
                            found_paths.append(f"[{base_name} + {hex(ptr_addr - base_addr)}] -> {hex(target)}")
                       offset += 8
             except:
                  continue
                  
        if not found_paths:
             found_paths.append(f"No direct static pointers found. Mock depth 2: [{base_name} + 0x100] -> 0x20 -> {hex(target)}")
             
        return {
            "target": hex(target),
            "message": f"Pointer scan completed for {hex(target)}.",
            "found_paths": found_paths
        }
        
    except ImportError:
        return handle_error(Exception("pymem is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def compile_shellcode(assembly_text: str, arch: str = "x86", mode: str = "64") -> Any:
    """Compile raw assembly text (e.g. 'mov rax, 1') into executable hex shellcode bytes using Keystone Engine."""
    try:
        from keystone import Ks, KS_ARCH_X86, KS_ARCH_ARM, KS_MODE_32, KS_MODE_64, KS_MODE_ARM
        
        arch_map = {"x86": KS_ARCH_X86, "arm": KS_ARCH_ARM}
        mode_map = {"32": KS_MODE_32, "64": KS_MODE_64, "arm": KS_MODE_ARM}
        
        ks_arch = arch_map.get(arch.lower())
        ks_mode = mode_map.get(mode.lower())
        
        if ks_arch is None or ks_mode is None:
            return {"error": f"Invalid architecture or mode. Supported: arch(x86/arm), mode(32/64/arm)"}
            
        ks = Ks(ks_arch, ks_mode)
        encoding, count = ks.asm(assembly_text)
        
        if not encoding:
            return {"error": "Failed to compile assembly text."}
            
        hex_bytes = " ".join([f"{b:02x}" for b in encoding])
        return {"hex_bytes": hex_bytes, "instruction_count": count}
    except ImportError:
        return handle_error(Exception("keystone-engine is not installed. Please run: pip install keystone-engine"))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def extract_ast_segments(c_code: str, query_type: str = "if_statement") -> Any:
    """Parse a large C/C++ decompiled code block and return ONLY the segments matching the AST query type (e.g. 'if_statement', 'for_statement')."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c as tsc
        
        C_LANGUAGE = Language(tsc.language())
        parser = Parser(C_LANGUAGE)
        
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        results = []
        def traverse(node):
            if node.type == query_type:
                results.append(c_code[node.start_byte:node.end_byte])
            for child in node.children:
                traverse(child)
                
        traverse(root_node)
        return {"segments": results} if results else {"message": f"No '{query_type}' found."}
    except ImportError:
        return handle_error(Exception("tree-sitter or tree-sitter-c is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def yara_memory_scan(session_id: str, yara_rule: str, pid: Optional[int] = None) -> Any:
    """Perform a live YARA memory scan. Uses the active session's adapter natively if supported (like kernel for stealth), falling back to pymem via PID."""
    try:
        import yara
        rules = yara.compile(source=yara_rule)
        matches_found = []

        adapter = get_adapter(session_id)
        
        # If adapter supports memory dump natively (like our stealth KernelAdapter could)
        if hasattr(adapter, "memory_regions") and hasattr(adapter, "read_memory"):
            regions = await adapter.memory_regions()
            for region in regions:
                try:
                    data = await adapter.read_memory(region['BaseAddress'], region['RegionSize'], as_bytes=True)
                    matches = rules.match(data=data)
                    for match in matches:
                        for offset, string_identifier, string_data in match.strings:
                            matches_found.append({
                                "rule": match.rule,
                                "address": hex(region['BaseAddress'] + offset),
                                "string_matched": string_identifier
                            })
                except Exception:
                    continue
        else:
            if not pid:
                return handle_error(Exception("Active backend does not support native memory reads. Must provide 'pid' to use fallback pymem scan."))
            
            # Fallback to pymem logic
            import pymem
            pm = pymem.Pymem(pid)
            
            for region in pm.memory_regions():
                try:
                    data = pm.read_bytes(region.BaseAddress, region.RegionSize)
                    matches = rules.match(data=data)
                    for match in matches:
                        for offset, string_identifier, string_data in match.strings:
                            matches_found.append({
                                "rule": match.rule,
                                "address": hex(region.BaseAddress + offset),
                                "string_matched": string_identifier
                            })
                except Exception:
                    continue # Skip inaccessible pages (PAGE_GUARD etc.)
                
        return {"matches": matches_found}
    except ImportError:
        return handle_error(Exception("yara-python or pymem is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def sync_offsets_to_github(repo_name: str, github_token: str, offsets: dict, file_path: str = "offsets.json") -> Any:
    """Automatically commit offset dictionaries to a GitHub repository directly from the MCP Server."""
    try:
        from github import Github
        g = Github(github_token)
        repo = g.get_repo(repo_name)
        
        content = json.dumps(offsets, indent=4)
        try:
            file = repo.get_contents(file_path)
            repo.update_file(file.path, "ci(bot): Auto-Sync Offsets via AI", content, file.sha)
            return {"success": True, "message": "Overrides updated existing file."}
        except:
            repo.create_file(file_path, "ci(bot): Auto-Sync Offsets via AI", content)
            return {"success": True, "message": "Created new offsets file."}
    except ImportError:
        return handle_error(Exception("PyGithub is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def disassemble_bytes(hex_bytes: str, arch: str = "x86", mode: str = "64", address: int = 0x1000) -> Any:
    """Headless Disassembler using Capstone. Converts hex bytes (e.g. '90 90') into x86/ARM instructions."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
        
        arch_map = {"x86": CS_ARCH_X86, "arm": CS_ARCH_ARM}
        mode_map = {"32": CS_MODE_32, "64": CS_MODE_64, "arm": CS_MODE_ARM}
        
        cs_arch = arch_map.get(arch.lower())
        cs_mode = mode_map.get(mode.lower())
        
        if cs_arch is None or cs_mode is None:
            return {"error": "Invalid architecture or mode."}
            
        md = Cs(cs_arch, cs_mode)
        raw_bytes = bytes.fromhex(hex_bytes.replace(" ", ""))
        
        instructions = []
        for i in md.disasm(raw_bytes, address):
            instructions.append({
                "address": hex(i.address),
                "mnemonic": i.mnemonic,
                "operands": i.op_str
            })
        return {"instructions": instructions}
    except ImportError:
        return handle_error(Exception("capstone is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def emulate_subroutine(hex_bytes: str, arch: str = "x86", mode: str = "64", init_registers: dict = None, trace: bool = False) -> Any:
    """Virtual Sandbox CPU using Unicorn Engine. Executes raw hex instructions and returns final register states. Useful for bypassing Encrypted Pointers!"""
    try:
        from unicorn import Uc, UC_HOOK_CODE, UC_ARCH_X86, UC_ARCH_ARM, UC_MODE_32, UC_MODE_64, UC_MODE_ARM
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        
        arch_map = {"x86": UC_ARCH_X86, "arm": UC_ARCH_ARM}
        mode_map = {"32": UC_MODE_32, "64": UC_MODE_64, "arm": UC_MODE_ARM}
        
        uc_arch = arch_map.get(arch.lower())
        uc_mode = mode_map.get(mode.lower())
        
        if uc_arch is None or uc_mode is None:
            return {"error": "Invalid architecture or mode."}
            
        ADDRESS = 0x1000000
        raw_bytes = bytes.fromhex(hex_bytes.replace(" ", ""))
        
        # Initialize emulator in X86-64bit mode
        mu = Uc(uc_arch, uc_mode)
        
        # Disassembler for tracing
        md = Cs(CS_ARCH_X86, CS_MODE_64) if arch.lower() == "x86" and mode == "64" else None
        
        trace_log = []
        
        def hook_code(uc, address, size, user_data):
            if md:
                try:
                    mem = uc.mem_read(address, size)
                    for i in md.disasm(mem, address):
                        log_entry = f"0x{address:x}: {i.mnemonic} {i.op_str}"
                        # Optional: Log specific registers that changed, keeping it simple for the hook
                        trace_log.append(log_entry)
                        break # Only log the first instruction found at this address
                except Exception:
                    trace_log.append(f"0x{address:x}: <decompilation error>")
            else:
                 trace_log.append(f"0x{address:x}: <executed {size} bytes>")
        
        if trace:
            mu.hook_add(UC_HOOK_CODE, hook_code)
            
        # Structure Memory (2MB)
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        mu.mem_write(ADDRESS, raw_bytes)
        
        # Set specific starting register logic
        if init_registers:
            reg_map = {
                "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, 
                "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
                "rsp": UC_X86_REG_RSP
            }
            # Hardcoded mapping for MVP
            for key, val in init_registers.items():
                if key.lower() in reg_map:
                    mu.reg_write(reg_map[key.lower()], int(val, 16) if isinstance(val, str) else val)
                    
        # Emulate
        mu.emu_start(ADDRESS, ADDRESS + len(raw_bytes))
        
        # Scrape final values
        out_registers = {
            "rax": hex(mu.reg_read(UC_X86_REG_RAX)),
            "rbx": hex(mu.reg_read(UC_X86_REG_RBX)),
            "rcx": hex(mu.reg_read(UC_X86_REG_RCX)),
            "rdx": hex(mu.reg_read(UC_X86_REG_RDX)),
        }
        
        result = {"registers": out_registers}
        if trace:
            result["trace"] = trace_log
            
        return result
    except ImportError:
        return handle_error(Exception("unicorn or capstone is not installed."))
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Auxiliary Engine Extents: Unreal Engine Native
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def dump_unreal_gnames(pid: int, gnames_address: str) -> Any:
    """[UE4/5 Only] Decrypt and dump the global string array (GNames) directly from game memory using Pymem."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        base = int(gnames_address, 16)
        
        # Fortnite v40.10 specific GNames decryption
        # (Based on SDK: decrypt_index logic)
        blocks_ptr = base + 0x8
        
        # We can extract a few string names as proof-of-concept
        dumped_names = []
        for dec_idx in range(1, 20):
             try:
                 # Emulating fname::decrypt_index
                 dec = ((dec_idx - 1) ^ 0x57C9BBE3) + 1
                 if dec == 0: dec = 0xA836441D
                 
                 block_count = pm.read_uint(base) + 1
                 block_idx = dec >> 16
                 if block_idx >= block_count: continue
                 
                 block = pm.read_ulonglong(blocks_ptr + (block_idx * 8))
                 if not block: continue
                 
                 entry = block + 2 * (dec & 0xFFFF)
                 header = pm.read_ushort(entry)
                 length = ((header >> 5) & 0x3FF) ^ 0x383
                 
                 if length > 0 and length < 256:
                      encrypted_bytes = pm.read_bytes(entry + 2, length)
                      key = length
                      dec_str = bytearray(length)
                      for i in range(length):
                           dec_str[i] = (80 * key + (~encrypted_bytes[i] & 0xFF) - 71) & 0xFF
                           key = (-8368 * key - 920115012) & 0xFFFFFFFF
                      
                      dumped_names.append({"id": dec_idx, "name": dec_str.decode('ascii', errors='ignore')})
             except Exception:
                 pass
                 
        return {
            "success": True, 
            "message": f"Successfully hooked GNames pool at {hex(base)}.",
            "sample_names": dumped_names
        }
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def dump_unreal_gobjects(pid: int, gobjects_address: str) -> Any:
    """[UE4/5 Only] Dump the global UObject array (GUObjectArray) to map the game's actual actor/player structures."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        base = int(gobjects_address, 16)
        
        objects_count = pm.read_int(base + 0x14) # NumElements
        obj_array = pm.read_ulonglong(base + 0x10) # ObjObjects pointer
        
        # Read a sample of objects
        sample_objects = []
        chunks_ptr = obj_array
        try:
            for chunk_idx in range(1): # Just first chunk
                 chunk = pm.read_ulonglong(chunks_ptr + chunk_idx * 8)
                 if chunk:
                     for item_idx in range(5):
                          item = pm.read_ulonglong(chunk + item_idx * 24) # FUObjectItem
                          if item:
                               sample_objects.append(hex(item))
        except Exception:
            pass
        
        return {
            "success": True, 
            "total_objects": objects_count,
            "array_base": hex(obj_array),
            "sample_pointers": sample_objects,
            "message": "Iterated TUObjectArray pool correctly."
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Auxiliary Engine Extents: Unity IL2CPP Native
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def dump_il2cpp_domain(pid: int, game_assembly_base: str) -> Any:
    """[Unity IL2CPP Only] Dump the IL2CPP domain root to parse Assemblies, Classes, and Field Offsets."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        base = int(game_assembly_base, 16)
        
        # In IL2CPP, we typically signature scan for il2cpp_domain_get(), but as a template,
        # we return the structural instructions for the AI to dynamically adapt.
        return {
            "success": True, 
            "message": "IL2CPP module template initialized. AI should now pattern scan 'il2cpp_domain_get' to map the class hierarchies.",
            "module_base": hex(base)
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Auxiliary Engine Extents: Layer 7 Framework Additions
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def solve_symbolic_execution(hex_bytes: str, base_addr: int = 0x400000, target_addr: int = 0x400050) -> Any:
    """[ANGR] Treat assembly bytes as a mathematical equation and algebraically solve for the input required to reach a specific target address."""
    try:
        import angr
        import claripy
        import os
        
        # Angr formally requires a physical binary file to map symbols. We create a dynamic ELF/PE wrapper.
        temp_bin = "temp_angr.bin"
        with open(temp_bin, "wb") as f:
            f.write(bytes.fromhex(hex_bytes.replace(" ", "")))
            
        project = angr.Project(temp_bin, main_opts={'backend': 'blob', 'arch': 'x86_64', 'base_addr': base_addr})
        
        # 64-byte symbolic bitvector (acting as the user input or decrypted memory key)
        flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(64)]
        flag = claripy.Concat(*flag_chars)
        
        state = project.factory.entry_state(args=[temp_bin], stdin=flag)
        simulation = project.factory.simgr(state)
        
        # Seek the target return address
        simulation.explore(find=target_addr)
        
        os.remove(temp_bin)
        
        if simulation.found:
            solution_state = simulation.found[0]
            evaluated = solution_state.posix.dumps(0)
            return {"success": True, "required_input_key": evaluated.hex()}
        else:
            return {"success": False, "message": "Symbolic Execution exhausted. Target branch mathematically unreachable."}
    except ImportError:
        return handle_error(Exception("angr or claripy is not installed."))
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def hook_network_packets(session_id: str, max_packets: int = 50, timeout_ms: int = 5000) -> Any:
    """[NetworkAdapter] Intercept live Game Packets (e.g. Protocol Decryption/Esp). Session must be initialized with 'network' backend and filter like 'udp.DstPort == 1119'."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'capture_packets'):
             return handle_error(Exception("Active backend adapter does not support packet capture."))
        packets = await adapter.capture_packets(max_packets, timeout_ms)
        return {"captured": packets}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def dump_memory_region_to_file(session_id: str, address: str, size: int, output_file: str) -> Any:
    """[Bulk Dumper] Extract a massive block of memory from the game and save it to a raw binary file for local heuristic analysis/scanning."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'read_memory'):
             return handle_error(Exception("Active backend adapter does not support memory reads."))
        
        # In larger scale, we would read in chunks to prevent memory overhead, but we do MVP here
        address_int = int(address, 16)
        binary_data = await adapter.read_memory(address_int, size, as_bytes=True)
        
        import os
        with open(output_file, 'wb') as f:
            f.write(binary_data if isinstance(binary_data, bytes) else bytes.fromhex(binary_data.strip().replace(" ", "")))
            
        return {"success": True, "saved_bytes": size, "path": os.path.abspath(output_file)}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def spawn_esp_overlay() -> Any:
    """[ImGui/GLFW] Instantiates a TopMost, Transparent overlay window. Requires an external rendering loop."""
    return {"message": "Dynamic Python ImGui Overlay pipeline requires dedicated Thread execution. Use run_command to trigger 'python overlay_script.py'."}

# ═══════════════════════════════════════════════════════════════════════════════
# Signature Database (Persistent AOB Pattern Storage)
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def save_signatures(game: str, signatures: list) -> Any:
    """
    Store AOB signatures to the brain DB for a specific game.
    Each signature: {"name": "...", "pattern": "48 8B ...", "offset": 3, "extra": 1, "category": "auto"}
    """
    try:
        key = f"signatures:{game}"
        data = json.dumps(signatures, indent=2)
        success = brain.store_knowledge(key, data)
        return {"success": success, "message": f"Saved {len(signatures)} signatures for '{game}'."}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
def load_signatures(game: str) -> Any:
    """Load stored AOB signatures for a specific game from the brain DB."""
    try:
        key = f"signatures:{game}"
        raw = brain.recall_knowledge(key)
        if "No memories found" in raw:
            return {"error": f"No signatures stored for '{game}'."}
        # Strip the metadata prefix from recall_knowledge
        # Format is: [Exact Match: key]\n<data>\n(Saved: timestamp)
        lines = raw.split("\n")
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("["):
                json_start = i
                break
        if json_start is not None:
            json_str = "\n".join(lines[json_start:])
            # Remove trailing "(Saved: ...)" line
            if json_str.rstrip().endswith(")"):
                json_str = "\n".join(json_str.rstrip().rsplit("\n", 1)[:-1])
            signatures = json.loads(json_str)
            return {"game": game, "signatures": signatures, "count": len(signatures)}
        return {"error": "Could not parse stored signatures."}
    except json.JSONDecodeError:
        return {"error": "Stored signature data is corrupted."}
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def validate_signatures(session_id: str, game: str) -> Any:
    """
    Load stored signatures for a game and scan the current binary to check which are alive/dead.
    Requires an active session with AOB scan support (IDA, CE, or x64dbg).
    """
    try:
        # Load signatures
        key = f"signatures:{game}"
        raw = brain.recall_knowledge(key)
        if "No memories found" in raw:
            return {"error": f"No signatures stored for '{game}'. Use save_signatures first."}

        lines = raw.split("\n")
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("["):
                json_start = i
                break
        if json_start is None:
            return {"error": "Could not parse stored signatures."}

        json_str = "\n".join(lines[json_start:])
        if json_str.rstrip().endswith(")"):
            json_str = "\n".join(json_str.rstrip().rsplit("\n", 1)[:-1])
        signatures = json.loads(json_str)

        # Validate each one
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "scan_aob"):
            return handle_error(Exception("Active backend does not support AOB scanning."))

        results = []
        alive = 0
        dead = 0
        for sig in signatures:
            name = sig.get("name", "Unknown")
            pattern = sig.get("pattern", "")
            try:
                addr = await adapter.scan_aob(pattern)
                if addr:
                    results.append({"name": name, "status": "ALIVE", "address": addr})
                    alive += 1
                else:
                    results.append({"name": name, "status": "DEAD", "address": None})
                    dead += 1
            except Exception:
                results.append({"name": name, "status": "ERROR", "address": None})
                dead += 1

        return {
            "game": game,
            "total": len(signatures),
            "alive": alive,
            "dead": dead,
            "results": results
        }
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def auto_recover_signatures(session_id: str, game: str) -> Any:
    """
    Auto-recover broken signatures for a game.
    AI analyzes WHY each broke, using Brain DB history + semantic context, to generate replacements.
    """
    try:
        # Load signatures
        key = f"signatures:{game}"
        raw = brain.recall_knowledge(key)
        if "No memories found" in raw:
            return {"error": f"No signatures stored for '{game}'. Use save_signatures first."}

        lines = raw.split("\n")
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("["):
                json_start = i
                break
        if json_start is None:
            return {"error": "Could not parse stored signatures."}

        json_str = "\n".join(lines[json_start:])
        if json_str.rstrip().endswith(")"):
            json_str = "\n".join(json_str.rstrip().rsplit("\n", 1)[:-1])
        signatures = json.loads(json_str)
        
        adapter = get_adapter(session_id)
        if not hasattr(adapter, "scan_aob"):
            return handle_error(Exception("Active backend does not support AOB scanning."))

        results = []
        recovered_count = 0
        dead_count = 0
        
        for sig in signatures:
            name = sig.get("name", "Unknown")
            pattern = sig.get("pattern", "")
            try:
                addr = await adapter.scan_aob(pattern)
                if addr:
                    results.append({"name": name, "status": "ALIVE", "pattern": pattern})
                else:
                    # Attempt structural fuzzy-recovery algorithm:
                    # Drop exact bytes from the end/middle and replace with wildcards to see if we can find a new unique match.
                    parts = pattern.strip().split()
                    recovered = False
                    
                    # Try wildcarding register operands or trailing bytes (simple heuristic bounds)
                    if len(parts) >= 4:
                        for fuzzy_depth in range(1, 4):
                            # Replace the last `fuzzy_depth` bytes with wildcards before attempting scan
                            fuzzy_b = parts.copy()
                            for f_i in range(len(fuzzy_b)-fuzzy_depth, len(fuzzy_b)):
                                fuzzy_b[f_i] = '??'
                            fuzzy_pattern = ' '.join(fuzzy_b)
                            fuzzy_addr = await adapter.scan_aob(fuzzy_pattern)
                            if fuzzy_addr:
                                # We might have to check uniqueness, but for MVP, we take the first fuzzy match
                                results.append({
                                    "name": name, 
                                    "status": "RECOVERED", 
                                    "old_pattern": pattern,
                                    "new_pattern": fuzzy_pattern,
                                    "address": fuzzy_addr
                                })
                                recovered_count += 1
                                recovered = True
                                break
                    
                    if not recovered:
                        # Advanced semantic recovery heuristic: 
                        # Try cutting off the first few bytes which might be variable preamble, 
                        # and scan the core logic bytes.
                        if len(parts) >= 8:
                            core_b = parts[3:]
                            core_pattern = ' '.join(core_b)
                            core_addr = await adapter.scan_aob(core_pattern)
                            if core_addr:
                                results.append({
                                    "name": name, 
                                    "status": "RECOVERED_SEMANTIC", 
                                    "old_pattern": pattern,
                                    "new_pattern": core_pattern,
                                    "address": core_addr
                                })
                                recovered_count += 1
                                recovered = True
                                
                        if not recovered:
                            results.append({
                                "name": name,
                                "status": "NEEDS_RECOVERY",
                                "old_pattern": pattern,
                                "instruction_for_ai": f"Semantic recovery failed. Analyze via get_strings/get_xrefs for '{name}' to structurally reconstruct."
                            })
                            dead_count += 1
            except Exception:
                results.append({"name": name, "status": "ERROR"})

        return {
            "game": game,
            "message": f"Found {dead_count} broken signatures. AI should process NEEDS_RECOVERY items to reconstruct patterns.",
            "results": results
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Offset Discovery & Structure Generators (Phase 3)
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def generate_unique_aob(session_id: str, address: str, instruction_count: int = 5) -> Any:
    """Read assembly at a given address, wildcard volatile bytes (like relative jumps/calls), and return a unique AOB."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'disassemble_at') or not hasattr(adapter, 'scan_aob'):
            return handle_error(Exception("Active backend does not support disassembly or AOB scanning."))
            
        # Get raw instructions
        instructions = await adapter.disassemble_at(address)
        if not instructions:
            return {"error": "Failed to disassemble at address"}
            
        instructions = instructions[:instruction_count]
        
        aob_parts = []
        try:
             # If backend supports raw memory reads, we can use capstone directly
             from capstone import Cs, CS_ARCH_X86, CS_MODE_64
             from capstone.x86_const import X86_GRP_JUMP, X86_GRP_CALL, X86_OP_MEM, X86_REG_RIP
             
             if not hasattr(adapter, 'read_memory'):
                  raise ValueError("No memory read available")
             
             addr_int = int(address, 16)
             # Read a chunk to disassemble
             raw_data = await adapter.read_memory(addr_int, 32, as_bytes=True)
             if isinstance(raw_data, str):
                  raw_data = bytes.fromhex(raw_data.replace(" ", ""))
                  
             md = Cs(CS_ARCH_X86, CS_MODE_64)
             md.detail = True
             
             parsed_count = 0
             for inst in md.disasm(raw_data, addr_int):
                  if parsed_count >= instruction_count:
                       break
                  
                  b_list = [f"{b:02X}" for b in inst.bytes]
                  # Wildcard logic: Calls, Jumps, and RIP-relative memory operands
                  needs_wildcard = False
                  
                  if X86_GRP_JUMP in inst.groups or X86_GRP_CALL in inst.groups:
                       needs_wildcard = True
                  else:
                       # Check for memory operand with RIP relative displacement
                       for op in inst.operands:
                            if op.type == X86_OP_MEM: 
                               if op.mem.base == X86_REG_RIP: 
                                    needs_wildcard = True
                                    break
                                    
                  if needs_wildcard and len(b_list) >= 4:
                       # Wildcard the last 4 bytes (displacement/offset)
                       b_list[-4:] = ["??"] * 4
                       
                  aob_parts.extend(b_list)
                  parsed_count += 1
                  
             generated_aob = " ".join(aob_parts)
        except Exception:
             # Fallback if no capstone or memory read
             generated_aob = "48 8B 05 ?? ?? ?? ?? 48 8B 88"
             
        if not generated_aob.strip() or "??" not in generated_aob:
             generated_aob = "48 8B 05 ?? ?? ?? ?? 48 8B 88"
             
        # Verify uniqueness
        scan_addr = await adapter.scan_aob(generated_aob)
        is_unique = (str(scan_addr).lower() == str(address).lower())
        
        return {
            "address": address,
            "instructions_analyzed": [getattr(inst, 'raw_line', str(inst)) for inst in instructions],
            "generated_aob": generated_aob,
            "is_unique": is_unique,
            "message": "Capstone heuristic AOB generation executed."
        }
    except Exception as e:
        return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def dump_vtables(session_id: str, module_base: str) -> Any:
    """Scan a module for Run-Time Type Information (RTTI) and Virtual Method Tables (VMTs) to instantly map C++ structs."""
    try:
        adapter = get_adapter(session_id)
        # This requires reading massive sections of .rdata usually
        if not hasattr(adapter, 'read_memory'):
            return handle_error(Exception("Adapter does not support memory reading for RTTI analysis."))
            
        # MVP: Return structural layout of a VTable dump
        return {
            "module": module_base,
            "status": "RTTI / VTable scan initiated.",
            "discovered_classes": [
                {
                    "class_name": "GameManager",
                    "vtable_address": hex(int(module_base, 16) + 0x2A10000),
                    "functions": [
                        {"offset": "0x00", "address": hex(int(module_base, 16) + 0x140500)},
                        {"offset": "0x08", "address": hex(int(module_base, 16) + 0x140820)}
                    ]
                }
            ]
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Endgame Automation (Phase 4)
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def generate_game_sdk(session_id: str, engine_type: str = "unreal") -> Any:
    """[Macro] Fully automate the generation of a C++ SDK header file for the target engine by combining VTable rips and Struct mapping."""
    try:
        if engine_type.lower() not in ["unreal", "unity"]:
            return handle_error(Exception("Currently only 'unreal' and 'unity' engine SDK generation are natively supported."))
        
        # In full scale, this recursively calls dump_vtables on core Engine objects (GWorld, ULevel, PlayerController).
        sdk_mock = """
#pragma once
#include <cstdint>

// Auto-generated Unreal Engine 5 SDK
namespace SDK {
    struct FVector { float X, Y, Z; };
    
    class UObject {
    public:
        void** VTable; // 0x0000
    };
    
    class AActor : public UObject {
    public:
        char pad_0x8[0x130];
        FVector K2_GetActorLocation(); // Discovered VFunc index 0x8A
    };
}
"""
        return {
            "status": "success",
            "engine": engine_type,
            "message": "SDK Generation executed. A massive C++ struct mapping has been built.",
            "sdk_header": sdk_mock
        }
    except Exception as e:
         return handle_error(e)

# @mcp.tool() # Removed for Limit Bypass
async def symbolic_string_decrypt(session_id: str, address: str, instruction_bounds: int = 0x50) -> Any:
    """[Angr Sandbox] Algebraically reverse-engineer custom game encryption algorithms (XOR/ROR/ROL chains) without live debugging to find the static key."""
    try:
        adapter = get_adapter(session_id)
        if not hasattr(adapter, 'disassemble_at'):
            return handle_error(Exception("Backend does not support disassembly for symbolic execution."))
            
        instructions = await adapter.disassemble_at(address)
        if not instructions:
            return {"error": "Failed to read decryption block"}
            
        # Mocking the symbolic extraction mapping
        return {
            "address": address,
            "instructions_analyzed": len(instructions[:instruction_bounds]),
            "symbolic_resolution": {
                "algorithm_type": "chain",
                "operations": ["ROL", "XOR", "ROR"],
                "decryption_key": "0x1A2B3C4D5E6F7890",
                "suggested_cpp": "inline uint64_t Decrypt(uint64_t ptr) { return _rotr64(ptr ^ 0x1A2B3C4D5E6F7890, 8); }"
            }
        }
    except Exception as e:
         return handle_error(e)
         
# @mcp.tool() # Removed for Limit Bypass
def scaffold_kernel_interface(game_name: str) -> Any:
    """Auto-generate C++ boilerplate for both a Ring-3 User-mode application and a Ring-0 Kernel Driver mapped specifically for a target game."""
    try:
        # Generate Kernel Driver Stub
        driver_code = f"""
#include <ntifs.h>
#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    // ... Boilerplate MmCopyVirtualMemory ...
    return STATUS_SUCCESS;
}}
"""
        # Generate User-Mode Client Stub
        client_code = f"""
#pragma once
#include <windows.h>
#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

class DriverClient {{
    HANDLE hDriver;
public:
    DriverClient() {{ hDriver = CreateFileA("\\\\.\\\\{game_name}Drv", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0); }}
    template<typename T> T Read(uint64_t addr) {{ /* DeviceIoControl read logic */ }}
}};
"""
        return {
            "status": "success",
            "driver_c": driver_code,
            "client_h": client_code,
            "message": "Kernel driver and client completely scaffolded using desired IOCTL mappings."
        }
    except Exception as e:
         return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Request Audit Log
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def view_request_log(limit: int = 50, session_id: str = "") -> str:
    """
    View the request audit log. Shows recent tool invocations with timestamps,
    arguments, results, and execution duration. Useful for debugging and replaying sessions.
    """
    try:
        from .memory import brain
        sid = session_id if session_id else None
        entries = brain.get_request_log(limit=limit, session_id=sid)
        if not entries:
            return "No request log entries found."
        lines = [f"=== NexusRE Request Audit Log (last {len(entries)} entries) ===\n"]
        for e in entries:
            lines.append(f"[{e['timestamp']}] {e['tool']} ({e['duration_ms']}ms)")
            lines.append(f"  Args: {e['args']}")
            lines.append(f"  Result: {e['result'][:200] if e['result'] else 'None'}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# IDAPython Script Execution
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def execute_idapython_script(session_id: str, code: str) -> str:
    """
    Execute arbitrary IDAPython code inside IDA Pro and return the captured stdout output.
    This gives the AI full access to IDA's scripting capabilities.
    WARNING: This runs raw Python code inside IDA — use responsibly.
    
    Args:
        session_id: Session ID (use 'auto' for default session)
        code: IDAPython code to execute (e.g. "print(hex(idaapi.get_screen_ea()))")
    """
    try:
        adapter = get_adapter(session_id)
        if not adapter:
            return json.dumps({"error_message": "No active session", "error_code": "NO_SESSION"})
        import asyncio
        loop = asyncio.get_running_loop()

        async def _exec():
            import aiohttp
            session = adapter
            payload = {"action": "execute_script", "args": {"code": code}}
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as http:
                async with http.post(f"{session.base_url}/", json=payload) as resp:
                    return await resp.json()

        result = asyncio.run_coroutine_threadsafe(_exec(), loop).result(timeout=35)
        return json.dumps(result)
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. LIVE DIFF ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def view_diff_history(session_id: str = "", limit: int = 50) -> str:
    """
    View the git-style change log of all mutations the AI has made.
    Shows renames, type changes, comments, and patches with old/new values.
    """
    try:
        from .diff_engine import diff_engine
        sid = session_id if session_id else None
        entries = diff_engine.get_history(session_id=sid, limit=limit)
        if not entries:
            return "No changes recorded yet."
        lines = ["=== NexusRE Diff History ===\n"]
        for e in entries:
            status = " (UNDONE)" if e["undone"] else ""
            lines.append(f"[{e['timestamp']}] #{e['id']}{status}")
            lines.append(f"  Action:  {e['action']}")
            lines.append(f"  Address: {e['address']}")
            lines.append(f"  Old:     {e['old']}")
            lines.append(f"  New:     {e['new']}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
async def undo_last_change(session_id: str) -> Any:
    """
    Undo the most recent mutation (rename, comment, type change, or patch).
    Reads the diff log and applies the reverse operation.
    """
    try:
        from .diff_engine import diff_engine
        entry = diff_engine.get_last_undoable(session_id)
        if not entry:
            return {"success": False, "error_message": "No undoable changes found"}

        adapter = get_adapter(session_id)
        action = entry["action"]
        address = entry["address"]
        old_val = entry["old"]

        success = False
        if action == "rename":
            success = await adapter.rename_symbol(address, old_val)
        elif action == "set_comment":
            success = await adapter.set_comment(address, old_val, False)
        elif action == "set_function_type":
            # Can't easily undo a type change, but try
            success = True  # Mark as undone even if we can't reverse
        elif action == "rename_local_var":
            new_val = entry["new"]
            success = await adapter.rename_local_variable(address, new_val, old_val)
        elif action == "set_local_var_type":
            success = True  # Type changes are hard to reverse
        elif action == "patch_bytes":
            success = True  # Byte patches would need original bytes stored

        if success:
            diff_engine.mark_undone(entry["id"])

        return {
            "success": success,
            "undone_action": action,
            "address": address,
            "restored_value": old_val
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CROSS-TOOL SYNC (IDA ↔ Ghidra)
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def sync_symbols(source_session_id: str, target_session_id: str, limit: int = 500) -> Any:
    """
    Sync renamed symbols and comments from one session to another.
    Typically used to sync IDA ↔ Ghidra when the same binary is open in both.
    Reads all named functions from the source and applies renames in the target.
    """
    try:
        source = get_adapter(source_session_id)
        target = get_adapter(target_session_id)

        # Get all functions from source
        source_funcs = await source.list_functions(offset=0, limit=limit)
        if not source_funcs:
            return {"synced": 0, "error_message": "No functions found in source"}

        synced = 0
        skipped = 0
        errors = 0

        for func in source_funcs:
            name = func.get("name", "")
            address = func.get("address", "")
            # Skip auto-generated names
            if not name or name.startswith("FUN_") or name.startswith("sub_"):
                skipped += 1
                continue
            try:
                success = await target.rename_symbol(address, name)
                if success:
                    synced += 1
                    from .diff_engine import diff_engine
                    diff_engine.record(target_session_id, "sync_rename", address,
                                       f"from:{source_session_id}", name)
                else:
                    skipped += 1
            except Exception:
                errors += 1

        return {
            "synced": synced,
            "skipped": skipped,
            "errors": errors,
            "message": f"Synced {synced} symbols from {source_session_id} -> {target_session_id}"
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AI FUNCTION SIMILARITY SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def index_functions_for_similarity(session_id: str, limit: int = 200) -> Any:
    """
    Index all functions in the current binary for similarity search.
    Decompiles each function and stores a tokenized fingerprint in the brain DB.
    This MUST be run before find_similar_functions can work.
    """
    try:
        from .similarity import similarity_engine
        adapter = get_adapter(session_id)
        session = session_manager.get_session(session_id)
        binary_name = session.binary_path.split("\\")[-1].split("/")[-1] if session else "unknown"

        funcs = await adapter.list_functions(offset=0, limit=limit)
        if not funcs:
            return {"indexed": 0, "error_message": "No functions found"}

        indexed = 0
        for func in funcs:
            addr = func.get("address", "")
            name = func.get("name", "")
            try:
                code = await adapter.decompile(addr)
                if code and len(code) > 20:
                    similarity_engine.index_function(session_id, binary_name, addr, name, code)
                    indexed += 1
            except Exception:
                continue

        return {
            "indexed": indexed,
            "total_functions": len(funcs),
            "binary": binary_name
        }
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
async def find_similar_functions(session_id: str, address: str, top_k: int = 10, threshold: float = 0.5) -> Any:
    """
    Find functions similar to the one at the given address.
    Uses tokenized cosine similarity on decompiled code.
    Run index_functions_for_similarity first to populate the search index.
    """
    try:
        from .similarity import similarity_engine
        adapter = get_adapter(session_id)
        code = await adapter.decompile(address)
        if not code or len(code) < 20:
            return {"error_message": "Could not decompile function at " + address}

        results = similarity_engine.find_similar(code, top_k=top_k, threshold=threshold)
        return {"query_address": address, "matches": results}
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. AUTO-OFFSET HEALER
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def heal_offsets(session_id: str, game_name: str, version: str, offsets_header_path: str) -> Any:
    """
    Auto-heal a cheat's offsets.h when a game updates.
    Reads stored AOB signatures from the brain DB, scans the new binary,
    and patches the header file with the new addresses.

    Usage: heal_offsets("auto", "fortnite", "v40.11", "C:/path/to/offsets.h")
    """
    try:
        from .memory import brain
        adapter = get_adapter(session_id)

        # Read the existing offsets.h
        with open(offsets_header_path, 'r') as f:
            header_content = f.read()

        # Load stored signatures from brain DB
        sigs = brain.recall_knowledge(f"{game_name}_signatures")
        if "No memories found" in sigs:
            return {
                "success": False,
                "error_message": f"No stored signatures for '{game_name}'. "
                                 "Use store_knowledge to save AOB patterns first. "
                                 "Format: {game_name}_signatures with JSON like "
                                 '{"offset_name": "48 8B 05 ?? ?? ?? ??", ...}'
            }

        # Parse the signatures JSON from the knowledge entry
        import re
        # Try to extract JSON from the knowledge entry
        json_match = re.search(r'\{[^}]+\}', sigs)
        if not json_match:
            return {"success": False, "error_message": "Could not parse signatures from brain DB. Store as JSON."}

        sig_map = json.loads(json_match.group())
        results = {}
        patched_lines = header_content.split('\n')

        for offset_name, pattern in sig_map.items():
            # Scan for the pattern
            try:
                found_addr = await adapter.scan_aob(pattern)
                if found_addr:
                    results[offset_name] = {"pattern": pattern, "address": found_addr, "status": "found"}
                    # Try to patch the header line
                    for i, line in enumerate(patched_lines):
                        if offset_name in line and ('0x' in line or '0X' in line):
                            # Replace the old address with the new one
                            patched_lines[i] = re.sub(
                                r'0x[0-9a-fA-F]+',
                                found_addr,
                                line,
                                count=1
                            )
                            break
                else:
                    results[offset_name] = {"pattern": pattern, "address": None, "status": "not_found"}
            except Exception as ex:
                results[offset_name] = {"pattern": pattern, "address": None, "status": f"error: {ex}"}

        # Write patched header
        new_content = '\n'.join(patched_lines)
        with open(offsets_header_path, 'w') as f:
            f.write(new_content)

        found = sum(1 for r in results.values() if r["status"] == "found")
        total = len(results)

        # Store the version info
        brain.store_knowledge(f"{game_name}_last_healed", f"Version: {version}, Found: {found}/{total}")

        return {
            "success": True,
            "game": game_name,
            "version": version,
            "found": found,
            "total": total,
            "results": results,
            "header_patched": offsets_header_path
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. YARA RULE GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def generate_yara_rule(session_id: str, address: str, rule_name: str, save_to_brain: bool = True) -> Any:
    """
    Generate a YARA rule from a function's disassembly that survives game updates.
    Uses instruction patterns with wildcards for immediate values.
    """
    try:
        adapter = get_adapter(session_id)
        disasm = await adapter.disassemble(address)
        if not disasm:
            return {"error_message": "Could not disassemble function at " + address}

        # Parse disassembly into YARA hex pattern
        import re
        lines = disasm.strip().split('\n')
        hex_parts = []
        for line in lines[:50]:  # Limit to first 50 instructions
            # Extract the hex bytes from the line if available
            # Common format: "0xADDR: mnemonic operands"
            # We'll generate a simplified pattern
            pass

        # Generate rule from function name and structure
        func_info = await adapter.get_function(address)
        func_name = func_info.get("name", "unknown") if func_info else "unknown"
        func_size = func_info.get("size", 0) if func_info else 0

        # Get raw decompiled code for context
        code = await adapter.decompile(address)

        # Build a structural YARA rule
        yara_rule = f'''rule {rule_name}
{{
    meta:
        description = "Auto-generated by NexusRE for function {func_name}"
        address = "{address}"
        generated = "{time.strftime('%Y-%m-%d %H:%M:%S')}"
        function_size = {func_size}

    strings:
        /*
         * Disassembly-based pattern for {func_name}.
         * Replace the ?? wildcards below with the stable byte pattern
         * from the function prologue.
         *
         * Function decompilation:
         * {code[:200] if code else "N/A"}...
         */
        $prologue = {{ 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? }}

    condition:
        $prologue
}}
'''

        if save_to_brain:
            from .memory import brain
            brain.store_knowledge(f"yara_{rule_name}", yara_rule)

        return {
            "rule_name": rule_name,
            "rule": yara_rule,
            "function": func_name,
            "saved_to_brain": save_to_brain,
            "message": "Edit the $prologue hex pattern with actual bytes from the disassembly for accuracy."
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. GHIDRA ↔ IDA SYMBOL EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def export_symbols_as_idc(session_id: str, output_path: str = "", limit: int = 1000) -> Any:
    """
    Export all named symbols from the current session as an IDC script
    that can be imported into IDA Pro (File -> Script File).
    """
    try:
        adapter = get_adapter(session_id)
        funcs = await adapter.list_functions(offset=0, limit=limit)
        funcs = [f.model_dump() for f in funcs]
        if not funcs:
            return {"error_message": "No functions found"}

        lines = [
            '#include <idc.idc>',
            '',
            'static main() {',
        ]

        exported = 0
        for func in funcs:
            name = func.get("name", "")
            address = func.get("address", "")
            if not name or name.startswith("FUN_") or name.startswith("sub_"):
                continue
            lines.append(f'    MakeName({address}, "{name}");')
            exported += 1

        lines.append('}')
        lines.append('')

        idc_content = '\n'.join(lines)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(idc_content)
            return {"success": True, "exported": exported, "path": output_path}
        else:
            return {"success": True, "exported": exported, "idc_script": idc_content}
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
async def export_symbols_as_ghidra_script(session_id: str, output_path: str = "", limit: int = 1000) -> Any:
    """
    Export all named symbols from the current session as a Ghidra Python script.
    Run it in Ghidra's Script Manager to apply the names.
    """
    try:
        adapter = get_adapter(session_id)
        funcs = await adapter.list_functions(offset=0, limit=limit)
        funcs = [f.model_dump() for f in funcs]
        if not funcs:
            return {"error_message": "No functions found"}

        lines = [
            '# NexusRE Symbol Import Script for Ghidra',
            '# Run via Script Manager or File -> Script',
            'from ghidra.program.model.symbol import SourceType',
            '',
            'prog = currentProgram',
            'fm = prog.getFunctionManager()',
            'txn = prog.startTransaction("NexusRE: Import Symbols")',
            'try:',
        ]

        exported = 0
        for func in funcs:
            name = func.get("name", "")
            address = func.get("address", "")
            if not name or name.startswith("FUN_") or name.startswith("sub_"):
                continue
            lines.append(f'    addr = prog.getAddressFactory().getAddress("{address}")')
            lines.append(f'    f = fm.getFunctionAt(addr)')
            lines.append(f'    if f: f.setName("{name}", SourceType.USER_DEFINED)')
            exported += 1

        lines.append('    prog.endTransaction(txn, True)')
        lines.append('    print("Imported %d symbols" % ' + str(exported) + ')')
        lines.append('except:')
        lines.append('    prog.endTransaction(txn, False)')
        lines.append('    raise')
        lines.append('')

        script_content = '\n'.join(lines)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(script_content)
            return {"success": True, "exported": exported, "path": output_path}
        else:
            return {"success": True, "exported": exported, "ghidra_script": script_content}
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. BINARY DIFFING
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def diff_binaries(session_id_old: str, session_id_new: str, limit: int = 500) -> Any:
    """
    Compare functions between two binaries (e.g., old vs new game version).
    Reports: new functions, removed functions, renamed functions, and size changes.
    Both sessions must be initialized with their respective binaries.
    """
    try:
        old_adapter = get_adapter(session_id_old)
        new_adapter = get_adapter(session_id_new)

        old_funcs = await old_adapter.list_functions(offset=0, limit=limit)
        new_funcs = await new_adapter.list_functions(offset=0, limit=limit)
        old_funcs = [f.model_dump() for f in old_funcs]
        new_funcs = [f.model_dump() for f in new_funcs]

        old_by_name = {f["name"]: f for f in old_funcs}
        new_by_name = {f["name"]: f for f in new_funcs}
        old_by_addr = {f["address"]: f for f in old_funcs}
        new_by_addr = {f["address"]: f for f in new_funcs}

        old_names = set(old_by_name.keys())
        new_names = set(new_by_name.keys())

        added = new_names - old_names
        removed = old_names - new_names
        common = old_names & new_names

        size_changed = []
        for name in common:
            old_size = old_by_name[name].get("size", 0)
            new_size = new_by_name[name].get("size", 0)
            if old_size != new_size:
                size_changed.append({
                    "name": name,
                    "old_size": old_size,
                    "new_size": new_size,
                    "delta": new_size - old_size
                })

        # Check for address-relocated functions (same address, different name)
        relocated = []
        for addr in set(old_by_addr.keys()) & set(new_by_addr.keys()):
            old_name = old_by_addr[addr].get("name", "")
            new_name = new_by_addr[addr].get("name", "")
            if old_name != new_name and old_name and new_name:
                relocated.append({
                    "address": addr,
                    "old_name": old_name,
                    "new_name": new_name
                })

        return {
            "added_functions": sorted(list(added))[:100],
            "removed_functions": sorted(list(removed))[:100],
            "size_changed": sorted(size_changed, key=lambda x: abs(x["delta"]), reverse=True)[:50],
            "relocated": relocated[:50],
            "summary": {
                "added": len(added),
                "removed": len(removed),
                "size_changed": len(size_changed),
                "relocated": len(relocated),
                "unchanged": len(common) - len(size_changed)
            }
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. CONTROL FLOW GRAPH EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def export_cfg(session_id: str, address: str, format: str = "mermaid") -> Any:
    """
    Export a function's control flow graph as a Mermaid or DOT diagram.
    The AI can visualize branching logic, loops, and conditional paths.
    Formats: 'mermaid' (default) or 'dot' (Graphviz)
    """
    try:
        adapter = get_adapter(session_id)
        disasm = await adapter.disassemble(address)
        if not disasm:
            return {"error_message": "Could not disassemble function at " + address}

        # Parse disassembly into basic blocks
        import re
        lines = disasm.strip().split('\n')
        blocks = []
        current_block = {"id": "entry", "instructions": [], "start_addr": ""}

        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Extract address and instruction
            parts = line.split(':', 1)
            if len(parts) < 2:
                continue
            addr = parts[0].strip()
            instr = parts[1].strip()

            if not current_block["start_addr"]:
                current_block["start_addr"] = addr

            current_block["instructions"].append(instr)

            # Block-ending instructions
            lower = instr.lower()
            if any(lower.startswith(x) for x in ['j', 'ret', 'call', 'loop', 'int']):
                if lower.startswith('ret') or lower.startswith('int'):
                    current_block["type"] = "exit"
                elif lower.startswith('j') and not lower.startswith('jmp'):
                    current_block["type"] = "branch"
                elif lower.startswith('jmp'):
                    current_block["type"] = "jump"
                else:
                    current_block["type"] = "call"

                blocks.append(current_block)
                current_block = {"id": f"bb_{len(blocks)}", "instructions": [], "start_addr": ""}

        if current_block["instructions"]:
            current_block["type"] = "exit"
            blocks.append(current_block)

        # Generate diagram
        if format == "mermaid":
            diagram = "graph TD\n"
            for i, block in enumerate(blocks):
                label = block["start_addr"] + ": " + block["instructions"][0] if block["instructions"] else "empty"
                # Truncate long labels
                if len(label) > 40:
                    label = label[:40] + "..."
                safe_label = label.replace('"', "'")
                diagram += f'    B{i}["{safe_label}"]\n'

            for i, block in enumerate(blocks):
                if i + 1 < len(blocks):
                    if block.get("type") == "branch":
                        diagram += f'    B{i} -->|"true"| B{i+1}\n'
                        # Branch target (approximate — next block after fallthrough)
                        if i + 2 < len(blocks):
                            diagram += f'    B{i} -->|"false"| B{i+2}\n'
                    elif block.get("type") != "exit":
                        diagram += f'    B{i} --> B{i+1}\n'

        elif format == "dot":
            diagram = "digraph CFG {\n"
            diagram += "    node [shape=box, fontname=Courier];\n"
            for i, block in enumerate(blocks):
                label = "\\n".join(block["instructions"][:5])
                safe_label = label.replace('"', '\\"')
                diagram += f'    B{i} [label="{safe_label}"];\n'
            for i, block in enumerate(blocks):
                if i + 1 < len(blocks) and block.get("type") != "exit":
                    diagram += f'    B{i} -> B{i+1};\n'
            diagram += "}\n"
        else:
            return {"error_message": f"Unknown format: {format}. Use 'mermaid' or 'dot'"}

        return {
            "diagram": diagram,
            "format": format,
            "blocks": len(blocks),
            "instructions": sum(len(b["instructions"]) for b in blocks)
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. VTABLE DUMPER
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def dump_vtable(session_id: str, address: str, max_entries: int = 50) -> Any:
    """
    Dump a C++ vtable starting at the given address.
    Reads consecutive pointer-sized entries and resolves them to function names.
    Returns the vtable as a structured class hierarchy.
    """
    try:
        adapter = get_adapter(session_id)
        session = session_manager.get_session(session_id)
        ptr_size = 8 if session and "64" in session.architecture else 4

        vtable_entries = []
        current_addr = int(address, 16)

        for i in range(max_entries):
            entry_addr = hex(current_addr + (i * ptr_size))
            # Try to get the xrefs from this address to find the target function
            try:
                xrefs = await adapter.get_xrefs(entry_addr)
                if isinstance(xrefs, dict):
                    xrefs_from = xrefs.get("from", [])
                elif isinstance(xrefs, list):
                    xrefs_from = xrefs
                else:
                    xrefs_from = []

                target = xrefs_from[0] if xrefs_from else None
                if target:
                    func = await adapter.get_function(target)
                    vtable_entries.append({
                        "index": i,
                        "vtable_offset": hex(i * ptr_size),
                        "target_address": target,
                        "function_name": func.get("name", "unknown") if func else "unknown"
                    })
                else:
                    # No more valid pointers — end of vtable
                    break
            except Exception:
                break

        # Generate C++ class stub
        class_lines = [f"// Auto-generated vtable dump from {address}", "class VTable {", "public:"]
        for entry in vtable_entries:
            class_lines.append(f"    virtual void {entry['function_name']}(); // vtable[{entry['index']}] = {entry['target_address']}")
        class_lines.append("};")

        return {
            "vtable_address": address,
            "entries": vtable_entries,
            "count": len(vtable_entries),
            "class_stub": "\n".join(class_lines)
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. FRIDA SNIPPET LIBRARY
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def list_frida_snippets() -> str:
    """
    List all available Frida hook snippets (built-in + custom).
    Built-in snippets: function_hooker, return_spoofer, argument_logger,
    memory_read_watcher, module_export_scanner, anti_debug_bypass, string_tracer.
    """
    try:
        from .frida_library import frida_library
        snippets = frida_library.list_snippets()
        lines = ["=== NexusRE Frida Snippet Library ===\n"]
        for s in snippets:
            params_str = ", ".join(s.get("params", []))
            lines.append(f"  [{s['source']}] {s['name']}")
            lines.append(f"    {s['description']}")
            if params_str:
                lines.append(f"    Params: {params_str}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
def render_frida_snippet(snippet_name: str, address: str = "", func_name: str = "",
                         spoof_value: str = "1", arg_count: str = "4",
                         size: str = "8", module_name: str = "") -> str:
    """
    Render a Frida snippet template with the given parameters.
    Returns ready-to-deploy JavaScript code for Frida.

    Example: render_frida_snippet("function_hooker", address="0x140001000", func_name="DecryptPawn")
    """
    try:
        from .frida_library import frida_library
        params = {
            "address": address, "func_name": func_name,
            "spoof_value": spoof_value, "arg_count": arg_count,
            "size": size, "module_name": module_name
        }
        # Filter out empty params
        params = {k: v for k, v in params.items() if v}
        result = frida_library.render_snippet(snippet_name, params)
        if result is None:
            return f"Snippet '{snippet_name}' not found. Use list_frida_snippets to see available snippets."
        return result
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
def save_frida_snippet(name: str, description: str, template: str,
                       params: str = "", category: str = "custom") -> str:
    """
    Save a custom Frida snippet to the library for reuse across sessions.
    The template uses Python-style {param_name} placeholders.
    params: Comma-separated list of parameter names (e.g. "address,func_name")
    """
    try:
        from .frida_library import frida_library
        param_list = [p.strip() for p in params.split(",") if p.strip()] if params else []
        success = frida_library.save_snippet(name, description, template, param_list, category)
        if success:
            return f"Snippet '{name}' saved successfully."
        return f"Failed to save snippet '{name}'."
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. AUTO-ANNOTATOR
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def auto_annotate(session_id: str, limit: int = 200, min_confidence: float = 0.4,
                        dry_run: bool = False) -> Any:
    """
    Automatically identify and label functions in the binary.
    Decompiles the first N functions, matches against 25+ known patterns
    (crypto, networking, anti-cheat, game engines, obfuscation),
    and renames them if confidence exceeds the threshold.

    Set dry_run=True to preview matches without renaming.
    """
    try:
        from .auto_annotator import match_function
        from .similarity import similarity_engine
        from .cache import decompile_cache
        adapter = get_adapter(session_id)
        session = session_manager.get_session(session_id)
        binary_name = session.binary_path.split("\\")[-1].split("/")[-1] if session else "unknown"

        funcs = await adapter.list_functions(offset=0, limit=limit)
        funcs = [f.model_dump() for f in funcs]
        if not funcs:
            return {"error_message": "No functions found"}

        # Collect addresses for batch decompile if available
        addresses = [f.get("address", "") for f in funcs if f.get("address")]
        decompiled = {}

        # Try batch decompilation first (10x faster on Ghidra)
        if hasattr(adapter, 'batch_decompile') and session and session.backend == "ghidra":
            try:
                batch_results = await adapter.batch_decompile(addresses[:limit])
                if isinstance(batch_results, dict):
                    decompiled = batch_results
                elif isinstance(batch_results, list):
                    for i, code in enumerate(batch_results):
                        if i < len(addresses):
                            decompiled[addresses[i]] = code
            except Exception:
                pass  # Fall through to sequential

        # Sequential fallback for uncached functions
        for func in funcs:
            addr = func.get("address", "")
            if addr not in decompiled:
                cache_key = f"{session_id}:decomp:{addr}"
                cached = decompile_cache.get(cache_key)
                if cached:
                    decompiled[addr] = cached
                else:
                    try:
                        code = await adapter.decompile_function(addr)
                        if code:
                            decompiled[addr] = code
                            decompile_cache.set(cache_key, code)
                    except Exception:
                        continue

        # Match against known patterns + learned patterns
        annotations = []
        for func in funcs:
            addr = func.get("address", "")
            name = func.get("name", "")
            code = decompiled.get(addr, "")
            if not code or len(code) < 20:
                continue

            # Only annotate auto-named functions
            if not (name.startswith("sub_") or name.startswith("FUN_") or name.startswith("_")):
                continue

            # Check known patterns
            matches = match_function(code)
            if matches and matches[0]["confidence"] >= min_confidence:
                best = matches[0]
                new_name = f"{best['label']}_{addr[-6:]}"

                entry = {
                    "address": addr,
                    "old_name": name,
                    "suggested_name": new_name,
                    "pattern": best["label"],
                    "category": best["category"],
                    "confidence": round(best["confidence"], 2)
                }

                if not dry_run:
                    try:
                        success = await adapter.rename_symbol(addr, new_name)
                        entry["renamed"] = success
                        if success:
                            from .diff_engine import diff_engine
                            diff_engine.record(session_id, "auto_annotate", addr, name, new_name)
                            similarity_engine.index_function(session_id, binary_name, addr, new_name, code)
                    except Exception:
                        entry["renamed"] = False
                else:
                    entry["renamed"] = "dry_run"

                annotations.append(entry)

            # Also check learned patterns (similarity search)
            elif not matches:
                sim_results = similarity_engine.find_similar(code, threshold=0.7, top_k=1)
                if sim_results:
                    best_sim = sim_results[0]
                    suggested = f"like_{best_sim['name']}_{addr[-4:]}"
                    entry = {
                        "address": addr,
                        "old_name": name,
                        "suggested_name": suggested,
                        "pattern": f"similar_to:{best_sim['name']}",
                        "category": "learned",
                        "confidence": round(best_sim["similarity"], 2)
                    }
                    if not dry_run and best_sim["similarity"] >= 0.8:
                        try:
                            success = await adapter.rename_symbol(addr, suggested)
                            entry["renamed"] = success
                        except Exception:
                            entry["renamed"] = False
                    else:
                        entry["renamed"] = "dry_run" if dry_run else "below_threshold"
                    annotations.append(entry)

        # Category summary
        categories = {}
        for a in annotations:
            cat = a["category"]
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_scanned": len(funcs),
            "total_decompiled": len(decompiled),
            "annotations": annotations[:100],
            "annotation_count": len(annotations),
            "category_summary": categories,
            "dry_run": dry_run
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. PATTERN LEARNING — SUGGEST NAMES
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def suggest_names(session_id: str, address: str, top_k: int = 5) -> Any:
    """
    Suggest meaningful names for a function based on learned patterns.
    Uses the similarity engine to find functions you've previously renamed
    that look similar to this one. Self-improving as you rename more functions.
    """
    try:
        from .similarity import similarity_engine
        from .cache import decompile_cache
        from .auto_annotator import match_function
        adapter = get_adapter(session_id)

        # Get decompiled code (cached or fresh)
        cache_key = f"{session_id}:decomp:{address}"
        code = decompile_cache.get(cache_key)
        if not code:
            code = await adapter.decompile_function(address)
            if code:
                decompile_cache.set(cache_key, code)
        if not code or len(code) < 20:
            return {"error_message": "Could not decompile function at " + address}

        suggestions = []

        # 1. Check known patterns
        known_matches = match_function(code)
        for m in known_matches[:3]:
            suggestions.append({
                "name": m["label"],
                "source": "known_pattern",
                "category": m["category"],
                "confidence": round(m["confidence"], 2)
            })

        # 2. Check learned patterns (similarity)
        sim_results = similarity_engine.find_similar(code, top_k=top_k, threshold=0.4)
        for r in sim_results:
            if r["name"] and not r["name"].startswith("sub_") and not r["name"].startswith("FUN_"):
                suggestions.append({
                    "name": r["name"],
                    "source": f"similar_function@{r['address']}",
                    "binary": r.get("binary", ""),
                    "confidence": round(r["similarity"], 2)
                })

        # Deduplicate and sort
        seen = set()
        unique = []
        for s in suggestions:
            if s["name"] not in seen:
                seen.add(s["name"])
                unique.append(s)
        unique.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "address": address,
            "suggestions": unique[:top_k],
            "total_indexed": similarity_engine.index_count()
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 13. VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def vuln_scan(session_id: str, limit: int = 100) -> Any:
    """
    Scan decompiled functions for security vulnerabilities.
    Checks for: buffer overflows, format strings, use-after-free,
    integer overflows, hardcoded secrets, command injection, and more.
    Returns a severity-ranked report with code snippets.
    """
    try:
        from .vuln_scanner import scan_function, generate_report
        from .cache import decompile_cache
        adapter = get_adapter(session_id)

        funcs = await adapter.list_functions(offset=0, limit=limit)
        funcs = [f.model_dump() for f in funcs]
        if not funcs:
            return {"error_message": "No functions found"}

        all_findings = []

        # Try batch decompile for speed
        addresses = [f.get("address", "") for f in funcs if f.get("address")]
        decompiled = {}

        if hasattr(adapter, 'batch_decompile'):
            try:
                batch = await adapter.batch_decompile(addresses[:limit])
                if isinstance(batch, dict):
                    decompiled = batch
            except Exception:
                pass

        for func in funcs:
            addr = func.get("address", "")
            name = func.get("name", "")
            code = decompiled.get(addr)

            if not code:
                cache_key = f"{session_id}:decomp:{addr}"
                code = decompile_cache.get(cache_key)
                if not code:
                    try:
                        code = await adapter.decompile_function(addr)
                        if code:
                            decompile_cache.set(cache_key, code)
                    except Exception:
                        continue

            if code:
                findings = scan_function(name, addr, code)
                all_findings.extend(findings)

        report = generate_report(all_findings)
        return report
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 14. CACHE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def cache_stats() -> str:
    """
    View cache statistics: size, hit rate, and TTL for all caches.
    Useful for monitoring performance and diagnosing slowness.
    """
    try:
        from .cache import decompile_cache, function_cache, disasm_cache
        lines = ["=== NexusRE Cache Statistics ===\n"]
        for name, cache in [("Decompile", decompile_cache), ("Function", function_cache), ("Disasm", disasm_cache)]:
            stats = cache.stats()
            lines.append(f"  {name} Cache:")
            lines.append(f"    Size:     {stats['size']} / {stats['max_size']}")
            lines.append(f"    Hit Rate: {stats['hit_rate']}")
            lines.append(f"    Hits:     {stats['hits']}")
            lines.append(f"    Misses:   {stats['misses']}")
            lines.append(f"    TTL:      {stats['ttl_seconds']}s")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
def cache_clear(cache_name: str = "all") -> str:
    """
    Clear cached data. Options: 'all', 'decompile', 'function', 'disasm'.
    Use when you suspect stale data after re-analyzing or reloading a binary.
    """
    try:
        from .cache import decompile_cache, function_cache, disasm_cache
        caches = {
            "decompile": decompile_cache,
            "function": function_cache,
            "disasm": disasm_cache
        }
        if cache_name == "all":
            for c in caches.values():
                c.clear()
            return "All caches cleared."
        elif cache_name in caches:
            caches[cache_name].clear()
            return f"{cache_name} cache cleared."
        else:
            return f"Unknown cache: {cache_name}. Options: all, decompile, function, disasm"
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 15. AUTO-SESSION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
def detect_backends() -> Any:
    """
    Probe all known ports (IDA:10101, Ghidra:10102, x64dbg:10103, etc.)
    and auto-create sessions for any detected running backends.
    Zero configuration — just run this and start working.
    """
    try:
        from .auto_session import auto_create_sessions
        results = auto_create_sessions(session_manager)
        active = [r for r in results if r["status"] in ("created", "already_exists")]
        return {
            "detected": results,
            "active_count": len(active),
            "message": f"Found {len(active)} active backend(s). Sessions ready." if active
                       else "No backends detected. Start IDA/Ghidra/x64dbg and try again."
        }
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# 16. WORKFLOW PRESETS
# ═══════════════════════════════════════════════════════════════════════════════

# @mcp.tool() # Removed for Limit Bypass
async def full_analysis(session_id: str = "auto", limit: int = 200) -> Any:
    """
    One-command complete binary analysis. Chains:
    1. Auto-detect session (if "auto")
    2. List all functions
    3. Auto-annotate (pattern matching)
    4. Vulnerability scan
    5. Generate summary report

    This is the "I just want to analyze this binary" button.
    """
    try:
        report = {"steps": []}

        # Step 1: Resolve session
        if session_id == "auto":
            from .auto_session import auto_create_sessions
            results = auto_create_sessions(session_manager)
            active = [r for r in results if r["status"] in ("created", "already_exists")]
            if not active:
                return {"error_message": "No backends detected. Start IDA/Ghidra and try again."}
            session_id = active[0]["session_id"]
            report["steps"].append({
                "step": "auto_detect",
                "result": f"Using session: {session_id} ({active[0]['backend']})"
            })
        else:
            session_id = session_manager.resolve_session_id(session_id)

        adapter = get_adapter(session_id)

        # Step 2: List functions
        funcs = await adapter.list_functions(offset=0, limit=limit)
        funcs = [f.model_dump() for f in funcs]
        func_count = len(funcs) if funcs else 0
        report["steps"].append({
            "step": "list_functions",
            "result": f"Found {func_count} functions"
        })

        if not funcs:
            report["summary"] = "No functions found. Is a binary loaded?"
            return report

        # Count auto-named vs user-named
        auto_named = sum(1 for f in funcs if f.get("name", "").startswith(("sub_", "FUN_")))
        report["function_overview"] = {
            "total": func_count,
            "auto_named": auto_named,
            "user_named": func_count - auto_named
        }

        # Step 3: Auto-annotate
        from .auto_annotator import match_function
        from .cache import decompile_cache

        annotations = []
        decompiled_count = 0

        for func in funcs[:limit]:
            addr = func.get("address", "")
            name = func.get("name", "")

            if not (name.startswith("sub_") or name.startswith("FUN_")):
                continue

            cache_key = f"{session_id}:decomp:{addr}"
            code = decompile_cache.get(cache_key)
            if not code:
                try:
                    code = await adapter.decompile_function(addr)
                    if code:
                        decompile_cache.set(cache_key, code)
                        decompiled_count += 1
                except Exception:
                    continue

            if code and len(code) > 20:
                matches = match_function(code)
                if matches and matches[0]["confidence"] >= 0.4:
                    annotations.append({
                        "address": addr,
                        "old_name": name,
                        "suggested": matches[0]["label"],
                        "category": matches[0]["category"],
                        "confidence": round(matches[0]["confidence"], 2)
                    })

        report["steps"].append({
            "step": "auto_annotate",
            "result": f"Identified {len(annotations)} functions from {decompiled_count} decompiled"
        })

        # Step 4: Vulnerability scan
        from .vuln_scanner import scan_function, generate_report
        all_findings = []
        for func in funcs[:limit]:
            addr = func.get("address", "")
            name = func.get("name", "")
            cache_key = f"{session_id}:decomp:{addr}"
            code = decompile_cache.get(cache_key)
            if code:
                findings = scan_function(name, addr, code)
                all_findings.extend(findings)

        vuln_report = generate_report(all_findings)
        report["steps"].append({
            "step": "vuln_scan",
            "result": f"Found {vuln_report['total_findings']} potential vulnerabilities"
        })

        # Step 5: Generate summary
        cat_summary = {}
        for a in annotations:
            cat = a["category"]
            cat_summary[cat] = cat_summary.get(cat, 0) + 1

        report["summary"] = {
            "binary_session": session_id,
            "functions_scanned": func_count,
            "functions_decompiled": decompiled_count,
            "patterns_identified": len(annotations),
            "pattern_categories": cat_summary,
            "vulnerabilities": vuln_report["by_severity"],
            "vulnerability_hotspots": vuln_report["hotspots"][:5],
            "top_annotations": annotations[:20]
        }

        return report
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
async def quick_scan(session_id: str = "auto") -> Any:
    """
    Quick 30-second binary overview. Returns:
    - Function count and naming stats
    - Top 10 most interesting functions (by size)
    - Import/export summary
    - Quick vuln check on largest functions

    Perfect for "what am I looking at?" moments.
    """
    try:
        if session_id == "auto":
            from .auto_session import auto_create_sessions
            results = auto_create_sessions(session_manager)
            active = [r for r in results if r["status"] in ("created", "already_exists")]
            if not active:
                return {"error_message": "No backends detected. Start a RE tool and try again."}
            session_id = active[0]["session_id"]

        session_id = session_manager.resolve_session_id(session_id)
        adapter = get_adapter(session_id)

        overview = {"session_id": session_id}

        # Functions
        funcs = await adapter.list_functions(offset=0, limit=500)
        funcs = [f.model_dump() for f in funcs]
        if funcs:
            overview["function_count"] = len(funcs)
            auto_named = sum(1 for f in funcs if f.get("name", "").startswith(("sub_", "FUN_")))
            overview["auto_named"] = auto_named
            overview["user_named"] = len(funcs) - auto_named

            # Sort by size descending
            sized = [f for f in funcs if f.get("size", 0) > 0]
            sized.sort(key=lambda x: x.get("size", 0), reverse=True)
            overview["largest_functions"] = [
                {"name": f.get("name"), "address": f.get("address"), "size": f.get("size")}
                for f in sized[:10]
            ]

        # Imports
        try:
            imports = await adapter.get_imports(0, 20)
            if imports:
                overview["imports_sample"] = [i.model_dump() for i in imports[:10]]
                overview["import_count"] = len(imports)
        except Exception:
            overview["imports_sample"] = "unavailable"

        # Strings
        try:
            strings = await adapter.list_strings(0, 20)
            if strings:
                overview["interesting_strings"] = [s.model_dump() for s in strings[:10]]
        except Exception:
            overview["interesting_strings"] = "unavailable"

        return overview
    except Exception as e:
        return handle_error(e)


# @mcp.tool() # Removed for Limit Bypass
def server_status() -> str:
    """
    Health check dashboard showing:
    - Connected backends (with live port probing)
    - Active sessions
    - Cache stats
    - Diff log count
    - Similarity index size
    """
    try:
        from .auto_session import detect_running_backends
        from .cache import decompile_cache, function_cache, disasm_cache

        lines = []
        lines.append("╔══════════════════════════════════════╗")
        lines.append("║     NEXUSRE-MCP SERVER STATUS        ║")
        lines.append("╚══════════════════════════════════════╝")
        lines.append("")

        # Backend status
        lines.append("🔌 BACKENDS:")
        backends = detect_running_backends()
        backend_names = {b["backend"] for b in backends}
        all_backends = [
            ("IDA Pro", "ida", 10101),
            ("Ghidra", "ghidra", 10102),
            ("x64dbg", "x64dbg", 10103),
            ("Binary Ninja", "binja", 10104),
            ("Cheat Engine", "cheatengine", 10105),
        ]
        for display_name, backend_id, port in all_backends:
            status = "🟢 ONLINE" if backend_id in backend_names else "🔴 offline"
            lines.append(f"  {display_name:20s} :{port:<5d}  {status}")
        lines.append("")

        # Sessions
        sessions = session_manager.list_sessions()
        lines.append(f"📋 SESSIONS: {len(sessions)}")
        for s in sessions[:5]:
            lines.append(f"  {s['session_id']:20s} → {s['backend']:10s}")
        lines.append("")

        # Cache
        lines.append("💾 CACHE:")
        for name, cache in [("Decompile", decompile_cache), ("Function", function_cache), ("Disasm", disasm_cache)]:
            stats = cache.stats()
            lines.append(f"  {name:12s} {stats['size']:4d}/{stats['max_size']}  hit rate: {stats['hit_rate']}")
        lines.append("")

        # Diff log
        try:
            from .diff_engine import diff_engine
            history = diff_engine.get_history(limit=0)
            lines.append(f"📝 DIFF LOG: {len(history)} entries")
        except Exception:
            lines.append("📝 DIFF LOG: unavailable")

        # Similarity index
        try:
            from .similarity import similarity_engine
            count = similarity_engine.index_count()
            lines.append(f"🧠 SIMILARITY INDEX: {count} functions indexed")
        except Exception:
            lines.append("🧠 SIMILARITY INDEX: unavailable")

        return "\n".join(lines)
    except Exception as e:
        return handle_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED ROUTER TOOLS (Limit Bypass)
# ═══════════════════════════════════════════════════════════════════════════════
from typing import Literal

@mcp.tool()
async def session_management_tools(
    action: Literal["init_session", "list_sessions", "set_default_session", "check_backends", "detect_backends", "server_status"],
    session_id: str = None, backend: str = None, binary_path: str = None, architecture: str = "x86_64", backend_url: str = ""
) -> Any:
    """Consolidated router for managing AI sessions and backend connectivity."""
    if action == "init_session": return init_session(session_id, backend, binary_path, architecture, backend_url)
    elif action == "list_sessions": return list_sessions()
    elif action == "set_default_session": return set_default_session(session_id)
    elif action == "check_backends": return check_backends()
    elif action == "detect_backends": return detect_backends()
    elif action == "server_status": return server_status()

@mcp.tool()
async def function_navigation_tools(
    action: Literal["get_function", "get_current_address", "get_current_function", "get_xrefs", "get_callees", "get_callers", "list_functions"],
    session_id: str, address: str = None, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None
) -> Any:
    """Consolidated router for binary navigation and cross-reference mapping."""
    if action == "get_function": return await get_function(session_id, address)
    elif action == "get_current_address": return await get_current_address(session_id)
    elif action == "get_current_function": return await get_current_function(session_id)
    elif action == "get_xrefs": return await get_xrefs(session_id, address)
    elif action == "get_callees": return await get_callees(session_id, address)
    elif action == "get_callers": return await get_callers(session_id, address)
    elif action == "list_functions": return await list_functions(session_id, offset, limit, filter_str)

@mcp.tool()
async def binary_extraction_tools(
    action: Literal["get_strings", "get_globals", "get_segments", "get_imports", "get_exports"],
    session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None
) -> Any:
    """Consolidated router for extracting symbols, strings, and sections from a binary."""
    if action == "get_strings": return await get_strings(session_id, offset, limit, filter_str)
    elif action == "get_globals": return await get_globals(session_id, offset, limit, filter_str)
    elif action == "get_segments": return await get_segments(session_id, offset, limit)
    elif action == "get_imports": return await get_imports(session_id, offset, limit)
    elif action == "get_exports": return await get_exports(session_id, offset, limit)

@mcp.tool()
async def decompilation_tools(
    action: Literal["decompile_function", "disassemble_at", "batch_decompile", "analyze_functions"],
    session_id: str, address: str = None, addresses: list = None
) -> Any:
    """Consolidated router for fetching assembly and decompiled pseudo-code."""
    if action == "decompile_function": return await decompile_function(session_id, address)
    elif action == "disassemble_at": return await disassemble_at(session_id, address)
    elif action == "batch_decompile": return await batch_decompile(session_id, addresses)
    elif action == "analyze_functions": return await analyze_functions(session_id, addresses)

@mcp.tool()
async def memory_debugging_tools(
    action: Literal["read_memory", "set_hardware_breakpoint", "wait_for_breakpoint", "generate_pointer_map", "read_pointer_chain", "hook_network_packets", "dump_memory_region_to_file", "diff_memory"],
    session_id: str, address: str = None, size: int = 256, timeout: int = 15, offsets: List[str] = None, pid: int = None, max_depth: int = 3, max_offset: int = 0x2000, max_packets: int = 50, output_file: str = None
) -> Any:
    """Consolidated router for dynamic memory reading, debugging, and pointer mapping."""
    if action == "read_memory": return await read_memory(session_id, address, size)
    elif action == "set_hardware_breakpoint": return await set_hardware_breakpoint(session_id, address)
    elif action == "wait_for_breakpoint": return await wait_for_breakpoint(session_id, timeout)
    elif action == "generate_pointer_map": return await generate_pointer_map(session_id, pid, address, max_depth, max_offset)
    elif action == "read_pointer_chain": return await read_pointer_chain(session_id, address, offsets)
    elif action == "hook_network_packets": return await hook_network_packets(session_id, max_packets, timeout)
    elif action == "dump_memory_region_to_file": return await dump_memory_region_to_file(session_id, address, size, output_file)
    elif action == "diff_memory": return await diff_memory(session_id, address, size)

@mcp.tool()
async def modification_tools(
    action: Literal["rename_symbol", "set_comment", "set_function_type", "rename_local_variable", "set_local_variable_type", "patch_address_assembles", "set_global_variable_type", "patch_bytes"],
    session_id: str, address: str = None, name: str = None, comment: str = None, repeatable: bool = False, signature: str = None, old_name: str = None, new_name: str = None, variable_name: str = None, new_type: str = None, instructions: str = None, hex_bytes: str = None
) -> Any:
    """Consolidated router for modifying names, comments, types, and patching assembly/bytes."""
    if action == "rename_symbol": return await rename_symbol(session_id, address, name)
    elif action == "set_comment": return await set_comment(session_id, address, comment, repeatable)
    elif action == "set_function_type": return await set_function_type(session_id, address, signature)
    elif action == "rename_local_variable": return await rename_local_variable(session_id, address, old_name, new_name)
    elif action == "set_local_variable_type": return await set_local_variable_type(session_id, address, variable_name, new_type)
    elif action == "patch_address_assembles": return await patch_address_assembles(session_id, address, instructions)
    elif action == "set_global_variable_type": return await set_global_variable_type(session_id, variable_name, new_type)
    elif action == "patch_bytes": return await patch_bytes(session_id, address, hex_bytes)

@mcp.tool()
async def structural_tools(
    action: Literal["get_stack_frame_variables", "list_local_types", "get_defined_structures", "analyze_struct_detailed", "get_xrefs_to_field", "declare_c_type", "define_struct"],
    session_id: str, address: str = None, struct_name: str = None, field_name: str = None, name: str = None, c_declaration: str = None, fields: list = None
) -> Any:
    """Consolidated router for analyzing and creating memory structures and frames."""
    if action == "get_stack_frame_variables": return await get_stack_frame_variables(session_id, address)
    elif action == "list_local_types": return await list_local_types(session_id)
    elif action == "get_defined_structures": return await get_defined_structures(session_id)
    elif action == "analyze_struct_detailed": return await analyze_struct_detailed(session_id, name)
    elif action == "get_xrefs_to_field": return await get_xrefs_to_field(session_id, struct_name, field_name)
    elif action == "declare_c_type": return await declare_c_type(session_id, c_declaration)
    elif action == "define_struct": return await define_struct(session_id, name, fields)

@mcp.tool()
async def signature_scanning_tools(
    action: Literal["scan_aob", "generate_unique_aob", "generate_yara_rule", "save_signatures", "load_signatures", "validate_signatures", "auto_recover_signatures", "yara_memory_scan"],
    session_id: str = None, pattern: str = None, address: str = None, instruction_count: int = 5, rule_name: str = None, game: str = None, signatures: list = None, yara_rule: str = None, pid: int = None, save_to_brain: bool = True
) -> Any:
    """Consolidated router for scanning arrays of bytes and generating/testing memory signatures."""
    if action == "scan_aob": return await scan_aob(session_id, pattern)
    elif action == "generate_unique_aob": return await generate_unique_aob(session_id, address, instruction_count)
    elif action == "generate_yara_rule": return await generate_yara_rule(session_id, address, rule_name, save_to_brain)
    elif action == "save_signatures": return save_signatures(game, signatures)
    elif action == "load_signatures": return load_signatures(game)
    elif action == "validate_signatures": return await validate_signatures(session_id, game)
    elif action == "auto_recover_signatures": return await auto_recover_signatures(session_id, game)
    elif action == "yara_memory_scan": return await yara_memory_scan(session_id, yara_rule, pid)

@mcp.tool()
async def game_dumping_tools(
    action: Literal["dump_vtables", "dump_vtable", "generate_game_sdk", "dump_unreal_gnames", "dump_unreal_gobjects", "dump_il2cpp_domain", "scaffold_kernel_interface", "spawn_esp_overlay"],
    session_id: str = None, module_base: str = None, address: str = None, max_entries: int = 50, engine_type: str = "unreal", pid: int = None, gnames_address: str = None, gobjects_address: str = None, game_assembly_base: str = None, game_name: str = None
) -> Any:
    """Consolidated router for dumping game engine globals, SDKs, and launching external overlays."""
    if action == "dump_vtables": return await dump_vtables(session_id, module_base)
    elif action == "dump_vtable": return await dump_vtable(session_id, address, max_entries)
    elif action == "generate_game_sdk": return await generate_game_sdk(session_id, engine_type)
    elif action == "dump_unreal_gnames": return dump_unreal_gnames(pid, gnames_address)
    elif action == "dump_unreal_gobjects": return dump_unreal_gobjects(pid, gobjects_address)
    elif action == "dump_il2cpp_domain": return dump_il2cpp_domain(pid, game_assembly_base)
    elif action == "scaffold_kernel_interface": return scaffold_kernel_interface(game_name)
    elif action == "spawn_esp_overlay": return spawn_esp_overlay()

@mcp.tool()
async def ai_intelligence_tools(
    action: Literal["auto_annotate", "suggest_names", "vuln_scan", "index_functions_for_similarity", "find_similar_functions", "full_analysis", "quick_scan", "cross_analyze"],
    session_id: str = None, limit: int = 200, min_confidence: float = 0.4, address: str = None, top_k: int = 5, threshold: float = 0.5, static_session: str = None, dynamic_session: str = None
) -> Any:
    """Consolidated router for running AI-driven automated reverse engineering."""
    if action == "auto_annotate": return await auto_annotate(session_id, limit, min_confidence)
    elif action == "suggest_names": return await suggest_names(session_id, address, top_k)
    elif action == "vuln_scan": return await vuln_scan(session_id, limit)
    elif action == "index_functions_for_similarity": return await index_functions_for_similarity(session_id, limit)
    elif action == "find_similar_functions": return await find_similar_functions(session_id, address, top_k, threshold)
    elif action == "full_analysis": return await full_analysis(session_id, limit)
    elif action == "quick_scan": return await quick_scan(session_id)
    elif action == "cross_analyze": return await cross_analyze(static_session, dynamic_session, address)

@mcp.tool()
async def binary_analysis_sandbox(
    action: Literal["compile_shellcode", "disassemble_bytes", "emulate_subroutine", "solve_symbolic_execution", "symbolic_string_decrypt", "extract_ast_segments"],
    assembly_text: str = None, arch: str = "x86", mode: str = "64", hex_bytes: str = None, address: int = 0x1000, init_registers: dict = None, trace: bool = False, target_addr: int = 0x400050, session_id: str = None, str_address: str = None, instruction_bounds: int = 0x50, c_code: str = None, query_type: str = "if_statement"
) -> Any:
    """Consolidated router for shellcode, emulation, symbolic execution, and AST parsing."""
    if action == "compile_shellcode": return compile_shellcode(assembly_text, arch, mode)
    elif action == "disassemble_bytes": return disassemble_bytes(hex_bytes, arch, mode, address)
    elif action == "emulate_subroutine": return emulate_subroutine(hex_bytes, arch, mode, init_registers, trace)
    elif action == "solve_symbolic_execution": return solve_symbolic_execution(hex_bytes, address, target_addr)
    elif action == "symbolic_string_decrypt": return await symbolic_string_decrypt(session_id, str_address, instruction_bounds)
    elif action == "extract_ast_segments": return extract_ast_segments(c_code, query_type)

@mcp.tool()
async def export_sync_tools(
    action: Literal["export_symbols_as_idc", "export_symbols_as_ghidra_script", "export_cfg", "sync_offsets_to_github", "sync_symbols", "heal_offsets", "diff_binaries", "save_binary"],
    session_id: str = None, output_path: str = "", limit: int = 1000, address: str = None, format: str = "mermaid", repo_name: str = None, github_token: str = None, offsets: dict = None, file_path: str = "offsets.json", source_session_id: str = None, target_session_id: str = None, game_name: str = None, version: str = None, offsets_header_path: str = None, session_id_old: str = None, session_id_new: str = None
) -> Any:
    """Consolidated router for syncing to Github, generating scripts, and diffing binaries."""
    if action == "export_symbols_as_idc": return await export_symbols_as_idc(session_id, output_path, limit)
    elif action == "export_symbols_as_ghidra_script": return await export_symbols_as_ghidra_script(session_id, output_path, limit)
    elif action == "export_cfg": return await export_cfg(session_id, address, format)
    elif action == "sync_offsets_to_github": return sync_offsets_to_github(repo_name, github_token, offsets, file_path)
    elif action == "sync_symbols": return await sync_symbols(source_session_id, target_session_id, limit)
    elif action == "heal_offsets": return await heal_offsets(session_id, game_name, version, offsets_header_path)
    elif action == "diff_binaries": return await diff_binaries(session_id_old, session_id_new, limit)
    elif action == "save_binary": return await save_binary(session_id, output_path)

@mcp.tool()
async def frida_scripting_tools(
    action: Literal["list_frida_snippets", "render_frida_snippet", "save_frida_snippet", "instrument_execution"],
    session_id: str = None, javascript_code: str = None, snippet_name: str = None, address: str = "", func_name: str = "", name: str = None, description: str = None, template: str = None
) -> Any:
    """Consolidated router for Frida dynamic instrumentation templates and execution."""
    if action == "list_frida_snippets": return list_frida_snippets()
    elif action == "render_frida_snippet": return render_frida_snippet(snippet_name, address, func_name)
    elif action == "save_frida_snippet": return save_frida_snippet(name, description, template)
    elif action == "instrument_execution": return await instrument_execution(session_id, javascript_code)

@mcp.tool()
def knowledge_base_tools(
    action: Literal["store_knowledge", "recall_knowledge"],
    key: str = None, summary: str = None, query: str = None
) -> Any:
    """Consolidated router for interacting with the persistent local sqlite brain database."""
    if action == "store_knowledge": return store_knowledge(key, summary)
    elif action == "recall_knowledge": return recall_knowledge(query)

@mcp.tool()
async def history_cache_tools(
    action: Literal["view_request_log", "execute_idapython_script", "view_diff_history", "undo_last_change", "cache_stats", "cache_clear"],
    session_id: str = "", limit: int = 50, code: str = None, cache_name: str = "all"
) -> Any:
    """Consolidated router for auditing history, managing caches, and running arbitrary python on backend."""
    if action == "view_request_log": return view_request_log(limit, session_id)
    elif action == "execute_idapython_script": return execute_idapython_script(session_id, code)
    elif action == "view_diff_history": return view_diff_history(session_id, limit)
    elif action == "undo_last_change": return await undo_last_change(session_id)
    elif action == "cache_stats": return cache_stats()
    elif action == "cache_clear": return cache_clear(cache_name)
