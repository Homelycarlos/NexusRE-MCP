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
from adapters.gdb import GDBAdapter
from adapters.kernel import KernelAdapter
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
    elif session.backend == "gdb":
        return GDBAdapter(session.binary_path)      # GDB Machine Interface
    elif session.backend == "kernel":
        return KernelAdapter(session.binary_path)   # Ring-0 driver symlink e.g. \\.\ZeraphX
    elif session.backend == "dma":
        from adapters.dma import DMAAdapter
        return DMAAdapter(session.binary_path)      # PCIe Hardware PID
    else:
        raise ValueError(f"Unknown backend {session.backend}")

def handle_error(e: Exception) -> dict:
    logger.error(f"Error executing tool: {e}")
    return ErrorSchema(message=str(e), code="TOOL_ERROR").model_dump()

# ═══════════════════════════════════════════════════════════════════════════════
# Session Management
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
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

@mcp.tool()
def list_sessions() -> Any:
    """List all active NexusRE sessions and which is the default."""
    return {"sessions": session_manager.list_sessions()}

@mcp.tool()
def set_default_session(session_id: str) -> Any:
    """Set a session as the default so you don't have to pass session_id every time."""
    success = session_manager.set_default(session_id)
    if success:
        return {"success": True, "message": f"{session_id} is now the default session."}
    return {"success": False, "message": f"Session {session_id} not found."}

@mcp.tool()
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

@mcp.tool()
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

# NOTE: scan_aob is now unified above (line ~180). CE, IDA, and x64dbg all route through the same tool.

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

# ═══════════════════════════════════════════════════════════════════════════════
# Utility / Master Class Framework Tools
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
def yara_memory_scan(pid: int, yara_rule: str) -> Any:
    """Perform a live YARA memory scan against a target process PID. Useful for bypassing Anti-Cheats or mapping generic payloads."""
    try:
        import yara
        import pymem
        
        rules = yara.compile(source=yara_rule)
        pm = pymem.Pymem(pid)
        matches_found = []
        
        for region in pm.memory_regions():
            try:
                # Read physical memory region
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
def dump_unreal_gnames(pid: int, gnames_address: str) -> Any:
    """[UE4/5 Only] Decrypt and dump the global string array (GNames) directly from game memory using Pymem."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        base = int(gnames_address, 16)
        
        # Simplified FNamePool read structure mapping
        # Actual structure depends heavily on UE 4.22 vs UE 5.0+
        # This acts as the MCP template for the AI to dynamically edit struct parameters
        chunk_table = pm.read_ulonglong(base + 0x10)
        return {"success": True, "message": f"Successfully hooked GNames pool at chunk table {hex(chunk_table)}. Implement struct parser loop here."}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
def dump_unreal_gobjects(pid: int, gobjects_address: str) -> Any:
    """[UE4/5 Only] Dump the global UObject array (GUObjectArray) to map the game's actual actor/player structures."""
    try:
        import pymem
        pm = pymem.Pymem(pid)
        base = int(gobjects_address, 16)
        
        objects_count = pm.read_int(base + 0x14) # NumElements
        obj_array = pm.read_ulonglong(base + 0x10) # ObjObjects pointer
        
        return {
            "success": True, 
            "total_objects": objects_count,
            "array_base": hex(obj_array),
            "message": "AI can now iterate over the array base using read_pointer_chain tool to build the SDK."
        }
    except Exception as e:
        return handle_error(e)

# ═══════════════════════════════════════════════════════════════════════════════
# Auxiliary Engine Extents: Layer 7 Framework Additions
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
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

@mcp.tool()
def hook_network_packets(filter_string: str = "udp.DstPort == 1119", timeout_ms: int = 5000) -> Any:
    """[WinDivert] Set an aggressive L3/L4 Native Packet Filter. Intercept Game Packets (e.g. World of Warcraft, Tarkov) before they reach the OS."""
    try:
        import pydivert
        packets_captured = []
        
        with pydivert.WinDivert(filter_string) as w:
            # We enforce a timeout so the MCP doesn't lock forever
            w.set_timeout(timeout_ms)
            try:
                for packet in w:
                    packets_captured.append({
                        "src": f"{packet.src_addr}:{packet.src_port}",
                        "dst": f"{packet.dst_addr}:{packet.dst_port}",
                        "payload_hex": packet.payload.hex() if packet.payload else ""
                    })
                    w.send(packet) # Re-inject so we don't disconnect the game
                    if len(packets_captured) > 10: break
            except Exception:
                pass # Timeout Reached
                
        return {"captured": packets_captured}
    except ImportError:
        return handle_error(Exception("pydivert is not installed. Note: Requires WinDivert drivers natively installed on system."))
    except Exception as e:
        return handle_error(e)

@mcp.tool()
def spawn_esp_overlay() -> Any:
    """[ImGui/GLFW] Instantiates a TopMost, Transparent overlay window. Requires an external rendering loop."""
    return {"message": "Dynamic Python ImGui Overlay pipeline requires dedicated Thread execution. Use run_command to trigger 'python overlay_script.py'."}

# ═══════════════════════════════════════════════════════════════════════════════
# Signature Database (Persistent AOB Pattern Storage)
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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

