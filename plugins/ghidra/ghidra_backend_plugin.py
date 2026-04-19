# NexusRE-MCP Ghidra Backend Plugin v2
# Compatible with Ghidra 11.x+ (PyGhidra / Jython)
# Starts a background HTTP server on port 10102 for AI connectivity.
#
# v2 Changes:
#   - Transaction wrapping on ALL write operations
#   - Health watchdog thread (detects stale program refs)
#   - Batch decompile support
#   - Struct definition via DataTypeManager
#   - AOB / signature scanning via Memory.findBytes()
#   - Explicit Java iterator .hasNext()/.next() for PyGhidra compat

import threading
import json
import sys
import time
import traceback

# Python 2 / 3 Compatibility
if sys.version_info[0] < 3:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
else:
    from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Ghidra API Imports ─────────────────────────────────────────────────────
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    HAS_GHIDRA = True
except ImportError:
    HAS_GHIDRA = False

# ── Transaction Helper ─────────────────────────────────────────────────────

def _run_in_transaction(prog, label, fn):
    """Execute fn() inside a Ghidra database transaction. Returns the result of fn()."""
    txn = prog.startTransaction(label)
    try:
        result = fn()
        prog.endTransaction(txn, True)
        return result
    except Exception as e:
        prog.endTransaction(txn, False)
        raise e

# ── Shared State ───────────────────────────────────────────────────────────

class GhidraRequestHandler(BaseHTTPRequestHandler):
    _program = None
    _location = None

    # ── HTTP verb handlers ─────────────────────────────────────────────

    def do_GET(self):
        """Health-check endpoint so NexusRE adapter can ping us."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        prog = self.__class__._program
        status = "ok" if prog else "no_program"
        program_name = ""
        if prog:
            try:
                program_name = prog.getName()
            except Exception:
                status = "stale"
                self.__class__._program = None
        self.wfile.write(json.dumps({"status": status, "program": program_name}).encode('utf-8'))

    def do_POST(self):
        try:
            cl = self.headers.get('Content-Length') or self.headers.get('content-length') or '0'
            content_length = int(cl)
        except (TypeError, ValueError):
            content_length = 0

        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        if not post_data:
            self._respond(400, {"error_message": "Empty request body", "error_code": "EMPTY_BODY"})
            return

        try:
            req = json.loads(post_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._respond(400, {"error_message": "Malformed JSON: " + str(e), "error_code": "BAD_JSON"})
            return

        action = req.get("action", "")
        args   = req.get("args", {})
        prog   = self.__class__._program

        try:
            result = self._dispatch(action, args, prog)
            self._respond(200, result)
        except Exception as e:
            traceback.print_exc()
            self._respond(500, {"error_message": str(e), "error_code": "INTERNAL"})

    def _respond(self, code, payload):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    # ── Action Router ──────────────────────────────────────────────────

    def _dispatch(self, action, args, prog):
        if not prog:
            return {"error_message": "No program loaded in Ghidra. Open a binary first.", "error_code": "NO_PROGRAM"}

        # ── Ping / Health ──────────────────────────────────────────────
        if action == "ping":
            return {"status": "ok", "program": prog.getName()}

        # ── Current Address ────────────────────────────────────────────
        elif action == "ghidra_get_current_address":
            loc = self.__class__._location
            if loc:
                return {"address": "0x" + loc.getAddress().toString()}
            return {"address": None}

        # ── Current Function ───────────────────────────────────────────
        elif action == "ghidra_get_current_function":
            loc = self.__class__._location
            if loc:
                fm = prog.getFunctionManager()
                func = fm.getFunctionContaining(loc.getAddress())
                if func:
                    return {"address": "0x" + func.getEntryPoint().toString(), "name": func.getName()}
            return {"address": None}

        # ── List Functions ─────────────────────────────────────────────
        elif action == "ghidra_list_functions":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            funcs  = []
            fm = prog.getFunctionManager()
            idx = 0
            it = fm.getFunctions(True)
            while it.hasNext():
                f = it.next()
                name = f.getName()
                if filt and filt.lower() not in name.lower():
                    continue
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                funcs.append({
                    "name": name,
                    "address": "0x" + f.getEntryPoint().toString(),
                    "size": int(f.getBody().getNumAddresses())
                })
                idx += 1
            return {"functions": funcs}

        # ── Get Function ───────────────────────────────────────────────
        elif action == "ghidra_get_function":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error_message": "Invalid address: " + addr_str, "error_code": "BAD_ADDR"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if func:
                return {
                    "name": func.getName(),
                    "address": "0x" + func.getEntryPoint().toString(),
                    "size": int(func.getBody().getNumAddresses())
                }
            return {"error_message": "Function not found at " + addr_str, "error_code": "NOT_FOUND"}

        # ── Decompile ──────────────────────────────────────────────────
        elif action == "ghidra_decompile_function":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error_message": "Invalid address: " + addr_str, "error_code": "BAD_ADDR"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if not func:
                return {"error_message": "Function not found at " + addr_str, "error_code": "NOT_FOUND"}
            decomp = DecompInterface()
            decomp.openProgram(prog)
            res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
            if res and res.getDecompiledFunction():
                return {"code": res.getDecompiledFunction().getC()}
            return {"code": "// Decompilation failed or timed out"}

        # ── Batch Decompile ────────────────────────────────────────────
        elif action == "ghidra_batch_decompile":
            addresses = args.get("addresses", [])
            decomp = DecompInterface()
            decomp.openProgram(prog)
            results = {}
            for addr_str in addresses:
                addr = prog.getAddressFactory().getAddress(addr_str)
                if not addr:
                    results[addr_str] = "// Invalid address"
                    continue
                func = prog.getFunctionManager().getFunctionAt(addr)
                if not func:
                    func = prog.getFunctionManager().getFunctionContaining(addr)
                if not func:
                    results[addr_str] = "// No function at address"
                    continue
                res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
                if res and res.getDecompiledFunction():
                    results[addr_str] = res.getDecompiledFunction().getC()
                else:
                    results[addr_str] = "// Decompilation failed"
            return {"results": results}

        # ── Disassemble ────────────────────────────────────────────────
        elif action == "ghidra_disassemble":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error_message": "Invalid address: " + addr_str, "error_code": "BAD_ADDR"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if not func:
                return {"code": "// No function at " + addr_str}
            listing = prog.getListing()
            body = func.getBody()
            lines = []
            it = listing.getInstructions(body, True)
            while it.hasNext():
                instr = it.next()
                a = "0x" + instr.getAddress().toString()
                lines.append(a + ": " + instr.toString())
            return {"code": "\n".join(lines)}

        # ── Cross-References ───────────────────────────────────────────
        elif action == "ghidra_get_xrefs":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error_message": "Invalid address", "error_code": "BAD_ADDR"}
            refs = []
            it = prog.getReferenceManager().getReferencesTo(addr)
            while it.hasNext():
                ref = it.next()
                refs.append({
                    "from": "0x" + ref.getFromAddress().toString(),
                    "to":   "0x" + ref.getToAddress().toString(),
                    "type": ref.getReferenceType().getName()
                })
            return {"xrefs": refs}

        # ── Strings ────────────────────────────────────────────────────
        elif action == "ghidra_get_strings":
            from ghidra.program.util import DefinedDataIterator
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            strings = []
            idx = 0
            it = DefinedDataIterator.definedStrings(prog)
            while it.hasNext():
                data = it.next()
                val = data.getDefaultValueRepresentation()
                if filt and filt.lower() not in val.lower():
                    continue
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                strings.append({
                    "address": "0x" + data.getAddress().toString(),
                    "value": val
                })
                idx += 1
            return {"strings": strings}

        # ── Globals ────────────────────────────────────────────────────
        elif action == "ghidra_get_globals":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            globs  = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                if sym.isExternal():
                    continue
                name = sym.getName()
                if name.startswith("DAT_") or name.startswith("s_") or name.startswith("u_"):
                    if filt and filt.lower() not in name.lower():
                        continue
                    if idx < offset:
                        idx += 1
                        continue
                    if idx >= offset + limit:
                        break
                    globs.append({
                        "address": "0x" + sym.getAddress().toString(),
                        "name": name,
                        "size": 0,
                        "value": None
                    })
                    idx += 1
            return {"globals": globs}

        # ── Segments ───────────────────────────────────────────────────
        elif action == "ghidra_get_segments":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            segs   = []
            idx = 0
            for block in prog.getMemory().getBlocks():
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                perms = ""
                if block.isRead():    perms += "R"
                if block.isWrite():   perms += "W"
                if block.isExecute(): perms += "X"
                segs.append({
                    "name": block.getName(),
                    "start_address": "0x" + block.getStart().toString(),
                    "end_address":   "0x" + block.getEnd().toString(),
                    "size": int(block.getSize()),
                    "permissions": perms
                })
                idx += 1
            return {"segments": segs}

        # ── Imports ────────────────────────────────────────────────────
        elif action == "ghidra_get_imports":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            imps   = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getExternalSymbols()
            while it.hasNext():
                sym = it.next()
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                parent = sym.getParentNamespace()
                imps.append({
                    "address": "0x" + sym.getAddress().toString(),
                    "name": sym.getName(),
                    "module": parent.getName() if parent else ""
                })
                idx += 1
            return {"imports": imps}

        # ── Exports ────────────────────────────────────────────────────
        elif action == "ghidra_get_exports":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            exps   = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                if sym.isExternalEntryPoint():
                    if idx < offset:
                        idx += 1
                        continue
                    if idx >= offset + limit:
                        break
                    exps.append({
                        "address": "0x" + sym.getAddress().toString(),
                        "name": sym.getName()
                    })
                    idx += 1
            return {"exports": exps}

        # ══════════════════════════════════════════════════════════════
        # WRITE OPERATIONS — All wrapped in transactions
        # ══════════════════════════════════════════════════════════════

        # ── Rename Symbol ──────────────────────────────────────────────
        elif action == "ghidra_rename_symbol":
            addr_str = args.get("address", "")
            new_name = args.get("name", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            def _do_rename():
                func = prog.getFunctionManager().getFunctionAt(addr)
                if func:
                    func.setName(new_name, SourceType.USER_DEFINED)
                    return {"success": True}
                st = prog.getSymbolTable()
                sym = st.getPrimarySymbol(addr)
                if sym:
                    sym.setName(new_name, SourceType.USER_DEFINED)
                    return {"success": True}
                return {"success": False, "error_message": "No symbol at address"}
            return _run_in_transaction(prog, "NexusRE: rename " + new_name, _do_rename)

        # ── Set Comment ────────────────────────────────────────────────
        elif action == "ghidra_set_comment":
            addr_str   = args.get("address", "")
            comment    = args.get("comment", "")
            repeatable = args.get("repeatable", False)
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            def _do_comment():
                listing = prog.getListing()
                cu = listing.getCodeUnitAt(addr)
                if cu:
                    comment_type = CodeUnit.REPEATABLE_COMMENT if repeatable else CodeUnit.EOL_COMMENT
                    cu.setComment(comment_type, comment)
                    return {"success": True}
                return {"success": False, "error_message": "No code unit at address"}
            return _run_in_transaction(prog, "NexusRE: set comment", _do_comment)

        # ── Set Function Type ──────────────────────────────────────────
        elif action == "ghidra_set_function_type":
            addr_str  = args.get("address", "")
            signature = args.get("signature", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error_message": "No function at address"}
            def _do_set_sig():
                from ghidra.app.util.parser import FunctionSignatureParser
                parser = FunctionSignatureParser(prog.getDataTypeManager(), None)
                fdef = parser.parse(func.getSignature(), signature)
                from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
                cmd = ApplyFunctionSignatureCmd(addr, fdef, SourceType.USER_DEFINED)
                cmd.applyTo(prog)
                return {"success": True}
            try:
                return _run_in_transaction(prog, "NexusRE: set function type", _do_set_sig)
            except Exception as e:
                return {"success": False, "error_message": "Signature parse error: " + str(e)}

        # ── Rename Local Variable ──────────────────────────────────────
        elif action == "ghidra_rename_local_variable":
            addr_str = args.get("address", "")
            old_name = args.get("old_name", "")
            new_name = args.get("new_name", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error_message": "No function at address"}
            def _do_rename_var():
                for var in func.getAllVariables():
                    if var.getName() == old_name:
                        var.setName(new_name, SourceType.USER_DEFINED)
                        return {"success": True}
                return {"success": False, "error_message": "Variable not found: " + old_name}
            return _run_in_transaction(prog, "NexusRE: rename var " + old_name, _do_rename_var)

        # ── Set Local Variable Type ────────────────────────────────────
        elif action == "ghidra_set_local_variable_type":
            addr_str = args.get("address", "")
            var_name = args.get("variable_name", "")
            new_type = args.get("new_type", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error_message": "No function at address"}
            def _do_set_var_type():
                dtm = prog.getDataTypeManager()
                dt = dtm.getDataType("/" + new_type)
                if not dt:
                    return {"success": False, "error_message": "Unknown type: " + new_type}
                for var in func.getAllVariables():
                    if var.getName() == var_name:
                        var.setDataType(dt, SourceType.USER_DEFINED)
                        return {"success": True}
                return {"success": False, "error_message": "Variable not found: " + var_name}
            return _run_in_transaction(prog, "NexusRE: set var type", _do_set_var_type)

        # ── Patch Bytes ────────────────────────────────────────────────
        elif action == "ghidra_patch_bytes":
            addr_str  = args.get("address", "")
            hex_bytes = args.get("hex_bytes", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error_message": "Invalid address"}
            def _do_patch():
                raw = bytes.fromhex(hex_bytes.replace(" ", ""))
                prog.getMemory().setBytes(addr, raw)
                return {"success": True}
            return _run_in_transaction(prog, "NexusRE: patch bytes", _do_patch)

        # ── Define Struct ──────────────────────────────────────────────
        elif action == "ghidra_define_struct":
            struct_name = args.get("name", "")
            fields = args.get("fields", [])
            if not struct_name:
                return {"success": False, "error_message": "Struct name is required"}
            def _do_define_struct():
                from ghidra.program.model.data import StructureDataType, CategoryPath
                dtm = prog.getDataTypeManager()
                # Calculate total size from fields
                max_end = 0
                for field in fields:
                    off = int(field.get("offset", "0"), 16) if isinstance(field.get("offset"), str) else int(field.get("offset", 0))
                    ftype = field.get("type", "byte")
                    # Estimate size from type name
                    type_sizes = {"byte": 1, "char": 1, "short": 2, "int": 4, "long": 8,
                                  "float": 4, "double": 8, "pointer": 8, "uint8_t": 1,
                                  "uint16_t": 2, "uint32_t": 4, "uint64_t": 8,
                                  "int8_t": 1, "int16_t": 2, "int32_t": 4, "int64_t": 8,
                                  "DWORD": 4, "QWORD": 8, "WORD": 2, "BYTE": 1, "BOOL": 4}
                    fsize = type_sizes.get(ftype, 4)
                    end = off + fsize
                    if end > max_end:
                        max_end = end
                struct_size = max(max_end, 1)
                struct_dt = StructureDataType(CategoryPath("/NexusRE"), struct_name, struct_size)
                for field in fields:
                    fname = field.get("name", "field")
                    ftype_str = field.get("type", "int")
                    off = int(field.get("offset", "0"), 16) if isinstance(field.get("offset"), str) else int(field.get("offset", 0))
                    # Resolve the data type from Ghidra's built-in types
                    dt = dtm.getDataType("/" + ftype_str)
                    if dt:
                        struct_dt.replaceAtOffset(off, dt, dt.getLength(), fname, "Added by NexusRE")
                dtm.addDataType(struct_dt, None)
                return {"success": True, "message": "Struct '%s' created with %d fields" % (struct_name, len(fields))}
            return _run_in_transaction(prog, "NexusRE: define struct " + struct_name, _do_define_struct)

        # ── AOB / Signature Scan ───────────────────────────────────────
        elif action == "ghidra_scan_aob":
            pattern = args.get("pattern", "")
            if not pattern:
                return {"error_message": "Pattern is required", "error_code": "BAD_ARGS"}
            memory = prog.getMemory()
            # Convert "48 8B 05 ?? ?? ?? ??" into bytes + mask
            parts = pattern.strip().split()
            search_bytes = []
            mask_bytes = []
            for p in parts:
                if p == "??" or p == "?":
                    search_bytes.append(0)
                    mask_bytes.append(0)  # 0 = don't care
                else:
                    search_bytes.append(int(p, 16) & 0xFF)
                    mask_bytes.append(0xFF)  # 0xFF = must match
            if sys.version_info[0] >= 3:
                search_arr = bytes(search_bytes)
                mask_arr = bytes(mask_bytes)
            else:
                search_arr = bytearray(search_bytes)
                mask_arr = bytearray(mask_bytes)
            min_addr = prog.getMinAddress()
            max_addr = prog.getMaxAddress()
            found = memory.findBytes(min_addr, max_addr, search_arr, mask_arr, True, ConsoleTaskMonitor())
            if found:
                return {"address": "0x" + found.toString()}
            return {"address": None}

        # ── Save / Analyze ─────────────────────────────────────────────
        elif action == "ghidra_save_binary":
            return {"success": True, "message": "Use File -> Save in Ghidra UI"}

        elif action == "ghidra_analyze_functions":
            def _do_analyze():
                from ghidra.app.cmd.function import CreateFunctionCmd
                addresses = args.get("addresses", [])
                for a in addresses:
                    addr = prog.getAddressFactory().getAddress(a)
                    if addr:
                        cmd = CreateFunctionCmd(addr)
                        cmd.applyTo(prog)
                return {"success": True}
            return _run_in_transaction(prog, "NexusRE: analyze functions", _do_analyze)

        else:
            return {"error_message": "Unknown action: " + action, "error_code": "UNKNOWN_ACTION"}

    def log_message(self, format, *args):
        pass  # Suppress noisy per-request logging


# ── Health Watchdog ────────────────────────────────────────────────────────

def _health_watchdog():
    """Background thread that checks if the program reference is still valid."""
    while True:
        time.sleep(10)
        prog = GhidraRequestHandler._program
        if prog is not None:
            try:
                prog.getName()  # Probe — throws if program was closed
            except Exception:
                print("[Ghidra-MCP] WARNING: Program reference went stale. Clearing.")
                GhidraRequestHandler._program = None


# ── Server Lifecycle ───────────────────────────────────────────────────────

_server_instance = None

def start_server():
    global _server_instance
    PORT = 10102

    if _server_instance is not None:
        try:
            _server_instance.shutdown()
            _server_instance.server_close()
            print("[Ghidra-MCP] Shut down previous server instance.")
        except Exception:
            pass

    _server_instance = HTTPServer(('127.0.0.1', PORT), GhidraRequestHandler)
    print("[Ghidra-MCP] Background HTTP server LIVE on 127.0.0.1:%d" % PORT)
    _server_instance.serve_forever()


# ── Entry Point ────────────────────────────────────────────────────────────

print("[Ghidra-MCP] Initializing NexusRE backend plugin v2...")

try:
    GhidraRequestHandler._program  = currentProgram   # noqa: F821
    print("[Ghidra-MCP] Program loaded: %s" % currentProgram.getName())   # noqa: F821
except NameError:
    GhidraRequestHandler._program = None
    print("[Ghidra-MCP] WARNING: No program loaded — open a binary first!")

try:
    GhidraRequestHandler._location = currentLocation   # noqa: F821
except NameError:
    GhidraRequestHandler._location = None

# Start health watchdog
wd = threading.Thread(target=_health_watchdog)
wd.daemon = True
wd.start()

# Start HTTP server
t = threading.Thread(target=start_server)
t.daemon = True
t.start()
print("[Ghidra-MCP] Server thread launched. Ready for AI connections.")
