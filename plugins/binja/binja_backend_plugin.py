import os
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import binaryninja as bn
    from binaryninja import BinaryView, PluginCommand, HighLevelILFunction, InstructionTextTokenType
except ImportError:
    pass

# Global reference to the active BinaryView
ACTIVE_BV = None
SERVER_INSTANCE = None

class BinjaOperations:

    @staticmethod
    def get_current_address():
        # Usually requires interacting with the UI context, but there is no reliable headless 'current_address' globally.
        # If running as a UI plugin and triggered on an address, we'd have it. 
        # Standard BN practice is to rely on the active UI context, which isn't fully exposed to background threads globally.
        # Fallback: Just return the entry point of the binary.
        try:
            if not ACTIVE_BV: return None
            return hex(ACTIVE_BV.entry_point)
        except Exception:
            return None

    @staticmethod
    def get_current_function():
        try:
            if not ACTIVE_BV: return None
            func = ACTIVE_BV.get_function_at(ACTIVE_BV.entry_point)
            return hex(func.start) if func else None
        except Exception:
            return None

    @staticmethod
    def get_function(address):
        try:
            if not ACTIVE_BV: return None
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            if not func:
                funcs = ACTIVE_BV.get_functions_containing(addr)
                if funcs: func = funcs[0]
                else: return None
            
            return {
                "name": func.name,
                "address": hex(func.start),
                "size": func.highest_address - func.lowest_address
            }
        except Exception:
            return None

    @staticmethod
    def list_functions(offset=0, limit=100, filter_str=None):
        try:
            if not ACTIVE_BV: return []
            funcs = []
            for func in ACTIVE_BV.functions:
                if filter_str and filter_str.lower() not in func.name.lower():
                    continue
                funcs.append({
                    "name": func.name,
                    "address": hex(func.start),
                    "size": func.highest_address - func.lowest_address
                })
            if limit <= 0: return funcs[offset:]
            return funcs[offset:offset+limit]
        except Exception:
            return []

    @staticmethod
    def decompile(address):
        try:
            if not ACTIVE_BV: return "No active BinaryView"
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            if not func:
                funcs = ACTIVE_BV.get_functions_containing(addr)
                if funcs: func = funcs[0]
                else: return "No function found"

            # Use High Level IL
            hlil = func.hlil
            if not hlil:
                # Force generation
                hlil = func.get_llil().hlil

            out = []
            for b in hlil.basic_blocks:
                for ins in b:
                    out.append(str(ins))
            return "\n".join(out)
        except Exception as e:
            return f"Decompilation error: {e}"

    @staticmethod
    def disassemble(address):
        try:
            if not ACTIVE_BV: return "No active BinaryView"
            addr = int(address, 16)
            # BN doesn't have a simple block disassembler without a function context, but using get_disassembly is okay.
            generator = ACTIVE_BV.get_basic_blocks_at(addr)
            if not generator: return f"{hex(addr)}: ???"
            
            out = []
            for block in generator:
                for ins in block:
                    out.append(f"{hex(ins[1])}: {ins[0]}")
            return "\n".join(out)
        except Exception as e:
            return str(e)

    @staticmethod
    def get_xrefs(address):
        try:
            if not ACTIVE_BV: return []
            addr = int(address, 16)
            xrefs = []
            # Code xrefs to
            for ref in ACTIVE_BV.get_code_refs(addr):
                xrefs.append({"to": hex(addr), "from": hex(ref.address), "type": "Code"})
            return xrefs
        except Exception:
            return []

    @staticmethod
    def rename(address, name):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            sym = ACTIVE_BV.get_symbol_at(addr)
            if func:
                func.name = name
                return True
            elif sym:
                ACTIVE_BV.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, addr, name))
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def set_comment(address, comment, repeatable=False):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            ACTIVE_BV.set_comment_at(addr, comment)
            return True
        except Exception:
            return False

    @staticmethod
    def set_function_type(address, signature):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            if not func: return False
            types = ACTIVE_BV.platform.parse_types_from_string(signature)
            return True
        except Exception:
            return False

    @staticmethod
    def patch_bytes(address, hex_bytes):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            bytes_list = bytes.fromhex(hex_bytes.replace(" ", ""))
            ACTIVE_BV.write(addr, bytes_list)
            return True
        except Exception:
            return False

    @staticmethod
    def save_binary(output_path):
        try:
            if not ACTIVE_BV: return False
            # If output_path is provided, try saving to that, otherwise just save current.
            if output_path and output_path.strip():
                ACTIVE_BV.save(output_path)
            else:
                ACTIVE_BV.save(ACTIVE_BV.file.filename)
            return True
        except Exception:
            return False

    @staticmethod
    def rename_local_variable(address, old_name, new_name):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            if not func: return False
            for var in func.vars:
                if var.name == old_name:
                    var.name = new_name
                    # BN vars aren't immediately properties, use create_user_var
                    func.create_user_var(var, var.type, new_name)
                    return True
            return False
        except Exception:
            return False

    @staticmethod
    def set_local_variable_type(address, variable_name, new_type):
        try:
            if not ACTIVE_BV: return False
            addr = int(address, 16)
            func = ACTIVE_BV.get_function_at(addr)
            if not func: return False
            
            parsed_type, _ = ACTIVE_BV.parse_type_string(new_type)
            if not parsed_type: return False
            
            for var in func.vars:
                if var.name == variable_name:
                    func.create_user_var(var, parsed_type, var.name)
                    return True
            return False
        except Exception:
            return False

    @staticmethod
    def get_strings(offset=0, limit=100, filter_str=None):
        try:
            if not ACTIVE_BV: return []
            strings = []
            for s in ACTIVE_BV.strings:
                val = str(s.value)
                if filter_str and filter_str.lower() not in val.lower():
                    continue
                strings.append({"address": hex(s.start), "value": val})
            if limit <= 0: return strings[offset:]
            return strings[offset:offset+limit]
        except Exception:
            return []

    @staticmethod
    def get_globals(offset=0, limit=100, filter_str=None):
        try:
            if not ACTIVE_BV: return []
            globals_lst = []
            for sym in ACTIVE_BV.get_symbols_of_type(bn.SymbolType.DataSymbol):
                if filter_str and filter_str.lower() not in sym.name.lower():
                    continue
                globals_lst.append({
                    "name": sym.name,
                    "address": hex(sym.address),
                    "size": 0,
                    "value": None
                })
            if limit <= 0: return globals_lst[offset:]
            return globals_lst[offset:offset+limit]
        except Exception:
            return []

    @staticmethod
    def get_segments(offset=0, limit=100):
        try:
            if not ACTIVE_BV: return []
            segs = []
            for seg in ACTIVE_BV.segments:
                perms = ""
                if seg.readable: perms += "R"
                if seg.writable: perms += "W"
                if seg.executable: perms += "X"
                segs.append({
                    "name": "segment",
                    "start_address": hex(seg.start),
                    "end_address": hex(seg.end),
                    "size": seg.data_length,
                    "permissions": perms
                })
            if limit <= 0: return segs[offset:]
            return segs[offset:offset+limit]
        except Exception:
            return []

    @staticmethod
    def get_imports(offset=0, limit=100):
        try:
            if not ACTIVE_BV: return []
            imports = []
            for sym in ACTIVE_BV.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol):
                imports.append({
                    "name": sym.name,
                    "address": hex(sym.address),
                    "module": ""
                })
            if limit <= 0: return imports[offset:]
            return imports[offset:offset+limit]
        except Exception:
            return []

    @staticmethod
    def get_exports(offset=0, limit=100):
        try:
            if not ACTIVE_BV: return []
            exports = []
            # Usually FunctionSymbol and exported
            for sym in ACTIVE_BV.get_symbols_of_type(bn.SymbolType.FunctionSymbol):
                exports.append({
                    "name": sym.name,
                    "address": hex(sym.address)
                })
            if limit <= 0: return exports[offset:]
            return exports[offset:offset+limit]
        except Exception:
            return []


class MCPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        if not post_data:
            self.send_response(400)
            self.end_headers()
            return
            
        try:
            req = json.loads(post_data.decode('utf-8'))
            action = req.get("action")
            args = req.get("args", {})
            
            result = {}

            if action == "binja_get_current_address":
                result = {"address": BinjaOperations.get_current_address()}
            elif action == "binja_get_current_function":
                result = {"address": BinjaOperations.get_current_function()}
            elif action == "binja_list_functions":
                result = {"functions": BinjaOperations.list_functions(args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "binja_get_function":
                result = BinjaOperations.get_function(args.get("address"))
                if result is None: result = {"error": "Function not found"}
            elif action == "binja_decompile_function":
                result = {"code": BinjaOperations.decompile(args.get("address"))}
            elif action == "binja_disassemble":
                result = {"code": BinjaOperations.disassemble(args.get("address"))}
            elif action == "binja_get_xrefs":
                result = {"xrefs": BinjaOperations.get_xrefs(args.get("address"))}
            elif action == "binja_set_comment":
                result = {"success": BinjaOperations.set_comment(args.get("address"), args.get("comment"), args.get("repeatable"))}
            elif action == "binja_rename_symbol":
                result = {"success": BinjaOperations.rename(args.get("address"), args.get("name"))}
            elif action == "binja_get_strings":
                result = {"strings": BinjaOperations.get_strings(args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "binja_get_globals":
                result = {"globals": BinjaOperations.get_globals(args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "binja_get_segments":
                result = {"segments": BinjaOperations.get_segments(args.get("offset", 0), args.get("limit", 100))}
            elif action == "binja_get_imports":
                result = {"imports": BinjaOperations.get_imports(args.get("offset", 0), args.get("limit", 100))}
            elif action == "binja_get_exports":
                result = {"exports": BinjaOperations.get_exports(args.get("offset", 0), args.get("limit", 100))}
            elif action == "binja_set_function_type":
                result = {"success": BinjaOperations.set_function_type(args.get("address"), args.get("signature"))}
            elif action == "binja_rename_local_variable":
                result = {"success": BinjaOperations.rename_local_variable(args.get("address"), args.get("old_name"), args.get("new_name"))}
            elif action == "binja_set_local_variable_type":
                result = {"success": BinjaOperations.set_local_variable_type(args.get("address"), args.get("variable_name"), args.get("new_type"))}
            elif action == "binja_patch_bytes":
                result = {"success": BinjaOperations.patch_bytes(args.get("address"), args.get("hex_bytes"))}
            elif action == "binja_save_binary":
                result = {"success": BinjaOperations.save_binary(args.get("output_path"))}
            elif action == "binja_analyze_functions":
                if ACTIVE_BV: ACTIVE_BV.update_analysis_and_wait()
                result = {"success": True}
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error": "action not found"}')
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def log_message(self, format, *args):
        pass


def start_server_thread():
    global SERVER_INSTANCE
    if SERVER_INSTANCE:
        return
    PORT = 10104
    SERVER_INSTANCE = HTTPServer(('127.0.0.1', PORT), MCPRequestHandler)
    print(f"[Binja-MCP] Server listening natively on port {PORT}")
    SERVER_INSTANCE.serve_forever()

def start_mcp_server(bv):
    global ACTIVE_BV
    ACTIVE_BV = bv
    print(f"[Binja-MCP] Bound session to BinaryView: {bv.file.filename}")
    
    t = threading.Thread(target=start_server_thread)
    t.daemon = True
    t.start()
    bn.show_message_box("NexusRE MCP", "MCP Background Server Started!\nYou can now connect Cursor/Claude to this binary using backend 'binja'", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.InformationIcon)

try:
    PluginCommand.register(
        "NexusRE MCP\\Start Background Server",
        "Starts the HTTP JSON-RPC listener for AI connections",
        start_mcp_server
    )
except NameError:
    # Not running inside BN UI
    pass
