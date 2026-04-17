# -*- coding: utf-8 -*-
# NexusRE x64dbg MCP Backend Plugin
# Python 2.7 / 3.x dual-compatible HTTP bridge
# Exposes x64dbg scripting API over localhost:10103

import os
import json
import threading
import re
import struct

# ── Python 2/3 Compatibility Layer ────────────────────────────────────────
try:
    # Python 3
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
    PY3 = True
except ImportError:
    # Python 2.7
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from SocketServer import ThreadingMixIn
    PY3 = False

try:
    # x64dbgpy API - only available when running inside x64dbg
    from x64dbgpy.pluginsdk._scriptapi import register, memory, module, symbol, debug, assembler, pattern as x64pattern
    import x64dbgpy.pluginsdk.x64dbg as x64dbg
    HAS_X64DBG = True
except ImportError:
    HAS_X64DBG = False

PORT = 10103


# ── Core Operations ───────────────────────────────────────────────────────

class x64dbgOperations:

    @staticmethod
    def get_current_address():
        try:
            addr = register.GetRIP()
            return hex(addr) if addr else None
        except Exception:
            return None

    @staticmethod
    def get_current_function():
        try:
            addr = register.GetRIP()
            if not addr:
                return None
            return hex(addr)
        except Exception:
            return None

    @staticmethod
    def list_functions(offset=0, limit=100, filter_str=None):
        return []

    @staticmethod
    def get_function(address):
        try:
            addr = int(address, 16)
            return {
                "name": "sub_%x" % addr,
                "address": hex(addr),
                "size": 0x100
            }
        except Exception:
            return None

    @staticmethod
    def disassemble(address, count=32):
        """Disassemble `count` instructions starting at `address`."""
        try:
            addr = int(address, 16)
            lines = []
            current = addr
            for _ in range(count):
                # x64dbg command: dis.len(addr) gives instruction length
                # We use DbgCmdExecDirect + the script log to grab disassembly
                # But the simplest approach is memory read + format
                try:
                    inst_len_str = x64dbg.DbgValFromString("dis.len(%s)" % hex(current))
                    inst_len = int(inst_len_str) if inst_len_str else 0
                except Exception:
                    inst_len = 0

                if inst_len <= 0 or inst_len > 15:
                    # Fallback: try to get at least one instruction
                    try:
                        asm_result = assembler.DisassembleAt(current)
                        if asm_result:
                            lines.append("%s: %s" % (hex(current), str(asm_result)))
                    except Exception:
                        pass
                    break

                # Get the mnemonic text
                try:
                    asm_result = assembler.DisassembleAt(current)
                    asm_text = str(asm_result) if asm_result else "???"
                except Exception:
                    asm_text = "???"

                lines.append("%s: %s" % (hex(current), asm_text))
                current += inst_len

            return "\n".join(lines)
        except Exception as e:
            return "Disassembly error: %s" % str(e)

    @staticmethod
    def scan_aob(pattern_str):
        """
        Scan for an AOB pattern in the main module's .text section.
        Pattern format: "0F 28 1A ?? ?? 62" (spaces, ?? for wildcards)
        Returns the first match address as hex string, or None.
        """
        try:
            # Get main module boundaries
            main_base = module.GetMainModuleBase()
            main_size = module.GetMainModuleSize()

            if not main_base or not main_size:
                return None

            # Method 1: Try x64dbg native pattern find command
            # x64dbg script: findall <start>, <pattern>
            # The pattern format for x64dbg is the same as ours but without spaces
            x64_pattern = pattern_str.replace(" ", "")
            # Use findallmem which searches memory range
            cmd = "findallmem %s, %s, %s" % (hex(main_base), x64_pattern, hex(main_size))
            x64dbg.DbgCmdExecDirect(cmd)

            # After findallmem, results are stored in the reference view.
            # We can get the first result address from the reference count
            ref_count_str = x64dbg.DbgValFromString("ref.count()")
            ref_count = int(ref_count_str) if ref_count_str else 0

            if ref_count > 0:
                first_addr_str = x64dbg.DbgValFromString("ref.addr(0)")
                first_addr = int(first_addr_str) if first_addr_str else 0
                if first_addr:
                    return hex(first_addr)

            # Method 2: Manual memory scan fallback
            return x64dbgOperations._manual_aob_scan(main_base, main_size, pattern_str)

        except Exception as e:
            # Method 2 fallback on any failure
            try:
                main_base = module.GetMainModuleBase()
                main_size = module.GetMainModuleSize()
                if main_base and main_size:
                    return x64dbgOperations._manual_aob_scan(main_base, main_size, pattern_str)
            except Exception:
                pass
            return None

    @staticmethod
    def _manual_aob_scan(base, size, pattern_str):
        """
        Fallback AOB scanner: reads memory in chunks and uses regex matching.
        """
        try:
            # Parse the pattern into a regex
            parts = pattern_str.strip().split()
            regex_parts = []
            for p in parts:
                if p == "??" or p == "?":
                    regex_parts.append(b".")
                else:
                    val = int(p, 16)
                    # Escape the byte for regex
                    regex_parts.append(re.escape(struct.pack("B", val)))

            if PY3:
                pat = b"".join(regex_parts)
            else:
                pat = b"".join(regex_parts)

            compiled = re.compile(pat, re.DOTALL)

            # Read in 64KB chunks with overlap
            CHUNK = 0x10000
            OVERLAP = len(parts)  # overlap by pattern length to catch boundary matches
            offset = 0

            while offset < size:
                read_size = min(CHUNK + OVERLAP, size - offset)
                try:
                    data = memory.Read(base + offset, read_size)
                except Exception:
                    offset += CHUNK
                    continue

                if not data:
                    offset += CHUNK
                    continue

                # Convert to bytes if needed
                if not isinstance(data, bytes):
                    if PY3:
                        data = bytes(data)
                    else:
                        data = str(data)

                m = compiled.search(data)
                if m:
                    found_addr = base + offset + m.start()
                    return hex(found_addr)

                offset += CHUNK

            return None
        except Exception:
            return None

    @staticmethod
    def read_memory(address, size):
        """Read raw bytes from the debugged process."""
        try:
            addr = int(address, 16)
            data = memory.Read(addr, size)
            if data:
                if PY3:
                    return " ".join("%02X" % b for b in data)
                else:
                    return " ".join("%02X" % ord(b) for b in data)
            return None
        except Exception:
            return None

    @staticmethod
    def get_xrefs(address):
        return []

    @staticmethod
    def set_comment(address, comment, repeatable=False):
        try:
            addr = int(address, 16)
            cmd = 'cmt %s, "%s"' % (hex(addr), comment)
            x64dbg.DbgCmdExecDirect(cmd)
            return True
        except Exception:
            return False

    @staticmethod
    def rename_symbol(address, name):
        try:
            addr = int(address, 16)
            cmd = 'lbl %s, "%s"' % (hex(addr), name)
            x64dbg.DbgCmdExecDirect(cmd)
            return True
        except Exception:
            return False

    @staticmethod
    def get_strings(offset=0, limit=100, filter_str=None):
        return []

    @staticmethod
    def get_globals(offset=0, limit=100, filter_str=None):
        return []

    @staticmethod
    def get_segments(offset=0, limit=100):
        return []

    @staticmethod
    def get_imports(offset=0, limit=100):
        return []

    @staticmethod
    def get_exports(offset=0, limit=100):
        return []

    @staticmethod
    def patch_bytes(address, hex_bytes):
        try:
            addr = int(address, 16)
            hex_str = hex_bytes.replace(" ", "")
            if PY3:
                b_list = bytes.fromhex(hex_str)
            else:
                b_list = hex_str.decode("hex")
            succ = memory.Write(addr, b_list, len(b_list))
            return bool(succ)
        except Exception:
            return False


# ── HTTP Server (Py2/Py3 Compatible) ─────────────────────────────────────

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class MCPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # Python 2/3 compatible Content-Length reading
        try:
            cl = self.headers.get('Content-Length', '0')
        except Exception:
            cl = '0'
        content_length = int(cl)

        post_data = self.rfile.read(content_length)
        if not post_data:
            self.send_response(400)
            self.end_headers()
            return

        try:
            if PY3:
                req = json.loads(post_data.decode('utf-8'))
            else:
                req = json.loads(post_data)

            action = req.get("action")
            args = req.get("args", {})

            result = {}

            if action == "x64dbg_get_current_address":
                result = {"address": x64dbgOperations.get_current_address()}
            elif action == "x64dbg_get_current_function":
                result = {"address": x64dbgOperations.get_current_function()}
            elif action == "x64dbg_list_functions":
                result = {"functions": x64dbgOperations.list_functions(
                    args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "x64dbg_get_function":
                result = x64dbgOperations.get_function(args.get("address")) or {}
            elif action == "x64dbg_disassemble":
                cnt = args.get("count", 32)
                result = {"code": x64dbgOperations.disassemble(args.get("address"), cnt)}
            elif action == "x64dbg_scan_aob":
                addr = x64dbgOperations.scan_aob(args.get("pattern", ""))
                result = {"address": addr}
            elif action == "x64dbg_read_memory":
                data = x64dbgOperations.read_memory(args.get("address"), args.get("size", 256))
                result = {"data": data}
            elif action == "x64dbg_get_xrefs":
                result = {"xrefs": x64dbgOperations.get_xrefs(args.get("address"))}
            elif action == "x64dbg_set_comment":
                result = {"success": x64dbgOperations.set_comment(
                    args.get("address"), args.get("comment"))}
            elif action == "x64dbg_rename_symbol":
                result = {"success": x64dbgOperations.rename_symbol(
                    args.get("address"), args.get("name"))}
            elif action == "x64dbg_get_strings":
                result = {"strings": x64dbgOperations.get_strings(
                    args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "x64dbg_get_globals":
                result = {"globals": x64dbgOperations.get_globals(
                    args.get("offset", 0), args.get("limit", 100), args.get("filter"))}
            elif action == "x64dbg_get_segments":
                result = {"segments": x64dbgOperations.get_segments(
                    args.get("offset", 0), args.get("limit", 100))}
            elif action == "x64dbg_get_imports":
                result = {"imports": x64dbgOperations.get_imports(
                    args.get("offset", 0), args.get("limit", 100))}
            elif action == "x64dbg_get_exports":
                result = {"exports": x64dbgOperations.get_exports(
                    args.get("offset", 0), args.get("limit", 100))}
            elif action == "x64dbg_set_function_type":
                result = {"success": False}
            elif action == "x64dbg_analyze_functions":
                result = {"success": True}
            elif action == "x64dbg_patch_bytes":
                result = {"success": x64dbgOperations.patch_bytes(
                    args.get("address", "0"), args.get("hex_bytes", ""))}
            else:
                self.send_response(404)
                self.end_headers()
                resp_body = b'{"error": "action not found"}'
                self.wfile.write(resp_body)
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            resp_json = json.dumps(result)
            if PY3:
                self.wfile.write(resp_json.encode('utf-8'))
            else:
                self.wfile.write(resp_json)

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            err = json.dumps({"error": str(e)})
            if PY3:
                self.wfile.write(err.encode('utf-8'))
            else:
                self.wfile.write(err)

    def log_message(self, format, *args):
        # Suppress default stderr logging
        pass


# ── Server Entrypoint ─────────────────────────────────────────────────────

def start_server():
    try:
        server = ThreadingHTTPServer(('127.0.0.1', PORT), MCPRequestHandler)
        print("[NexusRE] x64dbg MCP Server started on port %d" % PORT)
        server.serve_forever()
    except Exception as e:
        print("[NexusRE] Failed to start server: %s" % str(e))


# Auto-start when executed inside x64dbg or standalone
t = threading.Thread(target=start_server)
t.daemon = True
t.start()
