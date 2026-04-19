import threading
import json
import sys

# Python 2 / 3 Compatibility
if sys.version_info[0] < 3:
    import BaseHTTPServer
    from BaseHTTPServer import BaseHTTPRequestHandler
else:
    from http.server import HTTPServer as BaseHTTPServer
    from http.server import BaseHTTPRequestHandler

# Attempt to load ghidra-specific state, catching exceptions if run outside
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.address import AddressFactory
except ImportError:
    pass

class GhidraRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length_str = self.headers.get('Content-Length') or self.headers.get('content-length')
            content_length = int(content_length_str) if content_length_str else 0
        except Exception:
            content_length = 0
            
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
            
            # --- Native Ghidra Program Execution ---
            prog = getattr(self, 'currentProgram', None)
            if prog:
                if action == 'ghidra_get_current_address':
                    loc = getattr(self, 'currentLocation', None)
                    if loc:
                        result = {"address": "0x" + loc.getAddress().toString()}
                        
                elif action == 'ghidra_list_functions':
                    funcs = []
                    limit = int(args.get("limit", 100))
                    offset = int(args.get("offset", 0))
                    fm = prog.getFunctionManager()
                    for idx, f in enumerate(fm.getFunctions(True)):
                        if idx < offset: continue
                        if idx >= offset + limit: break
                        funcs.append({
                            "name": f.getName(),
                            "address": "0x" + f.getEntryPoint().toString(),
                            "size": f.getBody().getNumAddresses()
                        })
                    result = {"functions": funcs}
                    
                elif action == 'ghidra_decompile_function':
                    addr_str = args.get("address", "")
                    addr = prog.getAddressFactory().getAddress(addr_str)
                    func = prog.getFunctionManager().getFunctionAt(addr)
                    if func:
                        decomp = DecompInterface()
                        decomp.openProgram(prog)
                        res = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
                        if res and res.getDecompiledFunction():
                            result = {"code": res.getDecompiledFunction().getC()}
                        else:
                            result = {"code": "// Decompilation failed or timed out"}
                    else:
                        result = {"error": "Function not found"}

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def log_message(self, format, *args):
        pass # Suppress noisy logging

def start_server():
    server = BaseHTTPServer(('127.0.0.1', 10102), GhidraRequestHandler)
    print("\n[Ghidra-MCP] Starting background HTTP server on 127.0.0.1:10102 ...")
    server.serve_forever()

if __name__ == "__main__":
    print("\nStarting NexusRE MCP Ghidra Plugin...")
    if 'currentProgram' in globals():
        GhidraRequestHandler.currentProgram = currentProgram
    if 'currentLocation' in globals():
        GhidraRequestHandler.currentLocation = currentLocation
        
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()
