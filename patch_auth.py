import os

def patch_python_backend(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    auth_logic = """
    def _check_auth(self):
        import pathlib
        try:
            token_file = pathlib.Path.home() / ".nexusre" / "auth_token"
            if not token_file.exists():
                return True # Fail-open if no token deployed yet
            with open(token_file, "r") as f:
                expected = f.read().strip()
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer ") or auth_header[7:] != expected:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized"}')
                return False
            return True
        except Exception:
            return True
"""
    if 'def _check_auth' not in content:
        content = content.replace('class MCPRequestHandler(BaseHTTPRequestHandler):', 'class MCPRequestHandler(BaseHTTPRequestHandler):\n' + auth_logic)
        
    if 'if not self._check_auth(): return' not in content:
        content = content.replace('def do_GET(self):', 'def do_GET(self):\n        if not self._check_auth(): return')
        content = content.replace('def do_POST(self):', 'def do_POST(self):\n        if not self._check_auth(): return')
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

for p in ['plugins/ida/ida_backend_plugin.py', 'plugins/x64dbg/x64dbg_backend_plugin.py', 'plugins/binja/binja_backend_plugin.py']:
    if os.path.exists(p):
        patch_python_backend(p)
        print(f'Patched {p}')
