import os
import sys
import json
import platform

# Ensure the root directory is accessible so modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.server import mcp


def get_config_json() -> dict:
    """Generate the MCP client configuration JSON dynamically."""
    script_path = os.path.abspath(__file__)
    return {
        "mcpServers": {
            "nexusre-mcp": {
                "command": "uv",
                "args": [
                    "run",
                    "--with", "mcp[cli]",
                    "--with", "pydantic",
                    "--with", "aiohttp",
                    "--with", "frida",
                    "--with", "r2pipe",
                    "--with", "pymem",
                    "--with", "aiosqlite",
                    script_path
                ]
            }
        }
    }


def print_config():
    """Print the JSON configuration for manual copy-paste."""
    config = get_config_json()
    print("=========================================")
    print(" NEXUSRE-MCP SERVER CONFIGURATION")
    print("=========================================\n")
    print("Copy the JSON block below and paste it into your MCP client's configuration file:")
    print(" - Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json or ~/Library/Application Support/Claude/claude_desktop_config.json")
    print(" - Cursor / Roo Code / Cline: Add to your MCP settings or workspace mcp.json")
    print(" - Windsurf / Trae: Follow standard MCP initialization paths.\n")
    print(json.dumps(config, indent=2))
    print("\n=========================================")
    sys.exit(0)


def _find_claude_config_paths() -> list:
    """Return a list of possible Claude Desktop config file paths on this system."""
    paths = []
    system = platform.system()

    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            # Standard install
            paths.append(os.path.join(appdata, "Claude", "claude_desktop_config.json"))
        # Windows Store (UWP) app — scan for the package folder
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            packages_dir = os.path.join(local_appdata, "Packages")
            if os.path.isdir(packages_dir):
                for entry in os.listdir(packages_dir):
                    if entry.startswith("Claude_"):
                        uwp_path = os.path.join(packages_dir, entry, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json")
                        paths.append(uwp_path)
    elif system == "Darwin":
        home = os.path.expanduser("~")
        paths.append(os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
    elif system == "Linux":
        xdg = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        paths.append(os.path.join(xdg, "Claude", "claude_desktop_config.json"))

    return paths


def _find_cursor_config_paths() -> list:
    """Return a list of possible Cursor MCP config file paths on this system."""
    paths = []
    system = platform.system()

    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(os.path.join(appdata, "Cursor", "User", "globalStorage", "mcp.json"))
    elif system == "Darwin":
        home = os.path.expanduser("~")
        paths.append(os.path.join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "mcp.json"))
    elif system == "Linux":
        xdg = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        paths.append(os.path.join(xdg, "Cursor", "User", "globalStorage", "mcp.json"))

    return paths


def auto_install():
    """
    Automatically detect Claude Desktop and Cursor, then inject the MCP
    server configuration into their config files without any manual copy-paste.
    """
    config_fragment = get_config_json()
    server_key = "nexusre-mcp"
    server_block = config_fragment["mcpServers"][server_key]

    targets = []
    for path in _find_claude_config_paths():
        targets.append(("Claude Desktop", path))
    for path in _find_cursor_config_paths():
        targets.append(("Cursor", path))

    if not targets:
        print("[!] Could not find any known MCP client config directories on this system.")
        print("    Run --config to get the JSON and paste it manually.")
        sys.exit(1)

    installed_count = 0
    for client_name, config_path in targets:
        # Load existing config or start fresh
        existing = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing = {}

        # Ensure mcpServers key exists
        if "mcpServers" not in existing:
            existing["mcpServers"] = {}

        # Check if already installed
        if server_key in existing["mcpServers"]:
            print(f"[✓] {client_name} ({config_path})")
            print(f"    Already configured. Updating to latest path...")
        else:
            print(f"[+] {client_name} ({config_path})")
            print(f"    Installing NexusRE-MCP server config...")

        # Inject / update the server block
        existing["mcpServers"][server_key] = server_block

        # Ensure parent directories exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        # Write back
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        installed_count += 1
        print(f"    ✅ Done! Restart {client_name} for changes to take effect.\n")

    if installed_count == 0:
        print("[!] No config files were written. Check that your MCP clients are installed.")
    else:
        print(f"[✓] Successfully configured {installed_count} client(s).")

    sys.exit(0)

def install_plugins():
    """Auto-detect installed RE tools and copy the corresponding backend plugins."""
    import shutil
    import glob

    script_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(script_dir, "plugins")
    installed = 0

    # ── IDA Pro ──
    ida_targets = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        ida_targets.append(os.path.join(appdata, "Hex-Rays", "IDA Pro", "plugins"))
    for v in ["8.3", "8.4", "9.0"]:
        ida_targets.append(os.path.join("C:\\", f"IDA Pro {v}", "plugins"))
        ida_targets.append(os.path.join(os.environ.get("PROGRAMFILES", ""), f"IDA Pro {v}", "plugins"))

    for target in ida_targets:
        if os.path.isdir(target):
            src = os.path.join(plugins_dir, "ida", "ida_backend_plugin.py")
            dst = os.path.join(target, "ida_backend_plugin.py")
            shutil.copy2(src, dst)
            print(f"[+] IDA Pro: Copied plugin to {target}")
            installed += 1
            break
    else:
        print("[!] IDA Pro not found. Skipping.")

    # ── Ghidra ──
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    ghidra_targets = []
    if ghidra_dir:
        ghidra_targets.append(os.path.join(ghidra_dir, "Ghidra", "Features", "Python", "ghidra_scripts"))
    home = os.path.expanduser("~")
    ghidra_targets.append(os.path.join(home, "ghidra_scripts"))

    for target in ghidra_targets:
        if os.path.isdir(target):
            src = os.path.join(plugins_dir, "ghidra", "ghidra_backend_plugin.py")
            dst = os.path.join(target, "ghidra_backend_plugin.py")
            shutil.copy2(src, dst)
            print(f"[+] Ghidra: Copied plugin to {target}")
            installed += 1
            break
    else:
        # Create user scripts dir as fallback
        fallback = os.path.join(home, "ghidra_scripts")
        os.makedirs(fallback, exist_ok=True)
        src = os.path.join(plugins_dir, "ghidra", "ghidra_backend_plugin.py")
        shutil.copy2(src, os.path.join(fallback, "ghidra_backend_plugin.py"))
        print(f"[+] Ghidra: Created {fallback} and copied plugin. Add this to Script Manager.")
        installed += 1

    # ── Binary Ninja ──
    binja_target = os.path.join(appdata, "Binary Ninja", "plugins") if appdata else ""
    if binja_target and os.path.isdir(binja_target):
        src = os.path.join(plugins_dir, "binja", "binja_backend_plugin.py")
        shutil.copy2(src, os.path.join(binja_target, "binja_backend_plugin.py"))
        print(f"[+] Binary Ninja: Copied plugin to {binja_target}")
        installed += 1
    else:
        print("[!] Binary Ninja not found. Skipping.")

    # ── Cheat Engine ──
    for v in ["7.5", "7.4"]:
        ce_path = os.path.join(os.environ.get("PROGRAMFILES", ""), f"Cheat Engine {v}", "autorun")
        if os.path.isdir(ce_path):
            src = os.path.join(plugins_dir, "ce", "ce_backend_plugin.lua")
            shutil.copy2(src, os.path.join(ce_path, "ce_backend_plugin.lua"))
            print(f"[+] Cheat Engine: Copied plugin to {ce_path}")
            installed += 1
            break
    else:
        print("[!] Cheat Engine not found. Skipping.")

    print(f"\n[*] Installed {installed} plugin(s). Restart your RE tools for changes to take effect.")
    sys.exit(0)


def print_help():
    print("""
NexusRE-MCP Server
=======================================

Usage:
  uv run main.py                    Start the MCP server (stdio transport)
  uv run main.py --config           Print the JSON config for manual setup
  uv run main.py --install          Auto-detect & inject config into Claude/Cursor
  uv run main.py --install-plugins  Auto-copy backend plugins into RE tools
  uv run main.py --transport sse    Start the server with SSE transport (HTTP)
  uv run main.py --port 8080        Set the SSE server port (default: 8080)
  uv run main.py --help             Show this help message

Supported Backends:
  - ida         (Default port: 10101)
  - ghidra      (Default port: 10102)
  - x64dbg      (Default port: 10103)
  - binja       (Default port: 10104)
  - cheatengine (Default port: 10105)
  - radare2     (Headless)
  - frida       (Headless JS Trapping)
""")
    sys.exit(0)


def main_cli():
    if "--help" in sys.argv or "-h" in sys.argv:
        print_help()

    if "--config" in sys.argv:
        print_config()

    if "--install" in sys.argv:
        auto_install()

    if "--install-plugins" in sys.argv:
        install_plugins()

    # Determine transport mode
    import time
    transport = "stdio"
    port = 8080

    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1].lower()

    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    if transport == "sse":
        print(f"[*] Starting NEXUSRE-MCP SERVER with SSE transport on port {port}...")
        
        # Setup Auth & Rate Limiting for SSE
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse
        from collections import defaultdict
        
        API_KEY = os.environ.get("NEXUSRE_API_KEY")
        if API_KEY:
            print("[+] API Key authentication ENABLED.")
        else:
            print("[!] Warning: NEXUSRE_API_KEY not set. API is unauthenticated!")

        class SecurityMiddleware(BaseHTTPMiddleware):
            def __init__(self, app):
                super().__init__(app)
                self.rate_limits = defaultdict(list)
                self.MAX_REQUESTS = 100  # 100 requests per minute

            async def dispatch(self, request, call_next):
                client_ip = request.client.host if request.client else "unknown"
                
                # Check Auth
                if API_KEY:
                    auth_header = request.headers.get("Authorization", "")
                    if auth_header != f"Bearer {API_KEY}":
                        return JSONResponse({"error": "Unauthorized. Invalid API Key."}, status_code=401)
                
                # Rate Limiting
                now = time.time()
                self.rate_limits[client_ip] = [t for t in self.rate_limits[client_ip] if now - t < 60]
                if len(self.rate_limits[client_ip]) >= self.MAX_REQUESTS:
                    return JSONResponse({"error": "Rate limit exceeded. Try again later."}, status_code=429)
                self.rate_limits[client_ip].append(now)

                return await call_next(request)

        # Inject middleware into FastMCP's underlying Starlette app
        mcp._app.add_middleware(SecurityMiddleware)

        mcp.run(transport="sse", port=port)
    else:
        # Start the fastMCP server via standard CLI execution (stdio)
        mcp.run()

if __name__ == "__main__":
    main_cli()

