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
    print(" NEXUSRE MCP SERVER CONFIGURATION")
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


def print_help():
    print("""
NexusRE MCP Server
=======================================

Usage:
  uv run main.py                 Start the MCP server (stdio transport)
  uv run main.py --config        Print the JSON config for manual setup
  uv run main.py --install       Auto-detect & inject config into Claude/Cursor
  uv run main.py --transport sse Start the server with SSE transport (HTTP)
  uv run main.py --port 8080     Set the SSE server port (default: 8080)
  uv run main.py --help          Show this help message

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


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print_help()

    if "--config" in sys.argv:
        print_config()

    if "--install" in sys.argv:
        auto_install()

    # Determine transport mode
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
        print(f"[*] Starting NEXUSRE MCP SERVER with SSE transport on port {port}...")
        mcp.run(transport="sse", port=port)
    else:
        # Start the fastMCP server via standard CLI execution (stdio)
        mcp.run()
