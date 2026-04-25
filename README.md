<br/>
<div align="center">

# ⚡ NexusRE-MCP
**The easiest way to let your AI talk to your game hacking tools.**

[![PyPI version](https://badge.fury.io/py/nexusre-mcp.svg)](https://badge.fury.io/py/nexusre-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/discord/1234567890?label=Discord&logo=discord&color=5865F2)](https://discord.gg/se2jNpAmSq)

</div>

**What is this?**  
NexusRE is a bridge that connects AI coding assistants (like Cursor, Claude, or Windsurf) directly to your game hacking and reverse engineering tools (like Cheat Engine, IDA Pro, or x64dbg). 

Instead of opening a debugger and staring at memory yourself, you just highlight code in your text editor and tell the AI: *"Hey, look at the game's actual memory and tell me what the value is right here."* The AI will reach into your game, read the memory, and give you the answer.

---

## 🔥 Why is this awesome?

### 1. The "Game Updated" Auto-Healer 
When a game updates, cheats break because all the memory addresses change. Normally, fixing this means you have to spend several hours manually finding the new addresses.

**With NexusRE:** You tell the AI to fix it. It automatically scans the new game update, finds what changed, and updates your cheat's code for you in a few minutes.

### 2. The Universal Bridge
You don't need to write separate scripts for every tool you use. NexusRE connects your AI to everything at once.

---

## 🚀 How to Install (Zero-Dependency)

Our custom installer automatically downloads its own sandboxed Python toolchain (via `uv`) and injects the MCP configuration directly into your IDE. **You do not need Python installed on your system!**

### Option A: The "One-Click" Setup Wizard (Windows — Recommended)

Double-click **`inject_mcp_configs.bat`**. It will automatically request Administrator privileges and then:

1.  **Download & install** the `uv` package manager and a sandboxed Python 3.12 if you don't already have them.
2.  **Scan your system** for installed reverse engineering tools (IDA Pro, Ghidra, x64dbg, Binary Ninja, Cheat Engine).
3.  **Install backend plugins** directly into each tool it finds.
4.  **Inject MCP configuration** into all detected AI coding assistants — **Claude Desktop**, **Cursor**, **Windsurf**, **Kiro IDE**, **Trae IDE**, **Zed IDE**, **Roo Code**, **Cline**, **Claude Code**, and **LM Studio**.
5.  **Auto-fix IDA Pro Python bindings** by running `idapyswitch.exe` if IDA is detected, so you never have to deal with "Python not found" errors.
6.  **Probe for running backends** and auto-connect to any tools you already have open.

> **That's it.** One double-click and everything is wired up.

### Option B: Command Line Setup (Mac / Linux / Advanced)

```bash
cd path/to/NexusRE-MCP
uv run main.py setup
```

Or, for individual steps:

| Command | What it does |
|---|---|
| `uv run main.py setup` | Full setup wizard (recommended) |
| `uv run main.py --install` | Only inject MCP config into IDEs |
| `uv run main.py --install-plugins` | Only copy plugins to RE tools |
| `uv run main.py --config` | Print JSON config for manual paste |
| `uv run main.py quickstart` | Interactive quickstart guide |

### Option C: Manual Configuration
If you use an environment without global configuration files (like **VS Code Workspace**, **Augment Code**, **Qodo Gen**, etc.), simply run:
```bash
uv run main.py --config
```
Then paste the JSON output into your editor's local `.vscode/mcp.json` file.

**(Optional) Share it with your team over the network:**  
```bash
set NEXUSRE_API_KEY=your_secret_password
uv run main.py --transport sse --port 8080
```

---

## 🔌 What tools does it talk to?

NexusRE connects to backend plugins in the `plugins/` folder. Right now, it supports:

| Tool | Port | Type |
|---|---|---|
| **IDA Pro** | `10101` | Static analysis (dead code) |
| **Ghidra** | `10102` | Static analysis (dead code) |
| **x64dbg** | `10103` | Live debugging |
| **Binary Ninja** | `10104` | Static analysis |
| **Cheat Engine** | `10105` | Live memory editing |
| **Frida** | Headless | Dynamic instrumentation |
| **Radare2** | Headless | CLI analysis |
| **Kernel Drivers / DMA** | Headless | Anti-cheat bypass (EAC/BE) |

### What else can it do?
* **Auto-Dump C++ Code:** It can automatically read a game (like Fortnite or a Unity game) and write an entire C++ cheat SDK template for you.
* **Network Sniffing:** Tell the AI to intercept packets going to the game server.
* **Math Decryption:** If a game encrypts a memory address, the AI can automatically figure out the math formula to decrypt it for you.
* **Vulnerability Scanning:** Run AI-powered vuln scans against decompiled functions.
* **Function Similarity Search:** Find functions that look like known crypto, networking, or anti-cheat patterns.
* **YARA Rule Generation:** Auto-generate YARA rules from any function for signature scanning.
* **Cross-Tool Symbol Sync:** Rename a function in IDA and push it to Ghidra (or vice versa) in one command.

---

## 🛠 Setting up the Backend Plugins

### The Automatic Way (Windows)
Double-click **`inject_mcp_configs.bat`**. The setup wizard handles everything — finding your tools, copying plugins, and fixing Python bindings.

### The Manual Way (Mac/Linux or Custom Installs)
If you need to install them manually, here is how to set up each one from the `plugins/` folder:

### 🦇 IDA Pro
1. Copy `plugins/ida/ida_backend_plugin.py` into your IDA Plugins directory:
   - `%APPDATA%\Hex-Rays\IDA Pro\plugins\`  
   - Or the `plugins` folder inside your IDA install directory
2. Restart IDA. The server starts automatically on port `10101`.

> **⚠️ IDA Pro Python Fix:** If IDA complains about Python, run `idapyswitch.exe` from your IDA install folder. This binds IDA to your system's Python. Our setup wizard does this automatically on Windows.

### 🐉 Ghidra
1. Open Ghidra and navigate to your project.
2. Open the **Script Manager** (`Window -> Script Manager`).
3. Click the "Manage Script Directories" icon and add the `plugins/ghidra/` path, or copy the plugins to your `~/ghidra_scripts/` folder.
4. Filter for `ghidra_backend_plugin`. You will see two versions:
   - **`ghidra_backend_plugin.java`**: The **Universal Edition**. Use this one! It works on every single Ghidra installation out of the box with zero dependencies.
   - `ghidra_backend_plugin.py`: The PyGhidra edition. Only use this if you have PyGhidra properly configured.
5. Double-click the `.java` script to run it. Watch the console for *"Ghidra Java Backend LIVE"*.

> **⚠️ Ghidra Requires Java:** You **must** have **JDK 17 or JDK 21** installed and in your system PATH. Ghidra will not start without it. Download from [Adoptium](https://adoptium.net/).

### 🐞 x64dbg
1. Install [x64dbgpy](https://github.com/x64dbg/x64dbgpy) to enable Python support.
2. Open x64dbg and navigate to the Scripts tab.
3. Execute the `plugins/x64dbg/x64dbg_backend_plugin.py` script to start the backend listener.

### 🥷 Binary Ninja
1. Open your Binary Ninja plugins folder by clicking `Edit -> Open Plugin Folder...`
2. Copy `plugins/binja/binja_backend_plugin.py` into the plugins directory.
3. Restart Binja. The server will automatically initialize in the background.

### 💉 Cheat Engine
1. Copy `plugins/ce/ce_backend_plugin.lua` into your Cheat Engine `autorun` folder (e.g. `C:\Program Files\Cheat Engine 7.5\autorun\`).
2. Restart Cheat Engine. The plugin starts automatically — **no Python needed!**

> **💡 Tip:** If you can't get IDA or Ghidra working, Cheat Engine is a great alternative that works out of the box with zero dependencies.

---

## 🔧 Troubleshooting

| Problem | Fix |
|---|---|
| **IDA says "Python not found"** | Run `idapyswitch.exe` from your IDA install folder, or re-run `inject_mcp_configs.bat` which does it automatically. |
| **Ghidra won't start** | Install **JDK 17 or 21** and add it to your PATH. |
| **MCP server disconnects** | Make sure `uv` is installed. Re-run `inject_mcp_configs.bat` to re-sync dependencies. |
| **"Server not found" in Claude/Cursor** | Restart your IDE after running the installer. The config is injected but the IDE needs a restart to pick it up. |
| **Backend not detected** | Make sure your RE tool (IDA/Ghidra/CE) is actually running. The setup wizard probes for active backends on ports 10101-10105. |

---

## 📖 Quickstart (After Installation)

Once installed, open your AI coding assistant and try these commands:

```
"Detect my backends"              → Auto-find running tools
"Run full_analysis"               → Decompile 200 functions + vuln scan
"Suggest names for the function at 0x140001234"
"Generate a YARA rule for this function"
"Find functions similar to this decryption"
"Export all symbols as an IDA script"
"Sync symbols from IDA to Ghidra"
"Generate a Frida hook for this function"
```

> 💡 **Pro tip:** Every rename you do teaches the AI. The more you use it, the smarter it gets.

---

<div align="center">
<i>Built to make game hacking human-readable.</i>
</div>
