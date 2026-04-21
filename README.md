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

### Option A: The "One-Click" Batch Files (Windows Only)
Inside the downloaded folder, you'll find two scripts that automate everything. Simply double-click them (they will automatically request Administrator privileges):

1.  **`inject_mcp_configs.bat`**  
    Automatically detects and connects the MCP server to **Claude Desktop**, **Cursor**, **Windsurf**, **Kiro IDE**, **Trae IDE**, **Zed IDE**, **Roo Code**, **Cline**, **Claude Code**, and **LM Studio**.
2.  **`inject_plugins.bat`**  
    Automatically searches your hard drives for **IDA Pro, Ghidra, x64dbg, Binary Ninja, and Cheat Engine** and instantly drops the backend plugins into their respective directories.

### Option B: Command Line Installer (Mac / Linux)
If you are on macOS or Linux, you can run the core Python engine directly. We recommend using `uv`:

```bash
cd path/to/NexusRE-MCP
uv run main.py --install
```

### Option C: Manual Configuration
If you use an environment without global configuration files (like **VS Code Workspace**, **Augment Code**, **Qodo Gen**, etc.), simply run:
```bash
uv run main.py --config
```
Then paste the JSON output into your editor's local `.vscode/mcp.json` file.

**(Optional) Share it with your team:**  
If you want your friends or team to use your server over the internet, run:
```bash
set NEXUSRE_API_KEY=your_secret_password
nexusre-mcp --transport sse --port 8080
```

---

## 🔌 What tools does it talk to?

NexusRE connects to backend files in the `adapters/` folder. Right now, it supports:

* **IDA Pro & Ghidra** (For looking at dead game code)
* **x64dbg & Cheat Engine** (For looking at live game memory)
* **Frida** (For advanced live code messing)
* **Kernel Drivers & DMA (2nd PC hacking)** (For bypassing Anti-Cheats like EAC or BattlEye without getting caught)
* **ReClass.NET** (For reading memory structures)

### What else can it do?
* **Auto-Dump C++ Code:** It can automatically read a game (like Fortnite or a Unity game) and write an entire C++ cheat SDK template for you.
* **Network Sniffing:** Tell the AI to intercept packets going to the game server.
* **Math Decryption:** If a game encrypts a memory address, the AI can automatically figure out the math formula to decrypt it for you. 

## 🛠 Setting up the Backend Plugins

To let NexusRE talk to your specific tools, you need to run a small background plugin in them. 

### The Automatic Way (Windows)
Double-click **`inject_plugins.bat`**. It will automatically find where your tools are installed and inject the plugins for you without you lifting a finger!

### The Manual Way (Mac/Linux or Custom Installs)
If you need to install them manually, here is how to set up each one from the `plugins/` folder:

### 🦇 IDA Pro
1. Find the `ida_backend_plugin.py` file in the `plugins/ida/` folder.
2. Copy it into your IDA Plugins directory (usually `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or the `plugins` folder inside your IDA install directory).
3. Restart IDA. The server will start automatically in the background.

### 🐉 Ghidra
1. Open Ghidra and navigate to your project.
2. Open the **Script Manager** (`Window -> Script Manager`).
3. Click the "Manage Script Directories" icon and add the `plugins/ghidra/` path, or simply create a new Python script and paste the contents of `ghidra_backend_plugin.py`.
4. Run the script. Watch the console for *"Starting background HTTP server"*. *(Note: Requires PyGhidra).*

### 🐞 x64dbg
1. Install [x64dbgpy](https://github.com/x64dbg/x64dbgpy) to enable Python support.
2. Open x64dbg and navigate to the Scripts tab.
3. Execute the `plugins/x64dbg/x64dbg_backend_plugin.py` script to start the backend listener.

### 🥷 Binary Ninja
1. Open your Binary Ninja plugins folder by clicking `Edit -> Open Plugin Folder...`
2. Copy the `plugins/binja/binja_backend_plugin.py` script into the plugins directory.
3. Restart Binja. The server will automatically initialize in the background.

### 💉 Cheat Engine
1. Open Cheat Engine and attach to your target process.
2. Press `Ctrl+Alt+L` to open the Lua Engine.
3. Open or paste the contents of `plugins/ce/ce_backend_plugin.lua`.
4. Click **Execute** to start the internal CE HTTP server.

<div align="center">
<i>Built to make game hacking human-readable.</i>
</div>
