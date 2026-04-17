<br/>
<div align="center">

# ⚡ NexusRE MCP
**The Universal AI Bridge for Game Hacking & Reverse Engineering**

[![PyPI version](https://badge.fury.io/py/nexusre-mcp.svg)](https://badge.fury.io/py/nexusre-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/discord/1234567890?label=Discord&logo=discord&color=5865F2)](https://discord.gg/nexusre)

[Features](#-killer-features) • [Installation](#-installation) • [Supported Backends](#-supported-backends)

</div>

**NexusRE** is an Enterprise-grade Model Context Protocol (MCP) server that connects your AI assistants (Cursor, Claude, Windsurf) directly to your reverse engineering environments. 

Instead of writing isolated scripts for IDA, x64dbg, or Cheat Engine, NexusRE acts as a universal adapter. You can highlight a piece of C++ SDK code in Cursor and say, *"Check my live x64dbg session to see what the register value is here,"* and the AI will do exactly that.

---

## 🔥 Killer Features

### 1. The "Game Updated" Auto-Healer (The Biggest Selling Point)
Every time a game updates, cheats break because memory offsets and AOBs (signatures) change. Usually, a developer has to drop everything, open IDA, and spend hours fixing them.

**The Pitch**: Tell them NexusRE has an AI-driven `auto_recover_signatures` engine. When a game patches, the MCP automatically diffs the old signatures, analyzes the cross-references in the new binary, and spits out a fixed `offsets.json`. What used to take 4 hours now takes 4 minutes.

### 2. The Universal Bridge
Usually, a developer writes a Python script for IDA, a Lua script for Cheat Engine, and a C++ plugin for x64dbg.

**The Pitch**: NexusRE lets you connect Cursor or Claude to all of them at once. You can highlight a piece of C++ SDK code in Cursor and say, *"Claude, check x64dbg to see what the live register value is here,"* and the AI will actually reach into the debugger and check for you.

<div align="center">
  <i>(Insert Video of the AI fixing a broken signature automatically)</i>
</div>

---

## 🚀 Installation

Install universally via pip:

```bash
pip install nexusre-mcp[all]
```

### Quick Start
To attach NexusRE to Cursor or Claude Desktop automatically:
```bash
nexusre-mcp --install
```

To run the secure network-wide SSE server (with rate limiting and API key auth) so your dev team can connect remotely:
```bash
set NEXUSRE_API_KEY=your_secret_key
nexusre-mcp --transport sse --port 8080
```

---

## 🔌 Supported Backends

NexusRE is modular. Drop any `.py` file into the `adapters/` folder and it auto-registers.

| Environment | Type | Best For |
|---|---|---|
| **IDA Pro** | Static | Decompilation, Struct generation, X-refs |
| **Ghidra** | Static | Headless analysis, Symbol resolution |
| **x64dbg** | Dynamic | Live instruction patching, Register reading |
| **Cheat Engine** | Dynamic | Multi-level pointer chasing, Lua environments |
| **Frida** | Dynamic | JavaScript instruction trapping and hooking |
| **DMA / PCILeech**| Hardware | 100% undetected memory read/writes |

## 🛠 Usage in Cursor IDE
1. Open Cursor Settings -> Features -> MCP Servers
2. Add new server: `nexusre`
3. Command: `uv run main.py`
4. Open the AI pane and tell Cursor: *"Initialize an x64dbg session and scan for this player health AOB."*

<div align="center">
<i>Built for the modern reverse engineer.</i>
</div>
