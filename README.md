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

## 🚀 How to Install

We recommend using `uv` (it makes running Python stuff way easier and cleaner).

### Option A: Run it from the folder (Recommended)
If you downloaded this folder directly:
```bash
cd path/to/NexusRE-MCP

# Run this command to automatically connect it to Claude or Cursor:
uv run main.py --install
```

### Option B: Install it globally
If you want to be able to just type `nexusre-mcp` from anywhere on your computer:
```bash
# Easy global install:
uv tool install .
```
Then, just type `nexusre-mcp --install` to connect it to your AI.

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

## 🛠 Setting up the IDA Pro Plugin

If you use IDA Pro, you need to add a quick plugin so they can talk:
1. Find the `ida_backend_plugin.py` file in the `plugins/ida/` folder of this project.
2. Copy it into your IDA Plugins folder (usually somewhere like `%APPDATA%\Hex-Rays\IDA Pro\plugins\`).
3. Restart IDA. That's it!

<div align="center">
<i>Built to make game hacking human-readable.</i>
</div>
