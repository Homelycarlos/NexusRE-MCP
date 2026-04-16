[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/releases)
[![GitHub stars](https://img.shields.io/github/stars/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/graphs/contributors)

# ⚡ Unified Reverse Engineering MCP Server

The **Unified Reverse Engineering MCP Server** is a powerful, stateless Model Context Protocol interface that seamlessly bridges both **IDA Pro** and **Ghidra** into a single, cohesive AI-driven reversing environment. 

Designed from the ground up for strict determinism and thread-safety, this server enables AI coding agents to autonomously decompile functions, rename symbols, and fetch cross-references without requiring manual UI interaction.

---

## 🌟 Architecture & Features

This project was built to address the boilerplate and state-leaking issues of older MCP plugins:

1. **Stateless Session Management**: A built-in `SessionManager` perfectly isolates concurrent tool requests using unique `session_id` identifiers, completely eliminating global state leaks.
2. **Pydantic Validation**: It is impossible to pass malformed arguments to the reverse engineering engines. All inputs and outputs are normalized to strict JSON-RPC 2.0 schemas.
3. **Multi-Backend Simplicity**: Write one prompt, use one client workflow, and seamlessly toggle between IDA Pro and Ghidra datasets securely over local background HTTP adapters.
4. **FastMCP Integration**: Fully asynchronous routing using standard stdio out of the box.

---

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://www.anthropic.com/code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://www.kilocode.com/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `uv run main.py --config` to get the JSON config for your client.

---

## 🚀 Installation

Install the latest version of the Unified MCP Server by cloning this repository:

```sh
git clone https://github.com/Homelycarlos/unified-re-mcp.git
cd unified-re-mcp
```

### 1. IDA Pro Integration
For the server to instantly interact with your IDA databases:
1. Copy `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
2. Launch IDA Pro. A background thread will securely start listening on port `10101`.

### 2. Ghidra Integration
The unified MCP server supports dispatching queries directly to Ghidra HTTP server plugins (such as GhidraMCP). You must have a compatible background listener running in Ghidra for the server to forward `session_id` mapped queries securely.

---

## 💻 MCP Client Configuration

Because `unified-re-mcp` is universally compatible, you can configure any client easily.

### Example 1: Claude Desktop
Run `uv run main.py --config` to generate your exact path config, or add the following to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unified-re-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--with", "mcp[cli]",
        "--with", "pydantic",
        "--with", "aiohttp",
        "C:\\ABSOLUTE_PATH\\TO\\unified-re-mcp\\main.py"
      ]
    }
  }
}
```
**Important**: Make sure you completely restart Claude from the system tray for the configuration to take effect.

### Example 2: Cline
In Cline, select `MCP Servers` at the top. Select `Command` as your integration type, and paste your `uv run` invocation exactly as written in the config output.

### Example 3: 5ire
Open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: `unified-re-mcp`
2. Name: UnifiedRE
3. Command: `uv run C:\ABSOLUTE_PATH_TO\unified-re-mcp\main.py`

---

## 🧠 Prompt Engineering

LLMs are prone to hallucinations, so precise prompting is critical. Below is a minimal, proven example prompt for use with our unified tools:

```md
Your task is to analyze a crackme binary. You can use the MCP tools to interact with my open IDA/Ghidra instance. Please strictly follow this systematic methodology:

1. **Decompilation Analysis**: Inspect the decompilation via tools, and analyze it carefully. 
2. **Readability**: Rename variables to sensible names based on algorithmic patterns. Change function names to describe their actual purpose.
3. **Deep Dives**: If more details are necessary, pull cross-references to identify calling functions or examine disassembly.
4. **Constraints**: NEVER convert number bases yourself. NEVER assume conclusions blindly. Derive all findings purely from tool data.
5. **Documentation**: Create a report at the end with your findings.
```

## 🎯 Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can struggle with extreme mathematical evaluation and heavy obfuscation. To guarantee accurate responses from the LLM agent, prepare the binary beforehand:

- Fix control flow flattening
- Strip string encryption
- Resolve import hashing and API hiding
- Reconstruct anti-decompilation tricks

Additionally, use tools like Lumina or FLIRT to resolve open-source library code (like the C++ STL). This enormously reduces the token count sent to the LLM and gives it incredible contextual accuracy.

---

## ⚙️ Core Operations

The Unified MCP Server currently exposes several highly validated tools:

- `get_function_decompilation(address)`: Safely pulls raw C pseudocode from either Hex-Rays or Ghidra decompilers.
- `rename_symbol(address, new_name)`: Pushes intelligent renaming back into the database.
- `get_function_xrefs(address)`: Pulls cross-reference mappings (`xrefs_to`, `xrefs_from`) for deep execution flow analysis.

## 🛠️ Development

Adding new features into `unified-re-mcp` is a streamlined process. There is no heavy boilerplate. Simply add a new function decorated with `@mcp.tool()` inside `server.py`, type-hint it, and the schema will auto-generate!

To independently debug or test the server without an LLM attached, run the MCP inspector:

```sh
npx -y @modelcontextprotocol/inspector uv run main.py
```
