[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/releases)
[![GitHub stars](https://img.shields.io/github/stars/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/graphs/contributors)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# ⚡ Unified Reverse Engineering MCP Server

The **Unified Reverse Engineering MCP Server** is a powerful, stateless Model Context Protocol interface that seamlessly bridges both **IDA Pro** and **Ghidra** into a single, cohesive AI-driven reversing environment. 

Designed from the ground up for strict determinism and thread-safety, this server enables AI coding agents to autonomously decompile functions, rename symbols, and fetch cross-references without requiring manual UI interaction.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

*(The binaries and prompts for testing are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.)*

---

## 🌟 Architecture & Features

This project was built to address the boilerplate and state-leaking issues of older MCP plugins:

1. **Stateless Session Management**: A built-in `SessionManager` perfectly isolates concurrent tool requests using unique `session_id` identifiers, completely eliminating global state leaks.
2. **Pydantic Validation**: It is impossible to pass malformed arguments to the reverse engineering engines. All inputs and outputs are normalized to strict JSON-RPC 2.0 schemas.
3. **Multi-Backend Simplicity**: Write one prompt, use one client workflow, and seamlessly toggle between IDA Pro and Ghidra datasets securely over local background HTTP adapters.
4. **FastMCP Integration**: Fully asynchronous routing using standard stdio out of the box.

---

## 🛠️ Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - *Use `idapyswitch` to bind IDA to your newest Python version if necessary.*
- [uv](https://docs.astral.sh/uv/) (highly recommended for automatic, sandboxed dependency execution)
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9.x recommended). *Note: IDA Free is not supported as it lacks IDAPython.*
- Ghidra + [GhidraMCP Plugin](https://github.com/LaurieWired/GhidraMCP/releases) *(If using the Ghidra backend)*

### Supported MCP Clients
Because this framework implements the strict MCP JSON-RPC standard, it inherently works with all major AI coding assistants. Pick the one you like:

* Amazon Q Developer CLI
* Augment Code
* Claude & Claude Code
* Cline
* Codex
* Copilot CLI
* Crush
* Cursor
* Gemini CLI
* Kilo Code
* Kiro
* LM Studio
* Opencode
* Qodo Gen
* Qwen Coder
* Roo Code
* Trae
* VS Code & VS Code Insiders
* Warp
* Windsurf
* Zed

**Other MCP Clients:** Just run `uv run main.py --config` to generate the correct JSON configuration for your specific client!

---

## 🚀 Installation

Install the latest version of the Unified MCP Server by cloning this repository to your local machine:

```sh
git clone https://github.com/Homelycarlos/unified-re-mcp.git
cd unified-re-mcp
```

### 1. IDA Pro Integration
For the server to instantly interact with your IDA databases:
1. Copy `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
2. Launch IDA Pro. A background thread will securely start listening on port `10101`.

### 2. Ghidra Integration
If you wish to use the Ghidra adapter, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from the GhidraMCP repository.

1. Select `File` -> `Install Extensions`
2. Click the `+` button and select the `GhidraMCP-1-x.zip` release
3. Restart Ghidra and ensure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

Video Installation Guide:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

---

## 💻 MCP Client Configuration

Theoretically, any MCP client should work perfectly. Below are three examples on how to easily plug the server in.

### Example 1: Claude Desktop
To set up Claude Desktop, run `uv run main.py --config` to generate your exact path config, or add the following to `%APPDATA%\Claude\claude_desktop_config.json`:

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

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

### Example 3: 5ire
Open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: `unified-re-mcp`
2. Name: UnifiedRE
3. Command: `uv run C:\ABSOLUTE_PATH_TO\unified-re-mcp\main.py`

---

## 🧠 Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. Below is a minimal, proven example prompt for use with our unified tools:

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

### Ghidra Dependency Overrides (Optional)
If you wish to compile or override the Ghidra backend directly from source:
1. Copy `Base.jar`, `Decompiler.jar`, `Docking.jar`, `Generic.jar`, `Project.jar`, `SoftwareModeling.jar`, `Utility.jar`, and `Gui.jar` from your Ghidra installation to `lib/`.
2. Build via Maven: `mvn clean package assembly:single`
