import os

readme_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'README.md')

with open(readme_path, 'r', encoding='utf8') as f:
    content = f.read()

offensive_feature = """
## ⚔️ Offensive Exploitation Module

NexusRE-MCP now goes beyond passive analysis and provides advanced, automated exploitation primitives through the `exploitation_tools` and `execute_pipeline` routers:
- **Automated Shellcode Injection** (CreateRemoteThread, APC, etc.)
- **Kernel Driver Scaffold Generation** (WDM with `MmCopyMemory` and CR3 manipulation)
- **VMT / IAT Detour Hooks Generation** (Auto-generates MinHook C++ templates)
- **Weaponized ROP Chain Generators**
"""

if "Offensive Exploitation Module" not in content:
    with open(readme_path, 'a', encoding='utf8') as f:
        f.write('\n' + offensive_feature)
    print("Updated README.")
