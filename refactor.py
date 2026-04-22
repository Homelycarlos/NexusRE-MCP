import os

SERVER_PY = r"C:\Users\cmb16\.gemini\antigravity\scratch\unified-re-mcp\core\server.py"

with open(SERVER_PY, "r", encoding="utf-8") as f:
    content = f.read()

# Replace all @mcp.tool() with commented out version
# Use replace instead of regex for safety, assuming `@mcp.tool()` is exactly how it's written
content = content.replace("@mcp.tool()", "# @mcp.tool() # Removed for Limit Bypass")

routers_code = """
# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED ROUTER TOOLS (Limit Bypass)
# ═══════════════════════════════════════════════════════════════════════════════
from typing import Literal

@mcp.tool()
async def session_management_tools(
    action: Literal["init_session", "list_sessions", "set_default_session", "check_backends", "detect_backends", "server_status"],
    session_id: str = None, backend: str = None, binary_path: str = None, architecture: str = "x86_64", backend_url: str = ""
) -> Any:
    \"\"\"Consolidated router for managing AI sessions and backend connectivity.\"\"\"
    if action == "init_session": return init_session(session_id, backend, binary_path, architecture, backend_url)
    elif action == "list_sessions": return list_sessions()
    elif action == "set_default_session": return set_default_session(session_id)
    elif action == "check_backends": return check_backends()
    elif action == "detect_backends": return detect_backends()
    elif action == "server_status": return server_status()

@mcp.tool()
async def function_navigation_tools(
    action: Literal["get_function", "get_current_address", "get_current_function", "get_xrefs", "get_callees", "get_callers", "list_functions"],
    session_id: str, address: str = None, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None
) -> Any:
    \"\"\"Consolidated router for binary navigation and cross-reference mapping.\"\"\"
    if action == "get_function": return await get_function(session_id, address)
    elif action == "get_current_address": return await get_current_address(session_id)
    elif action == "get_current_function": return await get_current_function(session_id)
    elif action == "get_xrefs": return await get_xrefs(session_id, address)
    elif action == "get_callees": return await get_callees(session_id, address)
    elif action == "get_callers": return await get_callers(session_id, address)
    elif action == "list_functions": return await list_functions(session_id, offset, limit, filter_str)

@mcp.tool()
async def binary_extraction_tools(
    action: Literal["get_strings", "get_globals", "get_segments", "get_imports", "get_exports"],
    session_id: str, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None
) -> Any:
    \"\"\"Consolidated router for extracting symbols, strings, and sections from a binary.\"\"\"
    if action == "get_strings": return await get_strings(session_id, offset, limit, filter_str)
    elif action == "get_globals": return await get_globals(session_id, offset, limit, filter_str)
    elif action == "get_segments": return await get_segments(session_id, offset, limit)
    elif action == "get_imports": return await get_imports(session_id, offset, limit)
    elif action == "get_exports": return await get_exports(session_id, offset, limit)

@mcp.tool()
async def decompilation_tools(
    action: Literal["decompile_function", "disassemble_at", "batch_decompile", "analyze_functions"],
    session_id: str, address: str = None, addresses: list = None
) -> Any:
    \"\"\"Consolidated router for fetching assembly and decompiled pseudo-code.\"\"\"
    if action == "decompile_function": return await decompile_function(session_id, address)
    elif action == "disassemble_at": return await disassemble_at(session_id, address)
    elif action == "batch_decompile": return await batch_decompile(session_id, addresses)
    elif action == "analyze_functions": return await analyze_functions(session_id, addresses)

@mcp.tool()
async def memory_debugging_tools(
    action: Literal["read_memory", "set_hardware_breakpoint", "wait_for_breakpoint", "generate_pointer_map", "read_pointer_chain", "hook_network_packets", "dump_memory_region_to_file", "diff_memory"],
    session_id: str, address: str = None, size: int = 256, timeout: int = 15, offsets: List[str] = None, pid: int = None, max_depth: int = 3, max_offset: int = 0x2000, max_packets: int = 50, output_file: str = None
) -> Any:
    \"\"\"Consolidated router for dynamic memory reading, debugging, and pointer mapping.\"\"\"
    if action == "read_memory": return await read_memory(session_id, address, size)
    elif action == "set_hardware_breakpoint": return await set_hardware_breakpoint(session_id, address)
    elif action == "wait_for_breakpoint": return await wait_for_breakpoint(session_id, timeout)
    elif action == "generate_pointer_map": return await generate_pointer_map(session_id, pid, address, max_depth, max_offset)
    elif action == "read_pointer_chain": return await read_pointer_chain(session_id, address, offsets)
    elif action == "hook_network_packets": return await hook_network_packets(session_id, max_packets, timeout)
    elif action == "dump_memory_region_to_file": return await dump_memory_region_to_file(session_id, address, size, output_file)
    elif action == "diff_memory": return await diff_memory(session_id, address, size)

@mcp.tool()
async def modification_tools(
    action: Literal["rename_symbol", "set_comment", "set_function_type", "rename_local_variable", "set_local_variable_type", "patch_address_assembles", "set_global_variable_type", "patch_bytes"],
    session_id: str, address: str = None, name: str = None, comment: str = None, repeatable: bool = False, signature: str = None, old_name: str = None, new_name: str = None, variable_name: str = None, new_type: str = None, instructions: str = None, hex_bytes: str = None
) -> Any:
    \"\"\"Consolidated router for modifying names, comments, types, and patching assembly/bytes.\"\"\"
    if action == "rename_symbol": return await rename_symbol(session_id, address, name)
    elif action == "set_comment": return await set_comment(session_id, address, comment, repeatable)
    elif action == "set_function_type": return await set_function_type(session_id, address, signature)
    elif action == "rename_local_variable": return await rename_local_variable(session_id, address, old_name, new_name)
    elif action == "set_local_variable_type": return await set_local_variable_type(session_id, address, variable_name, new_type)
    elif action == "patch_address_assembles": return await patch_address_assembles(session_id, address, instructions)
    elif action == "set_global_variable_type": return await set_global_variable_type(session_id, variable_name, new_type)
    elif action == "patch_bytes": return await patch_bytes(session_id, address, hex_bytes)

@mcp.tool()
async def structural_tools(
    action: Literal["get_stack_frame_variables", "list_local_types", "get_defined_structures", "analyze_struct_detailed", "get_xrefs_to_field", "declare_c_type", "define_struct"],
    session_id: str, address: str = None, struct_name: str = None, field_name: str = None, name: str = None, c_declaration: str = None, fields: list = None
) -> Any:
    \"\"\"Consolidated router for analyzing and creating memory structures and frames.\"\"\"
    if action == "get_stack_frame_variables": return await get_stack_frame_variables(session_id, address)
    elif action == "list_local_types": return await list_local_types(session_id)
    elif action == "get_defined_structures": return await get_defined_structures(session_id)
    elif action == "analyze_struct_detailed": return await analyze_struct_detailed(session_id, name)
    elif action == "get_xrefs_to_field": return await get_xrefs_to_field(session_id, struct_name, field_name)
    elif action == "declare_c_type": return await declare_c_type(session_id, c_declaration)
    elif action == "define_struct": return await define_struct(session_id, name, fields)

@mcp.tool()
async def signature_scanning_tools(
    action: Literal["scan_aob", "generate_unique_aob", "generate_yara_rule", "save_signatures", "load_signatures", "validate_signatures", "auto_recover_signatures", "yara_memory_scan"],
    session_id: str = None, pattern: str = None, address: str = None, instruction_count: int = 5, rule_name: str = None, game: str = None, signatures: list = None, yara_rule: str = None, pid: int = None, save_to_brain: bool = True
) -> Any:
    \"\"\"Consolidated router for scanning arrays of bytes and generating/testing memory signatures.\"\"\"
    if action == "scan_aob": return await scan_aob(session_id, pattern)
    elif action == "generate_unique_aob": return await generate_unique_aob(session_id, address, instruction_count)
    elif action == "generate_yara_rule": return await generate_yara_rule(session_id, address, rule_name, save_to_brain)
    elif action == "save_signatures": return save_signatures(game, signatures)
    elif action == "load_signatures": return load_signatures(game)
    elif action == "validate_signatures": return await validate_signatures(session_id, game)
    elif action == "auto_recover_signatures": return await auto_recover_signatures(session_id, game)
    elif action == "yara_memory_scan": return await yara_memory_scan(session_id, yara_rule, pid)

@mcp.tool()
async def game_dumping_tools(
    action: Literal["dump_vtables", "dump_vtable", "generate_game_sdk", "dump_unreal_gnames", "dump_unreal_gobjects", "dump_il2cpp_domain", "scaffold_kernel_interface", "spawn_esp_overlay"],
    session_id: str = None, module_base: str = None, address: str = None, max_entries: int = 50, engine_type: str = "unreal", pid: int = None, gnames_address: str = None, gobjects_address: str = None, game_assembly_base: str = None, game_name: str = None
) -> Any:
    \"\"\"Consolidated router for dumping game engine globals, SDKs, and launching external overlays.\"\"\"
    if action == "dump_vtables": return await dump_vtables(session_id, module_base)
    elif action == "dump_vtable": return await dump_vtable(session_id, address, max_entries)
    elif action == "generate_game_sdk": return await generate_game_sdk(session_id, engine_type)
    elif action == "dump_unreal_gnames": return dump_unreal_gnames(pid, gnames_address)
    elif action == "dump_unreal_gobjects": return dump_unreal_gobjects(pid, gobjects_address)
    elif action == "dump_il2cpp_domain": return dump_il2cpp_domain(pid, game_assembly_base)
    elif action == "scaffold_kernel_interface": return scaffold_kernel_interface(game_name)
    elif action == "spawn_esp_overlay": return spawn_esp_overlay()

@mcp.tool()
async def ai_intelligence_tools(
    action: Literal["auto_annotate", "suggest_names", "vuln_scan", "index_functions_for_similarity", "find_similar_functions", "full_analysis", "quick_scan", "cross_analyze"],
    session_id: str = None, limit: int = 200, min_confidence: float = 0.4, address: str = None, top_k: int = 5, threshold: float = 0.5, static_session: str = None, dynamic_session: str = None
) -> Any:
    \"\"\"Consolidated router for running AI-driven automated reverse engineering.\"\"\"
    if action == "auto_annotate": return await auto_annotate(session_id, limit, min_confidence)
    elif action == "suggest_names": return await suggest_names(session_id, address, top_k)
    elif action == "vuln_scan": return await vuln_scan(session_id, limit)
    elif action == "index_functions_for_similarity": return await index_functions_for_similarity(session_id, limit)
    elif action == "find_similar_functions": return await find_similar_functions(session_id, address, top_k, threshold)
    elif action == "full_analysis": return await full_analysis(session_id, limit)
    elif action == "quick_scan": return await quick_scan(session_id)
    elif action == "cross_analyze": return await cross_analyze(static_session, dynamic_session, address)

@mcp.tool()
async def binary_analysis_sandbox(
    action: Literal["compile_shellcode", "disassemble_bytes", "emulate_subroutine", "solve_symbolic_execution", "symbolic_string_decrypt", "extract_ast_segments"],
    assembly_text: str = None, arch: str = "x86", mode: str = "64", hex_bytes: str = None, address: int = 0x1000, init_registers: dict = None, trace: bool = False, target_addr: int = 0x400050, session_id: str = None, str_address: str = None, instruction_bounds: int = 0x50, c_code: str = None, query_type: str = "if_statement"
) -> Any:
    \"\"\"Consolidated router for shellcode, emulation, symbolic execution, and AST parsing.\"\"\"
    if action == "compile_shellcode": return compile_shellcode(assembly_text, arch, mode)
    elif action == "disassemble_bytes": return disassemble_bytes(hex_bytes, arch, mode, address)
    elif action == "emulate_subroutine": return emulate_subroutine(hex_bytes, arch, mode, init_registers, trace)
    elif action == "solve_symbolic_execution": return solve_symbolic_execution(hex_bytes, address, target_addr)
    elif action == "symbolic_string_decrypt": return await symbolic_string_decrypt(session_id, str_address, instruction_bounds)
    elif action == "extract_ast_segments": return extract_ast_segments(c_code, query_type)

@mcp.tool()
async def export_sync_tools(
    action: Literal["export_symbols_as_idc", "export_symbols_as_ghidra_script", "export_cfg", "sync_offsets_to_github", "sync_symbols", "heal_offsets", "diff_binaries", "save_binary"],
    session_id: str = None, output_path: str = "", limit: int = 1000, address: str = None, format: str = "mermaid", repo_name: str = None, github_token: str = None, offsets: dict = None, file_path: str = "offsets.json", source_session_id: str = None, target_session_id: str = None, game_name: str = None, version: str = None, offsets_header_path: str = None, session_id_old: str = None, session_id_new: str = None
) -> Any:
    \"\"\"Consolidated router for syncing to Github, generating scripts, and diffing binaries.\"\"\"
    if action == "export_symbols_as_idc": return await export_symbols_as_idc(session_id, output_path, limit)
    elif action == "export_symbols_as_ghidra_script": return await export_symbols_as_ghidra_script(session_id, output_path, limit)
    elif action == "export_cfg": return await export_cfg(session_id, address, format)
    elif action == "sync_offsets_to_github": return sync_offsets_to_github(repo_name, github_token, offsets, file_path)
    elif action == "sync_symbols": return await sync_symbols(source_session_id, target_session_id, limit)
    elif action == "heal_offsets": return await heal_offsets(session_id, game_name, version, offsets_header_path)
    elif action == "diff_binaries": return await diff_binaries(session_id_old, session_id_new, limit)
    elif action == "save_binary": return await save_binary(session_id, output_path)

@mcp.tool()
async def frida_scripting_tools(
    action: Literal["list_frida_snippets", "render_frida_snippet", "save_frida_snippet", "instrument_execution"],
    session_id: str = None, javascript_code: str = None, snippet_name: str = None, address: str = "", func_name: str = "", name: str = None, description: str = None, template: str = None
) -> Any:
    \"\"\"Consolidated router for Frida dynamic instrumentation templates and execution.\"\"\"
    if action == "list_frida_snippets": return list_frida_snippets()
    elif action == "render_frida_snippet": return render_frida_snippet(snippet_name, address, func_name)
    elif action == "save_frida_snippet": return save_frida_snippet(name, description, template)
    elif action == "instrument_execution": return await instrument_execution(session_id, javascript_code)

@mcp.tool()
def knowledge_base_tools(
    action: Literal["store_knowledge", "recall_knowledge"],
    key: str = None, summary: str = None, query: str = None
) -> Any:
    \"\"\"Consolidated router for interacting with the persistent local sqlite brain database.\"\"\"
    if action == "store_knowledge": return store_knowledge(key, summary)
    elif action == "recall_knowledge": return recall_knowledge(query)

@mcp.tool()
async def history_cache_tools(
    action: Literal["view_request_log", "execute_idapython_script", "view_diff_history", "undo_last_change", "cache_stats", "cache_clear"],
    session_id: str = "", limit: int = 50, code: str = None, cache_name: str = "all"
) -> Any:
    \"\"\"Consolidated router for auditing history, managing caches, and running arbitrary python on backend.\"\"\"
    if action == "view_request_log": return view_request_log(limit, session_id)
    elif action == "execute_idapython_script": return execute_idapython_script(session_id, code)
    elif action == "view_diff_history": return view_diff_history(session_id, limit)
    elif action == "undo_last_change": return await undo_last_change(session_id)
    elif action == "cache_stats": return cache_stats()
    elif action == "cache_clear": return cache_clear(cache_name)
"""

with open(SERVER_PY, "w", encoding="utf-8") as f:
    f.write(content + "\n" + routers_code)

print("SUCCESS: Refactored server.py")
