import sys
import re

with open(r'C:\Users\cmb16\.gemini\antigravity\scratch\NexusRE-MCP\plugins\ida\ida_backend_plugin.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Methods to add to IdaOperations
new_methods = """
    @staticmethod
    def get_string(address, length=-1):
        import idc
        addr = address if isinstance(address, int) else int(address, 16)
        try:
            val = idc.get_strlit_contents(addr, length, -1)
            return val.decode("utf-8", "ignore") if val else ""
        except Exception:
            return ""

    @staticmethod
    def get_int(address, size=4):
        import ida_bytes
        addr = address if isinstance(address, int) else int(address, 16)
        try:
            if size == 1:
                return ida_bytes.get_byte(addr)
            elif size == 2:
                return ida_bytes.get_word(addr)
            elif size == 4:
                return ida_bytes.get_dword(addr)
            elif size == 8:
                return ida_bytes.get_qword(addr)
            return None
        except Exception:
            return None

    @staticmethod
    def define_func(address, end_address=None):
        import ida_funcs
        import idaapi
        addr = address if isinstance(address, int) else int(address, 16)
        end_addr = int(end_address, 16) if end_address else idaapi.BADADDR
        return ida_funcs.add_func(addr, end_addr)

    @staticmethod
    def undefine(address, size=1):
        import ida_bytes
        addr = address if isinstance(address, int) else int(address, 16)
        return ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, size)

    @staticmethod
    def basic_blocks(address):
        import idaapi
        import ida_gdl
        addr = address if isinstance(address, int) else int(address, 16)
        f = idaapi.get_func(addr)
        if not f:
            return []
        try:
            fc = ida_gdl.FlowChart(f)
            blocks = []
            for block in fc:
                blocks.append({
                    "id": block.id,
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "succs": [succ.id for succ in block.succs()],
                    "preds": [pred.id for pred in block.preds()]
                })
            return blocks
        except Exception as e:
            return []

    @staticmethod
    def dbg_start(command_line="", args=""):
        import ida_dbg
        return ida_dbg.start_process(command_line, args, "") == 1

    @staticmethod
    def dbg_exit():
        import ida_dbg
        ida_dbg.exit_process()
        return True

    @staticmethod
    def dbg_continue():
        import ida_dbg
        return ida_dbg.continue_process() == 1

    @staticmethod
    def dbg_step_into():
        import ida_dbg
        return ida_dbg.step_into() == 1

    @staticmethod
    def dbg_step_over():
        import ida_dbg
        return ida_dbg.step_over() == 1
"""

content = content.replace("    # ── Dynamic Debugging & Memory ────────────────────────────", new_methods + "\n    # ── Dynamic Debugging & Memory ────────────────────────────")

# Add handlers
new_handlers = """
            elif action == "get_string":
                result = {"string": IdaOperations._execute_sync(IdaOperations.get_string, args.get("address"), args.get("length", -1))}
            elif action == "get_int":
                result = {"value": IdaOperations._execute_sync(IdaOperations.get_int, args.get("address"), args.get("size", 4))}
            elif action == "define_func":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.define_func, args.get("address"), args.get("end_address"))}
            elif action == "undefine":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.undefine, args.get("address"), args.get("size", 1))}
            elif action == "basic_blocks":
                result = {"blocks": IdaOperations._execute_sync(IdaOperations.basic_blocks, args.get("address"))}
            elif action == "dbg_start":
                result = {"success": IdaOperations._execute_sync(IdaOperations.dbg_start, args.get("command_line", ""), args.get("args", ""))}
            elif action == "dbg_exit":
                result = {"success": IdaOperations._execute_sync(IdaOperations.dbg_exit)}
            elif action == "dbg_continue":
                result = {"success": IdaOperations._execute_sync(IdaOperations.dbg_continue)}
            elif action == "dbg_step_into":
                result = {"success": IdaOperations._execute_sync(IdaOperations.dbg_step_into)}
            elif action == "dbg_step_over":
                result = {"success": IdaOperations._execute_sync(IdaOperations.dbg_step_over)}
"""

content = content.replace("            # ── Dynamic Debugging & Memory ────────────────────────────", new_handlers + "\n            # ── Dynamic Debugging & Memory ────────────────────────────")

with open(r'C:\Users\cmb16\.gemini\antigravity\scratch\NexusRE-MCP\plugins\ida\ida_backend_plugin.py', 'w', encoding='utf-8') as f:
    f.write(content)
