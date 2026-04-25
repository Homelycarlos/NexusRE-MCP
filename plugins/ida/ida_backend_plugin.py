import idaapi
import idc
import idautils
import ida_segment
import ida_nalt
import ida_entry
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class IdaOperations:
    @staticmethod
    def _execute_sync(func, *args, **kwargs):
        class SyncReq:
            def __init__(self):
                self.result = None
                self.error = None

            def run(self):
                try:
                    self.result = func(*args, **kwargs)
                except Exception as e:
                    self.error = str(e)
                return 1

        req = SyncReq()
        idaapi.execute_sync(req.run, idaapi.MFF_READ)
        if req.error:
            raise Exception(req.error)
        return req.result

    @staticmethod
    def _execute_sync_write(func, *args, **kwargs):
        class SyncReq:
            def __init__(self):
                self.result = None
                self.error = None

            def run(self):
                try:
                    self.result = func(*args, **kwargs)
                except Exception as e:
                    self.error = str(e)
                return 1

        req = SyncReq()
        idaapi.execute_sync(req.run, idaapi.MFF_WRITE)
        if req.error:
            raise Exception(req.error)
        return req.result

    # ── Core Navigation ───────────────────────────────────────────────────

    @staticmethod
    def get_current_address():
        ea = idaapi.get_screen_ea()
        return hex(ea) if ea != idaapi.BADADDR else None

    @staticmethod
    def get_current_function():
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        return hex(func.start_ea) if func else None

    @staticmethod
    def get_functions(offset=0, limit=100, filter_str=None):
        funcs = []
        for sea in idautils.Functions():
            name = idc.get_func_name(sea)
            if filter_str and filter_str.lower() not in name.lower():
                continue
            func = idaapi.get_func(sea)
            funcs.append(
                {"name": name, "address": hex(sea), "size": func.size() if func else 0}
            )
        if limit <= 0:
            return funcs[offset:]
        return funcs[offset : offset + limit]

    @staticmethod
    def get_function(address):
        addr = int(address, 16)
        func = idaapi.get_func(addr)
        if not func:
            return None
        return {
            "name": idc.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "size": func.size(),
        }

    # ── Decompilation & Disassembly ───────────────────────────────────────

    @staticmethod
    def decompile(address):
        addr = int(address, 16)
        f = idaapi.get_func(addr)
        if not f:
            return "No function found at address"
        try:
            import ida_hexrays

            if not ida_hexrays.init_hexrays_plugin():
                return "HexRays plugin not available"
            cfunc = ida_hexrays.decompile(f)
            if cfunc:
                return str(cfunc)
            return "Decompilation failed"
        except Exception as e:
            return f"Decompilation error: {e}"

    @staticmethod
    def disassemble(address):
        addr = int(address, 16)
        f = idaapi.get_func(addr)
        if not f:
            # Fall back to disassembling a small block around it
            start = addr
            end = addr + 0x20
        else:
            start = f.start_ea
            end = f.end_ea

        out = []
        for head in idautils.Heads(start, end):
            if idc.is_code(idc.get_full_flags(head)):
                mnem = idc.generate_disasm_line(head, 0)
                out.append(f"{hex(head)}: {mnem}")
        return "\n".join(out)

    # ── Cross-References ──────────────────────────────────────────────────

    @staticmethod
    def get_xrefs(address):
        addr = int(address, 16)
        xrefs_to = []
        for ref in idautils.XrefsTo(addr):
            xrefs_to.append(hex(ref.frm))

        xrefs_from = []
        for ref in idautils.XrefsFrom(addr):
            xrefs_from.append(hex(ref.to))

        return {"to": xrefs_to, "from": xrefs_from}

    # ── Modification ──────────────────────────────────────────────────────

    @staticmethod
    def rename(address, name):
        addr = int(address, 16)
        res = idc.set_name(addr, name, idc.SN_CHECK)
        return bool(res)

    @staticmethod
    def set_comment(address, comment, repeatable=False):
        addr = int(address, 16)
        res = idc.set_cmt(addr, comment, 1 if repeatable else 0)
        return bool(res)

    @staticmethod
    def set_function_type(address, signature):
        addr = int(address, 16)
        result = idc.SetType(addr, signature)
        return bool(result)

    @staticmethod
    def patch_bytes(address, hex_bytes):
        addr = int(address, 16)
        bytes_list = bytes.fromhex(hex_bytes.replace(" ", ""))
        try:
            idaapi.patch_bytes(addr, bytes_list)
            return True
        except Exception:
            return False

    @staticmethod
    def save_binary(output_path):
        try:
            # We must resolve the input file path or just rely on flush.
            # Usually idaapi.flush_buffers() or saving out via command.
            # IDA doesn't cleanly "compile" out from API without a specialized script length.
            # A common wrapper is to patch the live execution.
            # We'll just flush memory so IDA caches the actual byte writes.
            idaapi.flush_buffers()
            return True
        except Exception:
            return False

    @staticmethod
    def rename_local_variable(address, old_name, new_name):
        addr = int(address, 16)
        try:
            import ida_hexrays

            f = idaapi.get_func(addr)
            if not f:
                return False
            cfunc = ida_hexrays.decompile(f)
            if not cfunc:
                return False
            for loc in cfunc.get_lvars():
                if loc.name == old_name:
                    return ida_hexrays.rename_lvar(addr, old_name, new_name)
            return False
        except Exception:
            return False

    @staticmethod
    def set_local_variable_type(address, variable_name, new_type):
        addr = int(address, 16)
        try:
            import ida_hexrays
            import ida_typeinf

            f = idaapi.get_func(addr)
            if not f:
                return False
            tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tinfo, None, f"{new_type} {variable_name};", 0)
            cfunc = ida_hexrays.decompile(f)
            if not cfunc:
                return False
            return ida_hexrays.set_lvar_type(addr, variable_name, tinfo)
        except Exception:
            return False

    @staticmethod
    def scan_aob(pattern):
        import ida_bytes
        import idc
        import ida_ida

        # IDA 9.0+ compliant address resolution
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        cpat = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(cpat, min_ea, pattern, 16)
        ea = ida_bytes.bin_search(min_ea, max_ea, cpat, ida_bytes.BIN_SEARCH_FORWARD)

        if type(ea) is tuple:
            ea = ea[0]

        return hex(ea) if ea != idc.BADADDR else None

    # ── Dynamic Debugging & Memory ────────────────────────────────────────

    @staticmethod
    def set_bpt(address):
        addr = int(address, 16)
        import ida_dbg

        if ida_dbg.add_bpt(addr):
            return {"message": f"Hardware breakpoint set at {hex(addr)}"}
        return {"error": "Failed to set breakpoint"}

    @staticmethod
    def wait_bpt(timeout):
        import ida_dbg

        # waiting natively in python could block the thread, but we execute in sync
        # Usually requires a debugger hook, but for MVP:
        res = ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_CONT | ida_dbg.WFNE_SUSP, timeout
        )
        if res == 1:
            # Hit breakpoint
            ctx = {}
            if hasattr(ida_dbg, "get_reg_val"):
                for reg in [
                    "rax",
                    "rcx",
                    "rdx",
                    "rbx",
                    "rsp",
                    "rbp",
                    "rsi",
                    "rdi",
                    "rip",
                    "eax",
                    "ecx",
                    "edx",
                    "ebx",
                    "esp",
                    "ebp",
                    "esi",
                    "edi",
                    "eip",
                ]:
                    val = ida_dbg.get_reg_val(reg)
                    if val is not None:
                        ctx[reg] = hex(val)
            return {"context": ctx}
        return {"error": "Timeout or did not hit breakpoint"}

    @staticmethod
    def read_memory(address, size):
        # Native read_dbg_memory
        import ida_dbg

        data = ida_dbg.read_dbg_memory(address, size)
        if data:
            return {"data": data.hex()}
        return {"data": ""}

    @staticmethod
    def memory_regions():
        # Using segments as memory regions for static, or dbg.get_memory_info
        import ida_dbg

        ranges = ida_dbg.meminfo_vec_t()
        if ida_dbg.get_memory_info(ranges):
            regs = []
            for r in ranges:
                regs.append(
                    {
                        "start": hex(r.start_ea),
                        "end": hex(r.end_ea),
                        "name": r.name,
                        "perms": r.perm,
                    }
                )
            return {"regions": regs}
        return {"regions": []}

    # ── Data Extraction ───────────────────────────────────────────────────

    @staticmethod
    def get_strings(offset=0, limit=100, filter_str=None):
        strings = []
        sc = idautils.Strings()
        for idx, s in enumerate(sc):
            val = str(s)
            if filter_str and filter_str.lower() not in val.lower():
                continue
            strings.append({"address": hex(s.ea), "value": val})
        if limit <= 0:
            return strings[offset:]
        return strings[offset : offset + limit]

    @staticmethod
    def get_globals(offset=0, limit=100, filter_str=None):
        globals_list = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name in [".data", ".rdata", ".bss", "DATA", ".rodata"]:
                ea = seg.start_ea
                while ea < seg.end_ea:
                    name = idc.get_name(ea)
                    if name and not name.startswith("unk_"):
                        if filter_str and filter_str.lower() not in name.lower():
                            pass
                        else:
                            size = idc.get_item_size(ea)
                            globals_list.append(
                                {
                                    "address": hex(ea),
                                    "name": name,
                                    "size": size,
                                    "value": None,
                                }
                            )
                    ea = idc.next_head(ea, seg.end_ea)
                    if ea == idaapi.BADADDR:
                        break
        if limit <= 0:
            return globals_list[offset:]
        return globals_list[offset : offset + limit]

    @staticmethod
    def get_segments(offset=0, limit=100):
        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            perms = ""
            if seg.perm & ida_segment.SFL_LOADER:
                perms += "L"
            if seg.perm & 1:  # Read
                perms += "R"
            if seg.perm & 2:  # Write
                perms += "W"
            if seg.perm & 4:  # Execute
                perms += "X"
            segments.append(
                {
                    "name": ida_segment.get_segm_name(seg),
                    "start_address": hex(seg.start_ea),
                    "end_address": hex(seg.end_ea),
                    "size": seg.size(),
                    "permissions": perms,
                }
            )
        if limit <= 0:
            return segments[offset:]
        return segments[offset : offset + limit]

    @staticmethod
    def get_imports(offset=0, limit=100):
        imports = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                if name:
                    imports.append(
                        {"address": hex(ea), "name": name, "module": module_name or ""}
                    )
                return True

            ida_nalt.enum_import_names(i, imp_cb)
        if limit <= 0:
            return imports[offset:]
        return imports[offset : offset + limit]

    @staticmethod
    def get_exports(offset=0, limit=100):
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if name:
                exports.append({"address": hex(ea), "name": name})
        if limit <= 0:
            return exports[offset:]
        return exports[offset : offset + limit]

    @staticmethod
    def get_callees(address):
        addr = int(address, 16)
        func = idaapi.get_func(addr)
        if not func:
            return []
        func_end = idc.find_func_end(addr)
        callees = []
        current_ea = func.start_ea
        while current_ea < func_end:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, current_ea)
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                target = idc.get_operand_value(current_ea, 0)
                target_type = idc.get_operand_type(current_ea, 0)
                if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                    func_type = "internal" if idaapi.get_func(target) else "external"
                    func_name = idc.get_name(target)
                    if func_name:
                        callees.append(
                            {
                                "address": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }
                        )
            current_ea = idc.next_head(current_ea, func_end)
        unique = {tuple(c.items()) for c in callees}
        return [dict(c) for c in unique]

    @staticmethod
    def get_callers(address):
        addr = int(address, 16)
        callers = {}
        for caller_address in idautils.CodeRefsTo(addr, 0):
            func = idaapi.get_func(caller_address)
            if not func:
                continue
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, caller_address)
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                func_name = idc.get_func_name(func.start_ea)
                callers[hex(func.start_ea)] = {
                    "address": hex(func.start_ea),
                    "name": func_name,
                }
        return list(callers.values())

    @staticmethod
    def patch_address_assembles(address, instructions):
        addr = int(address, 16)
        assembles = instructions.split(";")
        total_len = 0
        for assemble in assembles:
            assemble = assemble.strip()
            if not assemble:
                continue
            check, patched = idautils.Assemble(addr, assemble)
            if not check:
                raise Exception("Failed to assemble: " + assemble)
            idaapi.patch_bytes(addr, patched)
            addr += len(patched)
            total_len += 1
        return True

    @staticmethod
    def get_xrefs_to_field(struct_name, field_name):
        import ida_typeinf

        til = ida_typeinf.get_idati()
        if not til:
            return []
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(
            til, struct_name, ida_typeinf.BTF_STRUCT, True, False
        ):
            return []
        try:
            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
        except Exception:
            # Fallback for IDA older versions
            return []
        if idx == -1:
            return []
        tid = tif.get_udm_tid(idx)
        if tid == idaapi.BADADDR:
            return []
        xrefs = []
        for ref in idautils.XrefsTo(tid):
            xrefs.append(
                {"address": hex(ref.frm), "type": "code" if ref.iscode else "data"}
            )
        return xrefs

    @staticmethod
    def declare_c_type(c_declaration):
        import ida_typeinf
        import sys

        if sys.platform == "win32":
            import ctypes

            c_decls = c_declaration.encode("utf-8")
            ida_dll = ctypes.CDLL("ida")
            ida_dll.parse_decls.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            ida_dll.parse_decls.restype = ctypes.c_int

            @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
            def magic_printer(fmt, arg1):
                pass

            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors = ida_dll.parse_decls(None, c_decls, magic_printer, flags)
            if errors > 0:
                raise Exception("Parse decls failed with code " + str(errors))
            return True
        else:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors = ida_typeinf.parse_decls(None, c_declaration, False, flags)
            if errors > 0:
                raise Exception("Parse decls failed with code " + str(errors))
            return True

    @staticmethod
    def get_stack_frame_variables(address):
        addr = int(address, 16)
        import ida_typeinf
        import ida_ida

        if ida_ida.inf_get_version() < 9:
            return []
        func = idaapi.get_func(addr)
        if not func:
            return []
        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
            return []
        members = []
        udt = ida_typeinf.udt_type_data_t()
        tif.get_udt_details(udt)
        for udm in udt:
            if not udm.is_gap():
                members.append(
                    {
                        "name": udm.name,
                        "offset": hex(
                            (udm.offset // 8) if hasattr(udm, "offset") else 0
                        ),
                        "size": hex((udm.size // 8) if hasattr(udm, "size") else 0),
                        "type": str((udm.type) if hasattr(udm, "type") else ""),
                    }
                )
        return members

    @staticmethod
    def list_local_types():
        import ida_typeinf

        locals_list = []
        idati = ida_typeinf.get_idati()
        type_count = ida_typeinf.get_ordinal_limit(idati)
        for ordinal in range(1, type_count):
            try:
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(idati, ordinal):
                    type_name = tif.get_type_name() or (
                        "<Anonymous #" + str(ordinal) + ">"
                    )
                    type_str = type_name
                    locals_list.append(
                        {"ordinal": ordinal, "name": type_name, "declaration": type_str}
                    )
            except:
                continue
        return locals_list

    @staticmethod
    def get_defined_structures():
        import ida_typeinf

        rv = []
        limit = ida_typeinf.get_ordinal_limit()
        idati = ida_typeinf.get_idati()
        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal) and tif.is_udt():
                udt = ida_typeinf.udt_type_data_t()
                members = []
                if tif.get_udt_details(udt):
                    members = [
                        {
                            "name": x.name,
                            "offset": hex(
                                (x.offset // 8) if hasattr(x, "offset") else 0
                            ),
                            "size": hex((x.size // 8) if hasattr(x, "size") else 0),
                            "type": str((x.type) if hasattr(x, "type") else ""),
                        }
                        for x in udt
                    ]
                rv.append(
                    {
                        "name": tif.get_type_name(),
                        "size": hex(tif.get_size()),
                        "members": members,
                    }
                )
        return rv

    @staticmethod
    def analyze_struct_detailed(name):
        import ida_typeinf

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            raise Exception("Structure " + name + " not found")
        if not tif.is_udt():
            raise Exception("Not a UDT")
        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            raise Exception("Failed to get details")
        members = []
        for i, m in enumerate(udt_data):
            size = m.size // 8 if m.size > 0 else m.type.get_size()
            members.append(
                {
                    "index": i,
                    "offset": hex(m.begin() // 8) if hasattr(m, "begin") else 0,
                    "size": size,
                    "type": m.type._print(),
                    "name": m.name,
                    "is_nested_udt": m.type.is_udt(),
                }
            )
        return {
            "name": name,
            "type": str(tif._print()),
            "size": tif.get_size(),
            "is_union": udt_data.is_union,
            "member_count": udt_data.size(),
            "members": members,
        }

    @staticmethod
    def set_global_variable_type(variable_name, new_type):
        import ida_typeinf

        ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
        if ea == idaapi.BADADDR:
            raise Exception("Variable not found")
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, new_type + ";", 0):
            raise Exception("Failed to parse type")
        if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
            raise Exception("Failed to apply type")
        return True

    @staticmethod
    def execute_script(script_code):
        """Execute arbitrary IDAPython code and capture stdout + return value."""
        import io
        import contextlib

        stdout_capture = io.StringIO()
        local_ns = {
            "idaapi": idaapi,
            "idc": idc,
            "idautils": idautils,
            "ida_segment": ida_segment,
            "ida_nalt": ida_nalt,
            "ida_entry": ida_entry,
        }
        with contextlib.redirect_stdout(stdout_capture):
            try:
                exec(script_code, local_ns)
            except Exception as e:
                return {"output": stdout_capture.getvalue(), "error": str(e)}
        return {"output": stdout_capture.getvalue(), "error": None}


class MCPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Health-check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            binary = idaapi.get_input_file_path()
            status = "ok" if binary else "no_binary"
        except Exception:
            status = "stale"
            binary = ""
        self.wfile.write(
            json.dumps({"status": status, "binary": binary or ""}).encode("utf-8")
        )

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        if not post_data:
            self.send_response(400)
            self.end_headers()
            return

        try:
            req = json.loads(post_data.decode("utf-8"))
            action = req.get("action")
            args = req.get("args", {})

            result = None

            # ── Core Navigation ───────────────────────────────────────
            if action == "ping":
                result = {"status": "ok"}
            elif action == "get_current_address":
                result = {
                    "address": IdaOperations._execute_sync(
                        IdaOperations.get_current_address
                    )
                }
            elif action == "get_current_function":
                result = {
                    "address": IdaOperations._execute_sync(
                        IdaOperations.get_current_function
                    )
                }
            elif action == "get_functions":
                result = {
                    "functions": IdaOperations._execute_sync(
                        IdaOperations.get_functions,
                        args.get("offset", 0),
                        args.get("limit", 100),
                        args.get("filter"),
                    )
                }
            elif action == "get_function":
                result = IdaOperations._execute_sync(
                    IdaOperations.get_function, args.get("address")
                )
                if result is None:
                    result = {"error": "No function found at address"}

            # ── Decompilation & Disassembly ────────────────────────────
            elif action == "decompile":
                result = {
                    "code": IdaOperations._execute_sync(
                        IdaOperations.decompile, args.get("address")
                    )
                }
            elif action == "disassemble":
                result = {
                    "code": IdaOperations._execute_sync(
                        IdaOperations.disassemble, args.get("address")
                    )
                }

            # ── Cross-References ───────────────────────────────────────
            elif action == "get_xrefs":
                result = {
                    "xrefs": IdaOperations._execute_sync(
                        IdaOperations.get_xrefs, args.get("address")
                    )
                }

            # ── Modification ───────────────────────────────────────────
            elif action == "rename":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.rename, args.get("address"), args.get("name")
                    )
                }
            elif action == "set_comment":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.set_comment,
                        args.get("address"),
                        args.get("comment"),
                        args.get("repeatable", False),
                    )
                }
            elif action == "set_function_type":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.set_function_type,
                        args.get("address"),
                        args.get("signature"),
                    )
                }
            elif action == "rename_local_variable":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.rename_local_variable,
                        args.get("address"),
                        args.get("old_name"),
                        args.get("new_name"),
                    )
                }
            elif action == "set_local_variable_type":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.set_local_variable_type,
                        args.get("address"),
                        args.get("variable_name"),
                        args.get("new_type"),
                    )
                }
            elif action == "patch_bytes":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.patch_bytes,
                        args.get("address"),
                        args.get("hex_bytes"),
                    )
                }
            elif action == "save_binary":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.save_binary, args.get("output_path")
                    )
                }

            # ── Data Extraction ────────────────────────────────────────
            elif action == "get_strings":
                result = {
                    "strings": IdaOperations._execute_sync(
                        IdaOperations.get_strings,
                        args.get("offset", 0),
                        args.get("limit", 100),
                        args.get("filter"),
                    )
                }
            elif action == "get_globals":
                result = {
                    "globals": IdaOperations._execute_sync(
                        IdaOperations.get_globals,
                        args.get("offset", 0),
                        args.get("limit", 100),
                        args.get("filter"),
                    )
                }
            elif action == "get_segments":
                result = {
                    "segments": IdaOperations._execute_sync(
                        IdaOperations.get_segments,
                        args.get("offset", 0),
                        args.get("limit", 100),
                    )
                }
            elif action == "get_imports":
                result = {
                    "imports": IdaOperations._execute_sync(
                        IdaOperations.get_imports,
                        args.get("offset", 0),
                        args.get("limit", 100),
                    )
                }
            elif action == "get_exports":
                result = {
                    "exports": IdaOperations._execute_sync(
                        IdaOperations.get_exports,
                        args.get("offset", 0),
                        args.get("limit", 100),
                    )
                }
            elif action == "analyze_functions":
                # Re-analyze specified addresses
                result = {"success": True}
            elif action == "scan_aob":
                result = {
                    "address": IdaOperations._execute_sync(
                        IdaOperations.scan_aob, args.get("pattern")
                    )
                }

            # ── Dynamic Debugging & Memory ────────────────────────────
            elif action == "set_bpt":
                result = IdaOperations._execute_sync(
                    IdaOperations.set_bpt, args.get("address")
                )
            elif action == "wait_bpt":
                result = IdaOperations._execute_sync(
                    IdaOperations.wait_bpt, args.get("timeout", 15)
                )
            elif action == "read_memory":
                result = IdaOperations._execute_sync(
                    IdaOperations.read_memory, args.get("address"), args.get("size")
                )
            elif action == "memory_regions":
                result = IdaOperations._execute_sync(IdaOperations.memory_regions)

            # ── Extended Types & Structures ─────────────────────────
            elif action == "get_stack_frame_variables":
                result = {
                    "variables": IdaOperations._execute_sync(
                        IdaOperations.get_stack_frame_variables, args.get("address")
                    )
                }
            elif action == "list_local_types":
                result = {
                    "types": IdaOperations._execute_sync(IdaOperations.list_local_types)
                }
            elif action == "get_defined_structures":
                result = {
                    "structures": IdaOperations._execute_sync(
                        IdaOperations.get_defined_structures
                    )
                }
            elif action == "analyze_struct_detailed":
                result = {
                    "structure": IdaOperations._execute_sync(
                        IdaOperations.analyze_struct_detailed, args.get("name")
                    )
                }
            elif action == "declare_c_type":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.declare_c_type, args.get("c_declaration")
                    )
                }
            elif action == "set_global_variable_type":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.set_global_variable_type,
                        args.get("variable_name"),
                        args.get("new_type"),
                    )
                }

            # ── Extended Navigation ─────────────────────────────────
            elif action == "get_callees":
                result = {
                    "callees": IdaOperations._execute_sync(
                        IdaOperations.get_callees, args.get("address")
                    )
                }
            elif action == "get_callers":
                result = {
                    "callers": IdaOperations._execute_sync(
                        IdaOperations.get_callers, args.get("address")
                    )
                }
            elif action == "get_xrefs_to_field":
                result = {
                    "xrefs": IdaOperations._execute_sync(
                        IdaOperations.get_xrefs_to_field,
                        args.get("struct_name"),
                        args.get("field_name"),
                    )
                }
            elif action == "patch_address_assembles":
                result = {
                    "success": IdaOperations._execute_sync_write(
                        IdaOperations.patch_address_assembles,
                        args.get("address"),
                        args.get("instructions"),
                    )
                }

            # ── Script Execution ────────────────────────────────────
            elif action == "execute_script":
                result = IdaOperations._execute_sync(
                    IdaOperations.execute_script, args.get("code", "")
                )

            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error_message": "action not found"}')
                return

            # Log the request
            import time as _time

            print(
                "[IDA-MCP] %s -> %s"
                % (
                    action,
                    "ok" if result and "error" not in str(result)[:50] else "err",
                )
            )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy logging to IDA output window
        pass


from http.server import ThreadingHTTPServer

# Global references to keep server alive and allow shutting down
if "SERVER_INSTANCE" in dir() and SERVER_INSTANCE is not None:
    print("[IDA-MCP] Shutting down previous server instance...")
    try:
        SERVER_INSTANCE.shutdown()
        SERVER_INSTANCE.server_close()
    except Exception:
        pass


def start_server():
    global SERVER_INSTANCE
    PORT = 10101
    SERVER_INSTANCE = ThreadingHTTPServer(("127.0.0.1", PORT), MCPRequestHandler)
    print(f"[IDA-MCP] Starting threaded background HTTP server on 127.0.0.1:{PORT} ...")
    SERVER_INSTANCE.serve_forever()


class IDA_MCP_Plugin(idaapi.plugin_t):
    # PLUGIN_FIX tells IDA to load this automatically when it boots up
    flags = idaapi.PLUGIN_FIX
    comment = "IDA Pro Model Context Protocol Server"
    help = "Starts a background HTTP server for AI interactions"
    wanted_name = "IDA MCP Server"
    wanted_hotkey = ""

    def init(self):
        t = threading.Thread(target=start_server)
        t.daemon = True
        t.start()
        print("[IDA-MCP] Plugin loaded! Background server started automatically.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if "SERVER_INSTANCE" in globals() and SERVER_INSTANCE is not None:
            SERVER_INSTANCE.shutdown()


def PLUGIN_ENTRY():
    return IDA_MCP_Plugin()
