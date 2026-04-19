from typing import List, Optional
import json
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class Radare2Adapter(BaseAdapter):
    """
    Adapter utilizing r2pipe logic to interact with Radare2 completely headlessly.
    Since R2 is headless by design, there is no background HTTP server running.
    This adapter spins up r2pipe.open() directly hitting the user's binary.
    """
    def __init__(self, backend_url: str):
        # backend_url for radare2 is effectively the absolute binary path
        import r2pipe
        import os
        self.r2 = r2pipe.open(backend_url)
        # Initialize basic analysis
        self.r2.cmd('aaa')

    # ── Core Integration ──────────────────────────────────────────────────

    async def get_current_address(self) -> Optional[str]:
        # Radare2 maintains state via seeking (s).
        res = self.r2.cmd('s')
        return res.strip() if res else None

    async def get_current_function(self) -> Optional[str]:
        res = self.r2.cmdj('afi.')
        if res and isinstance(res, list) and len(res):
            return hex(res[0].get("offset"))
        return None

    # ── Decompilation & Function Listing ──────────────────────────────────

    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]:
        funcs = self.r2.cmdj('aflj') or []
        filtered = []
        for f in funcs:
            if filter_str and filter_str.lower() not in f.get('name', '').lower():
                continue
            filtered.append(FunctionSchema(
                name=f.get('name', ''),
                address=hex(f.get('offset', 0)),
                size=f.get('size', 0),
                instructions=[],
                decompiled=None,
                xrefs=[]
            ))
        if limit <= 0: return filtered[offset:]
        return filtered[offset:offset+limit]

    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        addr = int(address, 16)
        self.r2.cmd(f's {addr}')
        info = self.r2.cmdj('afij')
        if not info or len(info) == 0: return None
        return FunctionSchema(
            name=info[0].get('name', ''),
            address=hex(info[0].get('offset', 0)),
            size=info[0].get('size', 0),
            instructions=[],
            decompiled=None,
            xrefs=[]
        )

    async def decompile_function(self, address: str) -> Optional[str]:
        # r2ghidra or r2dec decompilation
        addr = int(address, 16)
        self.r2.cmd(f's {addr}')
        # 'pdd' is r2dec, 'pdg' is r2ghidra. Fallback to pdc (pseudo)
        dec = self.r2.cmd('pdc')
        if not dec: dec = self.r2.cmd('pdd')
        return dec

    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        addr = int(address, 16)
        # Fetch 20 instructions
        res = self.r2.cmdj(f'pdj 20 @ {addr}') or []
        instructions = []
        for ins in res:
            instructions.append(InstructionSchema(
                address=hex(ins.get('offset', 0)),
                mnemonic=ins.get('opcode', '').split()[0] if ins.get('opcode') else '',
                operands=ins.get('opcode', ''),
                raw_line=ins.get('opcode', '')
            ))
        return instructions

    async def analyze_functions(self, addresses: List[str]) -> bool:
        for a in addresses:
            self.r2.cmd(f'af @ {a}')
        return True

    # ── Cross-References ──────────────────────────────────────────────────

    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        addr = int(address, 16)
        res = self.r2.cmdj(f'axtj @ {addr}') or []
        xrefs = []
        for x in res:
            xrefs.append(XrefSchema(
                from_addr=hex(x.get('from', 0)),
                to_addr=address,
                type="Code" if x.get('type') == 'C' else "Data"
            ))
        return xrefs

    # ── Data & Strings ────────────────────────────────────────────────────

    async def get_strings(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[StringSchema]:
        res = self.r2.cmdj('izj') or []
        strings = []
        for s in res:
            val = s.get('string', '')
            if filter_str and filter_str.lower() not in val.lower():
                continue
            strings.append(StringSchema(address=hex(s.get('vaddr', 0)), value=val))
        if limit <= 0: return strings[offset:]
        return strings[offset:offset+limit]

    async def get_globals(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[GlobalVarSchema]:
        # symbols or flags
        res = self.r2.cmdj('fj') or []
        glbs = []
        for f in res:
            name = f.get('name', '')
            if filter_str and filter_str.lower() not in name.lower():
                continue
            glbs.append(GlobalVarSchema(
                name=name,
                address=hex(f.get('offset', 0)),
                size=f.get('size', 0),
                value=None
            ))
        if limit <= 0: return glbs[offset:]
        return glbs[offset:offset+limit]

    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]:
        res = self.r2.cmdj('iSj') or []
        segs = []
        for s in res:
            segs.append(SegmentSchema(
                name=s.get('name', ''),
                start_address=hex(s.get('vaddr', 0)),
                end_address=hex(s.get('vaddr', 0) + s.get('vsize', 0)),
                size=s.get('vsize', 0),
                permissions=s.get('perm', '')
            ))
        if limit <= 0: return segs[offset:]
        return segs[offset:offset+limit]

    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]:
        res = self.r2.cmdj('iij') or []
        imps = []
        for i in res:
            imps.append(ImportSchema(
                name=i.get('name', ''),
                address=hex(i.get('plt', 0)),
                module=""
            ))
        if limit <= 0: return imps[offset:]
        return imps[offset:offset+limit]

    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]:
        res = self.r2.cmdj('iEj') or []
        exps = []
        for e in res:
            exps.append(ExportSchema(
                name=e.get('name', ''),
                address=hex(e.get('vaddr', 0))
            ))
        if limit <= 0: return exps[offset:]
        return exps[offset:offset+limit]

    # ── Modification ──────────────────────────────────────────────────────

    async def rename_symbol(self, address: str, name: str) -> bool:
        addr = int(address, 16)
        self.r2.cmd(f'afn {name} @ {addr}')
        return True

    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        addr = int(address, 16)
        self.r2.cmd(f'CC {comment} @ {addr}')
        return True

    async def set_function_type(self, address: str, signature: str) -> bool:
        addr = int(address, 16)
        self.r2.cmd(f'afs {signature} @ {addr}')
        return True

    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool:
        addr = int(address, 16)
        # afvn old new @ addr
        self.r2.cmd(f'afvn {old_name} {new_name} @ {addr}')
        return True

    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool:
        addr = int(address, 16)
        self.r2.cmd(f'afvt {variable_name} {new_type} @ {addr}')
        return True

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        addr = int(address, 16)
        self.r2.cmd(f'wx {hex_bytes} @ {addr}')
        return True

    async def save_binary(self, output_path: str) -> bool:
        self.r2.cmd('w') # Just write to disk if R2 was opened in write mode (-w)
        return True
