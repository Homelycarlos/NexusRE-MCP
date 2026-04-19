import asyncio
from typing import List, Optional
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)
import logging

logger = logging.getLogger("NexusRE")

class GDBAdapter(BaseAdapter):
    """
    Adapter utilizing pygdbmi to interact with a background GDB process natively.
    Can be used for Linux executables, Android libUE4.so, or any remote target.
    """
    def __init__(self, binary_path: str):
        from pygdbmi.gdbcontroller import GdbController
        self.target = binary_path
        # Start gdb headless process
        try:
            self.gdbmi = GdbController()
            self.gdbmi.write(f"-file-exec-and-symbols {self.target}")
        except Exception as e:
            logger.error(f"GDB Initialization Error: {e}")
            self.gdbmi = None

    async def _send(self, command: str) -> List[dict]:
        if not self.gdbmi: return []
        # Run in a separate thread to prevent blocking FastMCP event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.gdbmi.write, command)

    async def get_current_address(self) -> Optional[str]:
        # -data-evaluate-expression $pc
        resp = await self._send("-data-evaluate-expression $pc")
        for r in resp:
            if r.get("type") == "result" and "payload" in r and "value" in r["payload"]:
                # often formatted as '0x401000 <main>' or just '0x401000'
                val = r["payload"]["value"].split()[0]
                return val
        return None

    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        addr = int(address, 16)
        # Fetch 20 instructions starting at address
        resp = await self._send(f"-data-disassemble -s {addr} -e {addr + 64} -- 0")
        instructions = []
        for r in resp:
            if r.get("type") == "result" and "payload" in r and "asm_insns" in r["payload"]:
                for insn in r["payload"]["asm_insns"]:
                    instructions.append(InstructionSchema(
                        address=insn.get("address", ""),
                        mnemonic=insn.get("inst", "").split()[0] if insn.get("inst") else "",
                        operands=insn.get("inst", ""),
                        raw_line=insn.get("inst", "")
                    ))
        return instructions

    async def get_current_function(self) -> Optional[str]:
        resp = await self._send("-stack-info-frame")
        for r in resp:
            if r.get("type") == "result" and "payload" in r and "frame" in r["payload"]:
                return r["payload"]["frame"].get("addr", None)
        return None

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        # Pymem or direct write using GDB: set {char[4]} 0x401000 = {0x90, 0x90, 0x90, 0x90}
        addr = int(address, 16)
        b_list = bytes.fromhex(hex_bytes.replace(" ", ""))
        arr = "{" + ", ".join([hex(b) for b in b_list]) + "}"
        await self._send(f"-gdb-set {{char[{len(b_list)}]}} {addr} = {arr}")
        return True

    # ── Heavy Overrides (Stubbed for Dynamic GDB without static analysis plugin)

    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]: return []
    async def get_function(self, address: str) -> Optional[FunctionSchema]: return None
    async def decompile_function(self, address: str) -> Optional[str]: return None
    async def analyze_functions(self, addresses: List[str]) -> bool: return False
    async def get_xrefs(self, address: str) -> List[XrefSchema]: return []
    async def get_strings(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[StringSchema]: return []
    async def get_globals(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[GlobalVarSchema]: return []
    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]: return []
    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]: return []
    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]: return []
    async def rename_symbol(self, address: str, name: str) -> bool: return False
    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool: return False
    async def set_function_type(self, address: str, signature: str) -> bool: return False
    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool: return False
    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool: return False
    async def save_binary(self, output_path: str) -> bool: return False
