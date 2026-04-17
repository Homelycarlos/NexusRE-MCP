import asyncio
import logging
from typing import List, Optional
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

logger = logging.getLogger("NexusRE")

class CheatEngineAdapter(BaseAdapter):
    """
    Translates MCP calls to raw TCP pipe format to bridge into
    the Cheat Engine Lua script: `plugins/ce/ce_backend_plugin.lua`
    """
    def __init__(self, target_host: str = "127.0.0.1", port: int = 10105):
        self.host = target_host
        self.port = port

    async def _send_raw(self, payload: str) -> str:
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            writer.write((payload + "\n").encode())
            await writer.drain()
            data = await reader.readline()
            writer.close()
            await writer.wait_closed()
            return data.decode().strip()
        except Exception as e:
            logger.error(f"Cheat Engine connection error: {e}")
            return "ERROR|CONNECTION_FAILED"

    # ── Game Hacking Specific APIs (Native) ───────────────────────────────

    async def scan_aob(self, pattern: str) -> Optional[str]:
        res = await self._send_raw(f"AOB_SCAN|{pattern}")
        if "ERROR" in res or res == "NOT_FOUND": return None
        return res

    async def read_pointer_chain(self, base_address: str, offsets: List[str]) -> Optional[str]:
        payload = f"READ_POINTER_CHAIN|{base_address}"
        if offsets:
            payload += "|" + "|".join(offsets)
        res = await self._send_raw(payload)
        if "ERROR" in res or "INVALID" in res: return None
        return res

    # ── Overriding Base Adapter standard patching ───────────────────────

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        res = await self._send_raw(f"WRITE_BYTES|{address}|{hex_bytes}")
        return res == "SUCCESS"

    async def save_binary(self, output_path: str) -> bool:
        return False

    # ── Standard Base Methods (Unsupported in raw memory) ───────────────

    async def get_current_address(self) -> Optional[str]: return None
    async def get_current_function(self) -> Optional[str]: return None
    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]: return []
    async def get_function(self, address: str) -> Optional[FunctionSchema]: return None
    async def decompile_function(self, address: str) -> Optional[str]: return None
    async def disassemble_at(self, address: str) -> List[InstructionSchema]: return []
    async def batch_decompile(self, addresses: List[str]) -> List[str]: return []
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
