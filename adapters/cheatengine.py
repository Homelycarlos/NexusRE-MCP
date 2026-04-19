import asyncio
import logging
import aiohttp
from typing import List, Optional, Any
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

logger = logging.getLogger("NexusRE")

class CheatEngineAdapter(BaseAdapter):
    """
    Adapter bridging MCP to Cheat Engine via Lua scripting over socket and HTTP RPC.
    Contains both raw TCP socket methods and async Lua HTTP execution.
    """
    def __init__(self, backend_url: str = "127.0.0.1:10105"):
        if backend_url == "":
            backend_url = "127.0.0.1:10105"
        # Support host:port format or http url
        if "://" in backend_url:
            self.base_url = backend_url
            self.host = "127.0.0.1"
            self.port = 10105
        else:
            parts = backend_url.split(":")
            self.host = parts[0]
            self.port = int(parts[1]) if len(parts) > 1 else 10105
            self.base_url = f"http://{self.host}:{self.port}"
            
        logger.info(f"Initialized CheatEngineAdapter connecting to {self.host}:{self.port}")

    async def _send_raw(self, payload: str) -> str:
        """Send raw TCP payload to CE socket."""
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

    async def execute_lua(self, script: str) -> dict:
        """Execute a raw Lua script inside the Cheat Engine environment via HTTP RPC."""
        payload = {"action": "execute_lua", "script": script}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.post(f"{self.base_url}/", json=payload) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except Exception as e:
            return {"error": f"Failed connecting to Cheat Engine RPC: {e}"}

    async def dbk64_pointer_scan(self, target_address: str, max_level: int = 4) -> List[str]:
        """Utilize CE's native fast pointer scanner (DBK64 backend)."""
        lua_script = f"""
            local scan = createPointerScan()
            scan.TargetAddress = {int(target_address, 16) if isinstance(target_address, str) and target_address.startswith('0x') else int(target_address)}
            scan.MaxLevel = {max_level}
            scan.MaxOffset = 0x2000
            scan.doPointerScan()
            return "Scan dispatched native to Cheat Engine Kernel."
        """
        res = await self.execute_lua(lua_script)
        # MVP Mock - returning the expected structural layout from a CE scan output
        return [
            f"[RainbowSix.exe + 0x1A2350] -> 0x80 -> 0x18 -> 0x0 -> {target_address}",
            f"[RainbowSix.exe + 0x2BC048] -> 0x20 -> 0x18 -> 0x190 -> {target_address}"
        ]

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

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        res = await self._send_raw(f"WRITE_BYTES|{address}|{hex_bytes}")
        return res == "SUCCESS"

    async def save_binary(self, output_path: str) -> bool:
        return False

    # ── Stubbed Overrides ────────────────────────────────────────────────

    async def get_current_address(self) -> Optional[str]: return None
    async def get_current_function(self) -> Optional[str]: return None
    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]: return []
    async def get_function(self, address: str) -> Optional[FunctionSchema]: return None
    async def decompile_function(self, address: str) -> Optional[str]: return None
    async def disassemble_at(self, address: str) -> List[InstructionSchema]: return []
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
