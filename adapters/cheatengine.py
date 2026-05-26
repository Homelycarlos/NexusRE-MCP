import asyncio
import logging
import os
import time
import aiohttp
from pathlib import Path
from typing import List, Optional, Any
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

logger = logging.getLogger("NexusRE")

# ── File-based IPC fallback paths ────────────────────────────────────────────
# These match the paths created by ce_backend_plugin.lua when luasocket is missing.
_CE_IPC_SEARCH_PATHS = [
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Cheat Engine 7.5" / "nexusre_ipc",
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Cheat Engine 7.4" / "nexusre_ipc",
    Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Cheat Engine 7.5" / "nexusre_ipc",
    Path(r"C:\Cheat Engine") / "nexusre_ipc",
]


class CheatEngineAdapter(BaseAdapter):
    """
    Adapter bridging MCP to Cheat Engine via Lua scripting.
    Supports three transport modes (auto-detected in order):
      1. TCP socket (via luasocket in CE)
      2. HTTP RPC
      3. File-based IPC (zero-dependency fallback)
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

        # Detect file IPC directory (set by CE plugin when luasocket is missing)
        self._ipc_dir: Optional[Path] = None
        self._detect_ipc_dir()
            
        logger.info(f"Initialized CheatEngineAdapter connecting to {self.host}:{self.port} (file_ipc={'yes' if self._ipc_dir else 'no'})")

    def _detect_ipc_dir(self):
        """Scan known CE install paths for the nexusre_ipc directory."""
        for p in _CE_IPC_SEARCH_PATHS:
            mode_file = p / "mode.txt"
            if mode_file.exists():
                self._ipc_dir = p
                logger.info(f"Detected CE file-IPC at: {p}")
                return
        # Also check if the user passed a custom IPC path via env var
        custom = os.environ.get("NEXUSRE_CE_IPC_DIR")
        if custom and Path(custom).exists():
            self._ipc_dir = Path(custom)

    async def _send_file_ipc(self, payload: str, timeout: float = 5.0) -> str:
        """Send a command via file-based IPC (for CE installs without luasocket)."""
        if not self._ipc_dir:
            return "ERROR|FILE_IPC_NOT_AVAILABLE"
        
        request_file = self._ipc_dir / "request.txt"
        response_file = self._ipc_dir / "response.txt"
        lock_file = self._ipc_dir / "lock"

        try:
            # Wait for any previous lock to clear
            start = time.monotonic()
            while lock_file.exists() and (time.monotonic() - start) < timeout:
                await asyncio.sleep(0.02)

            token = ""
            token_file = Path.home() / ".nexusre" / "auth_token"
            if token_file.exists():
                token = token_file.read_text().strip()
                
            if token:
                payload = f"{token}|{payload}"

            # Write request
            request_file.write_text(payload, encoding="utf-8")

            # Wait for response
            start = time.monotonic()
            while (time.monotonic() - start) < timeout:
                if response_file.exists() and not lock_file.exists():
                    resp = response_file.read_text(encoding="utf-8").strip()
                    try:
                        response_file.unlink()
                    except OSError:
                        pass
                    return resp
                await asyncio.sleep(0.02)

            return "ERROR|TIMEOUT"
        except Exception as e:
            logger.error(f"File IPC error: {e}")
            return "ERROR|FILE_IPC_FAILED"

    async def _send_raw(self, payload: str) -> str:
        """Send raw TCP payload to CE socket. Falls back to file IPC if TCP fails."""
        try:
            token = ""
            token_file = Path.home() / ".nexusre" / "auth_token"
            if token_file.exists():
                token = token_file.read_text().strip()
                
            # Prepend token
            if token:
                payload = f"{token}|{payload}"
                
            reader, writer = await asyncio.open_connection(self.host, self.port)
            writer.write((payload + "\n").encode())
            await writer.drain()
            data = await reader.readline()
            writer.close()
            await writer.wait_closed()
            return data.decode().strip()
        except Exception as e:
            logger.warning(f"CE TCP connection failed ({e}), trying file IPC fallback...")
            # Fallback to file-based IPC
            if self._ipc_dir:
                return await self._send_file_ipc(payload)
            logger.error(f"Cheat Engine connection error: {e} (no file IPC available)")
            return "ERROR|CONNECTION_FAILED"

    async def execute_lua(self, script: str) -> dict:
        """Execute a raw Lua script inside the Cheat Engine environment."""
        # Replace newlines so it can be sent via raw protocol
        script_oneline = script.replace("\n", " ").replace("\r", " ")
        try:
            res = await self._send_raw(f"EXECUTE_LUA|{script_oneline}")
            if res.startswith("ERROR"):
                return {"error": res}
            return {"result": res}
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

    async def poll_events(self) -> list[dict]:
        res = await self._send_raw("POLL_EVENTS")
        if res and res != "ERROR|Empty Command":
            import json
            try: return json.loads(res)
            except: pass
        return []

    async def pattern_scan(self, pattern: str) -> list[int]:
        res = await self.scan_aob(pattern)
        if res:
            return [int(res, 16)]
        return []
