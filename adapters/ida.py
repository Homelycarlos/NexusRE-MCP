from typing import List, Optional
import aiohttp
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class IDAAdapter(BaseAdapter):
    """
    Adapter mapping NexusRE MCP tool calls to the IDA Pro background
    HTTP server (ida_backend_plugin.py) running on the local machine.
    All calls are dispatched as JSON POST requests with an 'action' key.
    """
    def __init__(self, backend_url: str):
        self.base_url = backend_url
        self._cache = {}

    async def _call(self, action: str, args: dict = None) -> dict:
        """Issue a JSON POST to the background HTTP server with Retry + Caching."""
        import asyncio
        args = args or {}
        
        # 1. Caching for read-only mass data endpoints
        # These are entirely deterministic data structures in static analysis.
        cacheable_actions = ["get_functions", "get_strings", "get_globals", "get_segments", "get_imports", "get_exports"]
        cache_key = None
        if action in cacheable_actions:
            # Create a string key out of args for the dictionary hash
            cache_key = f"{action}:{hash(frozenset(args.items()))}"
            if cache_key in self._cache:
                return self._cache[cache_key]

        payload = {"action": action, "args": args}
        
        # 2. 3x Retry Loop for Stability & Timeout protection
        timeout = aiohttp.ClientTimeout(total=30)
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(f"{self.base_url}/rpc", json=payload) as resp:
                        resp.raise_for_status()
                        data = await resp.json()
                        # Save to cache if it's a read op
                        if cache_key:
                            self._cache[cache_key] = data
                        return data
            except Exception as e:
                if attempt == 2:
                    raise Exception(f"Fatal IDA connection error after 3 retries: {e}")
                await asyncio.sleep(0.5)
        return {}

    # ── Decompilation & Function Listing ──────────────────────────────────

    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]:
        res = await self._call("get_functions", {"offset": offset, "limit": limit, "filter": filter_str})
        return [
            FunctionSchema(
                name=f.get('name', ''),
                address=f.get('address', ''),
                size=f.get('size', 0),
                instructions=[],
                decompiled=None,
                xrefs=[]
            ) for f in res.get("functions", [])
        ]

    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        res = await self._call("get_function", {"address": address})
        if not res or "error" in res:
            return None
        return FunctionSchema(
            name=res.get('name', ''),
            address=res.get('address', address),
            size=res.get('size', 0),
            instructions=[],
            decompiled=None,
            xrefs=[]
        )

    async def get_current_address(self) -> Optional[str]:
        res = await self._call("get_current_address")
        return res.get("address") if res else None

    async def get_current_function(self) -> Optional[str]:
        res = await self._call("get_current_function")
        return res.get("address") if res else None

    async def decompile_function(self, address: str) -> Optional[str]:
        res = await self._call("decompile", {"address": address})
        return res.get("code")

    async def scan_aob(self, pattern: str) -> Optional[str]:
        res = await self._call("scan_aob", {"pattern": pattern})
        return res.get("address")

    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        res = await self._call("disassemble", {"address": address})
        raw = res.get("code", "")
        instructions = []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Lines are formatted as "0xADDR: mnemonic operands"
            if ": " in line:
                addr_part, rest = line.split(": ", 1)
                parts = rest.split(None, 1)
                mnem = parts[0] if parts else rest
                ops = parts[1] if len(parts) > 1 else ""
                instructions.append(InstructionSchema(
                    address=addr_part, mnemonic=mnem, operands=ops, raw_line=line
                ))
            else:
                instructions.append(InstructionSchema(
                    address="", mnemonic=line, operands="", raw_line=line
                ))
        return instructions

    async def analyze_functions(self, addresses: List[str]) -> bool:
        res = await self._call("analyze_functions", {"addresses": addresses})
        return res.get("success", False)

    # ── Cross-References ──────────────────────────────────────────────────

    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        res = await self._call("get_xrefs", {"address": address})
        xrefs_data = res.get("xrefs", {})
        results = []
        for ref in xrefs_data.get("to", []):
            results.append(XrefSchema(from_addr=ref, to_addr=address, type="CodeTo"))
        for ref in xrefs_data.get("from", []):
            results.append(XrefSchema(from_addr=address, to_addr=ref, type="CodeFrom"))
        return results

    # ── Data & Strings ────────────────────────────────────────────────────

    async def get_strings(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[StringSchema]:
        res = await self._call("get_strings", {"offset": offset, "limit": limit, "filter": filter_str})
        return [StringSchema(**s) for s in res.get("strings", [])]

    async def get_globals(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[GlobalVarSchema]:
        res = await self._call("get_globals", {"offset": offset, "limit": limit, "filter": filter_str})
        return [GlobalVarSchema(**g) for g in res.get("globals", [])]

    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]:
        res = await self._call("get_segments", {"offset": offset, "limit": limit})
        return [SegmentSchema(**s) for s in res.get("segments", [])]

    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]:
        res = await self._call("get_imports", {"offset": offset, "limit": limit})
        return [ImportSchema(**i) for i in res.get("imports", [])]

    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]:
        res = await self._call("get_exports", {"offset": offset, "limit": limit})
        return [ExportSchema(**e) for e in res.get("exports", [])]

    # ── Modification ──────────────────────────────────────────────────────

    async def rename_symbol(self, address: str, name: str) -> bool:
        res = await self._call("rename", {"address": address, "name": name})
        return res.get("success", False)

    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        res = await self._call("set_comment", {"address": address, "comment": comment, "repeatable": repeatable})
        return res.get("success", False)

    async def set_function_type(self, address: str, signature: str) -> bool:
        res = await self._call("set_function_type", {"address": address, "signature": signature})
        return res.get("success", False)

    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool:
        res = await self._call("rename_local_variable", {"address": address, "old_name": old_name, "new_name": new_name})
        return res.get("success", False)

    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool:
        res = await self._call("set_local_variable_type", {"address": address, "variable_name": variable_name, "new_type": new_type})
        return res.get("success", False)

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        res = await self._call("patch_bytes", {"address": address, "hex_bytes": hex_bytes})
        return res.get("success", False)

    async def save_binary(self, output_path: str) -> bool:
        res = await self._call("save_binary", {"output_path": output_path})
        return res.get("success", False)

    # ── Dynamic Debugger & Memory ─────────────────────────────────────────

    async def set_hardware_breakpoint(self, address: str, context_lines: int = 5) -> str:
        """Set a breakpoint via IDA's internal debugger (ida_dbg)."""
        res = await self._call("set_bpt", {"address": address})
        return res.get("message", f"Breakpoint request sent for {address}")

    async def wait_for_breakpoint(self, timeout: int = 15) -> Optional[dict]:
        """Wait for IDA debugger to hit the breakpoint."""
        res = await self._call("wait_bpt", {"timeout": timeout})
        if "error" in res:
            return {"error": res["error"]}
        return {"context": res.get("context", {})}

    async def read_memory(self, address: int, size: int, as_bytes: bool = False) -> Any:
        """Read live debugged memory or statically mapped segments in IDA."""
        res = await self._call("read_memory", {"address": address, "size": size})
        hex_data = res.get("data", "")
        if as_bytes:
            return bytes.fromhex(hex_data.replace(" ", ""))
        return hex_data

    async def memory_regions(self) -> List[dict]:
        """Get all memory segments mapped in IDA database."""
        res = await self._call("memory_regions")
        return res.get("regions", [])
