from typing import List, Optional
import aiohttp
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class BinjaAdapter(BaseAdapter):
    """
    Adapter mapping NexusRE MCP tool calls to the Binary Ninja background
    HTTP server running inside the binja UI script.
    """
    def __init__(self, backend_url: str):
        # Default binja port if no port given (e.g. 10104)
        self.base_url = backend_url

    async def _call(self, action: str, args: dict = None) -> dict:
        payload = {"action": action, "args": args or {}}
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.base_url}/rpc", json=payload) as resp:
                resp.raise_for_status()
                return await resp.json()

    # ── Core Integration ──────────────────────────────────────────────────

    async def get_current_address(self) -> Optional[str]:
        res = await self._call("binja_get_current_address")
        return res.get("address") if res else None

    async def get_current_function(self) -> Optional[str]:
        res = await self._call("binja_get_current_function")
        return res.get("address") if res else None

    # ── Decompilation & Function Listing ──────────────────────────────────

    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]:
        res = await self._call("binja_list_functions", {"offset": offset, "limit": limit, "filter": filter_str})
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
        res = await self._call("binja_get_function", {"address": address})
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

    async def decompile_function(self, address: str) -> Optional[str]:
        res = await self._call("binja_decompile_function", {"address": address})
        return res.get("code")

    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        res = await self._call("binja_disassemble", {"address": address})
        raw = res.get("code", "")
        instructions = []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
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

    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        res = await self._call("binja_batch_decompile", {"addresses": addresses})
        return res.get("results", [])

    async def analyze_functions(self, addresses: List[str]) -> bool:
        res = await self._call("binja_analyze_functions", {"addresses": addresses})
        return res.get("success", False)

    # ── Cross-References ──────────────────────────────────────────────────

    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        res = await self._call("binja_get_xrefs", {"address": address})
        xrefs = []
        for x in res.get("xrefs", []):
            xrefs.append(XrefSchema(
                from_addr=x.get("from", ""),
                to_addr=x.get("to", ""),
                type=x.get("type", "Code")
            ))
        return xrefs

    # ── Data & Strings ────────────────────────────────────────────────────

    async def get_strings(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[StringSchema]:
        res = await self._call("binja_get_strings", {"offset": offset, "limit": limit, "filter": filter_str})
        return [StringSchema(**s) for s in res.get("strings", [])]

    async def get_globals(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[GlobalVarSchema]:
        res = await self._call("binja_get_globals", {"offset": offset, "limit": limit, "filter": filter_str})
        return [GlobalVarSchema(**g) for g in res.get("globals", [])]

    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]:
        res = await self._call("binja_get_segments", {"offset": offset, "limit": limit})
        return [SegmentSchema(**s) for s in res.get("segments", [])]

    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]:
        res = await self._call("binja_get_imports", {"offset": offset, "limit": limit})
        return [ImportSchema(**i) for i in res.get("imports", [])]

    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]:
        res = await self._call("binja_get_exports", {"offset": offset, "limit": limit})
        return [ExportSchema(**e) for e in res.get("exports", [])]

    # ── Modification ──────────────────────────────────────────────────────

    async def rename_symbol(self, address: str, name: str) -> bool:
        res = await self._call("binja_rename_symbol", {"address": address, "name": name})
        return res.get("success", False)

    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        res = await self._call("binja_set_comment", {"address": address, "comment": comment, "repeatable": repeatable})
        return res.get("success", False)

    async def set_function_type(self, address: str, signature: str) -> bool:
        res = await self._call("binja_set_function_type", {"address": address, "signature": signature})
        return res.get("success", False)

    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool:
        res = await self._call("binja_rename_local_variable", {"address": address, "old_name": old_name, "new_name": new_name})
        return res.get("success", False)

    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool:
        res = await self._call("binja_set_local_variable_type", {"address": address, "variable_name": variable_name, "new_type": new_type})
        return res.get("success", False)

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        res = await self._call("binja_patch_bytes", {"address": address, "hex_bytes": hex_bytes})
        return res.get("success", False)

    async def save_binary(self, output_path: str) -> bool:
        res = await self._call("binja_save_binary", {"output_path": output_path})
        return res.get("success", False)
