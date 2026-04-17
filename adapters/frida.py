from typing import List, Optional, Any
import asyncio
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)
import logging

logger = logging.getLogger("NexusRE")

class FridaAdapter(BaseAdapter):
    """
    FridaAdapter provides real-time dynamic instruction trapping.
    It doesn't utilize standard static capabilities like get_imports natively 
    (though it could via process maps). This module focuses purely on `instrument_execution`.
    """
    def __init__(self, target_process: str):
        # target_process can be a PID ("1234") or process name ("game.exe")
        self.target = target_process
        self.session = None

    def _attach(self):
        import frida
        if self.session is None:
            try:
                if self.target.isdigit():
                    self.session = frida.attach(int(self.target))
                else:
                    self.session = frida.attach(self.target)
            except Exception as e:
                raise Exception(f"Failed to attach to {self.target} via Frida: {e}")

    async def instrument_execution(self, javascript_code: str) -> List[str]:
        """
        Inject arbitrary javascript hooking payloads using frida.
        Any send(payload) calls in JS will be collected and returned.
        """
        self._attach()
        import frida
        
        script = self.session.create_script(javascript_code)
        
        results = []
        def on_message(message, data):
            if message['type'] == 'send':
                results.append(message['payload'])
            elif message['type'] == 'error':
                results.append(f"ERROR: {message['description']}")

        script.on('message', on_message)
        script.load()

        # Let the script run for 3 seconds to catch live execution streams
        await asyncio.sleep(3)
        
        script.unload()
        return results

    # ── Unsupported Static Methods ────────────────────────────────────────

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
    async def patch_bytes(self, address: str, hex_bytes: str) -> bool: return False
    async def save_binary(self, output_path: str) -> bool: return False
