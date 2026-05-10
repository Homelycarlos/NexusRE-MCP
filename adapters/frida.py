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

    async def set_hardware_breakpoint(self, address: str, context_lines: int = 5) -> str:
        """Place an execution breakpoint via frida's Interceptor."""
        self._attach()
        import frida

        js = f"""
        Interceptor.attach(ptr('{address}'), {{
            onEnter: function(args) {{
                send({{'context': this.context}});
            }}
        }});
        """
        script = self.session.create_script(js)
        
        self.last_bp_hit = None
        def on_message(message, data):
            if message['type'] == 'send':
                self.last_bp_hit = message['payload']
        
        script.on('message', on_message)
        script.load()
        return f"Breakpoint set at {address}"

    async def wait_for_breakpoint(self, timeout: int = 15) -> Optional[dict]:
        """Wait for the previously set breakpoint to trigger, returning CPU registers."""
        for _ in range(timeout):
            if getattr(self, 'last_bp_hit', None):
                res = self.last_bp_hit
                self.last_bp_hit = None
                return res
            await asyncio.sleep(1)
        return {"error": "Breakpoint timeout reached"}

    async def read_memory(self, address: str, size: int) -> Optional[bytes]:
        """Read live process memory using frida."""
        self._attach()
        js = f"""
        try {{
            var ptr_addr = ptr('{address}');
            var buf = ptr_addr.readByteArray({size});
            send({{'data': buf}});
        }} catch (e) {{
            send({{'error': e.toString()}});
        }}
        """
        script = self.session.create_script(js)
        
        result = [None]
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if 'data' in payload:
                    result[0] = data  # The actual byte array is sent as the second arg (data)
                elif 'error' in payload:
                    logger.error(f"Frida read_memory error: {payload['error']}")
        
        script.on('message', on_message)
        script.load()
        await asyncio.sleep(0.5) # Wait for script to execute
        script.unload()
        return result[0]

    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        """Patch live process memory using frida."""
        self._attach()
        # Convert hex string to JS array
        byte_array = [int(b, 16) for b in hex_bytes.split()]
        js_array = "[" + ",".join(str(b) for b in byte_array) + "]"
        
        js = f"""
        try {{
            var ptr_addr = ptr('{address}');
            var bytes = {js_array};
            Memory.protect(ptr_addr, bytes.length, 'rwx');
            ptr_addr.writeByteArray(bytes);
            send({{'success': true}});
        }} catch (e) {{
            send({{'error': e.toString()}});
        }}
        """
        script = self.session.create_script(js)
        
        success = [False]
        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                if payload.get('success'):
                    success[0] = True
                elif 'error' in payload:
                    logger.error(f"Frida patch_bytes error: {payload['error']}")

        script.on('message', on_message)
        script.load()
        await asyncio.sleep(0.5)
        script.unload()
        return success[0]

    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]:
        """Enumerate live process modules as segments."""
        self._attach()
        js = """
        var modules = Process.enumerateModules();
        var result = [];
        for (var i = 0; i < modules.length; i++) {
            result.push({
                'name': modules[i].name,
                'start': modules[i].base.toString(),
                'end': modules[i].base.add(modules[i].size).toString(),
                'size': modules[i].size
            });
        }
        send({'modules': result});
        """
        script = self.session.create_script(js)
        
        segments = []
        def on_message(message, data):
            if message['type'] == 'send' and 'modules' in message['payload']:
                for m in message['payload']['modules']:
                    segments.append(SegmentSchema(
                        name=m['name'],
                        start_addr=m['start'],
                        end_addr=m['end'],
                        size=m['size'],
                        permissions="r-x" # Approximated
                    ))
                    
        script.on('message', on_message)
        script.load()
        await asyncio.sleep(0.5)
        script.unload()
        
        # Apply pagination
        return segments[offset:offset+limit]

    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]:
        """Enumerate imports of the main module."""
        self._attach()
        js = """
        var mainModule = Process.enumerateModules()[0];
        var imports = mainModule.enumerateImports();
        var result = [];
        for (var i = 0; i < imports.length; i++) {
            result.push({
                'name': imports[i].name,
                'module': imports[i].module || 'unknown',
                'address': imports[i].address ? imports[i].address.toString() : '0x0'
            });
        }
        send({'imports': result});
        """
        script = self.session.create_script(js)
        
        imports_list = []
        def on_message(message, data):
            if message['type'] == 'send' and 'imports' in message['payload']:
                for i in message['payload']['imports']:
                    imports_list.append(ImportSchema(
                        name=i['name'],
                        library=i['module'],
                        address=i['address']
                    ))
                    
        script.on('message', on_message)
        script.load()
        await asyncio.sleep(0.5)
        script.unload()
        
        return imports_list[offset:offset+limit]

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
    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]: return []
    async def rename_symbol(self, address: str, name: str) -> bool: return False
    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool: return False
    async def set_function_type(self, address: str, signature: str) -> bool: return False
    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool: return False
    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool: return False
    async def save_binary(self, output_path: str) -> bool: return False
