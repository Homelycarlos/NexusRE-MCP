import abc
from typing import List, Optional
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class BaseAdapter(abc.ABC):
    """
    Abstract interface guaranteeing all tool implementations are pure functions
    that return normalized deterministic schemas.
    """

    # ── Decompilation & Function Listing ──────────────────────────────────

    @abc.abstractmethod
    async def list_functions(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[FunctionSchema]:
        pass

    @abc.abstractmethod
    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        pass

    @abc.abstractmethod
    async def get_current_address(self) -> Optional[str]:
        """Get the user's currently selected address in the UI."""
        pass

    @abc.abstractmethod
    async def get_current_function(self) -> Optional[str]:
        """Get the user's currently selected function in the UI."""
        pass

    @abc.abstractmethod
    async def decompile_function(self, address: str) -> Optional[str]:
        pass

    @abc.abstractmethod
    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        """Disassemble the function or block at the given address."""
        pass

    @abc.abstractmethod
    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        pass

    @abc.abstractmethod
    async def analyze_functions(self, addresses: List[str]) -> bool:
        pass

    # ── Cross-References ──────────────────────────────────────────────────

    @abc.abstractmethod
    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        pass

    # ── Data & Strings ────────────────────────────────────────────────────

    @abc.abstractmethod
    async def get_strings(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[StringSchema]:
        pass

    @abc.abstractmethod
    async def get_globals(self, offset: int = 0, limit: int = 100, filter_str: Optional[str] = None) -> List[GlobalVarSchema]:
        """Get global data items from the binary."""
        pass

    @abc.abstractmethod
    async def get_segments(self, offset: int = 0, limit: int = 100) -> List[SegmentSchema]:
        """Get memory segments."""
        pass

    @abc.abstractmethod
    async def get_imports(self, offset: int = 0, limit: int = 100) -> List[ImportSchema]:
        """Get imported symbols."""
        pass

    @abc.abstractmethod
    async def get_exports(self, offset: int = 0, limit: int = 100) -> List[ExportSchema]:
        """Get exported symbols."""
        pass

    # ── Modification ──────────────────────────────────────────────────────

    @abc.abstractmethod
    async def rename_symbol(self, address: str, name: str) -> bool:
        pass

    @abc.abstractmethod
    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        """Set a comment at the given address."""
        pass

    @abc.abstractmethod
    async def set_function_type(self, address: str, signature: str) -> bool:
        """Apply a C function prototype to the function at address."""
        pass

    @abc.abstractmethod
    async def rename_local_variable(self, address: str, old_name: str, new_name: str) -> bool:
        """Rename a local variable within a function."""
        pass

    @abc.abstractmethod
    async def set_local_variable_type(self, address: str, variable_name: str, new_type: str) -> bool:
        """Set the type of a local variable."""
        pass

    @abc.abstractmethod
    async def patch_bytes(self, address: str, hex_bytes: str) -> bool:
        """Overwrite raw execution bytes in the binary."""
        pass

    @abc.abstractmethod
    async def save_binary(self, output_path: str) -> bool:
        """Save the patched binary back to the file system to keep changes."""
        pass
