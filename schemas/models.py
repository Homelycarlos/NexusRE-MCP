from typing import List, Optional
from pydantic import BaseModel, Field

class FunctionSchema(BaseModel):
    name: str
    address: str
    size: int
    instructions: List[str]
    decompiled: Optional[str] = None
    xrefs: List[str]

class StringSchema(BaseModel):
    address: str
    value: str

class XrefSchema(BaseModel):
    from_addr: str = Field(alias="from")
    to_addr: str = Field(alias="to")
    type: str

    class Config:
        populate_by_name = True

class ErrorSchema(BaseModel):
    error_message: str
    error_code: str

class InstructionSchema(BaseModel):
    """Schema for a single disassembled instruction."""
    address: str
    mnemonic: str
    operands: str = ""
    raw_line: str = ""

class CommentSchema(BaseModel):
    """Schema for a comment set on an address."""
    address: str
    comment: str
    repeatable: bool = False

class GlobalVarSchema(BaseModel):
    """Schema for a global data item."""
    address: str
    name: str
    size: int = 0
    value: Optional[str] = None

class SegmentSchema(BaseModel):
    """Schema for a memory segment."""
    name: str
    start_address: str
    end_address: str
    size: int
    permissions: str = ""

class ImportSchema(BaseModel):
    """Schema for an imported symbol."""
    address: str
    name: str
    module: str = ""

class ExportSchema(BaseModel):
    """Schema for an exported symbol."""
    address: str
    name: str
