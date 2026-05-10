import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("NexusRE")

class UnicornSandbox:
    def __init__(self, arch: str, mode: str):
        try:
            import unicorn
            import unicorn.x86_const as x86
        except ImportError:
            raise Exception("unicorn module not installed. Please install unicorn to use emulation features.")

        self.arch_str = arch.lower()
        self.mode_str = mode.lower()
        self.uc = None

        if self.arch_str == 'x86':
            uc_arch = unicorn.UC_ARCH_X86
            if self.mode_str == '32':
                uc_mode = unicorn.UC_MODE_32
            elif self.mode_str == '64':
                uc_mode = unicorn.UC_MODE_64
            else:
                raise ValueError("Unsupported x86 mode. Use '32' or '64'.")
        else:
            raise NotImplementedError(f"Architecture {arch} is not yet supported by UnicornSandbox.")

        self.uc = unicorn.Uc(uc_arch, uc_mode)
        self.x86_const = x86
        self.unicorn = unicorn
        
        # Default Stack Setup
        self.stack_base = 0x70000000
        self.stack_size = 2 * 1024 * 1024 # 2MB
        self.uc.mem_map(self.stack_base, self.stack_size)
        
        # Set RSP/ESP to middle of stack
        stack_ptr = self.stack_base + (self.stack_size // 2)
        if self.mode_str == '64':
            self.uc.reg_write(self.x86_const.UC_X86_REG_RSP, stack_ptr)
        else:
            self.uc.reg_write(self.x86_const.UC_X86_REG_ESP, stack_ptr)

        # Hook unmapped memory accesses to prevent hard crashes
        self.uc.hook_add(self.unicorn.UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        self.mem_faults = []

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        action = "READ" if access == self.unicorn.UC_MEM_READ_UNMAPPED else "WRITE" if access == self.unicorn.UC_MEM_WRITE_UNMAPPED else "FETCH"
        msg = f"Invalid memory {action} at 0x{address:x}, size {size}"
        logger.warning(f"UnicornSandbox: {msg}")
        self.mem_faults.append(msg)
        return False # Stop emulation on invalid access

    def map_memory(self, address: int, size: int, perms: int = None):
        if perms is None:
            perms = self.unicorn.UC_PROT_ALL
        # Align address down to 4KB page boundary
        aligned_addr = address & ~0xFFF
        # Calculate size covering the original range from the aligned base
        aligned_size = ((address + size - aligned_addr) + 0xFFF) & ~0xFFF
        
        try:
            self.uc.mem_map(aligned_addr, aligned_size, perms)
        except self.unicorn.UcError as e:
            # If already mapped, ignore or handle specifically
            pass

    def write_memory(self, address: int, data: bytes):
        self.map_memory(address, len(data))
        self.uc.mem_write(address, data)

    def set_registers(self, registers: Dict[str, int]):
        reg_map = {
            'rax': self.x86_const.UC_X86_REG_RAX, 'eax': self.x86_const.UC_X86_REG_EAX,
            'rbx': self.x86_const.UC_X86_REG_RBX, 'ebx': self.x86_const.UC_X86_REG_EBX,
            'rcx': self.x86_const.UC_X86_REG_RCX, 'ecx': self.x86_const.UC_X86_REG_ECX,
            'rdx': self.x86_const.UC_X86_REG_RDX, 'edx': self.x86_const.UC_X86_REG_EDX,
            'rsi': self.x86_const.UC_X86_REG_RSI, 'esi': self.x86_const.UC_X86_REG_ESI,
            'rdi': self.x86_const.UC_X86_REG_RDI, 'edi': self.x86_const.UC_X86_REG_EDI,
            'rbp': self.x86_const.UC_X86_REG_RBP, 'ebp': self.x86_const.UC_X86_REG_EBP,
            'rsp': self.x86_const.UC_X86_REG_RSP, 'esp': self.x86_const.UC_X86_REG_ESP,
            'rip': self.x86_const.UC_X86_REG_RIP, 'eip': self.x86_const.UC_X86_REG_EIP,
            'r8': self.x86_const.UC_X86_REG_R8,   'r9': self.x86_const.UC_X86_REG_R9,
            'r10': self.x86_const.UC_X86_REG_R10, 'r11': self.x86_const.UC_X86_REG_R11,
            'r12': self.x86_const.UC_X86_REG_R12, 'r13': self.x86_const.UC_X86_REG_R13,
            'r14': self.x86_const.UC_X86_REG_R14, 'r15': self.x86_const.UC_X86_REG_R15,
        }
        for reg_name, val in registers.items():
            r = reg_name.lower()
            if r in reg_map:
                self.uc.reg_write(reg_map[r], val)

    def get_registers(self) -> Dict[str, int]:
        regs = {}
        if self.mode_str == '64':
            keys = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
            for k in keys:
                regs[k] = self.uc.reg_read(getattr(self.x86_const, f"UC_X86_REG_{k.upper()}"))
        else:
            keys = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']
            for k in keys:
                regs[k] = self.uc.reg_read(getattr(self.x86_const, f"UC_X86_REG_{k.upper()}"))
        return regs

    def emulate(self, start_addr: int, end_addr: int, timeout: int = 0, count: int = 0) -> Dict[str, Any]:
        try:
            self.uc.emu_start(start_addr, end_addr, timeout=timeout, count=count)
            return {
                "status": "success",
                "registers": self.get_registers(),
                "faults": self.mem_faults
            }
        except self.unicorn.UcError as e:
            return {
                "status": "error",
                "error": str(e),
                "registers": self.get_registers(),
                "faults": self.mem_faults
            }
