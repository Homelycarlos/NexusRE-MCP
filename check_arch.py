import sys
import struct

def check_architecture(filepath):
    try:
        with open(filepath, 'rb') as f:
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[0:2] != b'MZ':
                print(f"Not a valid PE file: {filepath}")
                return
            
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                print(f"Invalid PE signature in {filepath}")
                return
                
            machine = struct.unpack('<H', f.read(2))[0]
            if machine == 0x8664:
                print(f"Architecture: x64 (64-bit) for {filepath}")
            elif machine == 0x014C:
                print(f"Architecture: x86 (32-bit) for {filepath}")
            else:
                print(f"Architecture: Unknown (0x{machine:04X}) for {filepath}")
    except Exception as e:
        print(f"Error checking {filepath}: {e}")

if __name__ == '__main__':
    paths = [
        r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\python27.dll",
        r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64"
    ]
    for path in paths:
        check_architecture(path)
