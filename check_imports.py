import sys
import struct

def print_imports(filepath):
    try:
        with open(filepath, 'rb') as f:
            dos_header = f.read(64)
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)
            pe_signature = f.read(4)
            machine, num_sections, timestamp, sym_ptr, num_sym, opt_hdr_size, chars = struct.unpack('<HHIIIHH', f.read(20))
            
            # Read Optional Header to get Data Directory
            magic = struct.unpack('<H', f.read(2))[0]
            
            if magic == 0x10B: # PE32
                f.seek(pe_offset + 24 + 96) # Offset to data directories
            elif magic == 0x20B: # PE32+
                f.seek(pe_offset + 24 + 112)
            else:
                return
                
            # Import Directory is the 2nd entry (index 1)
            import_rva, import_size = struct.unpack('<II', f.read(8))
            if import_rva == 0:
                print("No import table found")
                return
                
            # Need to map RVA to File Offset
            f.seek(pe_offset + 24 + opt_hdr_size) # Start of section headers
            sections = []
            for _ in range(num_sections):
                name = f.read(8).strip(b'\x00')
                vsize, vaddr, raw_size, raw_ptr, reloc_ptr, line_ptr, num_reloc, num_line, chars = struct.unpack('<IIIIIIIHH', f.read(32))
                sections.append((vaddr, vsize, raw_ptr, raw_size))
                
            def rva_to_offset(rva):
                for vaddr, vsize, raw_ptr, raw_size in sections:
                    if vaddr <= rva < vaddr + vsize:
                        return rva - vaddr + raw_ptr
                return 0
                
            import_offset = rva_to_offset(import_rva)
            if import_offset == 0:
                return
                
            f.seek(import_offset)
            print(f"Imports for {filepath}:")
            while True:
                data = f.read(20)
                if len(data) < 20: break
                orig_ft, time_stamp, chain, name_rva, first_thunk = struct.unpack('<IIIII', data)
                if orig_ft == 0 and name_rva == 0:
                    break
                name_offset = rva_to_offset(name_rva)
                if name_offset > 0:
                    pos = f.tell()
                    f.seek(name_offset)
                    dll_name = b""
                    while True:
                        c = f.read(1)
                        if c == b'\x00' or not c: break
                        dll_name += c
                    print(f" - {dll_name.decode('ascii', errors='ignore')}")
                    f.seek(pos)
    except Exception as e:
        pass

if __name__ == '__main__':
    print_imports(r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64")
