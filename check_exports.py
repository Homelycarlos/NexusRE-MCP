import sys
import struct

def print_exports(filepath):
    try:
        with open(filepath, 'rb') as f:
            dos_header = f.read(64)
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)
            pe_signature = f.read(4)
            machine, num_sections, timestamp, sym_ptr, num_sym, opt_hdr_size, chars = struct.unpack('<HHIIIHH', f.read(20))
            
            magic = struct.unpack('<H', f.read(2))[0]
            if magic == 0x10B:
                f.seek(pe_offset + 24 + 96)
            elif magic == 0x20B:
                f.seek(pe_offset + 24 + 112)
            else:
                return
                
            export_rva, export_size = struct.unpack('<II', f.read(8))
            if export_rva == 0:
                print("No export table found")
                return
                
            f.seek(pe_offset + 24 + opt_hdr_size)
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
                
            export_offset = rva_to_offset(export_rva)
            if export_offset == 0:
                return
                
            f.seek(export_offset)
            flags, ts, major, minor, name_rva, ordinal_base, num_funcs, num_names, addr_funcs_rva, addr_names_rva, addr_ordinals_rva = struct.unpack('<IIHHIIIIIII', f.read(40))
            
            addr_names_offset = rva_to_offset(addr_names_rva)
            
            print(f"Exports for {filepath}:")
            for i in range(num_names):
                f.seek(addr_names_offset + i * 4)
                name_rva = struct.unpack('<I', f.read(4))[0]
                name_offset = rva_to_offset(name_rva)
                f.seek(name_offset)
                name = b""
                while True:
                    c = f.read(1)
                    if c == b'\x00' or not c: break
                    name += c
                print(f" - {name.decode('ascii')}")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print_exports(r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64")
