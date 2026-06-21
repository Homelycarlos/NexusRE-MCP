import ctypes
import os

class PLUG_INITSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pluginHandle", ctypes.c_int),
        ("sdkVersion", ctypes.c_int),
        ("pluginVersion", ctypes.c_int),
        ("pluginName", ctypes.c_char * 256),
    ]

def main():
    dll_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64"
    x64dbg_dir = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64"
    
    # Python 3.8+ requires explicit DLL directories
    os.add_dll_directory(x64dbg_dir)
    
    try:
        plugin = ctypes.CDLL(dll_path)
    except Exception as e:
        print(f"Failed to load DLL: {e}")
        return
        
    init_struct = PLUG_INITSTRUCT()
    init_struct.pluginHandle = 1
    init_struct.sdkVersion = 1
    init_struct.pluginVersion = 1
    init_struct.pluginName = b"TestPlugin"
    
    try:
        print("Calling pluginit...")
        plugin.pluginit(ctypes.byref(init_struct))
        print("pluginit succeeded!")
        print("Plugin Name:", init_struct.pluginName.decode('utf-8'))
    except Exception as e:
        print(f"pluginit failed: {e}")

if __name__ == "__main__":
    main()
