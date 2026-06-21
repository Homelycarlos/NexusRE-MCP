import ctypes
import os

plugin_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64"

# Add the x64 directory to the DLL search path so it can find python312.dll and other dependencies
x64_dir = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64"
os.add_dll_directory(x64_dir)
os.environ['PATH'] = x64_dir + ';' + os.environ['PATH']

try:
    print(f"Attempting to load {plugin_path}...")
    dll = ctypes.WinDLL(plugin_path)
    print("Success! The DLL loaded successfully without missing dependencies.")
except Exception as e:
    print(f"Failed to load DLL: {e}")
