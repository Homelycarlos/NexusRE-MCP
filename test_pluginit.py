import ctypes
import os
import traceback
from ctypes import *

x64_dir = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64"
os.add_dll_directory(x64_dir)
os.environ['PATH'] = x64_dir + ';' + os.environ['PATH']

class PLUG_INITSTRUCT(Structure):
    _fields_ = [
        ("pluginHandle", c_int),
        ("sdkVersion", c_int),
        ("pluginVersion", c_int),
        ("pluginName", c_char * 256),
    ]

try:
    dll = ctypes.CDLL(r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\plugins\x64dbgpython.dp64")
    init = PLUG_INITSTRUCT()
    init.pluginHandle = 1
    init.sdkVersion = 1
    
    print("Calling pluginit...")
    dll.pluginit.argtypes = [POINTER(PLUG_INITSTRUCT)]
    dll.pluginit.restype = c_bool
    
    result = dll.pluginit(byref(init))
    print(f"pluginit returned: {result}")
    print(f"pluginName: {init.pluginName}")
    
except Exception as e:
    print(f"Exception: {e}")
    traceback.print_exc()
