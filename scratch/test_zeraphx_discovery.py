import winreg
import ctypes
from ctypes import wintypes

def discover_section_name():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(key, "MachineSession")
        winreg.CloseKey(key)
        if regtype == winreg.REG_SZ:
            return value
    except Exception as e:
        print(f"Error reading registry: {e}")
    return None

if __name__ == "__main__":
    section_name = discover_section_name()
    if section_name:
        print(f"Discovered ZeraphX Section Name: {section_name}")
    else:
        print("ZeraphX Driver session not found in registry. Is the driver loaded?")
