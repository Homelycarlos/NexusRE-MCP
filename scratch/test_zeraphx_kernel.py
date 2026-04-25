import asyncio
import sys
import os

# Ensure we can import from the parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.kernel import KernelAdapter

async def test_kernel():
    print("Initializing KernelAdapter (ZeraphX)...")
    adapter = KernelAdapter()
    
    if not adapter.shared_ptr:
        print("[-] Failed to initialize adapter. Is the driver loaded?")
        return

    print(f"[+] Attached to section: {adapter.section_name}")
    print(f"[+] Session Magic: {hex(adapter.magic)}")

    print("Probing driver (PING)...")
    success = await adapter.ping()
    if success:
        print("[+] Driver is ALIVE and responding!")
    else:
        print("[-] Driver failed to respond to PING.")
        return

    # Try to find a process
    print("Searching for Notepad.exe...")
    import subprocess
    # Get PID of notepad if running
    try:
        output = subprocess.check_output('tasklist /fi "imagename eq notepad.exe" /fo csv /nh', shell=True).decode()
        if "notepad.exe" in output.lower():
            pid = int(output.split(',')[1].strip('"'))
            print(f"[+] Found Notepad.exe with PID: {pid}")
            
            print(f"Resolving base address for notepad.exe...")
            base = await adapter.get_module_base(pid, "notepad.exe")
            if base:
                print(f"[+] Notepad Base: {hex(base)}")
                
                print(f"Reading first 16 bytes of Notepad base...")
                data = await adapter.read_memory(base, 16)
                if data:
                    print(f"[+] Data: {data}")
                    if data.startswith("4d 5a"):
                        print("[+] Verified 'MZ' header! Kernel read successful.")
                else:
                    print("[-] Failed to read memory.")
            else:
                print("[-] Failed to resolve module base.")
        else:
            print("[-] Notepad.exe not found. Start it to test full memory read.")
    except Exception as e:
        print(f"[-] Error finding notepad: {e}")

if __name__ == "__main__":
    asyncio.run(test_kernel())
