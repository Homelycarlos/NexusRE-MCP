import time
import subprocess
import os
import psutil

x64dbg_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\x64dbg.exe"
log_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\x64dbg.log"

for proc in psutil.process_iter(['name']):
    if 'x64dbg' in proc.info['name'].lower() or 'x32dbg' in proc.info['name'].lower():
        try:
            proc.kill()
        except:
            pass
time.sleep(1)

if os.path.exists(log_path):
    os.remove(log_path)

print("Starting x64dbg...")
proc = subprocess.Popen([x64dbg_path])
time.sleep(5)
proc.kill()

if os.path.exists(log_path):
    print("Log created!")
else:
    print("Log not created.")
