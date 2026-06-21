import time
import pywinauto
import psutil
import subprocess
import os

def main():
    x64dbg_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\x64dbg.exe"
    
    for proc in psutil.process_iter(['name']):
        if 'x64dbg' in proc.info['name'].lower() or 'x32dbg' in proc.info['name'].lower():
            try:
                proc.kill()
            except:
                pass
    time.sleep(1)
    
    print("Starting x64dbg...")
    proc = subprocess.Popen([x64dbg_path])
    time.sleep(5) # Wait for plugins to load
    
    try:
        app = pywinauto.Application(backend='uia').connect(process=proc.pid, timeout=10)
        w = app.top_window()
        
        with open(r"C:\Users\cmb16\Desktop\x64dbg_dump.txt", "w", encoding='utf-8') as f:
            for elem in w.descendants():
                try:
                    text = elem.window_text()
                    ctrl_type = elem.element_info.control_type
                    if text:
                        f.write(f"[{ctrl_type}] {text}\n")
                except:
                    pass
        print("Dumped UI text to desktop!")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
