import sys, time
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
    time.sleep(4)
    
    try:
        app = pywinauto.Application(backend='uia').connect(process=proc.pid, timeout=10)
        w = app.top_window()
        w.set_focus()
        
        script_path = r"C:\Users\cmb16\Desktop\test_msg.py"
        test_file = r"C:\Users\cmb16\Desktop\python3_plugin_works.txt"
        
        if os.path.exists(test_file):
            os.remove(test_file)
        
        commands = [
            f'python "{script_path}"',
            f'py "{script_path}"',
            f'python3 "{script_path}"',
            f'x64dbgpython "{script_path}"'
        ]
        
        for cmd in commands:
            print(f"Trying command: {cmd}")
            w.type_keys('{SPACE}')
            time.sleep(0.5)
            w.type_keys(cmd, with_spaces=True)
            time.sleep(0.5)
            w.type_keys('{ENTER}')
            time.sleep(1.5)
            
            if os.path.exists(test_file):
                print(f"SUCCESS with command: {cmd}")
                break
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
