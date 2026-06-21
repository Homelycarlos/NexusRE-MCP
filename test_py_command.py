import sys, time
import pywinauto
import psutil
import subprocess
import os
import pyperclip

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
        
        test_file = r"C:\Users\cmb16\Desktop\python3_plugin_works.txt"
        
        if os.path.exists(test_file):
            os.remove(test_file)
            
        time.sleep(0.5)
        w.type_keys('{SPACE}')
        time.sleep(0.5)
        
        # In the old plugin, the command is `py` or `PythonScript`
        script_path = r"C:\Users\cmb16\Desktop\test_msg.py"
        cmd = f'py "{script_path}"'
        pyperclip.copy(cmd)
        
        w.type_keys('^v')
        time.sleep(0.5)
        w.type_keys('{ENTER}')
        time.sleep(1.5)
        
        if os.path.exists(test_file):
            print("SUCCESS!! Script executed using py command!")
        else:
            print("Failed to execute script with py.")
            
            # Try x64dbgpy
            cmd = f'x64dbgpy "{script_path}"'
            pyperclip.copy(cmd)
            w.type_keys('{SPACE}')
            time.sleep(0.5)
            w.type_keys('^v')
            time.sleep(0.5)
            w.type_keys('{ENTER}')
            time.sleep(1.5)
            
            if os.path.exists(test_file):
                print("SUCCESS!! Script executed using x64dbgpy command!")
            else:
                print("Failed to execute script.")
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
