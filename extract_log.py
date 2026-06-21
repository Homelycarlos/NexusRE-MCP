import time
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
        
        # Click Log tab
        log_tab = w.child_window(title='Log', control_type='TabItem')
        log_tab.click_input()
        time.sleep(1)
        
        # The log view might be a list or edit. We can just send Ctrl+A and Ctrl+C 
        # to the main window while the Log tab is active. The Log view usually receives focus.
        w.type_keys('{TAB}')
        time.sleep(0.5)
        w.type_keys('^a')
        time.sleep(0.5)
        w.type_keys('^c')
        time.sleep(1)
        
        log_text = pyperclip.paste()
        with open(r"C:\Users\cmb16\Desktop\x64dbg_ui_log.txt", "w", encoding='utf-8') as f:
            f.write(log_text)
            
        print("Log saved to desktop!")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
