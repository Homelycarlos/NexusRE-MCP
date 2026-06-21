import sys, time
import pywinauto
import psutil
import subprocess

def main():
    x64dbg_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\x64dbg.exe"
    
    # Kill any existing instances
    for proc in psutil.process_iter(['name']):
        if 'x64dbg' in proc.info['name'].lower() or 'x32dbg' in proc.info['name'].lower():
            try:
                proc.kill()
            except:
                pass
    time.sleep(1)
    
    print("Starting x64dbg...")
    proc = subprocess.Popen([x64dbg_path])
    time.sleep(4) # Wait for it to open
    
    try:
        app = pywinauto.Application(backend='uia').connect(process=proc.pid, timeout=10)
        w = app.top_window()
        w.set_focus()
        
        plugins = w.child_window(title='Plugins', control_type='MenuItem')
        plugins.click_input()
        time.sleep(1)
        
        with open(r"C:\Users\cmb16\Desktop\x64dbg_plugins_list.txt", "w", encoding="utf-8") as f:
            f.write("Plugins menu items:\n")
            for child in plugins.children():
                f.write(f"- {child.window_text()}\n")
                if 'python' in child.window_text().lower() or 'x64dbgpy' in child.window_text().lower():
                    child.click_input()
                    time.sleep(0.5)
                    f.write(f"  Children of {child.window_text()}:\n")
                    for subchild in child.children():
                        f.write(f"  - {subchild.window_text()}\n")
                    
        print("Done dumping plugins list!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
