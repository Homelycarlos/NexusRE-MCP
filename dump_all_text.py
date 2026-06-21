import sys, time
import pywinauto
import psutil
import subprocess

def main():
    x64dbg_path = r"C:\Users\cmb16\Desktop\apps\x64dbg\release\x64\x64dbg.exe"
    
    for proc in psutil.process_iter(['name']):
        if 'x64dbg' in proc.info['name'].lower() or 'x32dbg' in proc.info['name'].lower():
            try:
                proc.kill()
            except:
                pass
    time.sleep(1)
    
    proc = subprocess.Popen([x64dbg_path])
    time.sleep(4)
    
    try:
        app = pywinauto.Application(backend='uia').connect(process=proc.pid, timeout=10)
        w = app.top_window()
        
        with open(r"C:\Users\cmb16\Desktop\x64dbg_all_text.txt", "w", encoding="utf-8") as f:
            for child in w.descendants():
                try:
                    text = child.window_text()
                    if text and len(text.strip()) > 0:
                        f.write(f"--- Control: {child.element_info.control_type} ---\n{text}\n\n")
                except:
                    pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
