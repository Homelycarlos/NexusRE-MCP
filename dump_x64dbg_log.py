import sys, time
import pywinauto
import psutil
import subprocess
import io

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
    time.sleep(3) # Wait for it to open
    
    try:
        app = pywinauto.Application(backend='uia').connect(process=proc.pid, timeout=10)
        w = app.top_window()
        
        print("Connected to window, dumping text...")
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            w.print_control_identifiers()
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
        with open(r"C:\Users\cmb16\Desktop\x64dbg_controls.txt", "w", encoding="utf-8") as f:
            f.write(output)
            
        print("Controls dumped to C:\\Users\\cmb16\\Desktop\\x64dbg_controls.txt")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
