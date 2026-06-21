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
            
        print("Finding Python3 control...")
        python3_found = False
        
        for cb in w.descendants(control_type="ComboBox"):
            cb.click_input()
            time.sleep(0.5)
            for item in app.top_window().descendants():
                try:
                    if item.window_text() == "Python3":
                        print("Clicking Python3!")
                        item.click_input()
                        python3_found = True
                        break
                except:
                    pass
            if python3_found:
                break
                
        if python3_found:
            time.sleep(0.5)
            w.type_keys('{SPACE}')
            time.sleep(0.5)
            
            # Use clipboard to avoid typing translation issues
            code = "import os; open(r'C:\\Users\\cmb16\\Desktop\\python3_plugin_works.txt', 'w').write('SUCCESS')"
            pyperclip.copy(code)
            
            w.type_keys('^v')
            time.sleep(0.5)
            w.type_keys('{ENTER}')
            time.sleep(1.5)
            
            if os.path.exists(test_file):
                print("SUCCESS!! Script executed using Python3 engine!")
            else:
                print("Failed to execute script. File not created.")
        else:
            print("Could not find Python3 anywhere.")
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.kill()

if __name__ == "__main__":
    main()
