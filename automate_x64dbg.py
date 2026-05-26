import sys, time
import pywinauto
import psutil

def main():
    if len(sys.argv) < 2:
        print("Usage: python automate_x64dbg.py <path_to_script>")
        sys.exit(1)
        
    script_path = sys.argv[1]
    
    print("Looking for x64dbg process...")
    x64dbg_pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if 'x64dbg' in proc.info['name'].lower() or 'x32dbg' in proc.info['name'].lower():
            x64dbg_pid = proc.info['pid']
            break
            
    if not x64dbg_pid:
        print("x64dbg process not found! Make sure x64dbg is running.")
        sys.exit(1)
        
    print(f"Found x64dbg PID: {x64dbg_pid}")
    
    # Connect to x64dbg
    print("Connecting to UI...")
    app = pywinauto.Application(backend='uia').connect(process=x64dbg_pid, timeout=10)
    w = app.top_window()
    w.set_focus()
    
    # Click Plugins
    print("Finding Plugins menu...")
    plugins = w.child_window(title='Plugins', control_type='MenuItem')
    plugins.click_input()
    time.sleep(0.5)
    
    # Try to find the Python plugin menu (could be x64dbgpy, x64dbg_python, or x64dbgpython)
    print("Finding Python plugin...")
    python_menu = None
    for child in plugins.children():
        text = child.window_text().lower()
        if 'python' in text or 'x64dbgpy' in text:
            python_menu = child
            break
            
    if not python_menu:
        print("Python plugin not found in the Plugins menu! Please install the Python plugin.")
        sys.exit(1)
        
    python_menu.click_input()
    time.sleep(0.5)
    
    # Click "Run Script" or similar
    print("Finding 'Run Script' option...")
    run_script = None
    for child in python_menu.children():
        if 'run' in child.window_text().lower() and 'script' in child.window_text().lower():
            run_script = child
            break
            
    if not run_script:
        print("'Run Script' option not found in the Python plugin menu!")
        sys.exit(1)
        
    run_script.click_input()
    time.sleep(1)
    
    # Now handle the Open File dialog
    print("Waiting for Open File dialog...")
    # Find the dialog that popped up
    dialog = app.window(title_re='.*Open.*')
    dialog.wait('ready', timeout=5)
    
    print(f"Entering script path: {script_path}")
    # Type the path into the filename edit box using type_keys
    # Escape spaces if any
    keys = script_path.replace(' ', '{SPACE}')
    dialog.type_keys(keys + "{ENTER}", with_spaces=True, set_foreground=False)
    
    print("Script successfully dispatched to x64dbg!")

if __name__ == "__main__":
    main()
