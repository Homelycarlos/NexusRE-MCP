import os
import sys
import string
import ctypes
import shutil

def deep_scan_for_re_tools():
    """Scan all local drives for RE tools."""
    tools = {
        "IDA Pro": {"markers": ["ida.exe", "ida64.exe"], "paths": [], "plugin_dest": "plugins", "src": ["ida/ida_backend_plugin.py"]},
        "Ghidra": {"markers": ["ghidraRun.bat", "ghidraRun"], "paths": [], "plugin_dest": "Ghidra/Features/Python/ghidra_scripts", "src": ["ghidra/ghidra_backend_plugin.py", "ghidra/ghidra_backend_plugin.java"]},
        "x64dbg": {"markers": ["x64dbg.exe", "x32dbg.exe"], "paths": [], "plugin_dest": "plugins/x64dbgpy/x64dbgpy/autorun", "src": ["x64dbg/x64dbg_backend_plugin.py"]},
        "Binary Ninja": {"markers": ["binaryninja.exe", "BinaryNinja.exe"], "paths": [], "plugin_dest": "plugins", "src": ["binja/binja_backend_plugin.py"]},
        "Cheat Engine": {"markers": ["Cheat Engine.exe"], "paths": [], "plugin_dest": "autorun", "src": ["ce/ce_backend_plugin.lua"]},
        "dnSpy": {"markers": ["dnSpy.exe", "dnSpy-x86.exe"], "paths": [], "plugin_dest": ".", "src": ["exdnspy/bin/Release/net9.0/NexusRE.Exdnspy.dll"]}
    }
    
    # Pre-add standard APPDATA paths
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        ida_appdata = os.path.join(appdata, "Hex-Rays", "IDA Pro")
        if os.path.exists(ida_appdata):
            tools["IDA Pro"]["paths"].append(ida_appdata)
        binja_appdata = os.path.join(appdata, "Binary Ninja")
        if os.path.exists(binja_appdata):
            tools["Binary Ninja"]["paths"].append(binja_appdata)
            
    home = os.path.expanduser("~")
    ghidra_scripts = os.path.join(home, "ghidra_scripts")
    tools["Ghidra"]["paths"].append(ghidra_scripts) # Always try to put Ghidra plugins here
    
    drives = []
    if sys.platform == 'win32':
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
    else:
        drives = ["/"]
        
    skip_dirs = {"Windows", "System32", "WinSxS", "$Recycle.Bin", "System Volume Information", ".git", "node_modules", "ProgramData", "AppData", "Local", "LocalLow", "Roaming", ".venv", "venv", "env", "site-packages", "Cache"}
    
    import concurrent.futures
    import threading
    lock = threading.Lock()

    def scan_drive(drive):
        try:
            for root, dirs, files in os.walk(drive):
                # Limit directory depth to 5 to avoid scanning huge nested trees
                depth = root[len(drive):].count(os.sep)
                if depth > 5:
                    dirs[:] = []
                    continue
                    
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith('.')]
                lower_files = [f.lower() for f in files]
                
                if "ida.exe" in lower_files or "ida64.exe" in lower_files:
                    with lock:
                        if root not in tools["IDA Pro"]["paths"]:
                            tools["IDA Pro"]["paths"].append(root)
                            print(f"  [+] Found IDA Pro at: {root}")
                            
                if "ghidrarun.bat" in lower_files or "ghidrarun" in lower_files:
                    with lock:
                        if root not in tools["Ghidra"]["paths"]:
                            tools["Ghidra"]["paths"].append(root)
                            print(f"  [+] Found Ghidra at: {root}")
                            
                if "x64dbg.exe" in lower_files or "x32dbg.exe" in lower_files:
                    with lock:
                        if root not in tools["x64dbg"]["paths"]:
                            tools["x64dbg"]["paths"].append(root)
                            print(f"  [+] Found x64dbg at: {root}")
                            
                if "binaryninja.exe" in lower_files or "binaryninja.exe".lower() in lower_files:
                    with lock:
                        if root not in tools["Binary Ninja"]["paths"]:
                            tools["Binary Ninja"]["paths"].append(root)
                            print(f"  [+] Found Binary Ninja at: {root}")
                            
                if "cheat engine.exe" in lower_files or "cheatengine-x86_64.exe" in lower_files:
                    with lock:
                        if root not in tools["Cheat Engine"]["paths"]:
                            tools["Cheat Engine"]["paths"].append(root)
                            print(f"  [+] Found Cheat Engine at: {root}")
                            
                if "dnspy.exe" in lower_files or "dnspy-x86.exe" in lower_files:
                    with lock:
                        if root not in tools["dnSpy"]["paths"]:
                            tools["dnSpy"]["paths"].append(root)
                            print(f"  [+] Found dnSpy at: {root}")
        except Exception:
            pass
            
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(drives))) as executor:
        executor.map(scan_drive, drives)
            
    return tools

def do_install_plugins(tools_found, silent=False):
    import shutil
    import urllib.request
    import json
    import zipfile
    import tempfile
    
    # Calculate the root NexusRE-MCP-master directory
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    plugins_dir = os.path.join(script_dir, "plugins")
    installed = 0
    
    for tool_name, data in tools_found.items():
        if not data["src"]:
            continue
            
        if tool_name == "x64dbg" and data["paths"]:
            for path in data["paths"]:
                dp32_path = os.path.join(path, "x32", "plugins", "x64dbgpy.dp32")
                dp64_path = os.path.join(path, "x64", "plugins", "x64dbgpy.dp64")
                if not os.path.exists(dp32_path) and not os.path.exists(dp64_path):
                    if not silent:
                        print(f"  [*] x64dbgpy is missing in {path}. Downloading and installing...")
                    try:
                        req = urllib.request.Request("https://api.github.com/repos/x64dbg/x64dbgpy/releases/latest", headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(req) as response:
                            release_info = json.loads(response.read().decode())
                            zip_url = next(asset['browser_download_url'] for asset in release_info['assets'] if 'x64dbgpy' in asset['name'] and asset['name'].endswith('.zip'))
                            
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                            tmp_path = tmp.name
                            req_zip = urllib.request.Request(zip_url, headers={'User-Agent': 'Mozilla/5.0'})
                            with urllib.request.urlopen(req_zip) as response_zip:
                                shutil.copyfileobj(response_zip, tmp)
                        
                        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                            # x64dbg path from scanner includes 'x32' or 'x64', we need to extract to the release root
                            extract_path = os.path.dirname(path) if path.endswith("x32") or path.endswith("x64") else path
                            zip_ref.extractall(extract_path)
                        
                        os.unlink(tmp_path)
                        if not silent:
                            print(f"  [+] x64dbgpy installed successfully into {path}.")
                    except Exception as e:
                        if not silent:
                            print(f"  [-] Failed to install x64dbgpy automatically: {e}")
            
        for path in data["paths"]:
            dest_dir = os.path.join(path, os.path.normpath(data["plugin_dest"]))
            if not os.path.exists(dest_dir):
                try:
                    os.makedirs(dest_dir, exist_ok=True)
                except Exception:
                    continue
                    
            for src_rel in data["src"]:
                src_full = os.path.join(plugins_dir, os.path.normpath(src_rel))
                if os.path.exists(src_full):
                    dst_full = os.path.join(dest_dir, os.path.basename(src_rel))
                    try:
                        shutil.copy2(src_full, dst_full)
                        if not silent:
                            print(f"  [+] {tool_name}: Copied plugin to {dest_dir}")
                        installed += 1
                        
                        # Auto-restart tools and configure autorun
                        import psutil
                        import subprocess
                        
                        # IDA Pro Zero-Touch Setup
                        if tool_name == "IDA Pro":
                            # Create or update idapythonrc.py in the user's APPDATA so it auto-starts
                            appdata = os.environ.get("APPDATA", "")
                            if appdata:
                                rc_path = os.path.join(appdata, "Hex-Rays", "IDA Pro", "idapythonrc.py")
                                try:
                                    os.makedirs(os.path.dirname(rc_path), exist_ok=True)
                                    hook_code = "\nimport ida_backend_plugin\n"
                                    if not os.path.exists(rc_path) or hook_code not in open(rc_path).read():
                                        with open(rc_path, "a") as f:
                                            f.write(hook_code)
                                        if not silent:
                                            print(f"  [+] Injected auto-start hook into {rc_path}")
                                except Exception as e:
                                    pass

                            # Auto-restart IDA
                            for proc in psutil.process_iter(['name', 'exe', 'pid']):
                                if proc.info['name'] and proc.info['name'].lower() in ('ida.exe', 'ida64.exe'):
                                    exe_path = proc.info.get('exe')
                                    if exe_path and os.path.exists(exe_path):
                                        if not silent:
                                            print(f"  [*] Restarting {proc.info['name']} (PID: {proc.info['pid']}) to load bridge...")
                                        try:
                                            os.system(f"taskkill /F /PID {proc.info['pid']} >nul 2>&1")
                                            subprocess.Popen([exe_path])
                                            if not silent:
                                                print(f"  [+] {proc.info['name']} restarted successfully.")
                                        except Exception as e:
                                            if not silent:
                                                print(f"  [-] Failed to restart {proc.info['name']}: {e}")

                        # x64dbg Auto-restart and Zero-Touch Auto-Run
                        if tool_name == "x64dbg":
                            # Configure x64dbg.ini to auto-execute the plugin on initialization
                            try:
                                base_dir = os.path.dirname(dest_dir) # plugins
                                release_dir = os.path.dirname(base_dir) # x32 or x64
                                ini_name = "x64dbg.ini" if "x64" in release_dir.lower() else "x32dbg.ini"
                                ini_path = os.path.join(release_dir, ini_name)
                                
                                scripts_dir = os.path.join(release_dir, "scripts")
                                os.makedirs(scripts_dir, exist_ok=True)
                                
                                mac_path = os.path.join(scripts_dir, "init.mac")
                                with open(mac_path, "w") as f:
                                    f.write('Python "import x64dbg_backend_plugin"\n')
                                
                                if os.path.exists(ini_path):
                                    import configparser
                                    config = configparser.ConfigParser()
                                    config.optionxform = str
                                    config.read(ini_path)
                                    if 'Events' not in config:
                                        config['Events'] = {}
                                    config['Events']['InitScript'] = r'scripts\init.mac'
                                    with open(ini_path, 'w') as f:
                                        config.write(f, space_around_delimiters=False)
                                    if not silent:
                                        print(f"  [+] Injected zero-touch Python hook into {ini_name}")
                            except Exception as e:
                                if not silent:
                                    print(f"  [-] Failed to configure x64dbg.ini autorun: {e}")

                            for proc in psutil.process_iter(['name', 'exe', 'pid']):
                                if proc.info['name'] and proc.info['name'].lower() in ('x64dbg.exe', 'x32dbg.exe'):
                                    exe_path = proc.info.get('exe')
                                    if exe_path and os.path.exists(exe_path):
                                        if not silent:
                                            print(f"  [*] Restarting {proc.info['name']} (PID: {proc.info['pid']}) to load bridge...")
                                        try:
                                            os.system(f"taskkill /F /PID {proc.info['pid']} >nul 2>&1")
                                            subprocess.Popen([exe_path])
                                            if not silent:
                                                print(f"  [+] {proc.info['name']} restarted successfully.")
                                        except Exception as e:
                                            if not silent:
                                                print(f"  [-] Failed to restart {proc.info['name']}: {e}")
                                                
                    except Exception as e:
                        if not silent:
                            print(f"  [!] Failed to copy {src_full} to {dest_dir}: {e}")
                            
    return installed
