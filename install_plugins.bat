@echo off
setlocal EnableDelayedExpansion

echo.
echo  ========================================
echo   NexusRE-MCP Plugin Auto-Installer
echo  ========================================
echo.

set "SCRIPT_DIR=%~dp0"
set INSTALLED=0

REM ── IDA Pro ──────────────────────────────────────────────────────────────

echo [*] Searching for IDA Pro...

set "IDA_PLUGIN=%SCRIPT_DIR%plugins\ida\ida_backend_plugin.py"

REM Check common IDA install locations
set "IDA_FOUND="
for %%D in (
    "%APPDATA%\Hex-Rays\IDA Pro\plugins"
    "%PROGRAMFILES%\IDA Pro 8.3\plugins"
    "%PROGRAMFILES%\IDA Pro 8.4\plugins"
    "%PROGRAMFILES%\IDA Pro 9.0\plugins"
    "%PROGRAMFILES(x86)%\IDA Pro 8.3\plugins"
    "C:\IDA\plugins"
    "C:\IDA Pro\plugins"
    "C:\IDA Pro 8.3\plugins"
    "C:\IDA Pro 9.0\plugins"
    "D:\IDA\plugins"
    "D:\IDA Pro\plugins"
) do (
    if exist %%D (
        set "IDA_FOUND=%%~D"
        goto :ida_found
    )
)

REM Try registry lookup
for /f "tokens=2*" %%A in ('reg query "HKCU\Software\Hex-Rays\IDA" /v "InstallDir" 2^>nul') do (
    if exist "%%B\plugins" (
        set "IDA_FOUND=%%B\plugins"
        goto :ida_found
    )
)

echo     [!] IDA Pro not found. Skipping.
goto :ida_done

:ida_found
echo     [+] Found IDA Pro at: !IDA_FOUND!
copy /Y "%IDA_PLUGIN%" "!IDA_FOUND!\ida_backend_plugin.py" >nul 2>&1
if !errorlevel! EQU 0 (
    echo     [OK] Copied ida_backend_plugin.py
    set /a INSTALLED+=1
) else (
    echo     [!] Failed to copy. Try running as Administrator.
)

:ida_done

REM ── Ghidra ───────────────────────────────────────────────────────────────

echo.
echo [*] Searching for Ghidra...

set "GHIDRA_PLUGIN=%SCRIPT_DIR%plugins\ghidra\ghidra_backend_plugin.py"
set "GHIDRA_FOUND="

REM Check GHIDRA_INSTALL_DIR env var
if defined GHIDRA_INSTALL_DIR (
    if exist "%GHIDRA_INSTALL_DIR%\Ghidra\Features\Python\ghidra_scripts" (
        set "GHIDRA_FOUND=%GHIDRA_INSTALL_DIR%\Ghidra\Features\Python\ghidra_scripts"
        goto :ghidra_found
    )
)

REM Check user's home Ghidra scripts dir
if exist "%USERPROFILE%\ghidra_scripts" (
    set "GHIDRA_FOUND=%USERPROFILE%\ghidra_scripts"
    goto :ghidra_found
)

REM Check common locations
for %%D in (
    "C:\ghidra\Ghidra\Features\Python\ghidra_scripts"
    "C:\ghidra_11.0\Ghidra\Features\Python\ghidra_scripts"
    "C:\ghidra_11.1\Ghidra\Features\Python\ghidra_scripts"
    "C:\ghidra_11.2\Ghidra\Features\Python\ghidra_scripts"
    "C:\ghidra_11.3\Ghidra\Features\Python\ghidra_scripts"
    "D:\ghidra\Ghidra\Features\Python\ghidra_scripts"
    "%PROGRAMFILES%\Ghidra\ghidra_scripts"
) do (
    if exist %%D (
        set "GHIDRA_FOUND=%%~D"
        goto :ghidra_found
    )
)

REM Fallback: create user scripts dir
echo     [!] Ghidra not found in standard paths.
echo     [+] Creating user scripts directory at %USERPROFILE%\ghidra_scripts
mkdir "%USERPROFILE%\ghidra_scripts" 2>nul
set "GHIDRA_FOUND=%USERPROFILE%\ghidra_scripts"

:ghidra_found
echo     [+] Ghidra scripts at: !GHIDRA_FOUND!
copy /Y "%GHIDRA_PLUGIN%" "!GHIDRA_FOUND!\ghidra_backend_plugin.py" >nul 2>&1
if !errorlevel! EQU 0 (
    echo     [OK] Copied ghidra_backend_plugin.py
    echo     [i] Open Ghidra Script Manager and add this directory to your script paths.
    set /a INSTALLED+=1
) else (
    echo     [!] Failed to copy.
)

REM ── x64dbg ──────────────────────────────────────────────────────────────

echo.
echo [*] Searching for x64dbg...

set "X64DBG_PLUGIN=%SCRIPT_DIR%plugins\x64dbg\x64dbg_backend_plugin.py"
set "X64DBG_FOUND="

for %%D in (
    "C:\x64dbg\release\x64\plugins"
    "C:\x64dbg\x64\plugins"
    "D:\x64dbg\release\x64\plugins"
    "C:\Program Files\x64dbg\release\x64\plugins"
    "%USERPROFILE%\Desktop\x64dbg\release\x64\plugins"
    "%USERPROFILE%\Downloads\x64dbg\release\x64\plugins"
) do (
    if exist %%D (
        set "X64DBG_FOUND=%%~D"
        goto :x64dbg_found
    )
)

REM Try 32-bit variant
for %%D in (
    "C:\x64dbg\release\x32\plugins"
    "C:\x64dbg\x32\plugins"
) do (
    if exist %%D (
        set "X64DBG_FOUND=%%~D"
        goto :x64dbg_found
    )
)

echo     [!] x64dbg not found. Skipping.
goto :x64dbg_done

:x64dbg_found
echo     [+] Found x64dbg at: !X64DBG_FOUND!
copy /Y "%X64DBG_PLUGIN%" "!X64DBG_FOUND!\x64dbg_backend_plugin.py" >nul 2>&1
if !errorlevel! EQU 0 (
    echo     [OK] Copied x64dbg_backend_plugin.py
    echo     [i] Make sure x64dbgpy is installed for Python support.
    set /a INSTALLED+=1
) else (
    echo     [!] Failed to copy. Try running as Administrator.
)

:x64dbg_done

REM ── Binary Ninja ────────────────────────────────────────────────────────

echo.
echo [*] Searching for Binary Ninja...

set "BINJA_PLUGIN=%SCRIPT_DIR%plugins\binja\binja_backend_plugin.py"
set "BINJA_FOUND="

REM Binary Ninja stores plugins in AppData
if exist "%APPDATA%\Binary Ninja\plugins" (
    set "BINJA_FOUND=%APPDATA%\Binary Ninja\plugins"
    goto :binja_found
)

for %%D in (
    "C:\Program Files\Vector35\BinaryNinja\plugins"
    "%PROGRAMFILES%\Vector35\BinaryNinja\plugins"
) do (
    if exist %%D (
        set "BINJA_FOUND=%%~D"
        goto :binja_found
    )
)

echo     [!] Binary Ninja not found. Skipping.
goto :binja_done

:binja_found
echo     [+] Found Binary Ninja at: !BINJA_FOUND!
copy /Y "%BINJA_PLUGIN%" "!BINJA_FOUND!\binja_backend_plugin.py" >nul 2>&1
if !errorlevel! EQU 0 (
    echo     [OK] Copied binja_backend_plugin.py
    set /a INSTALLED+=1
) else (
    echo     [!] Failed to copy.
)

:binja_done

REM ── Cheat Engine ────────────────────────────────────────────────────────

echo.
echo [*] Searching for Cheat Engine...

set "CE_PLUGIN=%SCRIPT_DIR%plugins\ce\ce_backend_plugin.lua"
set "CE_FOUND="

for %%D in (
    "C:\Program Files\Cheat Engine 7.5\autorun"
    "C:\Program Files\Cheat Engine 7.4\autorun"
    "%PROGRAMFILES%\Cheat Engine 7.5\autorun"
    "%PROGRAMFILES(x86)%\Cheat Engine 7.5\autorun"
    "C:\Cheat Engine\autorun"
) do (
    if exist %%D (
        set "CE_FOUND=%%~D"
        goto :ce_found
    )
)

echo     [!] Cheat Engine not found. Skipping.
goto :ce_done

:ce_found
echo     [+] Found Cheat Engine at: !CE_FOUND!
copy /Y "%CE_PLUGIN%" "!CE_FOUND!\ce_backend_plugin.lua" >nul 2>&1
if !errorlevel! EQU 0 (
    echo     [OK] Copied ce_backend_plugin.lua to autorun
    set /a INSTALLED+=1
) else (
    echo     [!] Failed to copy. Try running as Administrator.
)

REM ── Create File-IPC directory for zero-dependency fallback ──
set "CE_ROOT=!CE_FOUND:\autorun=!"
set "IPC_DIR=!CE_ROOT!\nexusre_ipc"
if not exist "!IPC_DIR!" (
    mkdir "!IPC_DIR!" 2>nul
    echo     [OK] Created file-IPC directory: !IPC_DIR!
)

REM ── Check for luasocket and attempt auto-install ──
echo     [*] Checking for luasocket (socket/core.dll)...
set "CLIBS_DIR=!CE_ROOT!\clibs64"
set "SOCKET_DLL=!CLIBS_DIR!\socket\core.dll"

if exist "!SOCKET_DLL!" (
    echo     [OK] luasocket already installed at !CLIBS_DIR!
) else (
    REM Check alternative locations
    if exist "!CE_ROOT!\socket\core.dll" (
        echo     [OK] luasocket found at !CE_ROOT!\socket\
    ) else (
        echo     [^!] luasocket NOT found. The plugin will use file-based IPC instead.
        echo     [i] For best performance, install luasocket manually:
        echo         1. Download socket/core.dll for Lua 5.3 ^(64-bit^)
        echo         2. Place it in: !CLIBS_DIR!\socket\core.dll
        echo         3. Restart Cheat Engine
        echo     [i] The plugin still works without luasocket using file IPC.
    )
)

:ce_done

REM ── Summary ─────────────────────────────────────────────────────────────

echo.
echo  ========================================
if !INSTALLED! GTR 0 (
    echo   Successfully installed !INSTALLED! plugin^(s^)^!
    echo   Restart your RE tools for changes to take effect.
) else (
    echo   No plugins were installed.
    echo   Make sure your RE tools are installed in standard paths,
    echo   or manually copy plugins from the plugins/ directory.
)
echo  ========================================
echo.

pause
endlocal
