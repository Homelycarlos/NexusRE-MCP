@echo off
:: Check for admin privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo ===================================================
echo    NexusRE MCP Backend Auto-Launcher
echo ===================================================
echo.
echo Please make sure x64dbg (or x32dbg) is open and running!
echo.

:: Loop until x64dbg is found
:wait_loop
tasklist /FI "IMAGENAME eq x64dbg.exe" 2>NUL | find /I /N "x64dbg.exe">NUL
if "%ERRORLEVEL%"=="0" goto :found
tasklist /FI "IMAGENAME eq x32dbg.exe" 2>NUL | find /I /N "x32dbg.exe">NUL
if "%ERRORLEVEL%"=="0" goto :found

echo Waiting for x64dbg.exe or x32dbg.exe to be running...
timeout /t 2 /nobreak > NUL
goto :wait_loop

:found
echo.
echo Found x64dbg running!
echo Handing over to the UI automation script to load the plugin...
python "%~dp0automate_x64dbg.py" "%~dp0plugins\x64dbg\x64dbg_backend_plugin.py"

echo.
echo Done! The backend script should now be loaded in x64dbg.
pause
