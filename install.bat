@echo off
title NexusRE-MCP Installer
color 0b

:: Auto-Elevate to Administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:: Force execution in the exact same directory as the batch file
pushd "%~dp0"

echo ==================================================
echo         NEXUSRE-MCP ONE-CLICK INSTALLER
echo ==================================================
echo.

echo [*] Checking for Python 3.10+...
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if %ERRORLEVEL% EQU 0 goto python_installed

echo [-] Python not found.
echo [*] Downloading Python 3.12 Installer...
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe' -OutFile '%TEMP%\python_installer.exe'"

echo [*] Installing Python 3.12 silently...
"%TEMP%\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1

echo [*] Refreshing environment variables...
for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path') do set "SYS_PATH=%%B"
set "PATH=%SYS_PATH%;%PATH%"

:python_installed
echo [+] Python is ready.

echo.
echo [*] Installing requirements...
python -m pip install --upgrade pip >nul 2>&1
if exist requirements.txt (
    python -m pip install -r requirements.txt
)

echo.
echo [*] Launching Setup Wizard...
python main.py setup

echo.
pause
