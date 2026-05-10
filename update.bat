@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo       NexusRE-MCP Auto-Updater
echo ==========================================
echo.

cd /d "%~dp0"

:: Check if git is installed and if this is a git repository
where git >nul 2>&1
if %errorlevel% equ 0 (
    if exist ".git" (
        echo [i] Git repository detected. Updating via git pull...
        git pull
        if !errorlevel! neq 0 (
            echo [!] Git pull failed. Please check your connection or resolve conflicts.
            pause
            exit /b !errorlevel!
        )
        goto SYNC
    )
)

:: Fallback to ZIP download
echo [i] Standard installation detected. Downloading latest master branch...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/Homelycarlos/NexusRE-MCP/archive/refs/heads/master.zip' -OutFile 'update.zip'"
if %errorlevel% neq 0 (
    echo [!] Failed to download update. Please check your internet connection.
    pause
    exit /b %errorlevel%
)

echo [i] Extracting update...
if exist "update_temp" rmdir /s /q "update_temp"
powershell -Command "Expand-Archive -Path 'update.zip' -DestinationPath 'update_temp' -Force"

echo [i] Applying update...
:: Copy all files from the extracted folder over the current directory, overwriting silently
xcopy /s /y /q "update_temp\NexusRE-MCP-master\*" ".\"

echo [i] Cleaning up...
rmdir /s /q "update_temp"
del /f /q "update.zip"

:SYNC
echo.
echo [i] Syncing Python dependencies...
if exist ".venv\Scripts\uv.exe" (
    .venv\Scripts\uv.exe sync
) else (
    where uv >nul 2>&1
    if !errorlevel! equ 0 (
        uv sync
    ) else (
        echo [i] 'uv' package manager not found. Installing it now...
        python -m pip install uv
        if !errorlevel! equ 0 (
            python -m uv sync
        ) else (
            echo [!] Failed to install uv. Please run 'pip install uv' manually.
        )
    )
)

echo.
echo [✓] Update complete! You can now restart your MCP client.
pause
