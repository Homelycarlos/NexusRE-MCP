@echo off
title NexusRE-MCP Installer
color 0b

:: Force execution in the exact same directory as the batch file
pushd "%~dp0"

echo ==================================================
echo         NEXUSRE-MCP ONE-CLICK INSTALLER
echo ==================================================
echo.

:: Detect Python executable (gracefully handles users who didn't click "Add to PATH")
set PYTHON_CMD=python
%PYTHON_CMD% --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    set PYTHON_CMD=py
    py --version >nul 2>&1
    IF ERRORLEVEL 1 (
        color 0c
        echo [ERROR] Python is not installed or not in your system PATH!
        echo Please install Python 3.10 or higher from python.org, select "Add to PATH", and try again.
        pause
        exit /b 1
    )
)

:: Check for uv package manager
%PYTHON_CMD% -m uv --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [~] 'uv' package manager not found. Installing via pip...
    %PYTHON_CMD% -m pip install uv
    IF ERRORLEVEL 1 (
        color 0c
        echo [ERROR] Failed to install 'uv' package manager via pip.
        pause
        exit /b 1
    )
)

echo [*] Synchronizing dependencies...
%PYTHON_CMD% -m uv sync

echo.
echo [*] Launching Setup Wizard...
%PYTHON_CMD% -m uv run main.py setup

echo.
pause
