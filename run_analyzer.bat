@echo off
title FiveM Crash Analyzer
echo.
echo ====================================
echo   FiveM Crash Analyzer
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH!
    echo.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)

REM Change to the script directory so imports and paths work correctly
cd /d "%~dp0"

REM Check for PySide6 (required for the GUI)
python -c "import PySide6" >nul 2>&1
if errorlevel 1 (
    echo.
    echo PySide6 is not installed. Installing dependencies...
    echo.
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo Installation failed. Try running manually:
        echo   python -m pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
    echo.
)

echo Starting analyzer...
echo.

REM Configuration: copy .env.example to .env and set FIVEM_SYMBOL_CACHE for local PDB symbolication.

REM Run in THIS window (no "start") so any error stays visible
python "%~dp0analyzer.py"

REM If Python exited (e.g. crash on startup), keep window open so you can read the error
if errorlevel 1 (
    echo.
    echo The application exited with an error. See the message above.
    echo.
    pause
)
exit /b 0
