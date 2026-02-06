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

echo Starting analyzer...
echo.

REM Run the analyzer - use pythonw to hide console window
REM Falls back to python if pythonw is not available
pythonw "%~dp0crash_analyzer\analyzer.py" 2>nul
if errorlevel 1 (
    REM pythonw failed, try regular python (will show console briefly)
    python "%~dp0crash_analyzer\analyzer.py"
)

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start the analyzer.
    echo.
    echo Make sure you have installed all dependencies:
    echo   pip install -r requirements.txt
    echo.
    pause
)
