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

REM Run the analyzer
python "%~dp0analyzer.py"

if errorlevel 1 (
    echo.
    echo Something went wrong. Press any key to close.
    pause >nul
)
