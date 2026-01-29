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
REM Prefer pythonw (no console) if available, otherwise fall back to python.
where pythonw.exe >nul 2>&1 && (
    start "" pythonw "%~dp0analyzer.py"
) || (
    start "" python "%~dp0analyzer.py"
)

REM Exit the batch immediately so the launching window closes.
exit /b 0
