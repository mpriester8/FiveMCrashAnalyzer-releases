@echo off
REM Drag and drop a FiveM crash dump file onto this batch file to analyze it
REM Or run from command line: analyze_crash.bat "path\to\dump.dmp"

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo.
    echo ========================================
    echo FiveM Crash Dump Analyzer
    echo ========================================
    echo.
    echo Usage: Drag a .dmp file onto this script
    echo    OR: analyze_crash.bat "path\to\dump.dmp"
    echo.
    pause
    exit /b 1
)

set DUMP_FILE=%~1

if not exist "%DUMP_FILE%" (
    echo Error: File not found: %DUMP_FILE%
    pause
    exit /b 1
)

echo.
echo Analyzing: %~nx1
echo.

REM Run the analyzer
python "%~dp0scripts\analyze_dump.py" "%DUMP_FILE%"

echo.
echo ========================================
echo Analysis complete!
echo ========================================
echo.
pause
