@echo off
REM FiveM Crash Analyzer - Build Script
REM Compiles the application into a standalone .exe

title FiveM Crash Analyzer - Build to EXE
echo.
echo ========================================
echo   Building FiveM Crash Analyzer .exe
echo ========================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install PyInstaller
        echo Please run: pip install pyinstaller
        pause
        exit /b 1
    )
)

echo Cleaning previous build...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist

echo.
echo Building executable...
echo This may take a few minutes...
echo.

python -m PyInstaller crash_analyzer.spec --clean

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo Check the output above for errors.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo Your executable is located at:
echo   dist\FiveM Crash Analyzer.exe
echo.
echo You can now:
echo   1. Run the .exe directly (no console window)
echo   2. Create a desktop shortcut to the .exe
echo   3. Distribute the .exe to others (single-file)
echo.
pause
