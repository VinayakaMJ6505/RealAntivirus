@echo off
title File Integrity Scanner
color 0A

echo ========================================
echo    File Integrity Scanner
echo    Starting Application...
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo Python detected!
echo.

REM Check if the script exists
if not exist "antivirus_scanner.py" (
    echo [ERROR] antivirus_scanner.py not found!
    echo.
    echo Please make sure antivirus_scanner.py is in the same directory as this batch file.
    echo.
    pause
    exit /b 1
)

echo Starting antivirus scanner...
echo.
echo ========================================
echo.

REM Run the Python script
python antivirus_scanner.py

REM If there was an error, pause so user can see it
if errorlevel 1 (
    echo.
    echo [ERROR] The application encountered an error!
    echo.
    pause
    exit /b 1
)

echo.
echo Application closed.
timeout /t 2 >nul
exit /b 0

