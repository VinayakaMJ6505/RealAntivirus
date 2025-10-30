@echo off
title File Integrity Scanner - Advanced Launcher
color 0B

:MENU
cls
echo ========================================
echo    File Integrity Scanner
echo    Advanced Launcher
echo ========================================
echo.
echo [1] Run Antivirus Scanner
echo [2] Check Python Installation
echo [3] Install Required Dependencies
echo [4] View Log File
echo [5] Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto RUN
if "%choice%"=="2" goto CHECK_PYTHON
if "%choice%"=="3" goto INSTALL_DEPS
if "%choice%"=="4" goto VIEW_LOG
if "%choice%"=="5" goto EXIT

echo Invalid choice! Please try again.
timeout /t 2 >nul
goto MENU

:RUN
cls
echo ========================================
echo    Running Antivirus Scanner...
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo.
    pause
    goto MENU
)

REM Check if the script exists
if not exist "antivirus_scanner.py" (
    echo [ERROR] antivirus_scanner.py not found!
    echo.
    pause
    goto MENU
)

python antivirus_scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application encountered an error!
    echo.
    pause
)
goto MENU

:CHECK_PYTHON
cls
echo ========================================
echo    Checking Python Installation
echo ========================================
echo.

python --version
if errorlevel 1 (
    echo.
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python from: https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
) else (
    echo.
    echo [OK] Python is installed correctly!
    echo.
    python -c "import tkinter; print('[OK] tkinter is available')"
    if errorlevel 1 (
        echo.
        echo [WARNING] tkinter module is not available!
        echo This is required for the GUI to work.
    ) else (
        echo [OK] All dependencies are available!
    )
)

echo.
pause
goto MENU

:INSTALL_DEPS
cls
echo ========================================
echo    Installing Dependencies
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    pause
    goto MENU
)

echo Installing required packages...
python -m pip install --upgrade pip
echo.

echo Dependencies installed!
echo.
pause
goto MENU

:VIEW_LOG
cls
echo ========================================
echo    Viewing Log File
echo ========================================
echo.

if exist "scan_log.txt" (
    type scan_log.txt
) else (
    echo No log file found. Run a scan first.
)

echo.
pause
goto MENU

:EXIT
cls
echo ========================================
echo    Thank you for using
echo    File Integrity Scanner
echo ========================================
echo.
timeout /t 1 >nul
exit /b 0

