@echo off
REM SAFECode-Web Interface Launcher (with Virtual Environment)
REM This script launches the web interface in a new PowerShell window

echo Starting SAFECode-Web Interface (with venv)...

REM Get the current directory
set CURRENT_DIR=%CD%

REM Check if we're in the right directory
if not exist "web_interface.py" (
    echo Error: web_interface.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

REM Check if virtual environment exists
if not exist "backend\venv\Scripts\Activate.ps1" (
    echo Creating virtual environment...
    cd backend
    python -m venv venv
    cd ..
)

REM Launch web interface in a new PowerShell window
echo Starting web interface on port 5000...
start "SAFECode-Web Interface (Port 5000)" powershell -NoExit -Command "cd '%CURRENT_DIR%'; .\backend\venv\Scripts\Activate.ps1; pip install flask requests; python web_interface.py"

echo.
echo Web interface is starting in a new PowerShell window...
echo.
echo Access points:
echo - Web Interface: http://localhost:5000
echo - Backend API: http://localhost:8001
echo - API Docs: http://localhost:8001/docs
echo.
echo Press any key to exit this launcher...
pause >nul
