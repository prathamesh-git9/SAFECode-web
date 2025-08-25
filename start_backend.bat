@echo off
REM SAFECode-Web Backend Launcher
REM This script launches the backend server in a new PowerShell window

echo Starting SAFECode-Web Backend (Version 2.0)...

REM Get the current directory
set CURRENT_DIR=%CD%

REM Check if we're in the right directory
if not exist "backend\app\main.py" (
    echo Error: backend\app\main.py not found!
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

REM Launch backend server in a new PowerShell window
echo Starting backend server on port 8001...
start "SAFECode-Web Backend (Port 8001)" powershell -NoExit -Command "cd '%CURRENT_DIR%\backend'; .\venv\Scripts\Activate.ps1; pip install -r requirements.txt; $env:SAFECODE_API_TOKEN = 'test-token'; $env:OPENAI_API_KEY = 'sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl'; python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload"

echo.
echo Backend server is starting in a new PowerShell window...
echo.
echo Access points:
echo - Backend API: http://localhost:8001
echo - Health Check: http://localhost:8001/health
echo - API Docs: http://localhost:8001/docs
echo - Metrics: http://localhost:8001/metrics
echo.
echo Press any key to exit this launcher...
pause >nul
