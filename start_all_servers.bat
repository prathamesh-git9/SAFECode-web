@echo off
REM SAFECode-Web Complete System Launcher
REM This script starts both backend and web interface in separate PowerShell windows

echo ========================================
echo SAFECode-Web Complete System Launcher
echo ========================================
echo.

REM Get the current directory
set CURRENT_DIR=%CD%

REM Check if we're in the right directory
if not exist "backend\app\main.py" (
    echo Error: backend\app\main.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

if not exist "web_interface.py" (
    echo Error: web_interface.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

echo Creating/checking virtual environment...
if not exist "backend\venv\Scripts\Activate.ps1" (
    echo Creating virtual environment...
    cd backend
    python -m venv venv
    cd ..
)

echo.
echo Starting SAFECode-Web Backend (Port 8001)...
start "SAFECode-Web Backend (Port 8001)" powershell -NoExit -Command "cd '%CURRENT_DIR%\backend'; .\venv\Scripts\Activate.ps1; pip install -r requirements.txt; $env:SAFECODE_API_TOKEN = 'test-token'; $env:OPENAI_API_KEY = 'sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl'; $env:ANALYZER = 'flawfinder'; python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload"

echo Waiting 5 seconds for backend to start...
timeout /t 5 /nobreak >nul

echo.
echo Starting SAFECode-Web Interface (Port 5000)...
start "SAFECode-Web Interface (Port 5000)" powershell -NoExit -Command "cd '%CURRENT_DIR%'; .\backend\venv\Scripts\Activate.ps1; pip install flask requests; python web_interface.py"

echo.
echo ========================================
echo 🚀 SAFECode-Web System Started!
echo ========================================
echo.
echo Access Points:
echo 🌐 Web Interface: http://localhost:5000
echo 🔧 Backend API: http://localhost:8001
echo 📚 API Docs: http://localhost:8001/docs
echo 📊 Health Check: http://localhost:8001/health
echo 📈 Metrics: http://localhost:8001/metrics
echo.
echo Instructions:
echo 1. Open http://localhost:5000 in your browser
echo 2. Paste your C/C++ code and click "Scan for Vulnerabilities"
echo 3. View detailed vulnerability analysis with AI-powered insights
echo.
echo Press any key to exit this launcher...
pause >nul
