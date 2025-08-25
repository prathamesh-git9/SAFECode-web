@echo off
REM SAFECode-Web Server Launcher
REM This script launches both backend and frontend servers in separate PowerShell windows

echo Starting SAFECode-Web servers...

REM Get the current directory
set CURRENT_DIR=%CD%

REM Launch backend server in a new PowerShell window on port 8001
echo Starting backend server on port 8001...
start "SAFECode-Web Backend (Port 8001)" powershell -NoExit -Command "cd '%CURRENT_DIR%\backend'; .\venv\Scripts\Activate.ps1; $env:PORT = '8001'; python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Launch frontend server in a new PowerShell window on port 3000
echo Starting frontend server on port 3000...
start "SAFECode-Web Frontend (Port 3000)" powershell -NoExit -Command "cd '%CURRENT_DIR%\frontend\safecode-ui'; npm start"

echo.
echo Servers are starting in separate windows:
echo - Backend: http://localhost:8001
echo - Frontend: http://localhost:3000
echo.
echo Press any key to exit this launcher...
pause >nul
