@echo off
echo ========================================
echo Starting SAFECode-Web Auto-Fix System
echo ========================================
echo.

echo Stopping any existing processes...
taskkill /f /im python.exe 2>nul
timeout /t 3 /nobreak >nul

echo Starting backend with GPT Auto-Fix...
start "Backend" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Waiting for backend to start...
timeout /t 5 /nobreak >nul

echo Starting web interface with Auto-Fix...
start "Web Interface" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo 🚀 Auto-Fix System Started!
echo ========================================
echo.
echo 📡 Backend: http://localhost:8002
echo 🌍 Web Interface: http://localhost:5000
echo.
echo 🎯 Open your browser and go to: http://localhost:5000
echo 📝 Paste vulnerable code, scan, then click "🤖 Auto-Fix with GPT"
echo.
echo Press any key to exit...
pause >nul
