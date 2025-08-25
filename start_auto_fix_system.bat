@echo off
echo ========================================
echo SAFECode-Web Auto-Fix System Launcher
echo ========================================
echo.

echo Starting backend with GPT Auto-Fix...
start "SAFECode-Web Backend (Auto-Fix)" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Waiting for backend to start...
timeout /t 3 /nobreak >nul

echo Starting web interface with Auto-Fix...
start "SAFECode-Web Interface (Auto-Fix)" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo 🚀 Auto-Fix System Started!
echo ========================================
echo.
echo 📡 Backend: http://localhost:8002
echo 🌍 Web Interface: http://localhost:5000
echo 🤖 GPT Auto-Fix: Available
echo.
echo 🎯 Open your browser and go to: http://localhost:5000
echo 📝 Paste C code, scan for vulnerabilities, then click "Auto-Fix with GPT"
echo.
echo Press any key to exit...
pause >nul
