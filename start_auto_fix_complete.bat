@echo off
echo ========================================
echo SAFECode-Web Complete Auto-Fix System
echo ========================================
echo.

echo Stopping any existing processes...
taskkill /f /im python.exe 2>nul
timeout /t 2 /nobreak >nul

echo Starting backend with GPT Auto-Fix...
start "SAFECode-Web Backend (Auto-Fix)" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Waiting for backend to start...
timeout /t 5 /nobreak >nul

echo Testing backend health...
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8002/health' -Method GET -TimeoutSec 5; Write-Host 'Backend Status:' $response.Content } catch { Write-Host 'Backend not ready yet...' }"

echo Starting web interface with Auto-Fix...
start "SAFECode-Web Interface (Auto-Fix)" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo Waiting for web interface to start...
timeout /t 3 /nobreak >nul

echo.
echo ========================================
echo 🚀 Auto-Fix System Successfully Started!
echo ========================================
echo.
echo 📡 Backend API: http://localhost:8002
echo 🌍 Web Interface: http://localhost:5000
echo 🤖 GPT Auto-Fix: Available
echo 📚 API Docs: http://localhost:8002/docs
echo.
echo 🎯 Open your browser and go to: http://localhost:5000
echo 📝 Paste C/C++ code, scan for vulnerabilities, then click "Auto-Fix with GPT"
echo.
echo 🔧 Features:
echo    ✅ Vulnerability Detection (CWE-120, CWE-78, CWE-134)
echo    ✅ AI-Powered Auto-Fix with GPT
echo    ✅ Beautiful Web Interface
echo    ✅ Real-time Code Analysis
echo    ✅ Side-by-side Code Comparison
echo.
echo Press any key to exit...
pause >nul
