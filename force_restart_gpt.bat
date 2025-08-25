@echo off
echo ========================================
echo FORCE RESTART - GPT Auto-Fix System
echo ========================================
echo.

echo Step 1: Force killing ALL Python processes...
taskkill /f /im python.exe 2>nul
taskkill /f /im python3.12.exe 2>nul
taskkill /f /im python3.exe 2>nul
timeout /t 5 /nobreak >nul

echo Step 2: Starting backend with GPT...
start "Backend with GPT" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Step 3: Waiting for backend to start...
timeout /t 10 /nobreak >nul

echo Step 4: Testing GPT availability...
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8002/health' -Method GET -TimeoutSec 5; $data = $response.Content | ConvertFrom-Json; Write-Host 'Backend Status:' $data.status; Write-Host 'GPT Available:' $data.gpt_available; } catch { Write-Host 'Backend not ready yet...' }"

echo Step 5: Testing GPT fix directly...
python debug_gpt.py

echo Step 6: Starting web interface...
start "Web Interface" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo 🚀 System Force Restarted!
echo ========================================
echo.
echo 📡 Backend: http://localhost:8002
echo 🌍 Web Interface: http://localhost:5000
echo.
echo 🎯 Go to http://localhost:5000 and test the auto-fix!
echo.
echo Press any key to exit...
pause >nul
