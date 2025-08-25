@echo off
echo ========================================
echo Restarting SAFECode-Web with GPT Working
echo ========================================
echo.

echo Step 1: Stopping all processes...
taskkill /f /im python.exe 2>nul
taskkill /f /im python3.12.exe 2>nul
timeout /t 3 /nobreak >nul

echo Step 2: Starting backend with GPT...
start "Backend with GPT" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Step 3: Waiting for backend to start...
timeout /t 8 /nobreak >nul

echo Step 4: Testing GPT availability...
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8002/health' -Method GET -TimeoutSec 5; $data = $response.Content | ConvertFrom-Json; if ($data.gpt_available -eq 'true') { Write-Host '✅ GPT is working!' } else { Write-Host '❌ GPT not working yet...' } } catch { Write-Host '❌ Backend not ready...' }"

echo Step 5: Starting web interface...
start "Web Interface" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo 🚀 System Restarted!
echo ========================================
echo.
echo 📡 Backend: http://localhost:8002
echo 🌍 Web Interface: http://localhost:5000
echo.
echo 🎯 Go to http://localhost:5000 and test the auto-fix!
echo.
echo Press any key to exit...
pause >nul
