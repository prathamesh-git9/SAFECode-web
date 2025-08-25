@echo off
echo ========================================
echo SAFECode-Web Server Startup
echo ========================================
echo.

echo Starting backend server...
start "SAFECode Backend" cmd /k "python simple_working_backend_with_fix.py"

echo Waiting 5 seconds for backend to start...
timeout /t 5 /nobreak > nul

echo Starting web interface...
start "SAFECode Web Interface" cmd /k "python web_interface_with_fix.py"

echo.
echo ========================================
echo Servers are starting...
echo ========================================
echo Backend: http://localhost:8002
echo Web Interface: http://localhost:5000
echo.
echo Opening web interface in browser...
timeout /t 3 /nobreak > nul
start http://localhost:5000

echo.
echo Press any key to exit this launcher...
pause > nul
