@echo off
echo 🚀 Starting SAFECode-Web Servers...
echo.

echo 📡 Starting Backend (Port 8002)...
start "SAFECode Backend" powershell -Command "python simple_working_backend_with_fix.py"

echo ⏳ Waiting for backend to start...
timeout /t 3 /nobreak >nul

echo 🌐 Starting Frontend (Port 5000)...
start "SAFECode Frontend" powershell -Command "python web_interface_with_fix.py"

echo ⏳ Waiting for frontend to start...
timeout /t 3 /nobreak >nul

echo.
echo ✅ Servers Started Successfully!
echo.
echo 🌐 Frontend: http://localhost:5000
echo 📡 Backend: http://localhost:8002
echo 📚 API Docs: http://localhost:8002/docs
echo.
echo 🎯 Ready to test! Open http://localhost:5000 in your browser
echo.
pause
