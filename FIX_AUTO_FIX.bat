@echo off
echo ========================================
echo FIXING SAFECode-Web Auto-Fix Issue
echo ========================================
echo.

echo PROBLEM: You are using the OLD web interface (Version 2.0)
echo SOLUTION: We need to use the NEW web interface (Version 3.0)
echo.

echo Step 1: Stopping all existing processes...
taskkill /f /im python.exe 2>nul
taskkill /f /im python3.12.exe 2>nul
timeout /t 3 /nobreak >nul

echo Step 2: Starting the CORRECT backend...
start "Backend (Auto-Fix)" powershell -Command "cd /d %~dp0 && python simple_working_backend_with_fix.py"

echo Step 3: Waiting for backend to start...
timeout /t 5 /nobreak >nul

echo Step 4: Starting the CORRECT web interface...
start "Web Interface (Auto-Fix)" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo ✅ FIXED! Auto-Fix System Started
echo ========================================
echo.
echo 🎯 Open your browser and go to: http://localhost:5000
echo.
echo 🔍 How to verify you're using the CORRECT interface:
echo    - Look for "Version 3.0" at the bottom (NOT 2.0)
echo    - Look for "🔧 Fix Endpoint: http://localhost:8002/fix" in startup
echo    - The auto-fix button appears AFTER scanning for vulnerabilities
echo.
echo 📝 To see the auto-fix button:
echo    1. Paste vulnerable C code
echo    2. Click "🔍 Scan for Vulnerabilities"  
echo    3. Click "🤖 Auto-Fix with GPT" (appears after scan)
echo.
echo Press any key to exit...
pause >nul
