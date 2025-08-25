@echo off
echo ========================================
echo Starting SAFECode-Web with Auto-Fix
echo ========================================
echo.

echo Stopping any existing web interfaces...
taskkill /f /im python.exe 2>nul
timeout /t 2 /nobreak >nul

echo Starting web interface with Auto-Fix...
start "SAFECode-Web Interface (Auto-Fix)" powershell -Command "cd /d %~dp0 && python web_interface_with_fix.py"

echo.
echo ========================================
echo 🌐 Web Interface Started!
echo ========================================
echo.
echo 🎯 Open your browser and go to: http://localhost:5000
echo.
echo 📝 To see the Auto-Fix button:
echo    1. Paste this vulnerable code:
echo.
echo    #include ^<stdio.h^>
echo    #include ^<string.h^>
echo.
echo    int main() {
echo        char buffer[10];
echo        strcpy(buffer, "Hello World");
echo        printf(buffer);
echo        return 0;
echo    }
echo.
echo    2. Click "🔍 Scan for Vulnerabilities"
echo    3. Click "🤖 Auto-Fix with GPT" (appears after scan)
echo.
echo Press any key to exit...
pause >nul
