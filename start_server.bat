@echo off
echo Starting SAFECode-Web Server with GPT API Key...
echo.

REM Set the GPT API Key (use environment variable)
REM set OPENAI_API_KEY=your_api_key_here

REM Start the server in a new PowerShell window
start "SAFECode-Web Server" powershell -NoExit -Command "cd 'D:\presentation\SAFECode-web'; Write-Host '🚀 Starting SAFECode-Web Server...' -ForegroundColor Green; Write-Host '🤖 GPT API Key: Use environment variable OPENAI_API_KEY' -ForegroundColor Yellow; Write-Host '📡 Server will run on: http://localhost:3000' -ForegroundColor Cyan; Write-Host 'Press Ctrl+C to stop the server' -ForegroundColor Red; Write-Host ''; node server.js"

echo.
echo ✅ Server is starting in a new PowerShell window...
echo 🌐 Open your browser and go to: http://localhost:3000
echo.
echo 📝 To set your API key, run:
echo    set OPENAI_API_KEY=your_api_key_here
echo.
pause