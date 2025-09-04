# SAFECode-Web Server Startup Script
Write-Host "🚀 Starting SAFECode-Web Server..." -ForegroundColor Green
Write-Host "🤖 Configuring GPT API Key..." -ForegroundColor Yellow

# Set the GPT API Key (use environment variable)
# $env:OPENAI_API_KEY = "your_api_key_here"

# Navigate to the project directory
Set-Location "D:\presentation\SAFECode-web"

Write-Host "📡 Server will run on: http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔒 GPT API Key: Use environment variable OPENAI_API_KEY" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Red
Write-Host ""

# Start the server
node server.js