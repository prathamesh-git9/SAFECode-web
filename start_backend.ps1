# SAFECode-Web Backend Launcher (PowerShell)
# This script launches the backend server in a new PowerShell window

Write-Host "Starting SAFECode-Web Backend (Version 2.0)..." -ForegroundColor Green

# Get the current directory
$CURRENT_DIR = Get-Location

# Check if we're in the right directory
if (-not (Test-Path "backend\app\main.py")) {
    Write-Host "Error: backend\app\main.py not found!" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if virtual environment exists
if (-not (Test-Path "backend\venv\Scripts\Activate.ps1")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    Set-Location backend
    python -m venv venv
    Set-Location ..
}

# Set environment variables
$env:SAFECODE_API_TOKEN = "test-token"
$env:OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
$env:ANALYZER = "flawfinder"

# Launch backend server in a new PowerShell window
Write-Host "Starting backend server on port 8001..." -ForegroundColor Cyan

$command = @"
cd '$CURRENT_DIR\backend'
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -WindowStyle Normal

Write-Host ""
Write-Host "Backend server is starting in a new PowerShell window..." -ForegroundColor Green
Write-Host ""
Write-Host "Access points:" -ForegroundColor Cyan
Write-Host "- Backend API: http://localhost:8001" -ForegroundColor White
Write-Host "- Health Check: http://localhost:8001/health" -ForegroundColor White
Write-Host "- API Docs: http://localhost:8001/docs" -ForegroundColor White
Write-Host "- Metrics: http://localhost:8001/metrics" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to exit this launcher..."
Read-Host
