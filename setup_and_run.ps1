# SAFECode-Web Complete Setup and Run Script
# This script sets up the environment, installs dependencies, and runs both servers

param(
    [string]$OpenAIKey = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
)

# Set UTF-8 encoding for PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "🚀 SAFECode-Web Complete Setup and Run Script" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# Function to check if command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

if (-not (Test-Command "python")) {
    Write-Host "❌ Python not found. Please install Python 3.11+ and try again." -ForegroundColor Red
    exit 1
}

if (-not (Test-Command "node")) {
    Write-Host "❌ Node.js not found. Please install Node.js and try again." -ForegroundColor Red
    exit 1
}

if (-not (Test-Command "npm")) {
    Write-Host "❌ npm not found. Please install npm and try again." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Prerequisites check passed" -ForegroundColor Green

# Set up backend environment
Write-Host "Setting up backend environment..." -ForegroundColor Yellow

# Set environment variables
$env:PYTHONIOENCODING = "utf-8"
$env:LANG = "C.UTF-8"
$env:LC_ALL = "C.UTF-8"
$env:SAFECODE_API_TOKEN = "your-secret-api-token-here"
$env:SEMGREP_TIMEOUT = "60"
$env:SEMGREP_JOBS = "4"
$env:SEMGREP_MAX_FINDINGS = "250"
$env:SEMGREP_MAX_TARGET_BYTES = "2000000"
$env:SAFE_MAX_FINDINGS_RESPONSE = "200"
$env:SAFE_MAX_INLINE_CODE_CHARS = "20000"
$env:SAFE_MAX_SNIPPET_CHARS = "600"
$env:RATE_LIMIT_REQUESTS = "100"
$env:RATE_LIMIT_WINDOW = "3600"
$env:ENABLE_GPT = "true"
$env:OPENAI_API_KEY = $OpenAIKey
$env:OPENAI_MODEL = "gpt-4o-mini"
$env:CACHE_TTL_SECONDS = "120"
$env:LOG_LEVEL = "info"
$env:HOST = "0.0.0.0"
$env:PORT = "8001"

# Create virtual environment if it doesn't exist
if (-not (Test-Path "backend\venv")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
    Set-Location backend
    python -m venv venv
    Set-Location ..
}

# Activate virtual environment and install dependencies
Write-Host "Installing backend dependencies..." -ForegroundColor Yellow
Set-Location backend
& "venv\Scripts\Activate.ps1"
pip install -r requirements.txt

# Install Semgrep if not available
if (-not (Test-Command "semgrep")) {
    Write-Host "Installing Semgrep..." -ForegroundColor Yellow
    pip install semgrep
}

Set-Location ..

# Set up frontend environment
Write-Host "Setting up frontend environment..." -ForegroundColor Yellow

if (Test-Path "frontend\safecode-ui") {
    Set-Location frontend\safecode-ui
    
    # Install npm dependencies
    if (-not (Test-Path "node_modules")) {
        Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
        npm install
    }
    
    Set-Location ..\..
} else {
    Write-Host "⚠️  Frontend directory not found. Skipping frontend setup." -ForegroundColor Yellow
}

# Use fixed ports instead of random
$backendPort = 8001
$frontendPort = 3000
$env:PORT = $backendPort

Write-Host "Backend will run on port: $backendPort" -ForegroundColor Cyan
Write-Host "Frontend will run on port: $frontendPort" -ForegroundColor Cyan

# Create .env file for backend if it doesn't exist
if (-not (Test-Path "backend\.env")) {
    Write-Host "Creating .env file..." -ForegroundColor Yellow
    Copy-Item "backend\.env.example" "backend\.env"
}

# Start backend server in background
Write-Host "Starting backend server..." -ForegroundColor Green
$backendJob = Start-Job -ScriptBlock {
    param($backendPath, $port)
    Set-Location $backendPath
    & "venv\Scripts\Activate.ps1"
    $env:PORT = $port
    python -m uvicorn app.main:app --host 0.0.0.0 --port $port --reload
} -ArgumentList (Resolve-Path "backend"), $backendPort

# Wait for backend to start
Write-Host "Waiting for backend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Test backend health
try {
    $healthResponse = Invoke-RestMethod -Uri "http://localhost:$backendPort/health" -Method Get -TimeoutSec 10
    Write-Host "✅ Backend is running: $($healthResponse.status)" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Backend health check failed, but continuing..." -ForegroundColor Yellow
}

# Start frontend if available
if (Test-Path "frontend\safecode-ui") {
    Write-Host "Starting frontend server..." -ForegroundColor Green
    $frontendJob = Start-Job -ScriptBlock {
        param($frontendPath)
        Set-Location $frontendPath
        npm start
    } -ArgumentList (Resolve-Path "frontend\safecode-ui")
    
    Write-Host "✅ Frontend server started" -ForegroundColor Green
} else {
    Write-Host "⚠️  Frontend not available" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 SAFECode-Web is running!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host "Backend:  http://localhost:$backendPort" -ForegroundColor Cyan
Write-Host "Health:   http://localhost:$backendPort/health" -ForegroundColor Cyan
Write-Host "Metrics:  http://localhost:$backendPort/metrics" -ForegroundColor Cyan
if (Test-Path "frontend\safecode-ui") {
    Write-Host "Frontend: http://localhost:$frontendPort" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Press Ctrl+C to stop all servers" -ForegroundColor Yellow

# Keep the script running and monitor jobs
try {
    while ($true) {
        $backendStatus = Get-Job -Id $backendJob.Id | Select-Object -ExpandProperty State
        if ($backendStatus -eq "Failed") {
            Write-Host "❌ Backend server failed" -ForegroundColor Red
            break
        }
        
        if (Test-Path "frontend\safecode-ui") {
            $frontendStatus = Get-Job -Id $frontendJob.Id | Select-Object -ExpandProperty State
            if ($frontendStatus -eq "Failed") {
                Write-Host "❌ Frontend server failed" -ForegroundColor Red
                break
            }
        }
        
        Start-Sleep -Seconds 5
    }
} catch {
    Write-Host "Stopping servers..." -ForegroundColor Yellow
} finally {
    # Clean up jobs
    if ($backendJob) {
        Stop-Job -Id $backendJob.Id
        Remove-Job -Id $backendJob.Id
    }
    if (Test-Path "frontend\safecode-ui" -and $frontendJob) {
        Stop-Job -Id $frontendJob.Id
        Remove-Job -Id $frontendJob.Id
    }
    Write-Host "Servers stopped." -ForegroundColor Green
}
