# SAFECode-Web Backend PowerShell Environment Setup Script

# Set UTF-8 encoding for PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "Setting up SAFECode-Web Backend environment..." -ForegroundColor Green

# Set UTF-8 environment variables
$env:PYTHONIOENCODING = "utf-8"
$env:LANG = "C.UTF-8"
$env:LC_ALL = "C.UTF-8"

# Set Semgrep environment variables
$env:SEMGREP_TIMEOUT = "60"
$env:SEMGREP_JOBS = "4"
$env:SEMGREP_MAX_FINDINGS = "250"
$env:SEMGREP_MAX_TARGET_BYTES = "2000000"

# Set SAFE environment variables
$env:SAFE_MAX_FINDINGS_RESPONSE = "200"
$env:SAFE_MAX_INLINE_CODE_CHARS = "20000"
$env:SAFE_MAX_SNIPPET_CHARS = "600"

# Set rate limiting
$env:RATE_LIMIT_REQUESTS = "100"
$env:RATE_LIMIT_WINDOW = "3600"

# Set caching
$env:CACHE_TTL_SECONDS = "120"

# Set logging
$env:LOG_LEVEL = "info"

# Set server configuration
$env:HOST = "0.0.0.0"
$env:PORT = "8001"

Write-Host "Environment variables set successfully!" -ForegroundColor Green

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Green
& "venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Green
pip install -r requirements.txt

# Check if .env file exists
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env file from template..." -ForegroundColor Yellow
    Copy-Item "env.example" ".env"
    Write-Host "Please edit .env file with your configuration" -ForegroundColor Yellow
}

# Check Semgrep availability
try {
    $semgrepVersion = semgrep --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Semgrep found: $semgrepVersion" -ForegroundColor Green
    } else {
        Write-Host "Semgrep not found. Install with: pip install semgrep" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Semgrep not found. Install with: pip install semgrep" -ForegroundColor Yellow
}

Write-Host "Environment setup complete!" -ForegroundColor Green
Write-Host "To start the application, run: python -m uvicorn app.main:app --host $env:HOST --port $env:PORT --reload" -ForegroundColor Cyan
