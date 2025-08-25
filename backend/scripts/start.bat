@echo off
REM SAFECode-Web Backend Startup Script for Windows

echo Starting SAFECode-Web Backend...

REM Set UTF-8 environment
set PYTHONIOENCODING=utf-8
set LANG=C.UTF-8
set LC_ALL=C.UTF-8

REM Set Semgrep environment variables
set SEMGREP_TIMEOUT=60
set SEMGREP_JOBS=4
set SEMGREP_MAX_FINDINGS=250
set SEMGREP_MAX_TARGET_BYTES=2000000

REM Set SAFE environment variables
set SAFE_MAX_FINDINGS_RESPONSE=200
set SAFE_MAX_INLINE_CODE_CHARS=20000
set SAFE_MAX_SNIPPET_CHARS=600

REM Set rate limiting
set RATE_LIMIT_REQUESTS=100
set RATE_LIMIT_WINDOW=3600

REM Set caching
set CACHE_TTL_SECONDS=120

REM Set logging
set LOG_LEVEL=info

REM Set server configuration
set HOST=0.0.0.0
set PORT=8001

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Check if .env file exists
if not exist ".env" (
    echo Creating .env file from template...
    copy .env.example .env
    echo Please edit .env file with your configuration
)

REM Check Semgrep availability
semgrep --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Semgrep found
) else (
    echo Semgrep not found. Install with: pip install semgrep
)

REM Start the application
echo Starting SAFECode-Web Backend on http://%HOST%:%PORT%
echo Press Ctrl+C to stop

python -m uvicorn app.main:app --host %HOST% --port %PORT% --reload
