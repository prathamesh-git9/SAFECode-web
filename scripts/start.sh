#!/bin/bash

# SAFECode-Web Backend Startup Script for Linux/Unix

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting SAFECode-Web Backend...${NC}"

# Set UTF-8 environment
export PYTHONIOENCODING=utf-8
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Set Semgrep environment variables
export SEMGREP_TIMEOUT=60
export SEMGREP_JOBS=4
export SEMGREP_MAX_FINDINGS=250
export SEMGREP_MAX_TARGET_BYTES=2000000

# Set SAFE environment variables
export SAFE_MAX_FINDINGS_RESPONSE=200
export SAFE_MAX_INLINE_CODE_CHARS=20000
export SAFE_MAX_SNIPPET_CHARS=600

# Set rate limiting
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW=3600

# Set caching
export CACHE_TTL_SECONDS=120

# Set logging
export LOG_LEVEL=info

# Set server configuration
export HOST=0.0.0.0
export PORT=8001

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
pip install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cp env.example .env
    echo -e "${YELLOW}Please edit .env file with your configuration${NC}"
fi

# Check Semgrep availability
if command -v semgrep &> /dev/null; then
    echo -e "${GREEN}Semgrep found: $(semgrep --version)${NC}"
else
    echo -e "${YELLOW}Semgrep not found. Install with: pip install semgrep${NC}"
fi

# Start the application
echo -e "${GREEN}Starting SAFECode-Web Backend on http://$HOST:$PORT${NC}"
echo -e "${GREEN}Press Ctrl+C to stop${NC}"

python -m uvicorn app.main:app --host $HOST --port $PORT --reload
