#!/usr/bin/env python3
"""
Simple working backend for SAFECode-Web
"""

import subprocess
import tempfile
import os
import json
import re
from typing import List, Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="SAFECode-Web Simple Backend", version="1.0.0")

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    filename: str
    code: str

class Finding(BaseModel):
    id: str
    cwe_id: str
    title: str
    severity: str
    status: str
    line: int
    snippet: str
    file: str
    tool: str
    confidence: float
    suppression_reason: str = None

class ScanResponse(BaseModel):
    findings: List[Finding]
    summary: Dict
    pagination: Dict
    baseline: Dict
    rate_limit: Dict
    telemetry: Dict

class HealthResponse(BaseModel):
    status: str
    name: str
    version: str
    available: bool

def run_flawfinder(code: str, filename: str) -> List[Dict]:
    """Run Flawfinder on the given code."""
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        # Run Flawfinder (try multiple paths)
        flawfinder_paths = [
            'flawfinder',  # System PATH
            'python', '-m', 'flawfinder',  # Python module
            'python.exe', '-m', 'flawfinder',  # Windows specific
        ]
        
        result = None
        for path in flawfinder_paths:
            try:
                if isinstance(path, list):
                    cmd = path + ['--csv', temp_file]
                else:
                    cmd = [path, '--csv', temp_file]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    break
            except:
                continue
        
        # Clean up temp file
        os.unlink(temp_file)
        
        if result is None or result.returncode != 0:
            print(f"Flawfinder failed to run. Return code: {result.returncode if result else 'None'}")
            if result and result.stderr:
                print(f"Error: {result.stderr}")
            return []
        
        # Parse CSV output
        findings = []
        lines = result.stdout.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = line.split(',')
                if len(parts) >= 6:
                    file_path, line_num, col, function, message, risk_level = parts[:6]
                    
                    # Extract line number
                    try:
                        line_num = int(line_num)
                    except:
                        line_num = 1
                    
                    # Map risk level to severity
                    risk_level = int(risk_level) if risk_level.isdigit() else 1
                    severity_map = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "MEDIUM", 1: "LOW", 0: "LOW"}
                    severity = severity_map.get(risk_level, "LOW")
                    
                    # Map function to CWE
                    cwe_mapping = {
                        "strcpy": "CWE-120", "strcat": "CWE-120", "gets": "CWE-120",
                        "sprintf": "CWE-134", "system": "CWE-78", "popen": "CWE-78",
                        "printf": "CWE-134", "scanf": "CWE-120", "memcpy": "CWE-787"
                    }
                    cwe_id = cwe_mapping.get(function, "CWE-120")
                    
                    # Get code snippet (simplified)
                    lines_code = code.split('\n')
                    snippet = ""
                    if 0 < line_num <= len(lines_code):
                        start = max(0, line_num - 2)
                        end = min(len(lines_code), line_num + 1)
                        snippet = '\n'.join(lines_code[start:end])
                    
                    finding = {
                        "id": f"flawfinder_{len(findings)}",
                        "cwe_id": cwe_id,
                        "title": f"Potential {function} vulnerability",
                        "severity": severity,
                        "status": "ACTIVE",
                        "line": line_num,
                        "snippet": snippet,
                        "file": filename,
                        "tool": "flawfinder",
                        "confidence": 0.8 if risk_level >= 4 else 0.6,
                        "suppression_reason": None
                    }
                    findings.append(finding)
        
        return findings
        
    except Exception as e:
        print(f"Error running Flawfinder: {e}")
        return []

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check if Flawfinder is available (try multiple paths)
        flawfinder_paths = [
            ['flawfinder', '--version'],
            ['python', '-m', 'flawfinder', '--version'],
            ['python.exe', '-m', 'flawfinder', '--version'],
        ]
        
        available = False
        for cmd in flawfinder_paths:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    available = True
                    break
            except:
                continue
    except:
        available = False
    
    return HealthResponse(
        status="healthy",
        name="SAFECode-Web Simple Backend",
        version="1.0.0",
        available=available
    )

@app.post("/scan")
async def scan_code(request: ScanRequest):
    """Scan code for vulnerabilities."""
    try:
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="No code provided")
        
        # Run Flawfinder
        findings_data = run_flawfinder(request.code, request.filename)
        
        # Convert to Finding objects
        findings = [Finding(**finding) for finding in findings_data]
        
        # Create summary
        total_findings = len(findings)
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        summary = {
            "total_findings": total_findings,
            "totals_by_severity": severity_counts,
            "totals_by_status": {"ACTIVE": total_findings, "SUPPRESSED": 0},
            "suppression_rate": 0.0
        }
        
        return ScanResponse(
            findings=findings,
            summary=summary,
            pagination={"limit": 200, "offset": 0, "total": total_findings},
            baseline={"active": total_findings, "suppressed": 0},
            rate_limit={"limit": 100, "remaining": 99, "reset": 3600},
            telemetry={"scan_requests_total": 1, "scan_duration_p50": 1.0}
        )
        
    except Exception as e:
        print(f"Error in scan: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

if __name__ == "__main__":
    print("🚀 Starting SAFECode-Web Simple Backend...")
    print("📡 Backend URL: http://localhost:8002")
    print("📚 Health Check: http://localhost:8002/health")
    print("🔍 Scan Endpoint: http://localhost:8002/scan")
    print("\n" + "="*50)
    print("🎯 Backend is ready!")
    print("="*50 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8002)
