#!/usr/bin/env python3
"""
Simple working backend for SAFECode-Web (with mock vulnerability scanner)
"""

import subprocess
import tempfile
import os
import json
import re
import sys
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
    suppression_reason: str | None = None

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

def mock_vulnerability_scan(code: str, filename: str) -> List[Dict]:
    """Mock vulnerability scanner that detects common C vulnerabilities."""
    findings = []
    lines = code.split('\n')
    
    # Define vulnerability patterns
    vulnerability_patterns = [
        {
            'pattern': r'\bstrcpy\s*\(',
            'cwe': 'CWE-120',
            'title': 'Buffer Overflow - strcpy',
            'severity': 'HIGH',
            'confidence': 0.9
        },
        {
            'pattern': r'\bstrcat\s*\(',
            'cwe': 'CWE-120',
            'title': 'Buffer Overflow - strcat',
            'severity': 'HIGH',
            'confidence': 0.9
        },
        {
            'pattern': r'\bgets\s*\(',
            'cwe': 'CWE-120',
            'title': 'Buffer Overflow - gets',
            'severity': 'CRITICAL',
            'confidence': 0.95
        },
        {
            'pattern': r'\bsystem\s*\(',
            'cwe': 'CWE-78',
            'title': 'Command Injection - system',
            'severity': 'HIGH',
            'confidence': 0.8
        },
        {
            'pattern': r'\bpopen\s*\(',
            'cwe': 'CWE-78',
            'title': 'Command Injection - popen',
            'severity': 'HIGH',
            'confidence': 0.8
        },
        {
            'pattern': r'\bprintf\s*\([^"]*[^,)]',
            'cwe': 'CWE-134',
            'title': 'Format String Vulnerability - printf',
            'severity': 'MEDIUM',
            'confidence': 0.7
        },
        {
            'pattern': r'\bsprintf\s*\(',
            'cwe': 'CWE-134',
            'title': 'Format String Vulnerability - sprintf',
            'severity': 'MEDIUM',
            'confidence': 0.7
        },
        {
            'pattern': r'\bmalloc\s*\([^)]*\)\s*[^;]*[^=]',
            'cwe': 'CWE-401',
            'title': 'Memory Leak - malloc without free',
            'severity': 'MEDIUM',
            'confidence': 0.6
        }
    ]
    
    for line_num, line in enumerate(lines, 1):
        for pattern_info in vulnerability_patterns:
            if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                # Get code snippet
                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                snippet = '\n'.join(lines[start:end])
                
                    finding = {
                        "id": f"mock_{len(findings)}",
                        "cwe_id": pattern_info['cwe'],
                        "title": pattern_info['title'],
                        "severity": pattern_info['severity'],
                        "status": "ACTIVE",
                        "line": line_num,
                        "snippet": snippet,
                        "file": filename,
                        "tool": "mock_scanner",
                        "confidence": pattern_info['confidence'],
                        "suppression_reason": ""
                    }
                findings.append(finding)
    
    return findings

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        name="SAFECode-Web Simple Backend (Mock Scanner)",
        version="1.0.0",
        available=True
    )

@app.post("/scan")
async def scan_code(request: ScanRequest):
    """Scan code for vulnerabilities."""
    try:
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="No code provided")
        
        print(f"Scanning code for file: {request.filename}")
        print(f"Code length: {len(request.code)} characters")
        
        # Run mock vulnerability scanner
        findings_data = mock_vulnerability_scan(request.code, request.filename)
        
        print(f"Found {len(findings_data)} vulnerabilities")
        
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
    print("🚀 Starting SAFECode-Web Simple Backend (Mock Scanner)...")
    print("📡 Backend URL: http://localhost:8002")
    print("📚 Health Check: http://localhost:8002/health")
    print("🔍 Scan Endpoint: http://localhost:8002/scan")
    print("\n" + "="*50)
    print("🎯 Backend is ready with Mock Vulnerability Scanner!")
    print("="*50 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8002)
