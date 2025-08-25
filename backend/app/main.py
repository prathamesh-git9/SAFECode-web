"""Main FastAPI application for SAFECode-Web backend."""
import sys
import time
import logging
import json
from typing import List, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_config, validate_config
from .models import (
    ScanRequest, ScanResponse, HealthResponse, 
    TelemetryData, Alert, AlertsResponse
)
from .auth import require_auth, optional_auth
from .rate_limit import check_rate_limit, add_rate_limit_headers
from .telemetry import get_telemetry_collector, generate_alerts
from .baseline import BaselineManager
from .utils import as_utf8, setup_utf8, setup_logging
from .middleware import (
    GzipMiddleware, CacheMiddleware, 
    UTF8SanitizationMiddleware, LoggingMiddleware
)

# Setup UTF-8 encoding
setup_utf8()

# Setup logging
setup_logging()

# Get configuration
config = get_config()
validation_errors = validate_config(config)

if validation_errors:
    logging.error(f"Configuration validation failed: {validation_errors}")
    sys.exit(1)

# Initialize FastAPI app
app = FastAPI(
    title="SAFECode-Web Backend",
    description="Security code analysis service with Flawfinder and AI-powered fixes",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(UTF8SanitizationMiddleware)
app.add_middleware(CacheMiddleware)
app.add_middleware(GzipMiddleware)

# Initialize components
telemetry = get_telemetry_collector()
baseline_manager = BaselineManager()

# Conditional analyzer import
if config.analyzer == "flawfinder":
    from .flawfinder_runner import analyze as run_analyzer
    analyzer_name = "flawfinder"
else:
    from .semgrep_runner import analyze as run_analyzer
    analyzer_name = "semgrep"

logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info(f"SAFECode-Web backend starting with analyzer: {analyzer_name}")
    
    # Check analyzer availability
    if analyzer_name == "flawfinder":
        from .flawfinder_runner import FlawfinderRunner
        runner = FlawfinderRunner()
        if not runner.check_availability():
            logger.warning("Flawfinder not available - install with: pip install flawfinder")
    else:
        from .semgrep_runner import SemgrepRunner
        runner = SemgrepRunner()
        if not runner.check_availability():
            logger.warning("Semgrep not available - install with: pip install semgrep")
    
    logger.info("SAFECode-Web backend started successfully")

@app.post("/scan")
async def scan_code(
    request: ScanRequest,
    req: Request,
    limit: int = Query(default=config.safe_max_findings_response, le=config.safe_max_findings_response),
    offset: int = Query(default=0, ge=0),
    auth: Optional[str] = Depends(optional_auth)
):
    """
    Scan code for security vulnerabilities with suppression and pagination.
    
    This endpoint applies false-positive suppression rules and returns paginated results.
    """
    start_time = time.time()
    rate_limit_info = check_rate_limit(req)
    
    try:
        # Validate input
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")
        
        if len(request.code) > config.safe_max_inline_code_chars:
            raise HTTPException(
                status_code=400, 
                detail=f"Code too long. Maximum {config.safe_max_inline_code_chars} characters allowed"
            )
        
        # Run analyzer
        findings, success = run_analyzer(request.filename, request.code)
        if not success:
            raise HTTPException(status_code=500, detail="Static analysis failed")
        
        # Apply AI post-processing if enabled
        if config.enable_gpt and config.openai_api_key:
            from .ai import adjust_findings_with_ai
            findings = adjust_findings_with_ai(findings, request.code)
        
        # Apply false-positive suppression
        from .suppression import apply_false_positive_suppression
        findings = apply_false_positive_suppression(findings, request.code)
        
        # Apply pagination
        total_findings = len(findings)
        paginated_findings = findings[offset:offset + limit]
        
        # Create summary
        from .utils import create_scan_summary
        summary = create_scan_summary(findings)
        
        # Get baseline comparison
        baseline = baseline_manager.get_baseline_comparison(
            request.filename, findings
        )
        
        # Update telemetry
        scan_duration = time.time() - start_time
        telemetry.record_scan_request(
            scan_duration,
            findings,
            len([f for f in findings if f["status"] == "SUPPRESSED"]),
            False,  # timeout
            len(paginated_findings) < len(findings)  # truncated
        )
        
        # Create response
        response = ScanResponse(
            findings=paginated_findings,
            summary=summary,
            pagination={
                "limit": limit,
                "offset": offset,
                "total": total_findings
            },
            baseline=baseline,
            rate_limit=rate_limit_info,
            telemetry=telemetry.get_telemetry_data()
        )
        
        # Add headers
        response_obj = JSONResponse(content=response.dict())
        add_rate_limit_headers(response_obj, rate_limit_info)
        
        if len(paginated_findings) < len(findings):
            response_obj.headers["X-Truncated"] = "true"
        
        return response_obj
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/scan/raw")
async def scan_code_raw(
    request: ScanRequest,
    req: Request,
    auth: str = Depends(require_auth)
):
    """
    Raw scan results without suppression or pagination (requires authentication).
    
    This endpoint returns all findings without applying false-positive suppression.
    """
    start_time = time.time()
    rate_limit_info = check_rate_limit(req)
    
    try:
        # Validate input
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")
        
        # Run analyzer
        findings, success = run_analyzer(request.filename, request.code)
        if not success:
            raise HTTPException(status_code=500, detail="Static analysis failed")
        
        # Create summary
        from .utils import create_scan_summary
        summary = create_scan_summary(findings)
        
        # Update telemetry
        scan_duration = time.time() - start_time
        telemetry.record_scan_request(scan_duration, findings, 0, False, False)
        
        # Create response
        response = ScanResponse(
            findings=findings,
            summary=summary,
            pagination={
                "limit": len(findings),
                "offset": 0,
                "total": len(findings)
            },
            baseline=None,
            rate_limit=rate_limit_info,
            telemetry=telemetry.get_telemetry_data()
        )
        
        # Add headers
        response_obj = JSONResponse(content=response.dict())
        add_rate_limit_headers(response_obj, rate_limit_info)
        
        return response_obj
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in raw scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check analyzer availability
        if analyzer_name == "flawfinder":
            from .flawfinder_runner import FlawfinderRunner
            runner = FlawfinderRunner()
            analyzer_available = runner.check_availability()
            analyzer_version = "Unknown"
            if analyzer_available:
                try:
                    import subprocess
                    result = subprocess.run(
                        [config.flawfinder_path, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        analyzer_version = result.stdout.strip()
                except:
                    analyzer_version = "Available"
        else:
            from .semgrep_runner import SemgrepRunner
            runner = SemgrepRunner()
            analyzer_available = runner.check_availability()
            analyzer_version = "Unknown"
            if analyzer_available:
                try:
                    import subprocess
                    result = subprocess.run(
                        ["semgrep", "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        analyzer_version = result.stdout.strip()
                except:
                    analyzer_version = "Available"
        
        return HealthResponse(
            status="healthy",
            analyzer=analyzer_name,
            analyzer_available=analyzer_available,
            analyzer_version=analyzer_version
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            analyzer=analyzer_name,
            analyzer_available=False,
            analyzer_version="Unknown"
        )

@app.get("/metrics")
async def get_metrics():
    """Get telemetry metrics."""
    return telemetry.get_telemetry_data()

@app.get("/alerts")
async def get_alerts():
    """Get security alerts based on telemetry thresholds."""
    alerts = generate_alerts()
    return AlertsResponse(alerts=alerts)

@app.post("/fix")
async def fix_code(
    request: ScanRequest,
    req: Request
):
    """
    Fix C code vulnerabilities automatically using GPT.
    This endpoint scans the code for vulnerabilities and returns the fixed version.
    """
    start_time = time.time()
    rate_limit_info = check_rate_limit(req)
    
    try:
        # Validate input
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")
        
        if len(request.code) > config.safe_max_inline_code_chars:
            raise HTTPException(
                status_code=400, 
                detail=f"Code too long. Maximum {config.safe_max_inline_code_chars} characters allowed"
            )
        
        # Run analyzer
        findings, success = run_analyzer(request.filename, request.code)
        if not success:
            raise HTTPException(status_code=500, detail="Static analysis failed")
        
        # Apply AI fixes if enabled
        if config.enable_gpt and config.openai_api_key:
            from .code_fixer import fix_code_with_gpt
            fixed_code, fix_details = fix_code_with_gpt(request.code, findings)
        else:
            fixed_code = request.code
            fix_details = []
        
        # Update telemetry
        scan_duration = time.time() - start_time
        telemetry.record_scan_request(scan_duration, findings, 0, False, False)
        
        # Create response
        response = {
            "original_code": request.code,
            "fixed_code": fixed_code,
            "vulnerabilities_found": len(findings),
            "fixes_applied": len(fix_details),
            "findings": findings,
            "fix_details": fix_details,
            "rate_limit": rate_limit_info
        }
        
        response_obj = JSONResponse(content=response)
        add_rate_limit_headers(response_obj, rate_limit_info)
        return response_obj
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in code fix: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=config.host,
        port=config.port,
        reload=True
    )
