"""Main FastAPI application for SAFECode-Web backend."""

import sys
import time
import logging
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import ORJSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import get_config, validate_config
from .models import (
    ScanRequest, ScanResponse, HealthResponse, AlertsResponse,
    Finding, ScanSummary, PaginationInfo, RateLimitInfo, TelemetryData
)
from .auth import require_auth, optional_auth
from .rate_limit import check_rate_limit, add_rate_limit_headers
from .sast_runner import run_flawfinder_scan
from .code_fixer import fix_code_with_gpt
from .suppression import apply_suppression
from .ai import process_findings_with_ai, is_ai_available
from .baseline import compare_with_baseline, save_baseline
from .telemetry import record_scan_metrics, get_current_telemetry, generate_alerts
from .utils import setup_utf8_encoding, setup_logging, paginate_results, create_summary_stats
from .middleware import (
    get_gzip_middleware, get_cache_middleware, get_utf8_middleware, get_logging_middleware
)


# Setup UTF-8 encoding
setup_utf8_encoding()

# Setup logging
config = get_config()
setup_logging(config.log_level)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="SAFECode-Web Backend",
    description="Production-ready security code analysis service with Semgrep and false-positive suppression",
    version="1.0.0",
    default_response_class=ORJSONResponse
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.middleware("http")(get_logging_middleware())
app.middleware("http")(get_utf8_middleware())
app.middleware("http")(get_cache_middleware())
app.middleware("http")(get_gzip_middleware())


@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info("Starting SAFECode-Web Backend...")
    
    # Validate configuration
    validation = validate_config()
    if not validation["valid"]:
        logger.error(f"Configuration validation failed: {validation['issues']}")
        sys.exit(1)
    
    # Check Flawfinder availability
    try:
        from .sast_runner import FlawfinderRunner
        runner = FlawfinderRunner()
        if runner.check_availability():
            logger.info("Flawfinder available for C code analysis")
        else:
            logger.warning("Flawfinder not available - install with: pip install flawfinder")
    except Exception as e:
        logger.warning(f"Flawfinder check failed: {e}")
    
    # Check AI availability
    if is_ai_available():
        logger.info("AI processing enabled")
    else:
        logger.info("AI processing disabled")
    
    logger.info("SAFECode-Web Backend started successfully")


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    status = "healthy"
    sast_version = None
    
    try:
        from .sast_runner import FlawfinderRunner
        runner = FlawfinderRunner()
        if runner.check_availability():
            sast_version = "Flawfinder 2.0.19"
        else:
            status = "degraded"
    except Exception:
        status = "degraded"
    
    return HealthResponse(
        status=status,
        semgrep_version=sast_version
    )


@app.get("/metrics", response_model=TelemetryData)
async def get_metrics():
    """Get telemetry metrics."""
    return get_current_telemetry()


@app.get("/alerts", response_model=AlertsResponse)
async def get_alerts():
    """Get security alerts."""
    alerts = generate_alerts()
    return AlertsResponse(
        alerts=alerts,
        total=len(alerts)
    )


@app.post("/scan", response_model=ScanResponse)
async def scan_code(
    request: ScanRequest,
    req: Request,
    limit: int = Query(default=None, description="Maximum findings to return"),
    offset: int = Query(default=0, description="Offset for pagination"),
    repo: Optional[str] = Query(default=None, description="Repository name for baseline comparison"),
    branch: Optional[str] = Query(default=None, description="Branch name for baseline comparison")
):
    """
    Scan code for security vulnerabilities.
    
    This endpoint applies false-positive suppression and returns paginated results.
    """
    start_time = time.time()
    
    # Check rate limit
    rate_limit_info = check_rate_limit(req)
    
    # Get configuration
    config = get_config()
    
    # Set default limit if not provided
    if limit is None:
        limit = config.safe_max_findings_response
    
    # Validate limit
    if limit > config.safe_max_findings_response:
        raise HTTPException(
            status_code=400,
            detail=f"Limit cannot exceed {config.safe_max_findings_response}"
        )
    
    try:
        # Run Flawfinder scan
        findings, success = run_flawfinder_scan(
            request.code,
            request.filename
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="SAST analysis failed")
        
        # Apply AI processing if enabled
        if is_ai_available():
            findings = process_findings_with_ai(findings, request.code)
        
        # Apply false-positive suppression
        findings = apply_suppression(findings, request.code)
        
        # Create summary statistics
        summary_data = create_summary_stats(findings)
        summary = ScanSummary(**summary_data)
        
        # Paginate results
        paginated = paginate_results(findings, limit, offset)
        paginated_findings = paginated['results']
        pagination = paginated['pagination']
        
        # Convert to Finding models
        finding_models = [Finding(**finding) for finding in paginated_findings]
        
        # Compare with baseline if provided
        baseline = None
        if repo and branch:
            baseline = compare_with_baseline(repo, branch, findings)
        
        # Create response
        response = ScanResponse(
            findings=finding_models,
            summary=summary,
            pagination=PaginationInfo(**pagination),
            baseline=baseline,
            rate_limit=RateLimitInfo(**rate_limit_info),
            telemetry=get_current_telemetry()
        )
        
        # Record metrics
        duration = time.time() - start_time
        suppressions = len([f for f in findings if f.get('status') == 'SUPPRESSED'])
        record_scan_metrics(duration, findings, suppressions, timeout, truncated)
        
        # Add rate limit headers
        add_rate_limit_headers(response, rate_limit_info)
        
        return response
        
    except Exception as e:
        logger.error(f"Error in scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/scan/raw", response_model=ScanResponse)
async def scan_code_raw(
    request: ScanRequest,
    req: Request,
    token: str = Depends(require_auth)
):
    """
    Scan code for security vulnerabilities (raw results).
    
    This endpoint requires authentication and returns full results without pagination.
    """
    start_time = time.time()
    
    # Check rate limit
    rate_limit_info = check_rate_limit(req)
    
    try:
        # Run Semgrep scan
        findings, timeout, truncated = run_semgrep_scan(
            request.filename,
            request.code,
            request.ruleset
        )
        
        # Apply AI processing if enabled
        if is_ai_available():
            findings = process_findings_with_ai(findings, request.code)
        
        # Apply false-positive suppression
        findings = apply_suppression(findings, request.code)
        
        # Create summary statistics
        summary_data = create_summary_stats(findings)
        summary = ScanSummary(**summary_data)
        
        # Convert to Finding models (no pagination for raw endpoint)
        finding_models = [Finding(**finding) for finding in findings]
        
        # Create response
        response = ScanResponse(
            findings=finding_models,
            summary=summary,
            pagination=PaginationInfo(
                limit=len(findings),
                offset=0,
                total=len(findings)
            ),
            baseline=None,
            rate_limit=RateLimitInfo(**rate_limit_info),
            telemetry=get_current_telemetry()
        )
        
        # Record metrics
        duration = time.time() - start_time
        suppressions = len([f for f in findings if f.get('status') == 'SUPPRESSED'])
        record_scan_metrics(duration, findings, suppressions, timeout, truncated)
        
        # Add rate limit headers
        add_rate_limit_headers(response, rate_limit_info)
        
        return response
        
    except Exception as e:
        logger.error(f"Error in raw scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


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
    
    # Check rate limit
    rate_limit_info = check_rate_limit(req)
    
    try:
        # Run Flawfinder scan
        findings, success = run_flawfinder_scan(
            request.code,
            request.filename
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="SAST analysis failed")
        
        # Fix code using GPT
        fixed_code, fix_details = fix_code_with_gpt(request.code, findings)
        
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
        
        # Add rate limit headers
        response_obj = Response(content=json.dumps(response), media_type="application/json")
        add_rate_limit_headers(response_obj, rate_limit_info)
        
        return response
        
    except Exception as e:
        logger.error(f"Error in code fix: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/baseline/{repo}/{branch}")
async def create_baseline(
    repo: str,
    branch: str,
    request: ScanRequest,
    req: Request,
    token: str = Depends(require_auth)
):
    """
    Create a baseline from scan results.
    
    This endpoint requires authentication.
    """
    try:
        # Run Semgrep scan
        findings, timeout, truncated = run_semgrep_scan(
            request.filename,
            request.code,
            request.ruleset
        )
        
        # Apply AI processing if enabled
        if is_ai_available():
            findings = process_findings_with_ai(findings, request.code)
        
        # Apply false-positive suppression
        findings = apply_suppression(findings, request.code)
        
        # Save baseline
        success = save_baseline(repo, branch, findings)
        
        if success:
            return {"message": f"Baseline created for {repo}/{branch}", "findings_count": len(findings)}
        else:
            raise HTTPException(status_code=500, detail="Failed to save baseline")
            
    except Exception as e:
        logger.error(f"Error creating baseline: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "SAFECode-Web Backend",
        "version": "1.0.0",
        "description": "Production-ready security code analysis service",
        "endpoints": {
            "POST /scan": "Scan code with suppression and pagination",
            "POST /scan/raw": "Scan code with full results (auth required)",
            "GET /health": "Health check",
            "GET /metrics": "Telemetry metrics",
            "GET /alerts": "Security alerts",
            "POST /baseline/{repo}/{branch}": "Create baseline (auth required)",
            "POST /auto-fix": "Auto-fix findings (not implemented)"
        },
        "features": {
            "semgrep_available": is_semgrep_available(),
            "ai_available": is_ai_available(),
            "suppression_rules": 8,
            "rate_limiting": True,
            "caching": True,
            "gzip_compression": True
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=config.host,
        port=config.port,
        reload=False,
        log_level=config.log_level
    )
