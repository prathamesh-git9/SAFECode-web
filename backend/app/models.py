"""Pydantic models for SAFECode-Web API."""

from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, validator
import re


class FindingStatus(str, Enum):
    """Status of a security finding."""
    ACTIVE = "ACTIVE"
    SUPPRESSED = "SUPPRESSED"


class Severity(str, Enum):
    """Severity levels for findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """Confidence levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A security finding from static analysis."""
    id: str = Field(..., description="Unique identifier for the finding")
    cwe_id: str = Field(..., description="CWE identifier")
    title: str = Field(..., description="Short title describing the issue")
    severity: Severity = Field(..., description="Severity level")
    status: FindingStatus = Field(..., description="Current status")
    line: int = Field(..., description="Line number where issue occurs")
    snippet: str = Field(..., description="Code snippet showing the issue")
    file: str = Field(..., description="File path where issue was found")
    tool: str = Field(default="semgrep", description="Tool that found the issue")
    confidence: Confidence = Field(..., description="Confidence level")
    suppression_reason: Optional[str] = Field(None, description="Reason for suppression if applicable")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    
    @validator('snippet')
    def truncate_snippet(cls, v):
        """Truncate snippet to safe length."""
        from .config import config
        if len(v) > config.safe_max_snippet_chars:
            # Try to cut on line boundaries
            lines = v.split('\n')
            result = ""
            for line in lines:
                if len(result + line + '\n') <= config.safe_max_snippet_chars - 3:
                    result += line + '\n'
                else:
                    break
            if result:
                return result.rstrip() + "..."
            else:
                return v[:config.safe_max_snippet_chars - 3] + "..."
        return v


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""
    totals_by_severity: Dict[Severity, int] = Field(default_factory=dict)
    totals_by_status: Dict[FindingStatus, int] = Field(default_factory=dict)
    suppression_rate: float = Field(..., description="Percentage of findings suppressed")
    by_cwe: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[FindingStatus, Dict[Severity, int]] = Field(default_factory=dict)
    
    @validator('suppression_rate')
    def validate_suppression_rate(cls, v):
        """Ensure suppression rate is between 0 and 1."""
        return max(0.0, min(1.0, v))


class PaginationInfo(BaseModel):
    """Pagination information for results."""
    limit: int = Field(..., description="Number of items per page")
    offset: int = Field(..., description="Offset from start")
    total: int = Field(..., description="Total number of items")


class BaselineReport(BaseModel):
    """Baseline comparison report."""
    active: Dict[Severity, int] = Field(default_factory=dict)
    suppressed: Dict[Severity, int] = Field(default_factory=dict)
    drift: Optional[float] = Field(None, description="Drift percentage from baseline")
    severity_changes: Optional[Dict[Severity, Dict[str, int]]] = Field(None, description="Changes by severity")


class TelemetryData(BaseModel):
    """Telemetry and metrics data."""
    scan_requests_total: int = Field(default=0, description="Total scan requests")
    scan_duration_p50: float = Field(default=0.0, description="50th percentile scan duration")
    scan_duration_p90: float = Field(default=0.0, description="90th percentile scan duration")
    findings_by_cwe: Dict[str, int] = Field(default_factory=dict, description="Findings count by CWE")
    suppressions_total: int = Field(default=0, description="Total suppressions applied")
    timeouts_total: int = Field(default=0, description="Total timeouts")
    truncations_total: int = Field(default=0, description="Total truncations")


class RateLimitInfo(BaseModel):
    """Rate limiting information."""
    limit: int = Field(..., description="Request limit per window")
    remaining: int = Field(..., description="Remaining requests")
    reset: int = Field(..., description="Reset timestamp")


class ScanResponse(BaseModel):
    """Response from a security scan."""
    findings: List[Finding] = Field(..., description="List of findings")
    summary: ScanSummary = Field(..., description="Summary statistics")
    pagination: PaginationInfo = Field(..., description="Pagination information")
    baseline: Optional[BaselineReport] = Field(None, description="Baseline comparison")
    rate_limit: RateLimitInfo = Field(..., description="Rate limiting info")
    telemetry: TelemetryData = Field(..., description="Telemetry data")


class ScanRequest(BaseModel):
    """Request for a security scan."""
    filename: str = Field(..., description="Name of the file to scan")
    code: str = Field(..., description="Source code to analyze")
    ruleset: Optional[str] = Field("p/security-audit", description="Semgrep ruleset to use")
    
    @validator('filename')
    def validate_filename(cls, v):
        """Validate filename format."""
        if not re.match(r'^[a-zA-Z0-9._\-/\\]+$', v):
            raise ValueError("Invalid filename format")
        return v
    
    @validator('code')
    def validate_code(cls, v):
        """Validate code content."""
        from .config import config
        if not v.strip():
            raise ValueError("Code cannot be empty")
        if len(v) > config.safe_max_inline_code_chars:
            raise ValueError(f"Code too long (max {config.safe_max_inline_code_chars} chars)")
        return v


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    semgrep_version: Optional[str] = Field(None, description="Semgrep version if available")


class Alert(BaseModel):
    """Security alert."""
    level: str = Field(..., description="Alert level (warning, critical)")
    message: str = Field(..., description="Alert message")
    timestamp: float = Field(..., description="Alert timestamp")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")


class AlertsResponse(BaseModel):
    """Alerts response."""
    alerts: List[Alert] = Field(..., description="List of active alerts")
    total: int = Field(..., description="Total number of alerts")
