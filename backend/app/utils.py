"""Utility functions for SAFECode-Web backend."""

import sys
import re
import hashlib
import time
from typing import Any, Dict, List, Optional, Union
import logging


def setup_utf8_encoding():
    """Configure UTF-8 encoding for stdout and stderr."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        # Python < 3.7 doesn't have reconfigure
        pass


def as_utf8(obj: Any) -> str:
    """Coerce object to UTF-8 string, sanitizing non-UTF-8 content."""
    if obj is None:
        return ""
    
    if isinstance(obj, str):
        # Try to encode/decode to ensure valid UTF-8
        try:
            return obj.encode('utf-8', errors='replace').decode('utf-8')
        except (UnicodeEncodeError, UnicodeDecodeError):
            return obj.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            return obj.decode('utf-8', errors='replace')
    
    # Convert to string and sanitize
    try:
        str_obj = str(obj)
        return str_obj.encode('utf-8', errors='replace').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return repr(obj).encode('utf-8', errors='replace').decode('utf-8')


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem operations."""
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    return sanitized


def generate_finding_id(filename: str, line: int, cwe: str, snippet: str) -> str:
    """Generate a unique ID for a finding."""
    content = f"{filename}:{line}:{cwe}:{snippet[:100]}"
    return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]


def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate text to maximum length, trying to break at word boundaries."""
    if len(text) <= max_length:
        return text
    
    # Try to break at word boundaries
    if max_length > len(suffix):
        available_length = max_length - len(suffix)
        truncated = text[:available_length]
        
        # Find last word boundary
        last_space = truncated.rfind(' ')
        if last_space > available_length * 0.8:  # Only use if it's not too far back
            truncated = truncated[:last_space]
        
        return truncated + suffix
    
    return text[:max_length]


def parse_semgrep_severity(severity: str) -> str:
    """Parse Semgrep severity to our standard format."""
    severity_map = {
        'ERROR': 'HIGH',
        'WARNING': 'MEDIUM',
        'INFO': 'LOW'
    }
    return severity_map.get(severity.upper(), 'MEDIUM')


def parse_semgrep_confidence(confidence: str) -> str:
    """Parse Semgrep confidence to our standard format."""
    confidence_map = {
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low'
    }
    return confidence_map.get(confidence.upper(), 'medium')


def extract_cwe_from_message(message: str) -> str:
    """Extract CWE ID from Semgrep message."""
    cwe_match = re.search(r'CWE-(\d+)', message, re.IGNORECASE)
    if cwe_match:
        return f"CWE-{cwe_match.group(1)}"
    return "CWE-000"  # Default unknown CWE


def calculate_suppression_rate(findings: List[Dict]) -> float:
    """Calculate suppression rate from findings."""
    if not findings:
        return 0.0
    
    suppressed = sum(1 for f in findings if f.get('status') == 'SUPPRESSED')
    return suppressed / len(findings)


def create_summary_stats(findings: List[Dict]) -> Dict:
    """Create summary statistics from findings."""
    summary = {
        'totals_by_severity': {},
        'totals_by_status': {},
        'by_cwe': {},
        'by_status': {}
    }
    
    for finding in findings:
        severity = finding.get('severity', 'MEDIUM')
        status = finding.get('status', 'ACTIVE')
        cwe = finding.get('cwe_id', 'CWE-000')
        
        # Count by severity
        summary['totals_by_severity'][severity] = summary['totals_by_severity'].get(severity, 0) + 1
        
        # Count by status
        summary['totals_by_status'][status] = summary['totals_by_status'].get(status, 0) + 1
        
        # Count by CWE
        summary['by_cwe'][cwe] = summary['by_cwe'].get(cwe, 0) + 1
        
        # Count by status and severity
        if status not in summary['by_status']:
            summary['by_status'][status] = {}
        summary['by_status'][status][severity] = summary['by_status'][status].get(severity, 0) + 1
    
    # Calculate suppression rate
    total = len(findings)
    suppressed = summary['totals_by_status'].get('SUPPRESSED', 0)
    summary['suppression_rate'] = suppressed / total if total > 0 else 0.0
    
    return summary


def create_scan_summary(findings: List[Dict]) -> Dict:
    """Create scan summary from findings (alias for create_summary_stats)."""
    return create_summary_stats(findings)


def paginate_results(results: List[Dict], limit: int, offset: int) -> Dict:
    """Paginate results with metadata."""
    total = len(results)
    paginated = results[offset:offset + limit]
    
    return {
        'results': paginated,
        'pagination': {
            'limit': limit,
            'offset': offset,
            'total': total
        }
    }


def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check for X-Forwarded-For header (common with proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to client host
    return request.client.host if request.client else "unknown"


def setup_logging(level: str = "info") -> None:
    """Setup logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def time_function(func):
    """Decorator to time function execution."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time
        
        # Log timing information
        logger = logging.getLogger(func.__module__)
        logger.debug(f"{func.__name__} took {duration:.3f} seconds")
        
        return result
    return wrapper


def validate_json_safe(obj: Any) -> bool:
    """Validate that object can be safely serialized to JSON."""
    try:
        import json
        json.dumps(obj)
        return True
    except (TypeError, ValueError):
        return False


def create_cache_key(*args) -> str:
    """Create a cache key from arguments."""
    key_parts = [as_utf8(arg) for arg in args]
    key_string = "|".join(key_parts)
    return hashlib.sha256(key_string.encode('utf-8')).hexdigest()


def is_safe_for_logging(text: str) -> bool:
    """Check if text is safe for logging (no sensitive data patterns)."""
    sensitive_patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
        r'\b[A-Za-z0-9+/]{20,}={0,2}\b',  # Base64 encoded data
        r'sk-[A-Za-z0-9]{20,}',  # OpenAI API key pattern
        r'ghp_[A-Za-z0-9]{36}',  # GitHub token pattern
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text):
            return False
    
    return True
