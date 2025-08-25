"""Configuration management for SAFECode-Web backend."""

import os
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration with environment variable support."""
    
    # API Authentication
    api_token: str = os.getenv("SAFECODE_API_TOKEN", "")
    
    # Semgrep Configuration
    semgrep_timeout: int = int(os.getenv("SEMGREP_TIMEOUT", "60"))
    semgrep_jobs: int = int(os.getenv("SEMGREP_JOBS", "4"))
    semgrep_max_findings: int = int(os.getenv("SEMGREP_MAX_FINDINGS", "250"))
    semgrep_max_target_bytes: int = int(os.getenv("SEMGREP_MAX_TARGET_BYTES", "2000000"))
    
    # Response Limits
    safe_max_findings_response: int = int(os.getenv("SAFE_MAX_FINDINGS_RESPONSE", "200"))
    safe_max_inline_code_chars: int = int(os.getenv("SAFE_MAX_INLINE_CODE_CHARS", "20000"))
    safe_max_snippet_chars: int = int(os.getenv("SAFE_MAX_SNIPPET_CHARS", "600"))
    
    # Rate Limiting
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))
    
    # AI/OpenAI Configuration
    enable_gpt: bool = os.getenv("ENABLE_GPT", "false").lower() == "true"
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    # Caching
    cache_ttl_seconds: int = int(os.getenv("CACHE_TTL_SECONDS", "120"))
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "info").lower()
    
    # Server Configuration
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8001"))
    
    # Suppression Safety Gates
    NEVER_SUPPRESS_FUNCS = [
        "strcpy", "strcat", "gets", "sprintf", "vsprintf", 
        "system", "popen"
    ]
    
    STRICT_MIN = {
        "CWE-120": 0.95, "CWE-121": 0.95, "CWE-122": 0.95,
        "CWE-415": 0.95, "CWE-416": 0.95,
        "CWE-78": 0.99,  "CWE-134": 0.95
    }


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance."""
    return config


def validate_config() -> Dict[str, Any]:
    """Validate configuration and return any issues."""
    issues = []
    
    if not config.api_token:
        issues.append("SAFECODE_API_TOKEN not set")
    
    if config.enable_gpt and not config.openai_api_key:
        issues.append("ENABLE_GPT=true but OPENAI_API_KEY not set")
    
    if config.semgrep_timeout < 10:
        issues.append("SEMGREP_TIMEOUT should be at least 10 seconds")
    
    if config.safe_max_findings_response < 1:
        issues.append("SAFE_MAX_FINDINGS_RESPONSE should be at least 1")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": []
    }
