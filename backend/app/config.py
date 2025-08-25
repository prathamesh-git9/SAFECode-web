"""Configuration management for SAFECode-Web backend."""
import os
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class Config:
    """Application configuration."""
    # API Configuration
    api_token: str
    host: str = "0.0.0.0"
    port: int = 8001
    
    # Analyzer Configuration
    analyzer: str = "flawfinder"  # choices: "flawfinder", "semgrep"
    flawfinder_path: str = "flawfinder"
    flawfinder_max_findings: int = 1000
    flawfinder_timeout: int = 60
    
    # Semgrep Configuration (legacy)
    semgrep_timeout: int = 60
    semgrep_jobs: int = 4
    semgrep_max_findings: int = 250
    semgrep_max_target_bytes: int = 2000000
    
    # Response Limits
    safe_max_findings_response: int = 200
    safe_max_inline_code_chars: int = 20000
    safe_max_snippet_chars: int = 600
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600
    
    # AI Configuration
    enable_gpt: bool = False
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    
    # Caching
    cache_ttl_seconds: int = 120
    
    # Logging
    log_level: str = "info"
    
    # Safety Gates
    never_suppress_funcs: List[str] = None
    safe_strict_min_thresholds: Dict[str, float] = None
    
    def __post_init__(self):
        """Initialize default values for complex fields."""
        if self.never_suppress_funcs is None:
            self.never_suppress_funcs = [
                "strcpy", "strcat", "gets", "sprintf", "vsprintf", 
                "system", "popen"
            ]
        
        if self.safe_strict_min_thresholds is None:
            self.safe_strict_min_thresholds = {
                "CWE-120": 0.95, "CWE-121": 0.95, "CWE-122": 0.95,
                "CWE-415": 0.95, "CWE-416": 0.95,
                "CWE-78": 0.99, "CWE-134": 0.95,
                "CWE-22": 0.95, "CWE-367": 0.95, "CWE-330": 0.95,
                "CWE-190": 0.95, "CWE-191": 0.95, "CWE-787": 0.95,
                "CWE-467": 0.95
            }

def get_config() -> Config:
    """Get application configuration from environment variables."""
    return Config(
        # API Configuration
        api_token=os.getenv("SAFECODE_API_TOKEN", "test-token"),
        host=os.getenv("SAFECODE_HOST", "0.0.0.0"),
        port=int(os.getenv("SAFECODE_PORT", "8001")),
        
        # Analyzer Configuration
        analyzer=os.getenv("ANALYZER", "flawfinder"),
        flawfinder_path=os.getenv("FLAWFINDER_PATH", "flawfinder"),
        flawfinder_max_findings=int(os.getenv("FLAWFINDER_MAX_FINDINGS", "1000")),
        flawfinder_timeout=int(os.getenv("FLAWFINDER_TIMEOUT", "60")),
        
        # Semgrep Configuration (legacy)
        semgrep_timeout=int(os.getenv("SEMGREP_TIMEOUT", "60")),
        semgrep_jobs=int(os.getenv("SEMGREP_JOBS", "4")),
        semgrep_max_findings=int(os.getenv("SEMGREP_MAX_FINDINGS", "250")),
        semgrep_max_target_bytes=int(os.getenv("SEMGREP_MAX_TARGET_BYTES", "2000000")),
        
        # Response Limits
        safe_max_findings_response=int(os.getenv("SAFE_MAX_FINDINGS_RESPONSE", "200")),
        safe_max_inline_code_chars=int(os.getenv("SAFE_MAX_INLINE_CODE_CHARS", "20000")),
        safe_max_snippet_chars=int(os.getenv("SAFE_MAX_SNIPPET_CHARS", "600")),
        
        # Rate Limiting
        rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "100")),
        rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "3600")),
        
        # AI Configuration
        enable_gpt=os.getenv("ENABLE_GPT", "false").lower() == "true",
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        
        # Caching
        cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "120")),
        
        # Logging
        log_level=os.getenv("LOG_LEVEL", "info"),
    )

def validate_config(config: Config) -> List[str]:
    """Validate configuration and return list of errors."""
    errors = []
    
    if not config.api_token:
        errors.append("SAFECODE_API_TOKEN not set")
    
    if config.analyzer not in ["flawfinder", "semgrep"]:
        errors.append(f"Invalid analyzer: {config.analyzer}. Must be 'flawfinder' or 'semgrep'")
    
    if config.enable_gpt and not config.openai_api_key:
        errors.append("ENABLE_GPT=true but OPENAI_API_KEY not set")
    
    if config.port < 1 or config.port > 65535:
        errors.append(f"Invalid port: {config.port}")
    
    return errors
