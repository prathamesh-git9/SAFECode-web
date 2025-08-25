"""Rate limiting module for SAFECode-Web backend."""

import time
from typing import Dict, List, Tuple
from collections import defaultdict
import threading

from .config import get_config
from .utils import get_client_ip


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, client_ip: str) -> Tuple[bool, Dict[str, int]]:
        """
        Check if request is allowed for the client.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Tuple[bool, Dict]: (allowed, rate limit info)
        """
        current_time = time.time()
        
        with self.lock:
            # Clean old requests outside the window
            window_start = current_time - self.window_seconds
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if req_time > window_start
            ]
            
            # Check if under limit
            current_requests = len(self.requests[client_ip])
            allowed = current_requests < self.max_requests
            
            if allowed:
                # Add current request
                self.requests[client_ip].append(current_time)
                current_requests += 1
            
            # Calculate reset time (next window start)
            if self.requests[client_ip]:
                reset_time = int(max(self.requests[client_ip]) + self.window_seconds)
            else:
                reset_time = int(current_time + self.window_seconds)
            
            rate_limit_info = {
                'limit': self.max_requests,
                'remaining': max(0, self.max_requests - current_requests),
                'reset': reset_time
            }
            
            return allowed, rate_limit_info
    
    def get_info(self, client_ip: str) -> Dict[str, int]:
        """
        Get rate limit information without consuming a request.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Dict: Rate limit information
        """
        current_time = time.time()
        
        with self.lock:
            # Clean old requests outside the window
            window_start = current_time - self.window_seconds
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if req_time > window_start
            ]
            
            current_requests = len(self.requests[client_ip])
            
            # Calculate reset time
            if self.requests[client_ip]:
                reset_time = int(max(self.requests[client_ip]) + self.window_seconds)
            else:
                reset_time = int(current_time + self.window_seconds)
            
            return {
                'limit': self.max_requests,
                'remaining': max(0, self.max_requests - current_requests),
                'reset': reset_time
            }


# Global rate limiter instance
_rate_limiter = None


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    
    if _rate_limiter is None:
        config = get_config()
        _rate_limiter = SlidingWindowRateLimiter(
            max_requests=config.rate_limit_requests,
            window_seconds=config.rate_limit_window
        )
    
    return _rate_limiter


def check_rate_limit(request) -> Dict[str, int]:
    """
    Check rate limit for a request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dict: Rate limit information
        
    Raises:
        HTTPException: If rate limit exceeded
    """
    from fastapi import HTTPException
    
    client_ip = get_client_ip(request)
    rate_limiter = get_rate_limiter()
    
    allowed, rate_limit_info = rate_limiter.is_allowed(client_ip)
    
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                'X-RateLimit-Limit': str(rate_limit_info['limit']),
                'X-RateLimit-Remaining': str(rate_limit_info['remaining']),
                'X-RateLimit-Reset': str(rate_limit_info['reset']),
                'Retry-After': str(rate_limit_info['reset'] - int(time.time()))
            }
        )
    
    return rate_limit_info


def get_rate_limit_info(request) -> Dict[str, int]:
    """
    Get rate limit information without consuming a request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dict: Rate limit information
    """
    client_ip = get_client_ip(request)
    rate_limiter = get_rate_limiter()
    
    return rate_limiter.get_info(client_ip)


def add_rate_limit_headers(response, rate_limit_info: Dict[str, int]):
    """
    Add rate limit headers to response.
    
    Args:
        response: FastAPI response object
        rate_limit_info: Rate limit information
    """
    response.headers['X-RateLimit-Limit'] = str(rate_limit_info['limit'])
    response.headers['X-RateLimit-Remaining'] = str(rate_limit_info['remaining'])
    response.headers['X-RateLimit-Reset'] = str(rate_limit_info['reset'])
