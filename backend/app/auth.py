"""Authentication module for SAFECode-Web backend."""

import hmac
import hashlib
from typing import Optional
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import get_config
from .utils import as_utf8


security = HTTPBearer(auto_error=False)


def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    """
    Require valid Bearer token authentication.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        str: The authenticated token
        
    Raises:
        HTTPException: If authentication fails
    """
    config = get_config()
    
    if not config.api_token:
        # If no token is configured, allow all requests
        return "no-auth-required"
    
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = as_utf8(credentials.credentials)
    
    if not verify_token(token, config.api_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return token


def verify_token(provided_token: str, expected_token: str) -> bool:
    """
    Verify token using constant-time comparison.
    
    Args:
        provided_token: Token provided by client
        expected_token: Expected token from configuration
        
    Returns:
        bool: True if tokens match, False otherwise
    """
    if not provided_token or not expected_token:
        return False
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(
        provided_token.encode('utf-8'),
        expected_token.encode('utf-8')
    )


def optional_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[str]:
    """
    Optional authentication - returns token if valid, None if not provided or invalid.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        Optional[str]: The authenticated token or None
    """
    config = get_config()
    
    if not config.api_token:
        return "no-auth-required"
    
    if not credentials:
        return None
    
    token = as_utf8(credentials.credentials)
    
    if verify_token(token, config.api_token):
        return token
    
    return None


def get_auth_status(request: Request) -> dict:
    """
    Get authentication status for the request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        dict: Authentication status information
    """
    config = get_config()
    
    if not config.api_token:
        return {
            "authenticated": True,
            "method": "none",
            "reason": "No authentication required"
        }
    
    auth_header = request.headers.get("Authorization")
    
    if not auth_header:
        return {
            "authenticated": False,
            "method": "bearer",
            "reason": "No Authorization header"
        }
    
    if not auth_header.startswith("Bearer "):
        return {
            "authenticated": False,
            "method": "bearer",
            "reason": "Invalid Authorization header format"
        }
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    if verify_token(token, config.api_token):
        return {
            "authenticated": True,
            "method": "bearer",
            "reason": "Valid token"
        }
    else:
        return {
            "authenticated": False,
            "method": "bearer",
            "reason": "Invalid token"
        }
