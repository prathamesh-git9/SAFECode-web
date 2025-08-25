"""Middleware module for SAFECode-Web backend."""

import time
import hashlib
import gzip
from typing import Dict, Any, Optional
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
import logging

from .config import get_config
from .utils import as_utf8, create_cache_key


class SimpleCache:
    """Simple in-memory cache with TTL."""
    
    def __init__(self, ttl_seconds: int = 120):
        """
        Initialize cache.
        
        Args:
            ttl_seconds: Time to live in seconds
        """
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, Any]] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Optional[Any]: Cached value or None
        """
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['timestamp'] < self.ttl_seconds:
                return entry['value']
            else:
                # Expired, remove it
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def clear(self):
        """Clear all cached items."""
        self.cache.clear()
    
    def size(self) -> int:
        """Get number of cached items."""
        return len(self.cache)


class GzipMiddleware:
    """Gzip compression middleware."""
    
    def __init__(self, min_size: int = 1024):
        """
        Initialize gzip middleware.
        
        Args:
            min_size: Minimum response size to compress (bytes)
        """
        self.min_size = min_size
    
    async def __call__(self, request: Request, call_next):
        """
        Process request and compress response if needed.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint
            
        Returns:
            Response: Compressed or original response
        """
        response = await call_next(request)
        
        # Check if response should be compressed
        if self._should_compress(response):
            return await self._compress_response(response)
        
        return response
    
    def _should_compress(self, response: Response) -> bool:
        """Check if response should be compressed."""
        # Don't compress if already compressed
        if 'content-encoding' in response.headers:
            return False
        
        # Check content type
        content_type = response.headers.get('content-type', '')
        if not any(ct in content_type.lower() for ct in ['json', 'text', 'xml', 'html']):
            return False
        
        # Check response size
        content_length = response.headers.get('content-length')
        if content_length:
            try:
                size = int(content_length)
                return size >= self.min_size
            except ValueError:
                pass
        
        return True
    
    async def _compress_response(self, response: Response) -> Response:
        """Compress response content."""
        try:
            # Get response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            # Compress
            compressed_body = gzip.compress(body)
            
            # Create new response
            compressed_response = Response(
                content=compressed_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type
            )
            
            # Add compression headers
            compressed_response.headers['content-encoding'] = 'gzip'
            compressed_response.headers['content-length'] = str(len(compressed_body))
            
            return compressed_response
            
        except Exception as e:
            logging.warning(f"Failed to compress response: {e}")
            return response


class CacheMiddleware:
    """Caching middleware for scan results."""
    
    def __init__(self, cache: SimpleCache):
        """
        Initialize cache middleware.
        
        Args:
            cache: Cache instance
        """
        self.cache = cache
    
    async def __call__(self, request: Request, call_next):
        """
        Process request with caching.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint
            
        Returns:
            Response: Cached or fresh response
        """
        # Only cache scan endpoints
        if request.url.path not in ['/scan', '/scan/raw']:
            return await call_next(request)
        
        # Create cache key
        cache_key = self._create_cache_key(request)
        
        # Check cache
        cached_response = self.cache.get(cache_key)
        if cached_response:
            return Response(
                content=cached_response['content'],
                status_code=cached_response['status_code'],
                headers=cached_response['headers'],
                media_type=cached_response['media_type']
            )
        
        # Get fresh response
        response = await call_next(request)
        
        # Cache successful responses
        if response.status_code == 200:
            try:
                # Get response body
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk
                
                # Cache response
                self.cache.set(cache_key, {
                    'content': body,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'media_type': response.media_type
                })
                
                # Return response with body
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
                
            except Exception as e:
                logging.warning(f"Failed to cache response: {e}")
        
        return response
    
    def _create_cache_key(self, request: Request) -> str:
        """Create cache key from request."""
        # Get request body
        body = b""
        try:
            body = request.body()
        except:
            pass
        
        # Create key from URL and body
        key_parts = [
            request.url.path,
            str(request.query_params),
            body.decode('utf-8', errors='replace') if body else ""
        ]
        
        return create_cache_key(*key_parts)


class UTF8SanitizationMiddleware:
    """UTF-8 sanitization middleware."""
    
    async def __call__(self, request: Request, call_next):
        """
        Process request with UTF-8 sanitization.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint
            
        Returns:
            Response: Sanitized response
        """
        # Process request
        response = await call_next(request)
        
        # Sanitize response headers
        sanitized_headers = {}
        for key, value in response.headers.items():
            sanitized_key = as_utf8(key)
            sanitized_value = as_utf8(value)
            sanitized_headers[sanitized_key] = sanitized_value
        
        # Get response body
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        
        # Sanitize response body if it's text
        content_type = response.headers.get('content-type', '')
        if any(ct in content_type.lower() for ct in ['json', 'text', 'xml', 'html']):
            try:
                body_text = body.decode('utf-8', errors='replace')
                sanitized_text = as_utf8(body_text)
                body = sanitized_text.encode('utf-8')
            except Exception as e:
                logging.warning(f"Failed to sanitize response body: {e}")
        
        # Return sanitized response
        return Response(
            content=body,
            status_code=response.status_code,
            headers=sanitized_headers,
            media_type=response.media_type
        )


class LoggingMiddleware:
    """Request logging middleware."""
    
    def __init__(self):
        """Initialize logging middleware."""
        self.logger = logging.getLogger(__name__)
    
    async def __call__(self, request: Request, call_next):
        """
        Process request with logging.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint
            
        Returns:
            Response: Response with logging
        """
        start_time = time.time()
        
        # Log request
        self.logger.info(f"Request: {request.method} {request.url.path}")
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log response
        self.logger.info(
            f"Response: {response.status_code} - {duration:.3f}s - {request.method} {request.url.path}"
        )
        
        # Add timing header
        response.headers['X-Response-Time'] = f"{duration:.3f}s"
        
        return response


# Global cache instance
_cache = None


def get_cache() -> SimpleCache:
    """Get the global cache instance."""
    global _cache
    
    if _cache is None:
        config = get_config()
        _cache = SimpleCache(ttl_seconds=config.cache_ttl_seconds)
    
    return _cache


def get_gzip_middleware() -> GzipMiddleware:
    """Get gzip middleware instance."""
    return GzipMiddleware(min_size=1024)


def get_cache_middleware() -> CacheMiddleware:
    """Get cache middleware instance."""
    cache = get_cache()
    return CacheMiddleware(cache)


def get_utf8_middleware() -> UTF8SanitizationMiddleware:
    """Get UTF-8 sanitization middleware instance."""
    return UTF8SanitizationMiddleware()


def get_logging_middleware() -> LoggingMiddleware:
    """Get logging middleware instance."""
    return LoggingMiddleware()
