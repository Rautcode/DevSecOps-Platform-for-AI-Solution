"""
Authentication Middleware
FastAPI middleware for authentication and rate limiting
"""

import time
import asyncio
from typing import Optional, Dict, Any, Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..core.production_logging import get_logger
from .models import User, UserRole
from .auth_manager import AuthManager


logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for FastAPI
    Validates JWT tokens and sets user context
    """
    
    def __init__(self, app, auth_manager: AuthManager):
        super().__init__(app)
        self.auth_manager = auth_manager
        
        # Paths that don't require authentication
        self.excluded_paths = {
            "/",
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and validate authentication"""
        
        # Skip authentication for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)
        
        # Extract token from request
        token = self._extract_token(request)
        
        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication required"}
            )
        
        # Verify token and get user
        user = await self.auth_manager.verify_token(token)
        
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired token"}
            )
        
        if not user.is_active:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Account is disabled"}
            )
        
        # Set user in request state
        request.state.user = user
        request.state.correlation_id = f"req_{int(time.time())}_{user.id}"
        
        # Log request
        logger.info(
            "Authenticated request",
            extra={
                "user_id": user.id,
                "username": user.username,
                "path": request.url.path,
                "method": request.method,
                "correlation_id": request.state.correlation_id,
                "ip_address": self._get_client_ip(request)
            }
        )
        
        response = await call_next(request)
        return response
    
    def _extract_token(self, request: Request) -> Optional[str]:
        """Extract JWT token from request"""
        # Try Authorization header first
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.split(" ")[1]
        
        # Try cookie
        token = request.cookies.get("access_token")
        if token:
            return token
        
        return None
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check for forwarded IP (in case of proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware
    Implements rate limiting based on IP address and user
    """
    
    def __init__(
        self, 
        app, 
        requests_per_minute: int = 60,
        burst_limit: int = 10
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        
        # In-memory storage (in production, use Redis)
        self.request_counts: Dict[str, list] = {}
        self.blocked_ips: Dict[str, float] = {}
        
        # Cleanup interval
        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # seconds
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and check rate limits"""
        
        # Get client identifier
        client_id = self._get_client_identifier(request)
        current_time = time.time()
        
        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            await self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Check if IP is temporarily blocked
        if client_id in self.blocked_ips:
            if current_time < self.blocked_ips[client_id]:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Rate limit exceeded. Try again later.",
                        "retry_after": int(self.blocked_ips[client_id] - current_time)
                    }
                )
            else:
                # Unblock IP
                del self.blocked_ips[client_id]
        
        # Check rate limit
        if not self._is_request_allowed(client_id, current_time):
            # Block IP for 5 minutes
            self.blocked_ips[client_id] = current_time + 300
            
            logger.warning(
                f"Rate limit exceeded for {client_id}",
                extra={
                    "client_id": client_id,
                    "path": request.url.path,
                    "user_agent": request.headers.get("User-Agent", ""),
                }
            )
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Access temporarily blocked.",
                    "retry_after": 300
                }
            )
        
        # Record this request
        self._record_request(client_id, current_time)
        
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = self._get_remaining_requests(client_id, current_time)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response
    
    def _get_client_identifier(self, request: Request) -> str:
        """Get unique identifier for client"""
        # Use user ID if authenticated
        if hasattr(request.state, "user") and request.state.user:
            return f"user_{request.state.user.id}"
        
        # Otherwise use IP address
        return self._get_client_ip(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _is_request_allowed(self, client_id: str, current_time: float) -> bool:
        """Check if request is allowed based on rate limits"""
        if client_id not in self.request_counts:
            return True
        
        # Remove requests older than 1 minute
        recent_requests = [
            req_time for req_time in self.request_counts[client_id]
            if current_time - req_time < 60
        ]
        
        self.request_counts[client_id] = recent_requests
        
        # Check if within limits
        return len(recent_requests) < self.requests_per_minute
    
    def _record_request(self, client_id: str, current_time: float) -> None:
        """Record a request for rate limiting"""
        if client_id not in self.request_counts:
            self.request_counts[client_id] = []
        
        self.request_counts[client_id].append(current_time)
        
        # Keep only recent requests to manage memory
        self.request_counts[client_id] = [
            req_time for req_time in self.request_counts[client_id]
            if current_time - req_time < 60
        ]
    
    def _get_remaining_requests(self, client_id: str, current_time: float) -> int:
        """Get remaining requests for the current window"""
        if client_id not in self.request_counts:
            return self.requests_per_minute
        
        recent_requests = [
            req_time for req_time in self.request_counts[client_id]
            if current_time - req_time < 60
        ]
        
        return max(0, self.requests_per_minute - len(recent_requests))
    
    async def _cleanup_old_entries(self, current_time: float) -> None:
        """Cleanup old entries to manage memory"""
        # Clean request counts
        for client_id in list(self.request_counts.keys()):
            recent_requests = [
                req_time for req_time in self.request_counts[client_id]
                if current_time - req_time < 120  # Keep 2 minutes of data
            ]
            
            if recent_requests:
                self.request_counts[client_id] = recent_requests
            else:
                del self.request_counts[client_id]
        
        # Clean blocked IPs
        for client_id in list(self.blocked_ips.keys()):
            if current_time >= self.blocked_ips[client_id]:
                del self.blocked_ips[client_id]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware
    Adds security headers to all responses
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response"""
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # HSTS (only in production with HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
