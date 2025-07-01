"""
Input Validation and Sanitization Module
Enterprise-grade input validation for production security
"""

import re
import html
import logging
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, validator, Field
from fastapi import HTTPException, status
from datetime import datetime
import ipaddress
import urllib.parse

from .config import ProductionSettings
from .logging_config import log_security_event


class SecurityValidationError(Exception):
    """Security validation error"""
    pass


class InputSanitizer:
    """Input sanitization and validation utilities"""
    
    # Security patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|\#|\/\*|\*\/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\'\s*(OR|AND)\s+\'\d+\'\s*=\s*\'\d+)",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(\||\&|\;|\$\(|\`)",
        r"(nc|netcat|wget|curl|ping|nslookup|dig)",
        r"(\.\./|\.\.\\\)",
        r"(/etc/passwd|/etc/shadow|cmd\.exe|powershell)",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"\.\.%2f",
        r"\.\.%5c",
    ]
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """Sanitize string input with security checks"""
        if not isinstance(value, str):
            raise SecurityValidationError("Input must be a string")
        
        # Length check
        if len(value) > max_length:
            raise SecurityValidationError(f"Input exceeds maximum length of {max_length}")
        
        # SQL injection detection
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                log_security_event(
                    event_type="sql_injection_attempt",
                    description=f"SQL injection pattern detected: {pattern}",
                    severity="HIGH",
                    metadata={"input": value[:100]}
                )
                raise SecurityValidationError("Potentially malicious SQL pattern detected")
        
        # XSS detection
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                log_security_event(
                    event_type="xss_attempt",
                    description=f"XSS pattern detected: {pattern}",
                    severity="HIGH",
                    metadata={"input": value[:100]}
                )
                raise SecurityValidationError("Potentially malicious XSS pattern detected")
        
        # Command injection detection
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                log_security_event(
                    event_type="command_injection_attempt",
                    description=f"Command injection pattern detected: {pattern}",
                    severity="HIGH",
                    metadata={"input": value[:100]}
                )
                raise SecurityValidationError("Potentially malicious command pattern detected")
        
        # Path traversal detection
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                log_security_event(
                    event_type="path_traversal_attempt",
                    description=f"Path traversal pattern detected: {pattern}",
                    severity="HIGH",
                    metadata={"input": value[:100]}
                )
                raise SecurityValidationError("Path traversal attempt detected")
        
        # HTML encode for XSS prevention
        return html.escape(value.strip())
    
    @classmethod
    def validate_email(cls, email: str) -> str:
        """Validate and sanitize email address"""
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        
        if not re.match(email_pattern, email):
            raise SecurityValidationError("Invalid email format")
        
        if len(email) > 254:  # RFC 5321 limit
            raise SecurityValidationError("Email address too long")
        
        return email.lower().strip()
    
    @classmethod
    def validate_ip_address(cls, ip: str) -> str:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise SecurityValidationError("Invalid IP address format")
    
    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate and sanitize URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise SecurityValidationError("URL must use HTTP or HTTPS")
            
            # Check for localhost/private IPs in production
            if parsed.hostname:
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private or ip.is_loopback:
                        settings = ProductionSettings()
                        if settings.environment == "production":
                            raise SecurityValidationError("Private/localhost URLs not allowed in production")
                except ValueError:
                    pass  # Not an IP address, hostname is OK
            
            return url
        except Exception as e:
            raise SecurityValidationError(f"Invalid URL: {str(e)}")
    
    @classmethod
    def validate_json_size(cls, data: Dict[str, Any], max_size_mb: int = 10) -> Dict[str, Any]:
        """Validate JSON payload size"""
        import json
        
        try:
            json_str = json.dumps(data)
            size_mb = len(json_str.encode('utf-8')) / (1024 * 1024)
            
            if size_mb > max_size_mb:
                raise SecurityValidationError(f"JSON payload exceeds {max_size_mb}MB limit")
            
            return data
        except (TypeError, ValueError) as e:
            raise SecurityValidationError(f"Invalid JSON data: {str(e)}")


# Pydantic models for request validation
class SecureBaseModel(BaseModel):
    """Base model with security validation"""
    
    model_config = {
        # Prevent extra fields
        "extra": "forbid",
        # Validate on assignment
        "validate_assignment": True,
        # Use enum values
        "use_enum_values": True,
    }


class SecureStringField(str):
    """Secure string field with automatic sanitization"""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v, field=None):
        if not isinstance(v, str):
            raise ValueError('String required')
        
        max_length = getattr(field, 'max_length', 1000) if field else 1000
        return InputSanitizer.sanitize_string(v, max_length)


class UserRegistrationRequest(SecureBaseModel):
    """Secure user registration request model"""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=100)
    department: Optional[str] = Field(None, max_length=100)
    
    @validator('email')
    def validate_email(cls, v):
        return InputSanitizer.validate_email(v)
    
    @validator('password')
    def validate_password(cls, v):
        # Password complexity requirements
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        
        return v
    
    @validator('full_name', 'department')
    def validate_text_fields(cls, v):
        if v is None:
            return v
        return InputSanitizer.sanitize_string(v, 100)


class LoginRequest(SecureBaseModel):
    """Secure login request model"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)
    remember_me: bool = Field(False)
    
    @validator('username')
    def validate_username(cls, v):
        return InputSanitizer.sanitize_string(v, 50)


class PolicyRequest(SecureBaseModel):
    """Secure policy request model"""
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=10, max_length=1000)
    severity: str = Field(..., pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    enabled: bool = Field(True)
    rules: List[Dict[str, Any]] = Field(..., min_items=1, max_items=50)
    
    @validator('name', 'description')
    def validate_text_fields(cls, v):
        return InputSanitizer.sanitize_string(v)
    
    @validator('rules')
    def validate_rules(cls, v):
        return InputSanitizer.validate_json_size({"rules": v}, max_size_mb=1)["rules"]


class SecurityFindingRequest(SecureBaseModel):
    """Secure security finding request model"""
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=2000)
    severity: str = Field(..., pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    resource: str = Field(..., min_length=1, max_length=500)
    source: str = Field(..., pattern=r"^(aws|azure|manual)$")
    
    @validator('title', 'description', 'resource')
    def validate_text_fields(cls, v):
        return InputSanitizer.sanitize_string(v)


# Validation middleware
async def validate_request_size(request, max_size_mb: int = 10):
    """Validate request body size"""
    if hasattr(request, 'headers'):
        content_length = request.headers.get('content-length')
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            if size_mb > max_size_mb:
                log_security_event(
                    event_type="oversized_request",
                    description=f"Request exceeds {max_size_mb}MB limit: {size_mb:.2f}MB",
                    severity="MEDIUM"
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Request body too large. Maximum {max_size_mb}MB allowed."
                )


def create_validation_error_response(errors: List[Dict[str, Any]]) -> HTTPException:
    """Create standardized validation error response"""
    log_security_event(
        event_type="validation_error",
        description="Request validation failed",
        severity="LOW",
        metadata={"errors": errors}
    )
    
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "message": "Validation failed",
            "errors": errors,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
