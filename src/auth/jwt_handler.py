"""
JWT Token Handler
Secure token generation, validation, and management
"""

import jwt
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any, Tuple
from pydantic import ValidationError

from ..core.production_config import SecuritySettings
from .models import User, UserRole


class JWTHandler:
    """
    JWT token handler with advanced security features
    """
    
    def __init__(self, security_settings: SecuritySettings):
        self.security_settings = security_settings
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
        
    def _get_secret_key(self) -> str:
        """Get JWT secret key"""
        if self.security_settings.jwt_secret:
            return self.security_settings.jwt_secret.get_secret_value()
        return self.security_settings.secret_key.get_secret_value()
    
    def create_access_token(
        self, 
        user: User, 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token
        
        Args:
            user: User object
            expires_delta: Custom expiration time
            
        Returns:
            JWT access token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.access_token_expire_minutes
            )
        
        # Core claims
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": "devsecops-platform",
            "aud": "devsecops-api",
            "type": "access",
            "jti": secrets.token_urlsafe(32),  # JWT ID for revocation
        }
        
        # Add user metadata
        payload.update({
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "is_superuser": user.is_superuser,
        })
        
        return jwt.encode(payload, self._get_secret_key(), algorithm=self.algorithm)
    
    def create_refresh_token(
        self, 
        user: User, 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token
        
        Args:
            user: User object
            expires_delta: Custom expiration time
            
        Returns:
            JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=self.refresh_token_expire_days
            )
        
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": "devsecops-platform",
            "aud": "devsecops-api",
            "type": "refresh",
            "jti": secrets.token_urlsafe(32),
        }
        
        return jwt.encode(payload, self._get_secret_key(), algorithm=self.algorithm)
    
    def create_token_pair(self, user: User) -> Tuple[str, str]:
        """
        Create both access and refresh tokens
        
        Args:
            user: User object
            
        Returns:
            Tuple of (access_token, refresh_token)
        """
        access_token = self.create_access_token(user)
        refresh_token = self.create_refresh_token(user)
        return access_token, refresh_token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token to verify
            
        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token, 
                self._get_secret_key(), 
                algorithms=[self.algorithm],
                audience="devsecops-api",
                issuer="devsecops-platform"
            )
            
            # Verify token type exists
            if "type" not in payload:
                return None
                
            # Check if token is expired
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except jwt.InvalidSignatureError:
            return None
        except jwt.InvalidAudienceError:
            return None
        except jwt.InvalidIssuerError:
            return None
        except Exception:
            return None
    
    def get_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Extract user information from token
        
        Args:
            token: JWT token
            
        Returns:
            User information if token is valid, None otherwise
        """
        payload = self.verify_token(token)
        if not payload:
            return None
            
        # Extract user information
        return {
            "id": int(payload["sub"]),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "role": payload.get("role"),
            "is_active": payload.get("is_active", True),
            "is_verified": payload.get("is_verified", False),
            "is_superuser": payload.get("is_superuser", False),
            "jti": payload.get("jti"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
        }
    
    def is_access_token(self, token: str) -> bool:
        """Check if token is an access token"""
        payload = self.verify_token(token)
        return payload is not None and payload.get("type") == "access"
    
    def is_refresh_token(self, token: str) -> bool:
        """Check if token is a refresh token"""
        payload = self.verify_token(token)
        return payload is not None and payload.get("type") == "refresh"
    
    def get_token_jti(self, token: str) -> Optional[str]:
        """Get JWT ID for token revocation"""
        payload = self.verify_token(token)
        return payload.get("jti") if payload else None
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Create new access token from refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New access token if refresh token is valid, None otherwise
        """
        if not self.is_refresh_token(refresh_token):
            return None
        
        payload = self.verify_token(refresh_token)
        if not payload:
            return None
        
        # Create minimal user object for new access token
        user_data = {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "email": payload.get("email", ""),
            "role": UserRole(payload.get("role", UserRole.VIEWER.value)),
            "is_active": payload.get("is_active", True),
            "is_verified": payload.get("is_verified", False),
            "is_superuser": payload.get("is_superuser", False),
        }
        
        # Create a temporary User object
        from types import SimpleNamespace
        temp_user = SimpleNamespace(**user_data)
        
        return self.create_access_token(temp_user)
    
    def create_password_reset_token(self, user_id: int, email: str) -> str:
        """
        Create password reset token
        
        Args:
            user_id: User ID
            email: User email
            
        Returns:
            Password reset token
        """
        expire = datetime.now(timezone.utc) + timedelta(hours=1)  # 1 hour expiry
        
        payload = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": "devsecops-platform",
            "aud": "devsecops-api",
            "type": "password_reset",
            "jti": secrets.token_urlsafe(32),
        }
        
        return jwt.encode(payload, self._get_secret_key(), algorithm=self.algorithm)
    
    def verify_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify password reset token
        
        Args:
            token: Password reset token
            
        Returns:
            Token payload if valid, None otherwise
        """
        payload = self.verify_token(token)
        if not payload or payload.get("type") != "password_reset":
            return None
        return payload
    
    def create_email_verification_token(self, user_id: int, email: str) -> str:
        """
        Create email verification token
        
        Args:
            user_id: User ID
            email: User email
            
        Returns:
            Email verification token
        """
        expire = datetime.now(timezone.utc) + timedelta(days=1)  # 24 hours
        
        payload = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": "devsecops-platform",
            "aud": "devsecops-api",
            "type": "email_verification",
            "jti": secrets.token_urlsafe(32),
        }
        
        return jwt.encode(payload, self._get_secret_key(), algorithm=self.algorithm)
    
    def verify_email_verification_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify email verification token
        
        Args:
            token: Email verification token
            
        Returns:
            Token payload if valid, None otherwise
        """
        payload = self.verify_token(token)
        if not payload or payload.get("type") != "email_verification":
            return None
        return payload
