"""
Authentication and Authorization Module
Production-grade security for DevSecOps Platform
"""

from .auth_manager import AuthManager
from .jwt_handler import JWTHandler
from .rbac import RBACManager, Permission, Role
from .models import User, UserRole, AuthResponse
from .middleware import AuthMiddleware, RateLimitMiddleware
from .dependencies import get_current_user, require_permission, require_role

__all__ = [
    "AuthManager",
    "JWTHandler", 
    "RBACManager",
    "Permission",
    "Role",
    "User",
    "UserRole",
    "AuthResponse",
    "AuthMiddleware",
    "RateLimitMiddleware",
    "get_current_user",
    "require_permission",
    "require_role"
]
