"""
FastAPI Dependencies for Authentication
Security dependencies and permission checks
"""

from typing import Optional, List
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .models import User, UserRole, Permission
from .auth_manager import AuthManager
from .rbac import RBACManager


# Global instances (will be set during app initialization)
auth_manager: Optional[AuthManager] = None
rbac_manager: Optional[RBACManager] = None

# HTTP Bearer token security scheme
security = HTTPBearer(auto_error=False)


def set_auth_dependencies(auth_mgr: AuthManager, rbac_mgr: RBACManager) -> None:
    """Set global authentication dependencies"""
    global auth_manager, rbac_manager
    auth_manager = auth_mgr
    rbac_manager = rbac_mgr


async def get_current_user(request: Request) -> User:
    """
    Get current authenticated user from request
    Used as FastAPI dependency
    """
    if not hasattr(request.state, "user") or not request.state.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return request.state.user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current active user
    Ensures user account is active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    return current_user


async def get_current_verified_user(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get current verified user
    Ensures user account is verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required"
        )
    
    return current_user


async def get_current_superuser(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Get current superuser
    Ensures user has superuser privileges
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser privileges required"
        )
    
    return current_user


def require_role(required_role: UserRole):
    """
    Dependency factory for role-based access control
    
    Args:
        required_role: Required user role
        
    Returns:
        FastAPI dependency function
    """
    async def check_role(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role != required_role and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role.value}' required"
            )
        return current_user
    
    return check_role


def require_permission(required_permission: Permission):
    """
    Dependency factory for permission-based access control
    
    Args:
        required_permission: Required permission
        
    Returns:
        FastAPI dependency function
    """
    async def check_permission(current_user: User = Depends(get_current_active_user)) -> User:
        if not rbac_manager:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="RBAC not initialized"
            )
        
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        # Check if user has required permission
        if not rbac_manager.user_has_permission(current_user.role, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{required_permission.value}' required"
            )
        
        return current_user
    
    return check_permission


def require_any_permission(required_permissions: List[Permission]):
    """
    Dependency factory for multiple permission options
    User needs at least one of the specified permissions
    
    Args:
        required_permissions: List of permissions (user needs at least one)
        
    Returns:
        FastAPI dependency function
    """
    async def check_any_permission(current_user: User = Depends(get_current_active_user)) -> User:
        if not rbac_manager:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="RBAC not initialized"
            )
        
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        # Check if user has any of the required permissions
        if not rbac_manager.user_has_any_permission(current_user.role, required_permissions):
            permission_names = [perm.value for perm in required_permissions]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these permissions required: {', '.join(permission_names)}"
            )
        
        return current_user
    
    return check_any_permission


def require_all_permissions(required_permissions: List[Permission]):
    """
    Dependency factory for multiple required permissions
    User needs all of the specified permissions
    
    Args:
        required_permissions: List of permissions (user needs all)
        
    Returns:
        FastAPI dependency function
    """
    async def check_all_permissions(current_user: User = Depends(get_current_active_user)) -> User:
        if not rbac_manager:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="RBAC not initialized"
            )
        
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        # Check if user has all required permissions
        if not rbac_manager.user_has_all_permissions(current_user.role, required_permissions):
            permission_names = [perm.value for perm in required_permissions]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"All of these permissions required: {', '.join(permission_names)}"
            )
        
        return current_user
    
    return check_all_permissions


def require_resource_access(resource_type: str, action: str):
    """
    Dependency factory for resource-based access control
    
    Args:
        resource_type: Type of resource (e.g., 'policy', 'user', 'vault')
        action: Action to perform (e.g., 'read', 'write', 'delete')
        
    Returns:
        FastAPI dependency function
    """
    async def check_resource_access(current_user: User = Depends(get_current_active_user)) -> User:
        if not rbac_manager:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="RBAC not initialized"
            )
        
        # Superusers have all access
        if current_user.is_superuser:
            return current_user
        
        # Check resource access
        if not rbac_manager.can_access_resource(current_user.role, resource_type, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied for {action} operation on {resource_type}"
            )
        
        return current_user
    
    return check_resource_access


# Convenience dependencies for common use cases
require_admin = require_role(UserRole.ADMIN)
require_security_analyst = require_role(UserRole.SECURITY_ANALYST)
require_policy_manager = require_role(UserRole.POLICY_MANAGER)
require_compliance_officer = require_role(UserRole.COMPLIANCE_OFFICER)
require_ai_engineer = require_role(UserRole.AI_ENGINEER)
require_auditor = require_role(UserRole.AUDITOR)

# Permission-based dependencies
require_user_read = require_permission(Permission.READ_USER)
require_user_create = require_permission(Permission.CREATE_USER)
require_user_update = require_permission(Permission.UPDATE_USER)
require_user_delete = require_permission(Permission.DELETE_USER)

require_policy_read = require_permission(Permission.READ_POLICY)
require_policy_create = require_permission(Permission.CREATE_POLICY)
require_policy_update = require_permission(Permission.UPDATE_POLICY)
require_policy_delete = require_permission(Permission.DELETE_POLICY)
require_policy_execute = require_permission(Permission.EXECUTE_POLICY)

require_vault_read = require_permission(Permission.READ_SECRETS)
require_vault_write = require_permission(Permission.WRITE_SECRETS)
require_vault_manage = require_permission(Permission.MANAGE_VAULT)

require_security_read = require_permission(Permission.READ_SECURITY_EVENTS)
require_security_create = require_permission(Permission.CREATE_SECURITY_EVENTS)
require_security_manage = require_permission(Permission.MANAGE_ALERTS)

require_cloud_read = require_permission(Permission.READ_CLOUD_SECURITY)
require_cloud_manage = require_permission(Permission.MANAGE_CLOUD_SECURITY)

require_compliance_read = require_permission(Permission.READ_COMPLIANCE)
require_compliance_manage = require_permission(Permission.MANAGE_COMPLIANCE)
require_reports_generate = require_permission(Permission.GENERATE_REPORTS)

require_ai_scan = require_permission(Permission.SCAN_AI_MODELS)
require_ai_manage = require_permission(Permission.MANAGE_AI_POLICIES)

require_system_manage = require_permission(Permission.MANAGE_SYSTEM)
require_audit_read = require_permission(Permission.VIEW_AUDIT_LOGS)

# Resource-based dependencies
require_user_access = lambda action: require_resource_access("user", action)
require_policy_access = lambda action: require_resource_access("policy", action)
require_vault_access = lambda action: require_resource_access("vault", action)
require_security_access = lambda action: require_resource_access("security", action)
require_cloud_access = lambda action: require_resource_access("cloud", action)
require_compliance_access = lambda action: require_resource_access("compliance", action)
require_ai_access = lambda action: require_resource_access("ai", action)
require_system_access = lambda action: require_resource_access("system", action)


async def get_correlation_id(request: Request) -> str:
    """Get correlation ID from request state"""
    return getattr(request.state, "correlation_id", "unknown")


async def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    # Check for forwarded IP (in case of proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "unknown"


async def get_user_agent(request: Request) -> str:
    """Get user agent from request headers"""
    return request.headers.get("User-Agent", "unknown")
