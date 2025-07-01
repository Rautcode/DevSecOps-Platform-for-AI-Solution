"""
Authentication Routes
FastAPI routes for user authentication and management
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel

from .models import (
    User, UserCreate, UserUpdate, LoginRequest, AuthResponse,
    PasswordChangeRequest, PasswordResetRequest, PasswordResetConfirm,
    AuditLogEntry, AuthSession, UserRole
)
from .dependencies import (
    get_current_user, get_current_active_user, get_current_superuser,
    require_admin, require_user_create, require_user_read, require_user_update,
    require_user_delete, require_audit_read, get_correlation_id,
    get_client_ip, get_user_agent, auth_manager
)
from ..core.production_logging import get_logger


logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


class TokenRefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


class UserListResponse(BaseModel):
    """User list response"""
    users: List[User]
    total: int
    page: int
    size: int


@router.post("/login", response_model=AuthResponse)
async def login(
    login_request: LoginRequest,
    request: Request,
    ip_address: str = Depends(get_client_ip),
    user_agent: str = Depends(get_user_agent)
):
    """
    Authenticate user and return JWT tokens
    
    - **username**: Username or email
    - **password**: User password
    - **remember_me**: Whether to issue refresh token
    """
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    auth_response = await auth_manager.authenticate_user(
        login_request, ip_address, user_agent
    )
    
    if not auth_response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or account locked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(
        f"User {auth_response.user.username} logged in successfully",
        extra={
            "user_id": auth_response.user.id,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    )
    
    return auth_response


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(refresh_request: TokenRefreshRequest):
    """
    Refresh access token using refresh token
    
    - **refresh_token**: Valid refresh token
    """
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    # Verify refresh token and get new access token
    new_access_token = auth_manager.jwt_handler.refresh_access_token(
        refresh_request.refresh_token
    )
    
    if not new_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Get user data from refresh token
    user_data = auth_manager.jwt_handler.get_user_from_token(refresh_request.refresh_token)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Get fresh user data
    user = await auth_manager.get_user_by_id(user_data["id"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return AuthResponse(
        access_token=new_access_token,
        refresh_token=refresh_request.refresh_token,
        expires_in=auth_manager.jwt_handler.access_token_expire_minutes * 60,
        user=user
    )


@router.post("/register", response_model=User, dependencies=[Depends(require_user_create)])
async def register(
    user_create: UserCreate,
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """
    Register a new user (admin only)
    
    - **email**: User email address
    - **username**: Unique username
    - **password**: Strong password
    - **confirm_password**: Password confirmation
    - **full_name**: User's full name
    - **role**: User role
    """
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    user = await auth_manager.create_user(user_create, created_by=current_user.id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or username already exists"
        )
    
    logger.info(
        f"User {user.username} created by {current_user.username}",
        extra={
            "created_user_id": user.id,
            "created_by": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return user


@router.get("/me", response_model=User)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user information"""
    return current_user


@router.put("/me", response_model=User)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """Update current user information"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    # Users can only update their own basic info
    # Role changes require admin privileges
    if user_update.role and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role changes require admin privileges"
        )
    
    updated_user = await auth_manager.update_user(
        current_user.id, user_update, updated_by=current_user.id
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update user"
        )
    
    logger.info(
        f"User {current_user.username} updated their profile",
        extra={
            "user_id": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return updated_user


@router.post("/change-password")
async def change_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """Change current user password"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    success = await auth_manager.change_password(
        current_user.id,
        password_change.current_password,
        password_change.new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    logger.info(
        f"User {current_user.username} changed password",
        extra={
            "user_id": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """Logout current user (revoke all sessions)"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    await auth_manager.revoke_all_user_sessions(current_user.id)
    
    logger.info(
        f"User {current_user.username} logged out",
        extra={
            "user_id": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return {"message": "Logged out successfully"}


@router.get("/users", response_model=UserListResponse, dependencies=[Depends(require_user_read)])
async def list_users(
    page: int = 1,
    size: int = 20,
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    List users (admin/manager only)
    
    - **page**: Page number (1-based)
    - **size**: Page size (max 100)
    - **role**: Filter by role
    - **is_active**: Filter by active status
    """
    # This would need to be implemented in AuthManager
    # For now, return empty list
    return UserListResponse(
        users=[],
        total=0,
        page=page,
        size=size
    )


@router.get("/users/{user_id}", response_model=User, dependencies=[Depends(require_user_read)])
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Get user by ID (admin/manager only)"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    user = await auth_manager.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.put("/users/{user_id}", response_model=User, dependencies=[Depends(require_user_update)])
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """Update user (admin only)"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    updated_user = await auth_manager.update_user(
        user_id, user_update, updated_by=current_user.id
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    logger.info(
        f"User {user_id} updated by {current_user.username}",
        extra={
            "updated_user_id": user_id,
            "updated_by": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return updated_user


@router.delete("/users/{user_id}", dependencies=[Depends(require_user_delete)])
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
):
    """Delete user (admin only)"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    # Prevent self-deletion
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # For now, just deactivate the user instead of hard delete
    user_update = UserUpdate(is_active=False)
    updated_user = await auth_manager.update_user(
        user_id, user_update, updated_by=current_user.id
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Revoke all user sessions
    await auth_manager.revoke_all_user_sessions(user_id)
    
    logger.info(
        f"User {user_id} deactivated by {current_user.username}",
        extra={
            "deactivated_user_id": user_id,
            "deactivated_by": current_user.id,
            "correlation_id": correlation_id
        }
    )
    
    return {"message": "User deactivated successfully"}


@router.get("/audit-logs", response_model=List[AuditLogEntry], dependencies=[Depends(require_audit_read)])
async def get_audit_logs(
    page: int = 1,
    size: int = 50,
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get audit logs (admin/auditor only)
    
    - **page**: Page number (1-based)
    - **size**: Page size (max 100)
    - **user_id**: Filter by user ID
    - **event_type**: Filter by event type
    """
    # This would need to be implemented in AuthManager
    # For now, return empty list
    return []


@router.get("/permissions")
async def get_user_permissions(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user's permissions and accessible resources"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    # Get user permissions
    permissions = auth_manager.rbac.get_user_permissions(current_user.role)
    accessible_resources = auth_manager.rbac.get_accessible_resources(current_user.role)
    
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role.value,
            "is_superuser": current_user.is_superuser
        },
        "permissions": [perm.value for perm in permissions],
        "accessible_resources": accessible_resources
    }


@router.get("/roles")
async def get_roles(
    current_user: User = Depends(require_admin)
):
    """Get role hierarchy (admin only)"""
    if not auth_manager:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication not initialized"
        )
    
    return auth_manager.rbac.get_role_hierarchy()
