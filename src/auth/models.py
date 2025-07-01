"""
Authentication Models
User, role, and authentication response models
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr, validator
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class UserRole(str, Enum):
    """User roles in the system"""
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    POLICY_MANAGER = "policy_manager"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    AI_ENGINEER = "ai_engineer"
    COMPLIANCE_OFFICER = "compliance_officer"


class Permission(str, Enum):
    """System permissions"""
    # User management
    CREATE_USER = "create_user"
    READ_USER = "read_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    
    # Policy management
    CREATE_POLICY = "create_policy"
    READ_POLICY = "read_policy"
    UPDATE_POLICY = "update_policy"
    DELETE_POLICY = "delete_policy"
    EXECUTE_POLICY = "execute_policy"
    
    # Security monitoring
    READ_SECURITY_EVENTS = "read_security_events"
    CREATE_SECURITY_EVENTS = "create_security_events"
    MANAGE_ALERTS = "manage_alerts"
    
    # Vault operations
    READ_SECRETS = "read_secrets"
    WRITE_SECRETS = "write_secrets"
    MANAGE_VAULT = "manage_vault"
    
    # Cloud security
    READ_CLOUD_SECURITY = "read_cloud_security"
    MANAGE_CLOUD_SECURITY = "manage_cloud_security"
    
    # Compliance
    READ_COMPLIANCE = "read_compliance"
    MANAGE_COMPLIANCE = "manage_compliance"
    GENERATE_REPORTS = "generate_reports"
    
    # AI/ML specific
    SCAN_AI_MODELS = "scan_ai_models"
    MANAGE_AI_POLICIES = "manage_ai_policies"
    
    # System administration
    MANAGE_SYSTEM = "manage_system"
    VIEW_AUDIT_LOGS = "view_audit_logs"


class UserORM(Base):
    """SQLAlchemy User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(200))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default=UserRole.VIEWER.value)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    
    # Security tracking
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, default=datetime.utcnow)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Preferences and settings
    preferences = Column(JSON, default=dict)
    
    # Relationships
    auth_sessions = relationship("AuthSessionORM", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLogORM", back_populates="user")


class AuthSessionORM(Base):
    """SQLAlchemy Auth Session model"""
    __tablename__ = "auth_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_token = Column(String(255), unique=True, index=True, nullable=False)
    refresh_token = Column(String(255), unique=True, index=True, nullable=True)
    
    # Session metadata
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(255))
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_accessed = Column(DateTime, default=datetime.utcnow)
    
    # Status
    is_active = Column(Boolean, default=True)
    revoked_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("UserORM", back_populates="auth_sessions")


class AuditLogORM(Base):
    """SQLAlchemy Audit Log model"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Event details
    event_type = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    action = Column(String(100), nullable=False)
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    correlation_id = Column(String(255), index=True)
    
    # Event data
    details = Column(JSON)
    outcome = Column(String(50))  # SUCCESS, FAILURE, PARTIAL
    
    # Timing
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("UserORM", back_populates="audit_logs")


# Pydantic models for API
class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=200)
    role: UserRole = UserRole.VIEWER
    
    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum() and '_' not in v and '-' not in v:
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v.lower()


class UserCreate(UserBase):
    """User creation model"""
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    """User update model"""
    full_name: Optional[str] = Field(None, max_length=200)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    preferences: Optional[Dict[str, Any]] = None


class User(UserBase):
    """Full user model"""
    id: int
    is_active: bool
    is_verified: bool
    is_superuser: bool
    failed_login_attempts: int
    locked_until: Optional[datetime]
    last_login: Optional[datetime]
    last_password_change: datetime
    created_at: datetime
    updated_at: datetime
    preferences: Dict[str, Any]
    
    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    """Login request model"""
    username: str
    password: str
    remember_me: bool = False


class AuthResponse(BaseModel):
    """Authentication response model"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: User


class TokenRefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordResetRequest(BaseModel):
    """Password reset request"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation"""
    token: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v


class AuditLogEntry(BaseModel):
    """Audit log entry"""
    id: int
    user_id: Optional[int]
    event_type: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    action: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    correlation_id: Optional[str]
    details: Optional[Dict[str, Any]]
    outcome: Optional[str]
    timestamp: datetime
    
    model_config = {"from_attributes": True}


class AuthSession(BaseModel):
    """Authentication session"""
    id: int
    user_id: int
    session_token: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    device_fingerprint: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_accessed: datetime
    is_active: bool
    
    model_config = {"from_attributes": True}
