"""
Authentication Manager
Core authentication and user management functionality
"""

import hashlib
import secrets
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple, List
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from sqlalchemy import and_, or_, update
from passlib.context import CryptContext
from passlib.hash import bcrypt

from ..core.production_config import SecuritySettings, DatabaseSettings
from ..core.production_logging import get_logger
from .models import (
    UserORM, AuthSessionORM, AuditLogORM, User, UserCreate, 
    UserUpdate, LoginRequest, AuthResponse, UserRole
)
from .jwt_handler import JWTHandler
from .rbac import RBACManager


logger = get_logger(__name__)


class AuthManager:
    """
    Authentication Manager
    Handles user authentication, session management, and security
    """
    
    def __init__(
        self, 
        security_settings: SecuritySettings,
        database_settings: DatabaseSettings
    ):
        self.security_settings = security_settings
        self.database_settings = database_settings
        
        # Password hashing
        self.pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=12
        )
        
        # JWT handler
        self.jwt_handler = JWTHandler(security_settings)
        
        # RBAC manager
        self.rbac = RBACManager()
        
        # Database
        self.engine = None
        self.async_session = None
        
        # Security tracking
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_times: Dict[str, datetime] = {}
        
    async def initialize(self) -> None:
        """Initialize authentication manager"""
        try:
            # Setup database connection
            database_url = (
                f"postgresql+asyncpg://{self.database_settings.username}:"
                f"{self.database_settings.password.get_secret_value()}@"
                f"{self.database_settings.host}:{self.database_settings.port}/"
                f"{self.database_settings.name}"
            )
            
            self.engine = create_async_engine(
                database_url,
                echo=self.database_settings.echo,
                pool_size=self.database_settings.pool_size,
                max_overflow=self.database_settings.max_overflow,
                pool_timeout=self.database_settings.pool_timeout,
                pool_recycle=self.database_settings.pool_recycle,
            )
            
            self.async_session = sessionmaker(
                self.engine, 
                class_=AsyncSession, 
                expire_on_commit=False
            )
            
            logger.info("Authentication manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize authentication manager: {e}")
            raise
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        if self.engine:
            await self.engine.dispose()
        logger.info("Authentication manager cleaned up")
    
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """Check if password hash needs updating"""
        return self.pwd_context.needs_update(hashed_password)
    
    async def create_user(
        self, 
        user_create: UserCreate, 
        created_by: Optional[int] = None
    ) -> Optional[User]:
        """Create a new user"""
        async with self.async_session() as session:
            try:
                # Check if user already exists
                existing_user = await session.execute(
                    select(UserORM).where(
                        or_(
                            UserORM.email == user_create.email,
                            UserORM.username == user_create.username
                        )
                    )
                )
                if existing_user.scalar_one_or_none():
                    return None
                
                # Create new user
                hashed_password = self.hash_password(user_create.password)
                
                db_user = UserORM(
                    email=user_create.email,
                    username=user_create.username,
                    full_name=user_create.full_name,
                    hashed_password=hashed_password,
                    role=user_create.role.value,
                    is_active=True,
                    is_verified=False,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                session.add(db_user)
                await session.commit()
                await session.refresh(db_user)
                
                # Log audit event
                await self._log_audit_event(
                    session,
                    user_id=created_by,
                    event_type="USER_CREATED",
                    resource_type="user",
                    resource_id=str(db_user.id),
                    action="create",
                    details={"created_user_id": db_user.id, "role": user_create.role.value}
                )
                
                return User.from_orm(db_user)
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to create user: {e}")
                return None
    
    async def authenticate_user(
        self, 
        login_request: LoginRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[AuthResponse]:
        """Authenticate user and create session"""
        async with self.async_session() as session:
            try:
                # Check for account lockout
                if self._is_account_locked(login_request.username):
                    await self._log_audit_event(
                        session,
                        event_type="LOGIN_BLOCKED",
                        action="login",
                        details={
                            "username": login_request.username,
                            "reason": "account_locked",
                            "ip_address": ip_address
                        },
                        ip_address=ip_address,
                        user_agent=user_agent,
                        outcome="FAILURE"
                    )
                    return None
                
                # Get user
                result = await session.execute(
                    select(UserORM).where(UserORM.username == login_request.username)
                )
                user = result.scalar_one_or_none()
                
                if not user or not self.verify_password(login_request.password, user.hashed_password):
                    # Increment failed attempts
                    self._increment_failed_attempts(login_request.username)
                    
                    await self._log_audit_event(
                        session,
                        user_id=user.id if user else None,
                        event_type="LOGIN_FAILED",
                        action="login",
                        details={
                            "username": login_request.username,
                            "reason": "invalid_credentials",
                            "ip_address": ip_address
                        },
                        ip_address=ip_address,
                        user_agent=user_agent,
                        outcome="FAILURE"
                    )
                    return None
                
                # Check if user is active
                if not user.is_active:
                    await self._log_audit_event(
                        session,
                        user_id=user.id,
                        event_type="LOGIN_BLOCKED",
                        action="login",
                        details={
                            "username": login_request.username,
                            "reason": "account_inactive",
                            "ip_address": ip_address
                        },
                        ip_address=ip_address,
                        user_agent=user_agent,
                        outcome="FAILURE"
                    )
                    return None
                
                # Reset failed attempts on successful authentication
                self._reset_failed_attempts(login_request.username)
                
                # Update password hash if needed
                if self.needs_rehash(user.hashed_password):
                    user.hashed_password = self.hash_password(login_request.password)
                    user.last_password_change = datetime.utcnow()
                
                # Update last login
                user.last_login = datetime.utcnow()
                
                # Create tokens
                user_obj = User.from_orm(user)
                access_token, refresh_token = self.jwt_handler.create_token_pair(user_obj)
                
                # Create session record
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.utcnow() + timedelta(seconds=self.security_settings.session_timeout)
                
                auth_session = AuthSessionORM(
                    user_id=user.id,
                    session_token=session_token,
                    refresh_token=refresh_token if login_request.remember_me else None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    device_fingerprint=self._generate_device_fingerprint(ip_address, user_agent),
                    expires_at=expires_at,
                    is_active=True
                )
                
                session.add(auth_session)
                await session.commit()
                
                # Log successful login
                await self._log_audit_event(
                    session,
                    user_id=user.id,
                    event_type="LOGIN_SUCCESS",
                    action="login",
                    details={
                        "username": user.username,
                        "ip_address": ip_address,
                        "session_id": auth_session.id
                    },
                    ip_address=ip_address,
                    user_agent=user_agent,
                    outcome="SUCCESS"
                )
                
                return AuthResponse(
                    access_token=access_token,
                    refresh_token=refresh_token if login_request.remember_me else None,
                    expires_in=self.jwt_handler.access_token_expire_minutes * 60,
                    user=user_obj
                )
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Authentication failed: {e}")
                return None
    
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        async with self.async_session() as session:
            try:
                result = await session.execute(
                    select(UserORM).where(UserORM.id == user_id)
                )
                user = result.scalar_one_or_none()
                return User.from_orm(user) if user else None
            except Exception as e:
                logger.error(f"Failed to get user by ID {user_id}: {e}")
                return None
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        async with self.async_session() as session:
            try:
                result = await session.execute(
                    select(UserORM).where(UserORM.username == username)
                )
                user = result.scalar_one_or_none()
                return User.from_orm(user) if user else None
            except Exception as e:
                logger.error(f"Failed to get user by username {username}: {e}")
                return None
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts"""
        if username in self.lockout_times:
            lockout_end = self.lockout_times[username]
            if datetime.utcnow() < lockout_end:
                return True
            else:
                # Lockout expired, remove it
                del self.lockout_times[username]
                if username in self.failed_attempts:
                    del self.failed_attempts[username]
        
        return False
    
    def _increment_failed_attempts(self, username: str) -> None:
        """Increment failed login attempts"""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
        
        if self.failed_attempts[username] >= self.security_settings.max_failed_attempts:
            # Lock account
            lockout_duration = timedelta(seconds=self.security_settings.lockout_duration)
            self.lockout_times[username] = datetime.utcnow() + lockout_duration
            logger.warning(f"Account {username} locked due to {self.failed_attempts[username]} failed attempts")
    
    def _reset_failed_attempts(self, username: str) -> None:
        """Reset failed login attempts"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
        if username in self.lockout_times:
            del self.lockout_times[username]
    
    def _generate_device_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """Generate device fingerprint"""
        fingerprint_data = f"{ip_address}:{user_agent}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    
    async def _log_audit_event(
        self,
        session: AsyncSession,
        event_type: str,
        action: str,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "SUCCESS"
    ) -> None:
        """Log audit event"""
        try:
            audit_log = AuditLogORM(
                user_id=user_id,
                event_type=event_type,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                ip_address=ip_address,
                user_agent=user_agent,
                correlation_id=correlation_id or secrets.token_urlsafe(16),
                details=details or {},
                outcome=outcome,
                timestamp=datetime.utcnow()
            )
            
            session.add(audit_log)
            # Note: We don't commit here as this is called within other transactions
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
