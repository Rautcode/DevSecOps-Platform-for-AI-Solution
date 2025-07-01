"""
Production-Grade Configuration Management
Environment-specific configurations with validation and security
"""

import os
import secrets
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from pydantic import Field, validator, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(str, Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AppSettings(BaseSettings):
    """Core application configuration"""
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        extra="ignore"  # Allow extra fields without error
    )
    
    # Basic app info
    name: str = Field(default="DevSecOps Platform for AI Solutions")
    version: str = Field(default="1.0.0")
    description: str = Field(default="Production-ready DevSecOps platform")
    
    # Environment
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    debug: bool = Field(default=False)
    
    # Server configuration
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1024, le=65535)
    workers: int = Field(default=1, ge=1, le=32)
    
    # Timeouts
    timeout_keep_alive: int = Field(default=5, ge=1, le=300)
    timeout_graceful_shutdown: int = Field(default=30, ge=5, le=120)
    
    # Logging
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_format: str = Field(default="json")
    log_file: Optional[Path] = None
    
    # Feature flags
    enable_docs: bool = Field(default=True)
    enable_metrics: bool = Field(default=True)
    enable_profiling: bool = Field(default=False)


class SecuritySettings(BaseSettings):
    """Security-specific configuration"""
    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        extra="ignore"
    )
    
    # Encryption
    secret_key: SecretStr = Field(
        default="demo-super-secret-key-for-development-only-change-in-production-32chars",
        min_length=32
    )
    encryption_key: Optional[SecretStr] = None
    jwt_secret: Optional[SecretStr] = None
    jwt_secret_key: SecretStr = Field(
        default="jwt-demo-secret-key-for-development-only-change-in-production-32chars",
        min_length=32
    )
    
    # Authentication
    session_timeout: int = Field(default=3600, ge=300, le=86400)  # 5min to 24h
    max_failed_attempts: int = Field(default=5, ge=1, le=10)
    lockout_duration: int = Field(default=900, ge=60, le=3600)  # 1min to 1h
    
    # API Security
    rate_limit_requests: int = Field(default=100, ge=10, le=10000)
    rate_limit_window: int = Field(default=60, ge=1, le=3600)
    cors_origins: List[str] = Field(default=["http://localhost:3000", "https://localhost:3000"])
    
    # TLS/SSL
    tls_enabled: bool = Field(default=False)
    tls_cert_path: Optional[Path] = None
    tls_key_path: Optional[Path] = None
    
    @validator('secret_key', 'encryption_key', 'jwt_secret')
    def validate_keys(cls, v):
        if v and len(v.get_secret_value()) < 32:
            raise ValueError('Security keys must be at least 32 characters')
        return v


class VaultSettings(BaseSettings):
    """HashiCorp Vault configuration"""
    model_config = SettingsConfigDict(
        env_prefix="VAULT_",
        extra="ignore"
    )
    
    addr: str = Field(default="http://localhost:8200", description="Vault server address")
    token: Optional[SecretStr] = Field(default=None, description="Vault token")
    role_id: Optional[str] = Field(default=None, description="AppRole role ID")
    secret_id: Optional[SecretStr] = Field(default=None, description="AppRole secret ID")
    
    # Connection settings
    timeout: int = Field(default=30, ge=5, le=300)
    max_retries: int = Field(default=3, ge=1, le=10)
    backoff_factor: float = Field(default=0.3, ge=0.1, le=2.0)
    
    # TLS settings
    ca_cert: Optional[Path] = None
    client_cert: Optional[Path] = None
    client_key: Optional[Path] = None
    verify_ssl: bool = Field(default=True)
    
    # Namespace and paths
    namespace: Optional[str] = None
    mount_point: str = Field(default="ai-solutions")
    policy_path: str = Field(default="sys/policies/acl")


class CloudSettings(BaseSettings):
    """Multi-cloud configuration"""
    model_config = SettingsConfigDict(extra="ignore")
    
    # AWS Settings
    aws_enabled: bool = Field(default=True)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[SecretStr] = None
    aws_region: str = Field(default="us-east-1")
    aws_account_id: Optional[str] = None
    aws_role_arn: Optional[str] = None
    
    # Azure Settings
    azure_enabled: bool = Field(default=True)
    azure_subscription_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[SecretStr] = None
    
    # GCP Settings (for future expansion)
    gcp_enabled: bool = Field(default=False)
    gcp_project_id: Optional[str] = None
    gcp_service_account_key: Optional[Path] = None


class DatabaseSettings(BaseSettings):
    """Database configuration for audit logs and metrics"""
    model_config = SettingsConfigDict(
        env_prefix="DB_",
        extra="ignore"
    )
    
    # Connection details
    host: str = Field(default="localhost")
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = Field(default="devsecops")
    username: str = Field(default="devsecops")
    password: SecretStr = Field(default="password")
    
    # Connection URL (overrides individual settings if provided)
    url: Optional[str] = None
    
    # Pool configuration
    pool_size: int = Field(default=20, ge=1, le=100)
    max_overflow: int = Field(default=30, ge=0, le=100)
    pool_timeout: int = Field(default=30, ge=5, le=300)
    pool_recycle: int = Field(default=3600, ge=300, le=86400)
    
    # Performance
    echo: bool = Field(default=False)
    
    # Security
    ssl_required: bool = Field(default=False)
    ssl_cert_path: Optional[Path] = None
    ssl_key_path: Optional[Path] = None
    ssl_ca_path: Optional[Path] = None


class MonitoringSettings(BaseSettings):
    """Monitoring and observability configuration"""
    model_config = SettingsConfigDict(extra="ignore")
    model_config = SettingsConfigDict(env_prefix="MONITORING_")
    
    # Metrics
    prometheus_enabled: bool = Field(default=True)
    prometheus_port: int = Field(default=9090, ge=1024, le=65535)
    metrics_retention_days: int = Field(default=30, ge=1, le=365)
    
    # Distributed tracing
    jaeger_enabled: bool = Field(default=False)
    jaeger_endpoint: Optional[str] = None
    trace_sampling_rate: float = Field(default=0.1, ge=0.0, le=1.0)
    
    # Health checks
    health_check_interval: int = Field(default=30, ge=5, le=300)
    health_check_timeout: int = Field(default=10, ge=1, le=60)


class ComplianceSettings(BaseSettings):
    """Compliance framework configuration"""
    model_config = SettingsConfigDict(extra="ignore")
    model_config = SettingsConfigDict(env_prefix="COMPLIANCE_")
    
    frameworks: List[str] = Field(default=["SOC2", "ISO27001", "GDPR", "HIPAA"])
    audit_retention_days: int = Field(default=2555, ge=365, le=3650)  # 7 years max
    encryption_at_rest: bool = Field(default=True)
    encryption_in_transit: bool = Field(default=True)
    data_residency_regions: List[str] = Field(default=["us-east-1", "eu-west-1"])


class AppSettings(BaseSettings):
    """Core application settings"""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Environment
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    debug: bool = Field(default=False)
    testing: bool = Field(default=False)
    
    # Application
    app_name: str = Field(default="DevSecOps-AI-Platform")
    app_version: str = Field(default="1.0.0")
    api_prefix: str = Field(default="/api/v1")
    
    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1024, le=65535)
    workers: int = Field(default=1, ge=1, le=32)
    
    # Logging
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_format: str = Field(default="json")
    log_file: Optional[Path] = None
    log_rotation: str = Field(default="1 day")
    log_retention: str = Field(default="30 days")
    
    # Features
    websocket_enabled: bool = Field(default=True)
    real_time_scanning: bool = Field(default=True)
    auto_remediation: bool = Field(default=False)  # Disabled by default in prod
    
    # Performance
    max_workers: int = Field(default=10, ge=1, le=100)
    cache_ttl: int = Field(default=300, ge=60, le=3600)
    batch_size: int = Field(default=100, ge=10, le=1000)


class ProductionSettings(BaseSettings):
    """
    Production configuration combining all settings
    Main configuration class for the DevSecOps Platform
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Core application settings
    app: AppSettings = Field(default_factory=AppSettings)
    
    # Security configuration
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    
    # HashiCorp Vault settings
    vault: VaultSettings = Field(default_factory=VaultSettings)
    
    # Multi-cloud settings
    cloud: CloudSettings = Field(default_factory=CloudSettings)
    
    # Database settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    
    # Monitoring settings
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.app.environment == Environment.PRODUCTION
    
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.app.environment == Environment.DEVELOPMENT
    
    def validate_configuration(self) -> List[str]:
        """Validate configuration and return issues"""
        issues = []
        
        # Production-specific validations
        if self.is_production():
            if self.app.debug:
                issues.append("ERROR: Debug mode enabled in production")
            
            if not self.security.tls_enabled:
                issues.append("WARNING: TLS not enabled in production")
            
            if self.vault.token and not self.vault.verify_ssl:
                issues.append("WARNING: SSL verification disabled for Vault")
            
            if self.app.workers < 2:
                issues.append("WARNING: Consider using multiple workers in production")
        
        # Security validations
        if len(self.security.secret_key.get_secret_value()) < 32:
            issues.append("ERROR: Secret key must be at least 32 characters")
        
        # Database validations
        if self.is_production() and "sqlite" in (self.database.url or ""):
            issues.append("WARNING: SQLite not recommended for production")
        
        return issues
    
    def get_database_url(self) -> str:
        """Get complete database URL"""
        if self.database.url:
            return self.database.url
        
        return (
            f"postgresql+asyncpg://{self.database.username}:"
            f"{self.database.password.get_secret_value()}@"
            f"{self.database.host}:{self.database.port}/"
            f"{self.database.name}"
        )
    
    def get_redis_url(self) -> str:
        """Get Redis URL for caching/sessions (if implemented)"""
        # This would be implemented if Redis is used
        return "redis://localhost:6379/0"


# Global settings instance
settings = ProductionSettings()


def get_settings() -> ProductionSettings:
    """Get global settings instance"""
    return settings


def validate_production_config() -> List[str]:
    """Validate production configuration and return warnings/errors"""
    issues = []
    
    if settings.is_production():
        # Security checks
        if settings.app.debug:
            issues.append("ERROR: Debug mode enabled in production")
        
        if not settings.security.tls_enabled:
            issues.append("WARNING: TLS not enabled in production")
        
        if settings.vault.token and not settings.vault.verify_ssl:
            issues.append("WARNING: SSL verification disabled for Vault")
        
        # Performance checks
        if settings.app.workers < 2:
            issues.append("WARNING: Consider using multiple workers in production")
        
        if settings.database.url.startswith("sqlite"):
            issues.append("WARNING: SQLite not recommended for production")
    
    return issues
