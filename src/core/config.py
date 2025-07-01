"""
Configuration management for DevSecOps Platform
"""

import os
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with validation"""
    
    # Application Configuration
    app_name: str = Field(default="DevSecOps-AI-Platform", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # HashiCorp Vault Configuration
    vault_addr: str = Field(default="http://localhost:8200", env="VAULT_ADDR")
    vault_token: str = Field(default="dev-token", env="VAULT_TOKEN")
    
    # AWS Configuration
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="us-east-1", env="AWS_REGION")
    aws_account_id: Optional[str] = Field(default=None, env="AWS_ACCOUNT_ID")
    
    # Azure Configuration
    azure_subscription_id: Optional[str] = Field(default=None, env="AZURE_SUBSCRIPTION_ID")
    azure_tenant_id: Optional[str] = Field(default=None, env="AZURE_TENANT_ID")
    azure_client_id: Optional[str] = Field(default=None, env="AZURE_CLIENT_ID")
    azure_client_secret: Optional[str] = Field(default=None, env="AZURE_CLIENT_SECRET")
    
    # Security Configuration
    secret_key: str = Field(default="dev-secret-key-change-in-production", env="SECRET_KEY")
    encryption_key: Optional[str] = Field(default=None, env="ENCRYPTION_KEY")
    
    # Dashboard Configuration
    dashboard_host: str = Field(default="localhost", env="DASHBOARD_HOST")
    dashboard_port: int = Field(default=8000, env="DASHBOARD_PORT")
    websocket_enabled: bool = Field(default=True, env="WEBSOCKET_ENABLED")
    
    # Monitoring Configuration
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    
    # Compliance Configuration
    compliance_frameworks: str = Field(default="SOC2,ISO27001,GDPR", env="COMPLIANCE_FRAMEWORKS")
    audit_retention_days: int = Field(default=365, env="AUDIT_RETENTION_DAYS")
    
    # Performance Configuration
    max_workers: int = Field(default=10, env="MAX_WORKERS")
    cache_ttl: int = Field(default=300, env="CACHE_TTL")
    batch_size: int = Field(default=100, env="BATCH_SIZE")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )
    
    @property
    def compliance_frameworks_list(self) -> List[str]:
        """Return compliance frameworks as a list"""
        return [fw.strip() for fw in self.compliance_frameworks.split(",")]
    
    def get_aws_config(self) -> dict:
        """Get AWS configuration dictionary"""
        config = {
            "region_name": self.aws_region
        }
        
        if self.aws_access_key_id and self.aws_secret_access_key:
            config.update({
                "aws_access_key_id": self.aws_access_key_id,
                "aws_secret_access_key": self.aws_secret_access_key
            })
        
        return config
    
    def get_azure_config(self) -> dict:
        """Get Azure configuration dictionary"""
        return {
            "subscription_id": self.azure_subscription_id,
            "tenant_id": self.azure_tenant_id,
            "client_id": self.azure_client_id,
            "client_secret": self.azure_client_secret
        }


class ProductionSettings(Settings):
    """Production-specific settings that inherit from base Settings"""
    
    # Override defaults for production
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="WARNING", env="LOG_LEVEL")
    
    # Production-specific configurations
    use_https: bool = Field(default=True, env="USE_HTTPS")
    ssl_keyfile: Optional[str] = Field(default=None, env="SSL_KEYFILE")
    ssl_certfile: Optional[str] = Field(default=None, env="SSL_CERTFILE")
    
    # Enhanced security for production
    cors_origins: str = Field(default="", env="CORS_ORIGINS")
    rate_limiting: bool = Field(default=True, env="RATE_LIMITING")
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Return CORS origins as a list"""
        if not self.cors_origins:
            return []
        return [origin.strip() for origin in self.cors_origins.split(",")]


# Create singleton instances
settings = Settings()
production_settings = ProductionSettings()
