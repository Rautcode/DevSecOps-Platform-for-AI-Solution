"""
HashiCorp Vault Manager for AI Solutions
Manages secrets, policies, and authentication for AI workloads
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

import hvac
from hvac.exceptions import VaultError

from ..core.config import Settings
from ..core.logging_config import log_security_event


@dataclass
class VaultSecret:
    """Vault secret data structure"""
    path: str
    data: Dict[str, Any]
    version: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class VaultManager:
    """HashiCorp Vault integration for AI solution secrets management"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.client: Optional[hvac.Client] = None
        self.logger = logging.getLogger(__name__)
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize Vault client and setup AI secrets engine"""
        try:
            # Check if this is demo mode
            if self.settings.vault_addr == "http://localhost:8200" and "demo" in self.settings.vault_token:
                self.logger.info("Running in DEMO mode - Vault integration simulated")
                self._initialized = True
                
                log_security_event(
                    event_type="vault_initialization",
                    description="Vault manager initialized in DEMO mode",
                    severity="INFO"
                )
                return
            
            self.client = hvac.Client(
                url=self.settings.vault_addr,
                token=self.settings.vault_token
            )
            
            # Verify authentication
            if not self.client.is_authenticated():
                raise VaultError("Vault authentication failed")
            
            # Setup AI secrets engine
            await self._setup_ai_secrets_engine()
            
            # Create default policies
            await self._create_default_policies()
            
            self._initialized = True
            self.logger.info("Vault manager initialized successfully")
            
            log_security_event(
                event_type="vault_initialization",
                description="Vault manager initialized and AI secrets engine configured",
                severity="INFO"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Vault manager: {e}")
            # In demo mode, don't fail - just log the warning
            if "demo" in self.settings.vault_token:
                self.logger.warning("Vault connection failed, continuing in demo mode")
                self._initialized = True
            else:
                log_security_event(
                    event_type="vault_initialization_failed",
                    description=f"Vault initialization failed: {str(e)}",
                    severity="ERROR"
                )
                raise
    
    async def _setup_ai_secrets_engine(self) -> None:
        """Setup KV secrets engine for AI solutions"""
        try:
            # Check if AI secrets engine already exists
            engines = self.client.sys.list_mounted_secrets_engines()
            
            if 'ai-solutions/' not in engines:
                self.client.sys.enable_secrets_engine(
                    backend_type='kv-v2',
                    path='ai-solutions',
                    description='Secrets engine for AI solution credentials'
                )
                self.logger.info("AI secrets engine created")
            else:
                self.logger.info("AI secrets engine already exists")
                
        except Exception as e:
            self.logger.error(f"Failed to setup AI secrets engine: {e}")
            raise
    
    async def _create_default_policies(self) -> None:
        """Create default security policies for AI workloads"""
        policies = {
            'ai-readonly': '''
                path "ai-solutions/*" {
                    capabilities = ["read", "list"]
                }
            ''',
            'ai-admin': '''
                path "ai-solutions/*" {
                    capabilities = ["create", "read", "update", "delete", "list"]
                }
                path "sys/mounts" {
                    capabilities = ["read"]
                }
            ''',
            'ai-service': '''
                path "ai-solutions/data/{{identity.entity.name}}/*" {
                    capabilities = ["read"]
                }
            '''
        }
        
        for policy_name, policy_rules in policies.items():
            try:
                self.client.sys.create_or_update_policy(
                    name=policy_name,
                    policy=policy_rules
                )
                self.logger.info(f"Created/updated policy: {policy_name}")
            except Exception as e:
                self.logger.error(f"Failed to create policy {policy_name}: {e}")
    
    async def store_ai_secret(
        self,
        path: str,
        secret_data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> VaultSecret:
        """Store AI-related secrets (API keys, model configs, etc.)"""
        if not self._initialized:
            raise RuntimeError("Vault manager not initialized")
        
        try:
            full_path = f"ai-solutions/data/{path}"
            
            # Store the secret
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
                mount_point='ai-solutions'
            )
            
            vault_secret = VaultSecret(
                path=path,
                data=secret_data,
                version=response['data']['version'],
                metadata=metadata
            )
            
            self.logger.info(f"Stored AI secret at path: {path}")
            
            log_security_event(
                event_type="secret_stored",
                description=f"AI secret stored at path: {path}",
                severity="INFO",
                resource=path
            )
            
            return vault_secret
            
        except Exception as e:
            self.logger.error(f"Failed to store AI secret at {path}: {e}")
            log_security_event(
                event_type="secret_store_failed",
                description=f"Failed to store AI secret at {path}: {str(e)}",
                severity="ERROR",
                resource=path
            )
            raise
    
    async def retrieve_ai_secret(self, path: str) -> Optional[VaultSecret]:
        """Retrieve AI-related secrets"""
        if not self._initialized:
            raise RuntimeError("Vault manager not initialized")
        
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='ai-solutions'
            )
            
            if not response:
                return None
            
            vault_secret = VaultSecret(
                path=path,
                data=response['data']['data'],
                version=response['data']['metadata']['version'],
                metadata=response['data']['metadata']
            )
            
            log_security_event(
                event_type="secret_accessed",
                description=f"AI secret accessed at path: {path}",
                severity="INFO",
                resource=path
            )
            
            return vault_secret
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve AI secret at {path}: {e}")
            log_security_event(
                event_type="secret_access_failed",
                description=f"Failed to access AI secret at {path}: {str(e)}",
                severity="ERROR",
                resource=path
            )
            return None
    
    async def rotate_ai_secret(self, path: str, new_secret_data: Dict[str, Any]) -> bool:
        """Rotate AI secrets for security compliance"""
        try:
            # Store new version
            await self.store_ai_secret(path, new_secret_data)
            
            log_security_event(
                event_type="secret_rotated",
                description=f"AI secret rotated at path: {path}",
                severity="INFO",
                resource=path
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rotate AI secret at {path}: {e}")
            return False
    
    async def list_ai_secrets(self) -> List[str]:
        """List all AI solution secret paths"""
        if not self._initialized:
            raise RuntimeError("Vault manager not initialized")
        
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path='',
                mount_point='ai-solutions'
            )
            
            return response['data']['keys'] if response else []
            
        except Exception as e:
            self.logger.error(f"Failed to list AI secrets: {e}")
            return []
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Vault health status"""
        # Demo mode health check
        if "demo" in self.settings.vault_token:
            return {
                "status": "demo_mode",
                "authenticated": True,
                "initialized": True,
                "sealed": False,
                "note": "Running in demo mode - replace with real Vault credentials for production"
            }
        
        if not self.client:
            return {"status": "not_initialized", "authenticated": False}
        
        try:
            health = self.client.sys.read_health_status()
            return {
                "status": "healthy" if health["initialized"] else "unhealthy",
                "authenticated": self.client.is_authenticated(),
                "initialized": health["initialized"],
                "sealed": health["sealed"]
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def cleanup(self) -> None:
        """Cleanup Vault connections"""
        if self.client:
            self.client = None
        self._initialized = False
        self.logger.info("Vault manager cleaned up")
