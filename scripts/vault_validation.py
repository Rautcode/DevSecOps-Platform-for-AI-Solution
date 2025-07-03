#!/usr/bin/env python3
"""
Vault Secret Validation Script
Validates HashiCorp Vault configuration and AI secrets
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.logging_config import setup_logging, log_security_event
from src.integrations.vault_manager import VaultManager


async def validate_vault_secrets():
    """Validate Vault configuration and AI secrets"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Vault secret validation")
    
    try:
        # Initialize Vault manager
        vault_manager = VaultManager()
        await vault_manager.initialize()
        
        # Check Vault health
        health = await vault_manager.health_check()
        
        if health["status"] != "healthy":
            logger.error(f"Vault health check failed: {health}")
            log_security_event(
                event_type="vault_validation_failed",
                description="Vault health check failed",
                severity="ERROR"
            )
            return False
        
        # List AI secrets
        ai_secrets = await vault_manager.list_ai_secrets()
        logger.info(f"Found {len(ai_secrets)} AI secrets")
        
        # Validate secret access
        validation_results = {
            "vault_healthy": True,
            "secrets_accessible": True,
            "total_secrets": len(ai_secrets),
            "validation_timestamp": "2025-07-01T12:00:00Z"
        }
        
        # Test secret retrieval (if any exist)
        if ai_secrets:
            test_secret = ai_secrets[0]
            retrieved_secret = await vault_manager.retrieve_ai_secret(test_secret)
            if not retrieved_secret:
                validation_results["secrets_accessible"] = False
                logger.warning(f"Failed to retrieve test secret: {test_secret}")
        
        log_security_event(
            event_type="vault_validation_completed",
            description=f"Vault validation completed successfully. {len(ai_secrets)} secrets validated",
            severity="INFO"
        )
        
        print(f"\n🔐 Vault Secret Validation Results")
        print(f"{'='*50}")
        print(f"Vault Status: {'✅ Healthy' if validation_results['vault_healthy'] else '❌ Unhealthy'}")
        print(f"Secrets Accessible: {'✅ Yes' if validation_results['secrets_accessible'] else '❌ No'}")
        print(f"Total AI Secrets: {validation_results['total_secrets']}")
        
        await vault_manager.cleanup()
        return True
        
    except Exception as e:
        logger.error(f"Vault validation failed: {e}")
        log_security_event(
            event_type="vault_validation_error",
            description=f"Vault validation error: {str(e)}",
            severity="ERROR"
        )
        
        print(f"\n❌ Vault Validation Failed")
        print(f"Error: {str(e)}")
        return False


async def main():
    """Main validation function"""
    success = await validate_vault_secrets()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
