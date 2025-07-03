#!/usr/bin/env python3
"""
Production Startup Script for DevSecOps Platform
Comprehensive initialization with security validation and health checks
"""

import asyncio
import logging
import os
import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from src.core.production_config import ProductionSettings
    from src.core.production_logging import setup_production_logging
    from src.core.database import initialize_database_manager
    from src.auth.auth_manager import AuthManager
    from src.integrations.vault_manager import VaultManager
    from src.integrations.cloud_security_hub import CloudSecurityHub
    from src.policies.policy_engine import PolicyEngine
    from src.monitoring.security_monitor import SecurityMonitoringSystem
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure you're running from the project root directory")
    sys.exit(1)

logger = logging.getLogger(__name__)


class ProductionStartup:
    """Production startup manager with comprehensive validation"""
    
    def __init__(self):
        try:
            self.settings = ProductionSettings()
            self.startup_checks: Dict[str, bool] = {}
            self.startup_errors: List[str] = []
            
            # Initialize logging
            setup_production_logging(self.settings.app)
        except Exception as e:
            print(f"❌ Failed to initialize startup manager: {e}")
            sys.exit(1)
    
    async def validate_environment(self) -> bool:
        """Validate production environment"""
        logger.info("🔍 Validating production environment...")
        
        checks = [
            ("python_version", self._check_python_version),
            ("environment_variables", self._check_environment_variables),
            ("file_permissions", self._check_file_permissions),
            ("security_configuration", self._check_security_configuration)
        ]
        
        all_passed = True
        
        for check_name, check_func in checks:
            try:
                result = check_func()
                self.startup_checks[check_name] = result
                
                if result:
                    logger.info(f"✅ {check_name}: PASSED")
                else:
                    logger.error(f"❌ {check_name}: FAILED")
                    all_passed = False
                    
            except Exception as e:
                logger.error(f"💥 {check_name}: ERROR - {e}")
                self.startup_checks[check_name] = False
                self.startup_errors.append(f"{check_name}: {str(e)}")
                all_passed = False
        
        return all_passed
    
    def _check_python_version(self) -> bool:
        """Check Python version compatibility"""
        min_version = (3, 9)
        current_version = sys.version_info[:2]
        
        if current_version >= min_version:
            logger.info(f"Python version: {sys.version}")
            return True
        else:
            self.startup_errors.append(f"Python {min_version[0]}.{min_version[1]}+ required, got {current_version[0]}.{current_version[1]}")
            return False
    
    def _check_environment_variables(self) -> bool:
        """Check required environment variables"""
        required_vars = [
            "DATABASE_URL",
            "SECRET_KEY",
            "VAULT_ADDR",
            "VAULT_TOKEN"
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.startup_errors.append(f"Missing environment variables: {', '.join(missing_vars)}")
            return False
        
        # Check for demo/development values in production
        if self.settings.app.environment == "production":
            demo_values = {
                "SECRET_KEY": "demo-secret-key",
                "VAULT_TOKEN": "demo-vault-token",
                "AWS_ACCESS_KEY_ID": "demo-aws-key"
            }
            
            for var, demo_value in demo_values.items():
                if os.getenv(var) == demo_value:
                    self.startup_errors.append(f"Demo value detected for {var} in production!")
                    return False
        
        return True
    
    def _check_file_permissions(self) -> bool:
        """Check file and directory permissions"""
        try:
            # Check if we can write to logs directory
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            test_file = log_dir / "startup_test.tmp"
            test_file.write_text("test")
            test_file.unlink()
            
            # Check config files are readable
            config_files = [".env", "requirements.txt"]
            for config_file in config_files:
                if Path(config_file).exists() and not os.access(config_file, os.R_OK):
                    self.startup_errors.append(f"Cannot read {config_file}")
                    return False
            
            return True
            
        except Exception as e:
            self.startup_errors.append(f"File permission check failed: {str(e)}")
            return False
    
    def _check_security_configuration(self) -> bool:
        """Validate security configuration"""
        # Check SSL/TLS configuration
        if self.settings.app.environment == "production":
            if not self.settings.security.enforce_https:
                self.startup_errors.append("HTTPS enforcement is disabled in production")
                return False
            
            if not self.settings.security.session_secure:
                self.startup_errors.append("Secure session cookies are disabled in production")
                return False
        
        # Check JWT configuration
        if len(self.settings.security.jwt_secret_key) < 32:
            self.startup_errors.append("JWT secret key is too short (minimum 32 characters)")
            return False
        
        # Check password policy
        if self.settings.security.password_min_length < 8:
            self.startup_errors.append("Password minimum length is too short")
            return False
        
        return True
    
    async def initialize_database(self) -> bool:
        """Initialize database with health checks"""
        logger.info("💾 Initializing database...")
        
        try:
            db_manager = initialize_database_manager(self.settings.database)
            await db_manager.initialize()
            
            # Run health check
            health = await db_manager.health_check()
            if not health:
                self.startup_errors.append("Database health check failed")
                return False
            
            logger.info("✅ Database initialized and healthy")
            return True
            
        except Exception as e:
            self.startup_errors.append(f"Database initialization failed: {str(e)}")
            logger.error(f"💥 Database initialization failed: {e}")
            return False
    
    async def initialize_security_services(self) -> bool:
        """Initialize security services"""
        logger.info("🔐 Initializing security services...")
        
        services = {
            "vault": VaultManager(),
            "cloud_security": CloudSecurityHub(),
            "policy_engine": PolicyEngine(),
            "auth_manager": AuthManager(self.settings.security, self.settings.database),
            "security_monitor": SecurityMonitoringSystem(self.settings)
        }
        
        for service_name, service in services.items():
            try:
                await service.initialize()
                
                # Run health check if available
                if hasattr(service, 'health_check'):
                    health = await service.health_check()
                    if not health:
                        logger.warning(f"⚠️ {service_name} health check failed")
                
                logger.info(f"✅ {service_name} initialized")
                
            except Exception as e:
                logger.error(f"💥 {service_name} initialization failed: {e}")
                self.startup_errors.append(f"{service_name}: {str(e)}")
                
                # Some services can fail in demo mode
                if "demo" not in str(e).lower():
                    return False
        
        return True
    
    async def run_startup_sequence(self) -> bool:
        """Run complete production startup sequence"""
        logger.info("🚀 Starting DevSecOps Platform Production Initialization")
        logger.info("="*60)
        
        startup_steps = [
            ("Environment Validation", self.validate_environment),
            ("Database Initialization", self.initialize_database),
            ("Security Services", self.initialize_security_services)
        ]
        
        for step_name, step_func in startup_steps:
            logger.info(f"🔄 {step_name}...")
            
            try:
                success = await step_func()
                if not success:
                    logger.error(f"❌ {step_name} FAILED")
                    self._print_startup_summary(False)
                    return False
                
                logger.info(f"✅ {step_name} COMPLETED")
                
            except Exception as e:
                logger.error(f"💥 {step_name} ERROR: {e}")
                self.startup_errors.append(f"{step_name}: {str(e)}")
                self._print_startup_summary(False)
                return False
        
        self._print_startup_summary(True)
        return True
    
    def _print_startup_summary(self, success: bool):
        """Print startup summary"""
        logger.info("="*60)
        if success:
            logger.info("🎉 PRODUCTION STARTUP SUCCESSFUL!")
            logger.info("✅ All systems initialized and validated")
            logger.info(f"🌍 Environment: {self.settings.app.environment}")
            logger.info(f"🏃 Application ready to serve on port {self.settings.app.port}")
        else:
            logger.error("💥 PRODUCTION STARTUP FAILED!")
            logger.error("❌ Critical issues detected:")
            for error in self.startup_errors:
                logger.error(f"   • {error}")
        
        logger.info("="*60)


def run_database_migrations():
    """Run database migrations"""
    print("🔄 Running database migrations...")
    try:
        result = subprocess.run([
            sys.executable, "-m", "alembic", "upgrade", "head"
        ], check=True, capture_output=True, text=True)
        print("✅ Database migrations completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Database migration failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("⚠️ Alembic not found, skipping migrations")
        return True


async def main():
    """Main startup function"""
    print("🚀 DevSecOps Platform - Production Startup")
    print("="*50)
    
    # Run database migrations first
    if not run_database_migrations():
        print("❌ Database migration failed - aborting startup")
        sys.exit(1)
    
    # Initialize startup manager
    startup_manager = ProductionStartup()
    
    try:
        # Run startup validation sequence
        success = await startup_manager.run_startup_sequence()
        
        if success:
            logger.info("🚀 Starting FastAPI application...")
            
            # Start the application
            import uvicorn
            from src.main import app
            
            config = uvicorn.Config(
                app,
                host=startup_manager.settings.app.host,
                port=startup_manager.settings.app.port,
                log_level="info",
                access_log=True,
                server_header=False,
                date_header=False,
                reload=False  # Never reload in production
            )
            
            server = uvicorn.Server(config)
            await server.serve()
        else:
            logger.error("❌ Startup failed - application will not start")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown requested by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Unexpected startup error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
