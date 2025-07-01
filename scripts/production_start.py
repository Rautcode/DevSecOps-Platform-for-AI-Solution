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

from src.core.production_config import ProductionSettings
from src.core.production_logging import setup_production_logging
from src.core.database import initialize_database_manager
from src.auth.auth_manager import AuthManager
from src.integrations.vault_manager import VaultManager
from src.integrations.cloud_security_hub import CloudSecurityHub
from src.policies.policy_engine import PolicyEngine
from src.monitoring.security_monitor import SecurityMonitoringSystem

logger = logging.getLogger(__name__)


class ProductionStartup:
    """Production startup manager with security validation and health checks"""
    
    @staticmethod
    def check_environment() -> bool:
        """Check if all required environment variables are set"""
        required_vars = [
            "SECURITY_SECRET_KEY",
            "DB_HOST",
            "DB_PASSWORD",
            "VAULT_ADDR"
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
            print("Please set these variables before starting the platform.")
            return False
def check_environment() -> bool:
    """Check if all required environment variables are set"""
    return ProductionStartup.check_environment()


def run_database_migrations():
        return True


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


def start_production_server():
    """Start the production server with Gunicorn"""
    print("🚀 Starting DevSecOps Platform in production mode...")
    
    # Get configuration from environment
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = os.getenv("APP_PORT", "8000")
    workers = os.getenv("APP_WORKERS", "4")
    
    cmd = [
        "gunicorn",
        "src.main:app",
        "--bind", f"{host}:{port}",
        "--workers", str(workers),
        "--worker-class", "uvicorn.workers.UvicornWorker",
        "--timeout", "30",
        "--keep-alive", "5",
        "--max-requests", "1000",
        "--max-requests-jitter", "100",
        "--preload",
        "--access-logfile", "-",
        "--error-logfile", "-",
        "--log-level", "info",
        "--capture-output"
    ]
    
    try:
        print(f"🌐 Starting server on {host}:{port} with {workers} workers")
        process = subprocess.Popen(cmd)
        
        # Handle graceful shutdown
        def signal_handler(signum, frame):
            print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
            process.terminate()
            process.wait()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Wait for process to complete
        process.wait()
        
    except FileNotFoundError:
        print("❌ Gunicorn not found. Please install it: pip install gunicorn")
        return False
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        return False


def main():
    """Main function"""
    print("🚀 DevSecOps Platform - Production Startup")
    print("=" * 50)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Run migrations
    if not run_database_migrations():
        sys.exit(1)
    
    # Start server
    if not start_production_server():
        sys.exit(1)


if __name__ == "__main__":
    main()
