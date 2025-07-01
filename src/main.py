"""
DevSecOps Platform for AI Solutions
Main application entry point - Production Ready with Advanced Security
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from .core.production_config import ProductionSettings
from .core.production_logging import setup_production_logging
from .core.database import initialize_database_manager
from .core.validation import validate_request_size, create_validation_error_response
from .dashboard.routes import router as dashboard_router
from .monitoring.metrics import setup_metrics
from .monitoring.security_monitor import SecurityMonitoringSystem, get_security_monitor
from .integrations.vault_manager import VaultManager
from .integrations.cloud_security_hub import CloudSecurityHub
from .policies.policy_engine import PolicyEngine
from .auth.auth_manager import AuthManager
from .auth.middleware import AuthMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from .auth.routes import router as auth_router
from .auth.dependencies import set_auth_dependencies, get_current_user, require_permission

# Load environment variables
load_dotenv()

# Global instances
settings = ProductionSettings()
vault_manager = VaultManager()
cloud_security_hub = CloudSecurityHub()
policy_engine = PolicyEngine()
security_monitor = SecurityMonitoringSystem(settings)
auth_manager = None
db_manager = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management"""
    global auth_manager, db_manager
    
    # Startup
    setup_production_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting DevSecOps Platform for AI Solutions")
    
    try:
        # Initialize database
        db_manager = initialize_database_manager(settings.database)
        await db_manager.initialize()
        
        # Initialize authentication
        auth_manager = AuthManager(settings.security, settings.database)
        await auth_manager.initialize()
        
        # Set auth dependencies
        set_auth_dependencies(auth_manager, auth_manager.rbac)
        
        # Initialize core components
        await vault_manager.initialize()
        await cloud_security_hub.initialize()
        await policy_engine.initialize()
        
        # Initialize security monitoring
        await security_monitor.start_monitoring()
        
        # Setup monitoring
        setup_metrics()
        
        logger.info("Platform initialized successfully - Advanced security monitoring active")
        
        yield
        
        # Shutdown
        logger.info("Shutting down DevSecOps Platform")
        await security_monitor.stop_monitoring()
        await auth_manager.cleanup()
        await db_manager.cleanup()
        await vault_manager.cleanup()
        await cloud_security_hub.cleanup()
        await policy_engine.cleanup()
        
    except Exception as e:
        logger.error(f"Failed to initialize platform: {e}")
        raise


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    app = FastAPI(
        title="DevSecOps Platform for AI Solutions",
        description="Production-ready comprehensive security pipeline with automated scanning and policy enforcement",
        version=settings.app.app_version,
        lifespan=lifespan,
        docs_url="/docs" if settings.app.environment != "production" else None,
        redoc_url="/redoc" if settings.app.environment != "production" else None,
        openapi_url="/openapi.json" if settings.app.environment != "production" else None,
    )
    
    # Security middleware (order matters!)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.security.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
    )
    
    # Trusted host middleware
    if settings.app.environment == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"]
        )
    
    # Rate limiting middleware
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=settings.security.rate_limit_requests,
        burst_limit=10
    )
    
    # Authentication middleware
    app.add_middleware(AuthMiddleware, auth_manager=auth_manager)
    
    # Include routers
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(dashboard_router, prefix="/api/v1")
    
    # Add new security endpoints
    _add_security_endpoints(app)
    
    return app


def _add_security_endpoints(app: FastAPI):
    """Add security monitoring and management endpoints"""
    
    @app.get("/api/v1/security/alerts")
    async def get_security_alerts(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_security_events"))
    ):
        """Get active security alerts"""
        monitor = await get_security_monitor()
        stats = monitor.get_alert_statistics()
        return {
            "alerts": list(monitor.active_alerts.values()),
            "statistics": stats
        }
    
    @app.post("/api/v1/security/alerts/{alert_id}/resolve")
    async def resolve_security_alert(
        alert_id: str,
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("manage_security_events"))
    ):
        """Resolve a security alert"""
        monitor = await get_security_monitor()
        resolved = await monitor.resolve_alert(alert_id, current_user.username)
        
        if resolved:
            return {"message": "Alert resolved successfully"}
        else:
            raise HTTPException(status_code=404, detail="Alert not found")
    
    @app.get("/api/v1/policies")
    async def get_policies(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_policies"))
    ):
        """Get security policies"""
        policies = await policy_engine.get_all_policies()
        return {"policies": policies}
    
    @app.post("/api/v1/policies")
    async def create_policy(
        policy_data: dict,
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("manage_policies"))
    ):
        """Create a new security policy"""
        policy = await policy_engine.create_policy(policy_data)
        return {"policy": policy, "message": "Policy created successfully"}
    
    @app.get("/api/v1/policies/violations")
    async def get_policy_violations(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_policy_violations"))
    ):
        """Get policy violations"""
        violations = await policy_engine.get_active_violations()
        return {"violations": violations}
    
    @app.get("/api/v1/monitoring/metrics")
    async def get_monitoring_metrics(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_monitoring_data"))
    ):
        """Get system monitoring metrics"""
        monitor = await get_security_monitor()
        stats = monitor.get_alert_statistics()
        
        return {
            "security_metrics": stats,
            "system_health": "healthy",  # Would integrate with actual health checks
            "performance_metrics": {
                "avg_response_time": stats.get("avg_response_time_seconds", 0),
                "threat_detection_accuracy": stats.get("threat_detection_accuracy", 0)
            }
        }
    
    @app.get("/api/v1/integrations/vault/status")
    async def get_vault_status(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_vault_status"))
    ):
        """Get HashiCorp Vault status"""
        status = await vault_manager.get_status()
        return {"vault_status": status}
    
    @app.get("/api/v1/integrations/aws/findings")
    async def get_aws_findings(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_cloud_findings"))
    ):
        """Get AWS Security Hub findings"""
        findings = await cloud_security_hub.get_aws_findings()
        return {"aws_findings": findings}
    
    @app.get("/api/v1/integrations/azure/findings")
    async def get_azure_findings(
        current_user = Depends(get_current_user),
        _auth = Depends(require_permission("read_cloud_findings"))
    ):
        """Get Azure Security Center findings"""
        findings = await cloud_security_hub.get_azure_findings()
        return {"azure_findings": findings}
    
    # Global exception handler for validation errors
    @app.exception_handler(422)
    async def validation_exception_handler(request: Request, exc):
        """Handle validation errors with security logging"""
        from fastapi.exceptions import RequestValidationError
        
        if isinstance(exc, RequestValidationError):
            errors = []
            for error in exc.errors():
                errors.append({
                    "field": " -> ".join(str(loc) for loc in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"]
                })
            
            return JSONResponse(
                status_code=422,
                content=create_validation_error_response(errors).detail
            )
        
        return JSONResponse(
            status_code=422,
            content={"message": "Validation failed", "details": str(exc)}
        )


app = create_app()


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "DevSecOps Platform for AI Solutions",
        "version": settings.app.version,
        "status": "operational",
        "environment": settings.app.environment.value
    }


@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": "2025-01-01T00:00:00Z",
        "version": settings.app.version,
        "environment": settings.app.environment.value,
        "services": {}
    }
    
    try:
        # Check database
        if db_manager:
            health_status["services"]["database"] = await db_manager.health_check()
        else:
            health_status["services"]["database"] = False
        
        # Check authentication
        if auth_manager:
            health_status["services"]["authentication"] = True
        else:
            health_status["services"]["authentication"] = False
        
        # Check core services
        health_status["services"]["vault"] = await vault_manager.health_check()
        health_status["services"]["cloud_security"] = await cloud_security_hub.health_check()
        health_status["services"]["policy_engine"] = await policy_engine.health_check()
        
        # Overall status
        all_healthy = all(health_status["services"].values())
        health_status["status"] = "healthy" if all_healthy else "degraded"
        
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
    
    return health_status


@app.get("/api/v1/status")
async def detailed_status(request: Request):
    """Detailed system status (authenticated endpoint)"""
    return {
        "platform": "DevSecOps for AI Solutions",
        "version": settings.app.version,
        "environment": settings.app.environment.value,
        "uptime": "N/A",  # Would calculate actual uptime
        "database": await db_manager.get_database_stats() if db_manager else {},
        "metrics": {
            "active_policies": await policy_engine.get_policy_count(),
            "security_events": "N/A",  # Would get from database
            "vault_secrets": "N/A",   # Would get count from vault
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=settings.app.environment == "development",
        access_log=True,
        server_header=False,
        date_header=False
    )


async def main():
    """Main function to run the application"""
    config = uvicorn.Config(
        app,
        host=settings.app.host,
        port=settings.app.port,
        log_level=settings.app.log_level.value.lower(),
        reload=settings.app.debug
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
