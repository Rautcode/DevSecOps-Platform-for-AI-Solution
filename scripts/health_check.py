"""
Production Health Check and System Validation Script
Comprehensive validation of all production components and integrations
"""

import asyncio
import logging
import time
import json
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import psutil
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class HealthCheckResult:
    """Health check result structure"""
    component: str
    status: str  # HEALTHY, DEGRADED, UNHEALTHY
    response_time: float
    details: Dict[str, Any]
    timestamp: datetime
    error_message: Optional[str] = None


class ProductionHealthChecker:
    """Comprehensive production health checker"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.results: List[HealthCheckResult] = []
        
        # Health check thresholds
        self.thresholds = {
            "response_time_warning": 1.0,  # seconds
            "response_time_critical": 5.0,  # seconds
            "cpu_warning": 70.0,  # percentage
            "cpu_critical": 90.0,  # percentage
            "memory_warning": 80.0,  # percentage
            "memory_critical": 95.0,  # percentage
            "disk_warning": 80.0,  # percentage
            "disk_critical": 95.0,  # percentage
        }
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load configuration for health checks"""
        default_config = {
            "api_base_url": "http://localhost:8000",
            "database_url": "postgresql://localhost:5432/devsecops",
            "vault_url": "http://localhost:8200",
            "redis_url": "redis://localhost:6379",
            "prometheus_url": "http://localhost:9090",
            "grafana_url": "http://localhost:3000",
            "check_external_services": True,
            "timeout": 30.0
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Could not load config file {config_file}: {e}")
        
        return default_config
    
    async def check_system_resources(self) -> HealthCheckResult:
        """Check system resource usage"""
        start_time = time.time()
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Network stats
            network = psutil.net_io_counters()
            
            # Process count
            process_count = len(psutil.pids())
            
            details = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_total_gb": memory.total / (1024**3),
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk_percent,
                "disk_total_gb": disk.total / (1024**3),
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "process_count": process_count
            }
            
            # Determine status
            status = "HEALTHY"
            if (cpu_percent > self.thresholds["cpu_warning"] or 
                memory_percent > self.thresholds["memory_warning"] or
                disk_percent > self.thresholds["disk_warning"]):
                status = "DEGRADED"
            
            if (cpu_percent > self.thresholds["cpu_critical"] or
                memory_percent > self.thresholds["memory_critical"] or
                disk_percent > self.thresholds["disk_critical"]):
                status = "UNHEALTHY"
            
            return HealthCheckResult(
                component="system_resources",
                status=status,
                response_time=time.time() - start_time,
                details=details,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="system_resources",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_api_endpoints(self) -> HealthCheckResult:
        """Check API endpoint health"""
        start_time = time.time()
        
        try:
            base_url = self.config["api_base_url"]
            timeout = self.config["timeout"]
            
            # Test critical endpoints
            endpoints = [
                ("/health", "GET"),
                ("/status", "GET"),
                ("/auth/health", "GET"),
                ("/monitoring/health", "GET")
            ]
            
            endpoint_results = {}
            
            for endpoint, method in endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    response = requests.get(url, timeout=timeout)
                    
                    endpoint_results[endpoint] = {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "healthy": 200 <= response.status_code < 300
                    }
                except Exception as e:
                    endpoint_results[endpoint] = {
                        "status_code": 0,
                        "response_time": timeout,
                        "healthy": False,
                        "error": str(e)
                    }
            
            # Determine overall status
            healthy_endpoints = sum(1 for result in endpoint_results.values() if result["healthy"])
            total_endpoints = len(endpoints)
            
            if healthy_endpoints == total_endpoints:
                status = "HEALTHY"
            elif healthy_endpoints >= total_endpoints * 0.7:  # 70% threshold
                status = "DEGRADED"
            else:
                status = "UNHEALTHY"
            
            return HealthCheckResult(
                component="api_endpoints",
                status=status,
                response_time=time.time() - start_time,
                details={
                    "endpoint_results": endpoint_results,
                    "healthy_count": healthy_endpoints,
                    "total_count": total_endpoints
                },
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="api_endpoints",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_database_connectivity(self) -> HealthCheckResult:
        """Check database connectivity and performance"""
        start_time = time.time()
        
        try:
            import asyncpg
            
            # Test basic connectivity
            conn = await asyncpg.connect(self.config["database_url"])
            
            # Test query performance
            query_start = time.time()
            result = await conn.fetchval("SELECT 1")
            query_time = time.time() - query_start
            
            # Check database stats
            stats_query = """
                SELECT 
                    pg_database_size(current_database()) as db_size,
                    (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') as active_connections,
                    (SELECT setting FROM pg_settings WHERE name = 'max_connections') as max_connections
            """
            stats = await conn.fetchrow(stats_query)
            
            await conn.close()
            
            details = {
                "connectivity": True,
                "query_response_time": query_time,
                "database_size_bytes": stats["db_size"],
                "active_connections": stats["active_connections"],
                "max_connections": int(stats["max_connections"]),
                "connection_utilization": stats["active_connections"] / int(stats["max_connections"]) * 100
            }
            
            # Determine status
            status = "HEALTHY"
            if query_time > self.thresholds["response_time_warning"]:
                status = "DEGRADED"
            if query_time > self.thresholds["response_time_critical"]:
                status = "UNHEALTHY"
            
            return HealthCheckResult(
                component="database",
                status=status,
                response_time=time.time() - start_time,
                details=details,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="database",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={"connectivity": False},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_vault_service(self) -> HealthCheckResult:
        """Check HashiCorp Vault service"""
        start_time = time.time()
        
        try:
            vault_url = self.config["vault_url"]
            timeout = self.config["timeout"]
            
            # Check Vault health endpoint
            response = requests.get(
                f"{vault_url}/v1/sys/health",
                timeout=timeout
            )
            
            vault_data = response.json() if response.content else {}
            
            details = {
                "vault_initialized": vault_data.get("initialized", False),
                "vault_sealed": vault_data.get("sealed", True),
                "vault_version": vault_data.get("version", "unknown"),
                "response_code": response.status_code
            }
            
            # Determine status
            if response.status_code == 200 and not vault_data.get("sealed", True):
                status = "HEALTHY"
            elif response.status_code in [429, 472, 473]:  # Vault sealed or standby
                status = "DEGRADED"
            else:
                status = "UNHEALTHY"
            
            return HealthCheckResult(
                component="vault_service",
                status=status,
                response_time=time.time() - start_time,
                details=details,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="vault_service",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_redis_service(self) -> HealthCheckResult:
        """Check Redis service"""
        start_time = time.time()
        
        try:
            import redis.asyncio as redis
            
            redis_client = redis.from_url(self.config["redis_url"])
            
            # Test basic operations
            await redis_client.ping()
            
            # Get Redis info
            info = await redis_client.info()
            
            await redis_client.close()
            
            details = {
                "redis_version": info.get("redis_version", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "used_memory": info.get("used_memory", 0),
                "used_memory_human": info.get("used_memory_human", "0B"),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0)
            }
            
            return HealthCheckResult(
                component="redis_service",
                status="HEALTHY",
                response_time=time.time() - start_time,
                details=details,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="redis_service",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_docker_services(self) -> HealthCheckResult:
        """Check Docker services if running in containers"""
        start_time = time.time()
        
        try:
            # Check if running in Docker
            result = subprocess.run(
                ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                services = []
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            services.append({
                                "name": parts[0],
                                "status": parts[1],
                                "healthy": "Up" in parts[1]
                            })
                
                healthy_services = sum(1 for s in services if s["healthy"])
                total_services = len(services)
                
                status = "HEALTHY" if healthy_services == total_services else "DEGRADED"
                if healthy_services == 0:
                    status = "UNHEALTHY"
                
                details = {
                    "services": services,
                    "healthy_count": healthy_services,
                    "total_count": total_services
                }
            else:
                # Not running in Docker or Docker not available
                details = {"docker_available": False}
                status = "HEALTHY"  # Not an error if not using Docker
            
            return HealthCheckResult(
                component="docker_services",
                status=status,
                response_time=time.time() - start_time,
                details=details,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="docker_services",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def check_monitoring_services(self) -> HealthCheckResult:
        """Check monitoring services (Prometheus, Grafana)"""
        start_time = time.time()
        
        try:
            services = {}
            
            # Check Prometheus
            try:
                prometheus_url = self.config["prometheus_url"]
                response = requests.get(f"{prometheus_url}/-/healthy", timeout=10)
                services["prometheus"] = {
                    "status_code": response.status_code,
                    "healthy": response.status_code == 200
                }
            except Exception as e:
                services["prometheus"] = {
                    "status_code": 0,
                    "healthy": False,
                    "error": str(e)
                }
            
            # Check Grafana
            try:
                grafana_url = self.config["grafana_url"]
                response = requests.get(f"{grafana_url}/api/health", timeout=10)
                services["grafana"] = {
                    "status_code": response.status_code,
                    "healthy": response.status_code == 200
                }
            except Exception as e:
                services["grafana"] = {
                    "status_code": 0,
                    "healthy": False,
                    "error": str(e)
                }
            
            healthy_count = sum(1 for s in services.values() if s["healthy"])
            total_count = len(services)
            
            if healthy_count == total_count:
                status = "HEALTHY"
            elif healthy_count > 0:
                status = "DEGRADED"
            else:
                status = "UNHEALTHY"
            
            return HealthCheckResult(
                component="monitoring_services",
                status=status,
                response_time=time.time() - start_time,
                details={
                    "services": services,
                    "healthy_count": healthy_count,
                    "total_count": total_count
                },
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="monitoring_services",
                status="UNHEALTHY",
                response_time=time.time() - start_time,
                details={},
                timestamp=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all health checks"""
        logger.info("🏥 Starting comprehensive health checks...")
        
        # Define all health check functions
        checks = [
            self.check_system_resources(),
            self.check_api_endpoints(),
            self.check_database_connectivity(),
            self.check_vault_service(),
            self.check_redis_service(),
            self.check_docker_services(),
            self.check_monitoring_services()
        ]
        
        # Run checks concurrently
        self.results = await asyncio.gather(*checks, return_exceptions=True)
        
        # Handle any exceptions
        for i, result in enumerate(self.results):
            if isinstance(result, Exception):
                self.results[i] = HealthCheckResult(
                    component=f"check_{i}",
                    status="UNHEALTHY",
                    response_time=0.0,
                    details={},
                    timestamp=datetime.utcnow(),
                    error_message=str(result)
                )
        
        return self.results
    
    def generate_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report"""
        if not self.results:
            return {"error": "No health check results available"}
        
        # Overall status
        statuses = [result.status for result in self.results]
        if "UNHEALTHY" in statuses:
            overall_status = "UNHEALTHY"
        elif "DEGRADED" in statuses:
            overall_status = "DEGRADED"
        else:
            overall_status = "HEALTHY"
        
        # Component breakdown
        component_status = {}
        for result in self.results:
            component_status[result.component] = {
                "status": result.status,
                "response_time": result.response_time,
                "timestamp": result.timestamp.isoformat(),
                "details": result.details,
                "error": result.error_message
            }
        
        # Summary statistics
        healthy_count = sum(1 for result in self.results if result.status == "HEALTHY")
        degraded_count = sum(1 for result in self.results if result.status == "DEGRADED")
        unhealthy_count = sum(1 for result in self.results if result.status == "UNHEALTHY")
        
        avg_response_time = sum(result.response_time for result in self.results) / len(self.results)
        
        return {
            "overall_status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_components": len(self.results),
                "healthy_components": healthy_count,
                "degraded_components": degraded_count,
                "unhealthy_components": unhealthy_count,
                "average_response_time": avg_response_time
            },
            "components": component_status
        }
    
    def print_health_summary(self):
        """Print human-readable health summary"""
        if not self.results:
            print("❌ No health check results available")
            return
        
        report = self.generate_health_report()
        
        print("\n" + "="*60)
        print("🏥 PRODUCTION HEALTH CHECK SUMMARY")
        print("="*60)
        print(f"Overall Status: {self._get_status_emoji(report['overall_status'])} {report['overall_status']}")
        print(f"Check Time: {report['timestamp']}")
        print(f"Components Checked: {report['summary']['total_components']}")
        print(f"Healthy: {report['summary']['healthy_components']}")
        print(f"Degraded: {report['summary']['degraded_components']}")
        print(f"Unhealthy: {report['summary']['unhealthy_components']}")
        print(f"Avg Response Time: {report['summary']['average_response_time']:.3f}s")
        print("="*60)
        
        print("\nCOMPONENT DETAILS:")
        for component, details in report['components'].items():
            emoji = self._get_status_emoji(details['status'])
            print(f"{emoji} {component}: {details['status']} ({details['response_time']:.3f}s)")
            if details['error']:
                print(f"   Error: {details['error']}")
        
        print("="*60)
    
    def _get_status_emoji(self, status: str) -> str:
        """Get emoji for status"""
        return {
            "HEALTHY": "✅",
            "DEGRADED": "⚠️",
            "UNHEALTHY": "❌"
        }.get(status, "❓")


async def main():
    """Main health check execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Production Health Check")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output file for JSON report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize health checker
    checker = ProductionHealthChecker(args.config)
    
    # Run health checks
    try:
        await checker.run_all_checks()
        
        # Generate and display report
        checker.print_health_summary()
        
        # Save JSON report if requested
        if args.output:
            report = checker.generate_health_report()
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Detailed report saved to: {args.output}")
        
        # Exit with appropriate code
        report = checker.generate_health_report()
        if report['overall_status'] == "UNHEALTHY":
            sys.exit(1)
        elif report['overall_status'] == "DEGRADED":
            sys.exit(2)
        else:
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        print(f"\n💥 Health check failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
