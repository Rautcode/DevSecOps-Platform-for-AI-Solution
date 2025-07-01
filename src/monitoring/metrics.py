"""
Prometheus Metrics Collection for DevSecOps Platform
Real-time monitoring of security events and performance metrics
"""

import time
import logging
from typing import Dict, Any
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, start_http_server

from ..core.config import Settings


# Global metrics registry
REGISTRY = CollectorRegistry()

# Security Metrics
SECURITY_EVENTS_TOTAL = Counter(
    'devsecops_security_events_total',
    'Total number of security events',
    ['event_type', 'severity'],
    registry=REGISTRY
)

POLICY_VIOLATIONS_TOTAL = Counter(
    'devsecops_policy_violations_total',
    'Total number of policy violations',
    ['policy_id', 'severity'],
    registry=REGISTRY
)

INCIDENT_RESPONSE_TIME = Histogram(
    'devsecops_incident_response_seconds',
    'Time taken to respond to security incidents',
    ['incident_type'],
    registry=REGISTRY
)

# Compliance Metrics
COMPLIANCE_SCORE = Gauge(
    'devsecops_compliance_score',
    'Compliance score percentage',
    ['framework'],
    registry=REGISTRY
)

# Cloud Security Metrics
CLOUD_FINDINGS_TOTAL = Counter(
    'devsecops_cloud_findings_total',
    'Total number of cloud security findings',
    ['provider', 'severity'],
    registry=REGISTRY
)

# Vault Metrics
VAULT_OPERATIONS_TOTAL = Counter(
    'devsecops_vault_operations_total',
    'Total number of Vault operations',
    ['operation', 'status'],
    registry=REGISTRY
)

SECRET_ROTATIONS_TOTAL = Counter(
    'devsecops_secret_rotations_total',
    'Total number of secret rotations',
    ['secret_type'],
    registry=REGISTRY
)

# Performance Metrics
API_REQUEST_DURATION = Histogram(
    'devsecops_api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint'],
    registry=REGISTRY
)

ACTIVE_CONNECTIONS = Gauge(
    'devsecops_active_connections',
    'Number of active connections',
    ['connection_type'],
    registry=REGISTRY
)

# System Metrics
SYSTEM_HEALTH = Gauge(
    'devsecops_system_health',
    'System component health status (1=healthy, 0=unhealthy)',
    ['component'],
    registry=REGISTRY
)


class SecurityMetrics:
    """Security metrics collection and management"""
    
    def __init__(self, settings: Settings = None):
        self.settings = settings or Settings()
        self.logger = logging.getLogger(__name__)
        self._start_time = time.time()
    
    def record_security_event(self, event_type: str, severity: str) -> None:
        """Record a security event"""
        SECURITY_EVENTS_TOTAL.labels(
            event_type=event_type,
            severity=severity
        ).inc()
    
    def record_policy_violation(self, policy_id: str, severity: str) -> None:
        """Record a policy violation"""
        POLICY_VIOLATIONS_TOTAL.labels(
            policy_id=policy_id,
            severity=severity
        ).inc()
    
    def record_incident_response_time(self, incident_type: str, response_time: float) -> None:
        """Record incident response time"""
        INCIDENT_RESPONSE_TIME.labels(
            incident_type=incident_type
        ).observe(response_time)
    
    def update_compliance_score(self, framework: str, score: float) -> None:
        """Update compliance score for a framework"""
        COMPLIANCE_SCORE.labels(framework=framework).set(score)
    
    def record_cloud_finding(self, provider: str, severity: str) -> None:
        """Record a cloud security finding"""
        CLOUD_FINDINGS_TOTAL.labels(
            provider=provider,
            severity=severity
        ).inc()
    
    def record_vault_operation(self, operation: str, status: str) -> None:
        """Record a Vault operation"""
        VAULT_OPERATIONS_TOTAL.labels(
            operation=operation,
            status=status
        ).inc()
    
    def record_secret_rotation(self, secret_type: str) -> None:
        """Record a secret rotation"""
        SECRET_ROTATIONS_TOTAL.labels(secret_type=secret_type).inc()
    
    def record_api_request(self, method: str, endpoint: str, duration: float) -> None:
        """Record API request metrics"""
        API_REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def update_active_connections(self, connection_type: str, count: int) -> None:
        """Update active connections count"""
        ACTIVE_CONNECTIONS.labels(connection_type=connection_type).set(count)
    
    def update_system_health(self, component: str, is_healthy: bool) -> None:
        """Update system component health"""
        SYSTEM_HEALTH.labels(component=component).set(1 if is_healthy else 0)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of current metrics"""
        uptime = time.time() - self._start_time
        
        return {
            "uptime_seconds": uptime,
            "security_events": self._get_metric_value(SECURITY_EVENTS_TOTAL),
            "policy_violations": self._get_metric_value(POLICY_VIOLATIONS_TOTAL),
            "cloud_findings": self._get_metric_value(CLOUD_FINDINGS_TOTAL),
            "vault_operations": self._get_metric_value(VAULT_OPERATIONS_TOTAL),
            "secret_rotations": self._get_metric_value(SECRET_ROTATIONS_TOTAL)
        }
    
    def _get_metric_value(self, metric) -> float:
        """Get current value of a metric"""
        try:
            # For counters, get the total value
            samples = list(metric.collect())[0].samples
            return sum(sample.value for sample in samples)
        except Exception:
            return 0.0


# Global metrics instance
security_metrics = SecurityMetrics()


def setup_metrics(port: int = None) -> None:
    """Setup Prometheus metrics server"""
    settings = Settings()
    metrics_port = port or settings.prometheus_port
    
    try:
        start_http_server(metrics_port, registry=REGISTRY)
        logging.getLogger(__name__).info(f"Metrics server started on port {metrics_port}")
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to start metrics server: {e}")


def get_metrics_instance() -> SecurityMetrics:
    """Get the global metrics instance"""
    return security_metrics
