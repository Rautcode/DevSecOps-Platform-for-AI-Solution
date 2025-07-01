"""
Advanced Security Monitoring with OpenTelemetry Integration
Real-time security event monitoring and distributed tracing
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

from opentelemetry import trace, metrics
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False
    JaegerExporter = None

try:
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    PrometheusMetricReader = None
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from ..core.config import ProductionSettings
from ..core.logging_config import log_security_event


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(Enum):
    """Threat assessment levels"""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class SecurityAlert:
    """Security alert data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.INFO
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    resource: Optional[str] = None
    event_type: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    ip_address: str
    reputation_score: float  # 0.0 to 1.0 (1.0 = definitely malicious)
    threat_types: List[str]
    first_seen: datetime
    last_seen: datetime
    sources: List[str]
    country: Optional[str] = None
    organization: Optional[str] = None


class SecurityMonitoringSystem:
    """Advanced security monitoring with real-time threat detection"""
    
    def __init__(self, settings: Optional[ProductionSettings] = None):
        self.settings = settings or ProductionSettings()
        self.logger = logging.getLogger(__name__)
        
        # OpenTelemetry setup
        self._setup_telemetry()
        
        # Security state
        self.active_alerts: Dict[str, SecurityAlert] = {}
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.blocked_ips: set = set()
        self.suspicious_users: Dict[str, int] = {}  # user_id -> violation_count
        
        # Monitoring rules
        self.monitoring_rules: List[Callable] = []
        self.alert_handlers: Dict[AlertSeverity, List[Callable]] = {
            severity: [] for severity in AlertSeverity
        }
        
        # Performance tracking
        self.response_times: List[float] = []
        self.threat_detection_accuracy = 0.0
        
        self._monitoring_active = False
        self._background_tasks: List[asyncio.Task] = []
    
    def _setup_telemetry(self):
        """Setup OpenTelemetry tracing and metrics"""
        try:
            # Configure resource
            resource = Resource.create({SERVICE_NAME: "devsecops-security-monitor"})
            
            # Setup tracing
            trace.set_tracer_provider(TracerProvider(resource=resource))
            self.tracer = trace.get_tracer(__name__)
            
            # Jaeger exporter for distributed tracing
            if hasattr(self.settings, 'monitoring') and self.settings.monitoring.jaeger_endpoint and JAEGER_AVAILABLE:
                jaeger_exporter = JaegerExporter(
                    agent_host_name=self.settings.monitoring.jaeger_endpoint.split("://")[1].split(":")[0],
                    agent_port=14268,
                )
                span_processor = BatchSpanProcessor(jaeger_exporter)
                trace.get_tracer_provider().add_span_processor(span_processor)
            
            # Setup metrics
            prometheus_reader = PrometheusMetricReader()
            metrics.set_meter_provider(MeterProvider(
                resource=resource,
                metric_readers=[prometheus_reader]
            ))
            self.meter = metrics.get_meter(__name__)
            
            # Create custom metrics
            self.security_events_counter = self.meter.create_counter(
                "security_events_total",
                description="Total security events detected"
            )
            
            self.threat_detection_histogram = self.meter.create_histogram(
                "threat_detection_duration_seconds",
                description="Time taken to detect threats"
            )
            
            self.active_threats_gauge = self.meter.create_up_down_counter(
                "active_threats_total",
                description="Number of active security threats"
            )
            
            self.logger.info("OpenTelemetry monitoring configured successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to setup OpenTelemetry: {e}")
    
    async def start_monitoring(self):
        """Start background security monitoring tasks"""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        
        # Start monitoring tasks
        tasks = [
            self._monitor_failed_logins(),
            self._monitor_suspicious_activities(),
            self._monitor_resource_access(),
            self._monitor_policy_violations(),
            self._update_threat_intelligence(),
            self._cleanup_old_alerts(),
        ]
        
        self._background_tasks = [asyncio.create_task(task) for task in tasks]
        
        self.logger.info("Security monitoring system started")
        
        log_security_event(
            event_type="monitoring_started",
            description="Advanced security monitoring system activated",
            severity="INFO"
        )
    
    async def stop_monitoring(self):
        """Stop background monitoring tasks"""
        self._monitoring_active = False
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()
        
        self.logger.info("Security monitoring system stopped")
    
    async def _monitor_failed_logins(self):
        """Monitor and detect brute force attacks"""
        failed_attempts: Dict[str, List[datetime]] = {}
        
        while self._monitoring_active:
            try:
                # This would typically connect to your authentication logs
                # For now, we'll simulate monitoring
                
                current_time = datetime.utcnow()
                
                # Check for brute force patterns
                for ip, attempts in list(failed_attempts.items()):
                    # Remove old attempts (older than 1 hour)
                    attempts = [a for a in attempts if current_time - a < timedelta(hours=1)]
                    failed_attempts[ip] = attempts
                    
                    # Check if threshold exceeded
                    if len(attempts) >= 5:  # 5 failed attempts in 1 hour
                        await self._create_alert(
                            title="Potential Brute Force Attack",
                            description=f"Multiple failed login attempts from IP {ip}",
                            severity=AlertSeverity.HIGH,
                            threat_level=ThreatLevel.MALICIOUS,
                            source_ip=ip,
                            event_type="brute_force_attack",
                            metadata={"attempt_count": len(attempts)}
                        )
                        
                        # Add to blocked IPs
                        self.blocked_ips.add(ip)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in failed login monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _monitor_suspicious_activities(self):
        """Monitor for suspicious user activities"""
        while self._monitoring_active:
            try:
                current_time = datetime.utcnow()
                
                # Monitor suspicious user patterns
                for user_id, violation_count in list(self.suspicious_users.items()):
                    if violation_count >= 3:  # 3 violations threshold
                        await self._create_alert(
                            title="Suspicious User Activity",
                            description=f"User {user_id} has multiple security violations",
                            severity=AlertSeverity.MEDIUM,
                            threat_level=ThreatLevel.SUSPICIOUS,
                            user_id=user_id,
                            event_type="suspicious_user_activity",
                            metadata={"violation_count": violation_count}
                        )
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in suspicious activity monitoring: {e}")
                await asyncio.sleep(120)
    
    async def _monitor_resource_access(self):
        """Monitor unauthorized resource access attempts"""
        while self._monitoring_active:
            try:
                # Monitor access patterns to sensitive resources
                # This would integrate with your access logs
                
                await asyncio.sleep(45)  # Check every 45 seconds
                
            except Exception as e:
                self.logger.error(f"Error in resource access monitoring: {e}")
                await asyncio.sleep(90)
    
    async def _monitor_policy_violations(self):
        """Monitor policy violations and compliance issues"""
        while self._monitoring_active:
            try:
                # Check for policy violations
                # This would integrate with your policy engine
                
                await asyncio.sleep(120)  # Check every 2 minutes
                
            except Exception as e:
                self.logger.error(f"Error in policy violation monitoring: {e}")
                await asyncio.sleep(180)
    
    async def _update_threat_intelligence(self):
        """Update threat intelligence data"""
        while self._monitoring_active:
            try:
                # Update threat intelligence from external sources
                # This would integrate with threat intel feeds
                
                await asyncio.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error updating threat intelligence: {e}")
                await asyncio.sleep(600)
    
    async def _cleanup_old_alerts(self):
        """Clean up resolved and old alerts"""
        while self._monitoring_active:
            try:
                current_time = datetime.utcnow()
                cutoff_time = current_time - timedelta(days=7)  # Keep alerts for 7 days
                
                # Remove old resolved alerts
                old_alerts = [
                    alert_id for alert_id, alert in self.active_alerts.items()
                    if alert.resolved and alert.resolved_at and alert.resolved_at < cutoff_time
                ]
                
                for alert_id in old_alerts:
                    del self.active_alerts[alert_id]
                
                if old_alerts:
                    self.logger.info(f"Cleaned up {len(old_alerts)} old alerts")
                
                await asyncio.sleep(3600)  # Clean up every hour
                
            except Exception as e:
                self.logger.error(f"Error in alert cleanup: {e}")
                await asyncio.sleep(3600)
    
    async def _create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        threat_level: ThreatLevel,
        event_type: str,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityAlert:
        """Create and process a security alert"""
        
        with self.tracer.start_as_current_span("create_security_alert") as span:
            start_time = time.time()
            
            try:
                alert = SecurityAlert(
                    title=title,
                    description=description,
                    severity=severity,
                    threat_level=threat_level,
                    source_ip=source_ip,
                    user_id=user_id,
                    resource=resource,
                    event_type=event_type,
                    metadata=metadata or {}
                )
                
                # Add to active alerts
                self.active_alerts[alert.id] = alert
                
                # Update metrics
                self.security_events_counter.add(1, {
                    "severity": severity.value,
                    "event_type": event_type,
                    "threat_level": threat_level.value
                })
                
                # Add span attributes
                span.set_attributes({
                    "alert.id": alert.id,
                    "alert.severity": severity.value,
                    "alert.threat_level": threat_level.value,
                    "alert.event_type": event_type
                })
                
                # Log security event
                log_security_event(
                    event_type="security_alert_created",
                    description=f"Security alert created: {title}",
                    severity=severity.value.upper(),
                    metadata={
                        "alert_id": alert.id,
                        "threat_level": threat_level.value,
                        "source_ip": source_ip,
                        "user_id": user_id
                    }
                )
                
                # Execute alert handlers
                await self._execute_alert_handlers(alert)
                
                # Record response time
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                self.threat_detection_histogram.record(response_time, {
                    "severity": severity.value,
                    "event_type": event_type
                })
                
                return alert
                
            except Exception as e:
                span.record_exception(e)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
    
    async def _execute_alert_handlers(self, alert: SecurityAlert):
        """Execute registered alert handlers"""
        handlers = self.alert_handlers.get(alert.severity, [])
        
        for handler in handlers:
            try:
                await handler(alert)
            except Exception as e:
                self.logger.error(f"Error executing alert handler: {e}")
    
    def register_alert_handler(self, severity: AlertSeverity, handler: Callable):
        """Register an alert handler for specific severity"""
        self.alert_handlers[severity].append(handler)
    
    async def resolve_alert(self, alert_id: str, resolved_by: str) -> bool:
        """Resolve a security alert"""
        if alert_id not in self.active_alerts:
            return False
        
        alert = self.active_alerts[alert_id]
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = resolved_by
        
        log_security_event(
            event_type="security_alert_resolved",
            description=f"Security alert resolved: {alert.title}",
            severity="INFO",
            metadata={
                "alert_id": alert_id,
                "resolved_by": resolved_by
            }
        )
        
        return True
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get security alert statistics"""
        total_alerts = len(self.active_alerts)
        resolved_alerts = sum(1 for alert in self.active_alerts.values() if alert.resolved)
        
        severity_counts = {}
        for severity in AlertSeverity:
            count = sum(1 for alert in self.active_alerts.values() 
                       if alert.severity == severity and not alert.resolved)
            severity_counts[severity.value] = count
        
        avg_response_time = sum(self.response_times[-100:]) / len(self.response_times[-100:]) if self.response_times else 0
        
        return {
            "total_alerts": total_alerts,
            "active_alerts": total_alerts - resolved_alerts,
            "resolved_alerts": resolved_alerts,
            "severity_breakdown": severity_counts,
            "avg_response_time_seconds": avg_response_time,
            "blocked_ips_count": len(self.blocked_ips),
            "suspicious_users_count": len(self.suspicious_users),
            "threat_detection_accuracy": self.threat_detection_accuracy
        }
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP address reputation"""
        return self.threat_intelligence.get(ip_address)
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP address is blocked"""
        return ip_address in self.blocked_ips
    
    def add_suspicious_activity(self, user_id: str):
        """Add suspicious activity for a user"""
        self.suspicious_users[user_id] = self.suspicious_users.get(user_id, 0) + 1


# Global security monitoring instance
security_monitor = SecurityMonitoringSystem()


async def get_security_monitor() -> SecurityMonitoringSystem:
    """Get security monitoring instance"""
    return security_monitor
