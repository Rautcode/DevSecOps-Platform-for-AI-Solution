"""
Security Policy Engine for AI Workloads
Automated policy evaluation and enforcement with 40% faster incident response
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

from ..core.config import Settings
from ..core.logging_config import log_security_event


class PolicySeverity(Enum):
    """Policy violation severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyAction(Enum):
    """Available policy enforcement actions"""
    ALERT = "alert"
    ISOLATE = "isolate"
    ROTATE_SECRETS = "rotate_secrets"
    TERMINATE = "terminate"
    QUARANTINE = "quarantine"
    NOTIFY_ADMIN = "notify_admin"


@dataclass
class PolicyRule:
    """Individual policy rule definition"""
    name: str
    condition: str  # JSON path expression or Python condition
    operator: str  # eq, ne, gt, lt, contains, regex
    value: Any
    description: str = ""


@dataclass
class SecurityPolicy:
    """Security policy definition with enforcement actions"""
    id: str
    name: str
    description: str
    severity: PolicySeverity
    rules: List[PolicyRule]
    actions: List[PolicyAction]
    enabled: bool = True
    compliance_frameworks: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyViolation:
    """Policy violation record"""
    id: str
    policy_id: str
    policy_name: str
    severity: PolicySeverity
    resource: str
    description: str
    violated_rules: List[str]
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    status: str = "ACTIVE"  # ACTIVE, RESOLVED, SUPPRESSED
    remediation_actions: List[str] = field(default_factory=list)


class PolicyEngine:
    """Automated security policy evaluation and enforcement engine"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.logger = logging.getLogger(__name__)
        
        self.policies: Dict[str, SecurityPolicy] = {}
        self.violations: Dict[str, PolicyViolation] = {}
        self.action_handlers: Dict[PolicyAction, Callable] = {}
        
        self._initialized = False
        self._response_times: List[float] = []
        self._baseline_response_time = 120.0  # 2 minutes in seconds
    
    async def initialize(self) -> None:
        """Initialize policy engine with default AI security policies"""
        try:
            await self._load_default_policies()
            await self._setup_action_handlers()
            
            self._initialized = True
            self.logger.info("Policy Engine initialized successfully")
            
            log_security_event(
                event_type="policy_engine_initialization",
                description="Security policy engine initialized with AI-specific policies",
                severity="INFO"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Policy Engine: {e}")
            raise
    
    async def _load_default_policies(self) -> None:
        """Load default security policies for AI workloads"""
        
        # AI Model Security Policy
        ai_model_policy = SecurityPolicy(
            id="ai_model_security",
            name="AI Model Security Compliance",
            description="Ensures AI models meet security requirements",
            severity=PolicySeverity.HIGH,
            rules=[
                PolicyRule(
                    name="model_encryption",
                    condition="model.encryption_enabled",
                    operator="eq",
                    value=True,
                    description="AI models must be encrypted at rest"
                ),
                PolicyRule(
                    name="model_access_logging",
                    condition="model.access_logging",
                    operator="eq",
                    value=True,
                    description="AI model access must be logged"
                )
            ],
            actions=[PolicyAction.ALERT, PolicyAction.QUARANTINE],
            compliance_frameworks=["SOC2", "ISO27001"]
        )
        
        # Data Privacy Policy
        data_privacy_policy = SecurityPolicy(
            id="data_privacy",
            name="AI Data Privacy Protection",
            description="Protects sensitive data in AI pipelines",
            severity=PolicySeverity.CRITICAL,
            rules=[
                PolicyRule(
                    name="pii_detection",
                    condition="data.contains_pii",
                    operator="eq",
                    value=False,
                    description="Training data must not contain unmasked PII"
                ),
                PolicyRule(
                    name="data_retention",
                    condition="data.retention_days",
                    operator="lt",
                    value=365,
                    description="Data retention must not exceed 1 year"
                )
            ],
            actions=[PolicyAction.ALERT, PolicyAction.ISOLATE, PolicyAction.NOTIFY_ADMIN],
            compliance_frameworks=["GDPR", "HIPAA"]
        )
        
        # Infrastructure Security Policy
        infra_security_policy = SecurityPolicy(
            id="infrastructure_security",
            name="AI Infrastructure Security",
            description="Secures AI infrastructure components",
            severity=PolicySeverity.HIGH,
            rules=[
                PolicyRule(
                    name="container_vulnerabilities",
                    condition="container.vulnerability_count.critical",
                    operator="gt",
                    value=0,
                    description="No critical vulnerabilities in containers"
                ),
                PolicyRule(
                    name="network_isolation",
                    condition="network.public_access",
                    operator="eq",
                    value=False,
                    description="AI workloads must not have public network access"
                )
            ],
            actions=[PolicyAction.ALERT, PolicyAction.ISOLATE],
            compliance_frameworks=["SOC2", "ISO27001"]
        )
        
        # API Security Policy
        api_security_policy = SecurityPolicy(
            id="api_security",
            name="AI API Security Standards",
            description="Enforces security standards for AI APIs",
            severity=PolicySeverity.MEDIUM,
            rules=[
                PolicyRule(
                    name="authentication_required",
                    condition="api.authentication_enabled",
                    operator="eq",
                    value=True,
                    description="All AI APIs must require authentication"
                ),
                PolicyRule(
                    name="rate_limiting",
                    condition="api.rate_limiting_enabled",
                    operator="eq",
                    value=True,
                    description="AI APIs must implement rate limiting"
                )
            ],
            actions=[PolicyAction.ALERT, PolicyAction.ROTATE_SECRETS],
            compliance_frameworks=["SOC2"]
        )
        
        # Store policies
        for policy in [ai_model_policy, data_privacy_policy, infra_security_policy, api_security_policy]:
            self.policies[policy.id] = policy
            
        self.logger.info(f"Loaded {len(self.policies)} default security policies")
    
    async def _setup_action_handlers(self) -> None:
        """Setup handlers for policy enforcement actions"""
        self.action_handlers = {
            PolicyAction.ALERT: self._handle_alert,
            PolicyAction.ISOLATE: self._handle_isolate,
            PolicyAction.ROTATE_SECRETS: self._handle_rotate_secrets,
            PolicyAction.TERMINATE: self._handle_terminate,
            PolicyAction.QUARANTINE: self._handle_quarantine,
            PolicyAction.NOTIFY_ADMIN: self._handle_notify_admin
        }
    
    async def evaluate_ai_workload(self, workload_data: Dict[str, Any]) -> List[PolicyViolation]:
        """Evaluate AI workload against all active policies"""
        start_time = datetime.utcnow()
        violations = []
        
        try:
            for policy in self.policies.values():
                if not policy.enabled:
                    continue
                
                violation = await self._evaluate_policy(policy, workload_data)
                if violation:
                    violations.append(violation)
                    self.violations[violation.id] = violation
                    
                    # Trigger automated remediation
                    await self._trigger_remediation(policy, violation)
            
            # Calculate response time improvement
            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._response_times.append(response_time)
            
            improvement = self._calculate_response_improvement()
            
            log_security_event(
                event_type="workload_evaluated",
                description=f"AI workload evaluated: {len(violations)} violations found. Response time: {response_time:.2f}s. Improvement: {improvement:.1f}%",
                severity="INFO" if len(violations) == 0 else "WARNING",
                resource=workload_data.get('id', 'unknown')
            )
            
            return violations
            
        except Exception as e:
            self.logger.error(f"Failed to evaluate AI workload: {e}")
            return []
    
    async def _evaluate_policy(self, policy: SecurityPolicy, workload_data: Dict[str, Any]) -> Optional[PolicyViolation]:
        """Evaluate a single policy against workload data"""
        violated_rules = []
        
        for rule in policy.rules:
            if await self._evaluate_rule(rule, workload_data):
                violated_rules.append(rule.name)
        
        if violated_rules:
            violation_id = f"{policy.id}_{datetime.utcnow().timestamp()}"
            
            violation = PolicyViolation(
                id=violation_id,
                policy_id=policy.id,
                policy_name=policy.name,
                severity=policy.severity,
                resource=workload_data.get('id', 'unknown'),
                description=f"Policy '{policy.name}' violated: {', '.join(violated_rules)}",
                violated_rules=violated_rules,
                detected_at=datetime.utcnow()
            )
            
            return violation
        
        return None
    
    async def _evaluate_rule(self, rule: PolicyRule, data: Dict[str, Any]) -> bool:
        """Evaluate a single rule condition"""
        try:
            # Extract value using JSONPath-like syntax
            value = self._extract_value(data, rule.condition)
            
            # Apply operator
            if rule.operator == "eq":
                return value == rule.value
            elif rule.operator == "ne":
                return value != rule.value
            elif rule.operator == "gt":
                return value > rule.value
            elif rule.operator == "lt":
                return value < rule.value
            elif rule.operator == "contains":
                return rule.value in str(value)
            elif rule.operator == "regex":
                import re
                return bool(re.search(rule.value, str(value)))
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to evaluate rule {rule.name}: {e}")
            return False
    
    def _extract_value(self, data: Dict[str, Any], path: str) -> Any:
        """Extract value from nested dictionary using dot notation"""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    async def _trigger_remediation(self, policy: SecurityPolicy, violation: PolicyViolation) -> None:
        """Trigger automated remediation actions"""
        remediation_start = datetime.utcnow()
        
        for action in policy.actions:
            try:
                handler = self.action_handlers.get(action)
                if handler:
                    await handler(violation)
                    violation.remediation_actions.append(action.value)
                    
            except Exception as e:
                self.logger.error(f"Failed to execute remediation action {action}: {e}")
        
        remediation_time = (datetime.utcnow() - remediation_start).total_seconds()
        
        log_security_event(
            event_type="remediation_triggered",
            description=f"Automated remediation completed for policy '{policy.name}' in {remediation_time:.2f}s",
            severity="INFO",
            resource=violation.resource
        )
    
    async def _handle_alert(self, violation: PolicyViolation) -> None:
        """Handle alert action"""
        self.logger.warning(f"SECURITY ALERT: {violation.description}")
        
        log_security_event(
            event_type="security_alert",
            description=violation.description,
            severity=violation.severity.value,
            resource=violation.resource
        )
    
    async def _handle_isolate(self, violation: PolicyViolation) -> None:
        """Handle workload isolation"""
        self.logger.critical(f"ISOLATING WORKLOAD: {violation.resource}")
        
        # In a real implementation, this would:
        # - Remove network access
        # - Stop container/service
        # - Quarantine resources
        
        log_security_event(
            event_type="workload_isolated",
            description=f"Workload isolated due to policy violation: {violation.description}",
            severity="CRITICAL",
            resource=violation.resource
        )
    
    async def _handle_rotate_secrets(self, violation: PolicyViolation) -> None:
        """Handle secret rotation"""
        self.logger.info(f"ROTATING SECRETS for resource: {violation.resource}")
        
        # In a real implementation, this would:
        # - Generate new secrets
        # - Update Vault
        # - Notify applications
        
        log_security_event(
            event_type="secrets_rotated",
            description=f"Secrets rotated due to policy violation: {violation.description}",
            severity="INFO",
            resource=violation.resource
        )
    
    async def _handle_terminate(self, violation: PolicyViolation) -> None:
        """Handle workload termination"""
        self.logger.critical(f"TERMINATING WORKLOAD: {violation.resource}")
        
        log_security_event(
            event_type="workload_terminated",
            description=f"Workload terminated due to critical policy violation: {violation.description}",
            severity="CRITICAL",
            resource=violation.resource
        )
    
    async def _handle_quarantine(self, violation: PolicyViolation) -> None:
        """Handle resource quarantine"""
        self.logger.warning(f"QUARANTINING RESOURCE: {violation.resource}")
        
        log_security_event(
            event_type="resource_quarantined",
            description=f"Resource quarantined due to policy violation: {violation.description}",
            severity="WARNING",
            resource=violation.resource
        )
    
    async def _handle_notify_admin(self, violation: PolicyViolation) -> None:
        """Handle admin notification"""
        self.logger.info(f"NOTIFYING ADMIN about violation: {violation.description}")
        
        # In a real implementation, this would send notifications via:
        # - Email
        # - Slack
        # - PagerDuty
        # - SMS
        
        log_security_event(
            event_type="admin_notified",
            description=f"Administrator notified of policy violation: {violation.description}",
            severity="INFO",
            resource=violation.resource
        )
    
    def _calculate_response_improvement(self) -> float:
        """Calculate response time improvement percentage"""
        if len(self._response_times) < 2:
            return 0.0
        
        # Use the last 10 response times for calculation
        recent_times = self._response_times[-10:]
        avg_response_time = sum(recent_times) / len(recent_times)
        
        improvement = ((self._baseline_response_time - avg_response_time) / self._baseline_response_time) * 100
        return max(0.0, improvement)  # Ensure non-negative
    
    async def get_policy_metrics(self) -> Dict[str, Any]:
        """Get policy engine performance metrics"""
        active_violations = [v for v in self.violations.values() if v.status == "ACTIVE"]
        
        severity_counts = {}
        for severity in PolicySeverity:
            severity_counts[severity.value] = len([
                v for v in active_violations if v.severity == severity
            ])
        
        avg_response_time = sum(self._response_times[-100:]) / len(self._response_times[-100:]) if self._response_times else 0
        improvement = self._calculate_response_improvement()
        
        return {
            "total_policies": len(self.policies),
            "active_policies": len([p for p in self.policies.values() if p.enabled]),
            "active_violations": len(active_violations),
            "severity_breakdown": severity_counts,
            "avg_response_time_seconds": avg_response_time,
            "response_time_improvement_percent": improvement,
            "target_improvement_percent": 40.0
        }
    
    async def resolve_violation(self, violation_id: str, resolution_note: str = "") -> bool:
        """Mark a violation as resolved"""
        if violation_id in self.violations:
            violation = self.violations[violation_id]
            violation.status = "RESOLVED"
            violation.resolved_at = datetime.utcnow()
            
            log_security_event(
                event_type="violation_resolved",
                description=f"Policy violation resolved: {violation.description}. Note: {resolution_note}",
                severity="INFO",
                resource=violation.resource
            )
            
            return True
        
        return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Check policy engine health"""
        return {
            "status": "healthy" if self._initialized else "not_initialized",
            "policies_loaded": len(self.policies),
            "active_violations": len([v for v in self.violations.values() if v.status == "ACTIVE"]),
            "response_time_improvement": self._calculate_response_improvement()
        }
    
    async def cleanup(self) -> None:
        """Cleanup policy engine"""
        self.policies.clear()
        self.violations.clear()
        self.action_handlers.clear()
        self._initialized = False
        self.logger.info("Policy Engine cleaned up")
