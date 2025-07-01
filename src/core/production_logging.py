"""
Production-Grade Logging with Security Audit Trail
Structured logging with correlation tracking, security events, and compliance audit
"""

import json
import logging
import logging.handlers
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union
from contextlib import contextmanager

import structlog

from .production_config import get_settings


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'message']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class SecurityAuditFilter(logging.Filter):
    """Filter for security-sensitive log records"""
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Add security context to all records
        if not hasattr(record, 'correlation_id'):
            record.correlation_id = str(uuid.uuid4())[:8]
        
        if not hasattr(record, 'timestamp'):
            record.timestamp = datetime.utcnow().isoformat()
        
        # Mark security events
        if hasattr(record, 'security_event'):
            record.event_category = 'SECURITY'
        
        return True


class ComplianceLogHandler(logging.handlers.RotatingFileHandler):
    """Specialized handler for compliance audit logs"""
    
    def __init__(self, filename: str, **kwargs):
        # Ensure compliance log directory exists
        log_path = Path(filename)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        super().__init__(filename, **kwargs)
        self.setLevel(logging.INFO)
        
        # Compliance-specific formatter
        formatter = JSONFormatter()
        self.setFormatter(formatter)


class ProductionLogger:
    """Production-grade logging manager"""
    
    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._correlation_context = {}
        self.security_logger = None
        self.audit_logger = None
        
    def setup_logging(self) -> None:
        """Configure production logging system"""
        # Clear existing handlers
        logging.root.handlers.clear()
        
        # Configure structlog
        self._configure_structlog()
        
        # Setup standard logging
        self._setup_standard_logging()
        
        # Setup security logging
        self._setup_security_logging()
        
        # Setup compliance audit logging
        self._setup_audit_logging()
        
        # Configure third-party loggers
        self._configure_third_party_loggers()
        
        logging.info(
            "Production logging configured",
            extra={
                'environment': self.settings.app.environment.value,
                'log_level': self.settings.app.log_level.value,
                'security_event': True
            }
        )
    
    def _configure_structlog(self) -> None:
        """Configure structlog for structured logging"""
        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
        ]
        
        if self.settings.app.log_format == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer(colors=not self.settings.is_production()))
        
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, self.settings.app.log_level.value)
            ),
            context_class=dict,
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    
    def _setup_standard_logging(self) -> None:
        """Setup standard application logging"""
        # Root logger configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.settings.app.log_level.value))
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.addFilter(SecurityAuditFilter())
        
        if self.settings.app.log_format == "json":
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(correlation_id)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler (if configured)
        if self.settings.app.log_file:
            file_handler = logging.handlers.TimedRotatingFileHandler(
                filename=self.settings.app.log_file,
                when='midnight',
                interval=1,
                backupCount=30,
                encoding='utf-8'
            )
            file_handler.addFilter(SecurityAuditFilter())
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    
    def _setup_security_logging(self) -> None:
        """Setup dedicated security event logging"""
        self.security_logger = logging.getLogger("security")
        self.security_logger.setLevel(logging.INFO)
        self.security_logger.propagate = False
        
        # Security log file
        security_log_path = Path("logs/security/security.log")
        security_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        security_handler = logging.handlers.TimedRotatingFileHandler(
            filename=security_log_path,
            when='midnight',
            interval=1,
            backupCount=365,  # Keep security logs for 1 year
            encoding='utf-8'
        )
        
        security_formatter = JSONFormatter()
        security_handler.setFormatter(security_formatter)
        security_handler.addFilter(SecurityAuditFilter())
        
        self.security_logger.addHandler(security_handler)
    
    def _setup_audit_logging(self) -> None:
        """Setup compliance audit logging"""
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False
        
        # Compliance audit log
        audit_log_path = Path("logs/audit/compliance.log")
        audit_handler = ComplianceLogHandler(
            filename=audit_log_path,
            maxBytes=100*1024*1024,  # 100MB
            backupCount=self.settings.compliance.audit_retention_days // 30,  # Monthly rotation
            encoding='utf-8'
        )
        
        self.audit_logger.addHandler(audit_handler)
    
    def _configure_third_party_loggers(self) -> None:
        """Configure third-party library loggers"""
        # Reduce noise from third-party libraries
        third_party_loggers = [
            'urllib3',
            'requests',
            'boto3',
            'botocore',
            'azure',
            'hvac'
        ]
        
        for logger_name in third_party_loggers:
            logger = logging.getLogger(logger_name)
            if self.settings.is_production():
                logger.setLevel(logging.WARNING)
            else:
                logger.setLevel(logging.INFO)
    
    @contextmanager
    def correlation_context(self, correlation_id: Optional[str] = None):
        """Context manager for correlation ID tracking"""
        correlation_id = correlation_id or str(uuid.uuid4())[:8]
        old_context = self._correlation_context.copy()
        self._correlation_context['correlation_id'] = correlation_id
        
        try:
            structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
            yield correlation_id
        finally:
            structlog.contextvars.clear_contextvars()
            self._correlation_context = old_context
    
    def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "INFO",
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        source_ip: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs
    ) -> None:
        """Log security events with standardized format"""
        if not self.security_logger:
            return
        
        correlation_id = correlation_id or str(uuid.uuid4())[:8]
        
        extra = {
            'event_type': event_type,
            'severity': severity,
            'description': description,
            'resource': resource,
            'user_id': user_id,
            'source_ip': source_ip,
            'correlation_id': correlation_id,
            'security_event': True,
            **kwargs
        }
        
        # Log to security logger
        log_method = getattr(self.security_logger, severity.lower(), self.security_logger.info)
        log_method(description, extra=extra)
        
        # Also log to audit logger for compliance
        if self.audit_logger:
            self.audit_logger.info(description, extra=extra)
    
    def log_compliance_event(
        self,
        framework: str,
        control_id: str,
        status: str,
        description: str,
        evidence: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        """Log compliance-related events"""
        if not self.audit_logger:
            return
        
        extra = {
            'event_type': 'compliance_check',
            'framework': framework,
            'control_id': control_id,
            'status': status,
            'description': description,
            'evidence': evidence or {},
            'correlation_id': str(uuid.uuid4())[:8]
        }
        extra.update(kwargs)
        
        self.audit_logger.info(description, extra=extra)
    
    def log_performance_metric(
        self,
        metric_name: str,
        value: Union[int, float],
        unit: str = "",
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> None:
        """Log performance metrics"""
        extra = {
            'event_type': 'performance_metric',
            'metric_name': metric_name,
            'value': value,
            'unit': unit,
            'tags': tags or {},
            'correlation_id': str(uuid.uuid4())[:8],
            **kwargs
        }
        
        logging.info(f"Metric {metric_name}: {value} {unit}", extra=extra)


# Global logger instance
production_logger = ProductionLogger()


def setup_production_logging() -> None:
    """Setup production logging system"""
    production_logger.setup_logging()


def get_logger(name: str) -> logging.Logger:
    """Get a logger with production configuration"""
    return logging.getLogger(name)


def get_security_logger() -> logging.Logger:
    """Get security event logger"""
    return production_logger.security_logger or logging.getLogger("security")


def get_audit_logger() -> logging.Logger:
    """Get compliance audit logger"""
    return production_logger.audit_logger or logging.getLogger("audit")


# Convenience functions
def log_security_event(event_type: str, description: str, **kwargs) -> None:
    """Log security event"""
    production_logger.log_security_event(event_type, description, **kwargs)


def log_compliance_event(framework: str, control_id: str, status: str, description: str, **kwargs) -> None:
    """Log compliance event"""
    production_logger.log_compliance_event(framework, control_id, status, description, **kwargs)


def log_performance_metric(metric_name: str, value: Union[int, float], **kwargs) -> None:
    """Log performance metric"""
    production_logger.log_performance_metric(metric_name, value, **kwargs)
