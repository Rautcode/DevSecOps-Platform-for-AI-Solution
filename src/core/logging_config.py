"""
Structured logging configuration for DevSecOps Platform
"""

import logging
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import structlog


class CorrelationIDFilter(logging.Filter):
    """Add correlation IDs to log records"""
    
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, 'correlation_id'):
            record.correlation_id = str(uuid.uuid4())[:8]
        return True


def add_correlation_id(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add correlation ID to structlog events"""
    if 'correlation_id' not in event_dict:
        event_dict['correlation_id'] = str(uuid.uuid4())[:8]
    return event_dict


def add_timestamp(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add timestamp to structlog events"""
    event_dict['timestamp'] = datetime.utcnow().isoformat()
    return event_dict


def setup_logging(log_level: str = "INFO") -> None:
    """Setup structured logging with security context"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            add_correlation_id,
            add_timestamp,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )
    
    # Add correlation ID filter to all handlers
    correlation_filter = CorrelationIDFilter()
    for handler in logging.root.handlers:
        handler.addFilter(correlation_filter)
    
    # Security-specific logger
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)
    
    # Create security event formatter
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(correlation_id)s - %(levelname)s - %(message)s'
    )
    
    # Add security handler if not exists
    if not security_logger.handlers:
        security_handler = logging.StreamHandler(sys.stdout)
        security_handler.setFormatter(security_formatter)
        security_handler.addFilter(correlation_filter)
        security_logger.addHandler(security_handler)


def get_security_logger() -> logging.Logger:
    """Get security-specific logger with correlation tracking"""
    return logging.getLogger("security")


def log_security_event(
    event_type: str,
    description: str,
    severity: str = "INFO",
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> None:
    """Log security events with structured data"""
    
    logger = get_security_logger()
    
    extra = {
        'event_type': event_type,
        'severity': severity,
        'resource': resource,
        'user_id': user_id,
        'correlation_id': correlation_id or str(uuid.uuid4())[:8]
    }
    
    getattr(logger, severity.lower())(description, extra=extra)
