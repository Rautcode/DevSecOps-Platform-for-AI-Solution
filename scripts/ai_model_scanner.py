#!/usr/bin/env python3
"""
AI Model Security Scanner
Scans AI models for security vulnerabilities and compliance issues
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.core.logging_config import setup_logging, log_security_event
from src.policies.policy_engine import PolicyEngine


async def scan_ai_model(model_path: str) -> Dict[str, Any]:
    """Scan an AI model for security issues"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info(f"Starting AI model security scan: {model_path}")
    
    # Simulate AI model analysis
    model_data = {
        "id": f"model_{Path(model_path).stem}",
        "model": {
            "encryption_enabled": True,  # Should be checked
            "access_logging": True,      # Should be enabled
        },
        "data": {
            "contains_pii": False,       # Should be False
            "retention_days": 300,       # Should be < 365
        },
        "container": {
            "vulnerability_count": {
                "critical": 0,           # Should be 0
                "high": 2,
                "medium": 5,
                "low": 10
            }
        },
        "network": {
            "public_access": False,      # Should be False
        },
        "api": {
            "authentication_enabled": True,  # Should be True
            "rate_limiting_enabled": True,   # Should be True
        }
    }
    
    # Initialize policy engine
    policy_engine = PolicyEngine()
    await policy_engine.initialize()
    
    # Evaluate model against policies
    violations = await policy_engine.evaluate_ai_workload(model_data)
    
    scan_results = {
        "model_path": model_path,
        "scan_timestamp": "2025-07-01T12:00:00Z",
        "violations_found": len(violations),
        "violations": [
            {
                "policy": v.policy_name,
                "severity": v.severity.value,
                "description": v.description,
                "violated_rules": v.violated_rules
            }
            for v in violations
        ],
        "recommendations": [
            "Ensure all AI models are encrypted at rest",
            "Enable comprehensive access logging",
            "Regular vulnerability scanning of containers",
            "Implement network isolation for AI workloads"
        ]
    }
    
    # Log security event
    log_security_event(
        event_type="ai_model_scan_completed",
        description=f"AI model scan completed: {len(violations)} violations found",
        severity="WARNING" if violations else "INFO",
        resource=model_path
    )
    
    logger.info(f"AI model scan completed: {len(violations)} violations found")
    return scan_results


async def main():
    """Main scanner function"""
    if len(sys.argv) < 2:
        print("Usage: python ai_model_scanner.py <model_path>")
        sys.exit(1)
    
    model_path = sys.argv[1]
    results = await scan_ai_model(model_path)
    
    print(f"\n🔍 AI Model Security Scan Results")
    print(f"{'='*50}")
    print(f"Model: {results['model_path']}")
    print(f"Violations Found: {results['violations_found']}")
    
    if results['violations']:
        print(f"\n⚠️  Security Violations:")
        for violation in results['violations']:
            print(f"  - {violation['policy']} ({violation['severity']})")
            print(f"    {violation['description']}")
    else:
        print(f"\n✅ No security violations found!")
    
    print(f"\n💡 Recommendations:")
    for rec in results['recommendations']:
        print(f"  - {rec}")


if __name__ == "__main__":
    asyncio.run(main())
