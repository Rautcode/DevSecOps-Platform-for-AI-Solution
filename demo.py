#!/usr/bin/env python3
"""
Simple Demo Script for DevSecOps Platform
Demonstrates core functionality without external dependencies
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def demo_security_scan():
    """Demonstrate security scanning functionality"""
    print("🛡️  DevSecOps Platform for AI Solutions - Demo")
    print("="*60)
    
    # Set minimal environment variables for demo
    os.environ.update({
        "VAULT_ADDR": "http://localhost:8200",
        "VAULT_TOKEN": "demo-token",
        "SECRET_KEY": "demo-secret-key-for-testing",
        "DEBUG": "true"
    })
    
    try:
        from src.policies.policy_engine import PolicyEngine, PolicySeverity
        
        print("🔧 Initializing Policy Engine...")
        engine = PolicyEngine()
        await engine.initialize()
        
        print("✅ Policy Engine initialized successfully!")
        print(f"📋 Loaded {len(engine.policies)} security policies")
        
        # Demo AI workload data
        demo_workload = {
            "id": "demo_ai_model",
            "model": {
                "encryption_enabled": False,  # This will trigger violation
                "access_logging": True,
            },
            "data": {
                "contains_pii": False,
                "retention_days": 200,
            },
            "container": {
                "vulnerability_count": {
                    "critical": 1,  # This will trigger violation
                    "high": 2,
                    "medium": 3,
                    "low": 5
                }
            },
            "network": {
                "public_access": False,
            },
            "api": {
                "authentication_enabled": True,
                "rate_limiting_enabled": True,
            }
        }
        
        print("\n🔍 Scanning demo AI workload...")
        violations = await engine.evaluate_ai_workload(demo_workload)
        
        print(f"\n📊 Scan Results:")
        print(f"   Violations Found: {len(violations)}")
        
        if violations:
            print(f"\n⚠️  Security Violations Detected:")
            for i, violation in enumerate(violations, 1):
                print(f"   {i}. {violation.policy_name} ({violation.severity.value})")
                print(f"      {violation.description}")
                print(f"      Violated Rules: {', '.join(violation.violated_rules)}")
                print()
        
        # Get performance metrics
        metrics = await engine.get_policy_metrics()
        print(f"📈 Performance Metrics:")
        print(f"   Response Time Improvement: {metrics['response_time_improvement_percent']:.1f}%")
        print(f"   Average Response Time: {metrics['avg_response_time_seconds']:.3f}s")
        print(f"   Target Improvement: {metrics['target_improvement_percent']}%")
        
        # Health check
        health = await engine.health_check()
        print(f"\n❤️  System Health: {health['status'].upper()}")
        
        await engine.cleanup()
        
        print(f"\n✨ Demo completed successfully!")
        print(f"   🚀 Start the full platform with: python start.py")
        print(f"   📊 View dashboard at: http://localhost:8000")
        
        return True
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return False

async def main():
    """Main demo function"""
    success = await demo_security_scan()
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
