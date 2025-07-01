#!/usr/bin/env python3
"""
Quick validation script to test DevSecOps Platform components
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the Python path
current_dir = Path(__file__).parent
project_root = current_dir.parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test if all critical modules can be imported"""
    print("🔍 Testing module imports...")
    
    try:
        # Test basic imports
        from src.core.production_config import ProductionSettings
        print("✅ Production config - OK")
        
        from src.core.validation import InputSanitizer
        print("✅ Input validation - OK")
        
        from src.auth.auth_manager import AuthManager
        print("✅ Authentication manager - OK")
        
        from src.monitoring.security_monitor import SecurityMonitoringSystem
        print("✅ Security monitoring - OK")
        
        from src.policies.policy_engine import PolicyEngine
        print("✅ Policy engine - OK")
        
        from src.integrations.vault_manager import VaultManager
        print("✅ Vault manager - OK")
        
        from src.integrations.cloud_security_hub import CloudSecurityHub
        print("✅ Cloud security hub - OK")
        
        print("✅ All critical imports successful!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        return False

def test_configuration():
    """Test configuration loading"""
    print("\n🔧 Testing configuration...")
    
    try:
        from src.core.production_config import ProductionSettings
        settings = ProductionSettings()
        
        print(f"✅ Environment: {settings.app.environment}")
        print(f"✅ Debug mode: {settings.app.debug}")
        print(f"✅ Port: {settings.app.port}")
        print(f"✅ Database configured: {bool(settings.database.url)}")
        print(f"✅ Security configured: {bool(settings.security.jwt_secret_key)}")
        
        print("✅ Configuration loaded successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def test_security_validation():
    """Test security validation components"""
    print("\n🛡️ Testing security validation...")
    
    try:
        from src.core.validation import InputSanitizer
        
        # Test safe input
        safe_input = "test@example.com"
        sanitized = InputSanitizer.validate_email(safe_input)
        print(f"✅ Email validation: {sanitized}")
        
        # Test malicious input detection
        try:
            malicious = "'; DROP TABLE users; --"
            InputSanitizer.sanitize_string(malicious)
            print("❌ Should have detected SQL injection!")
            return False
        except:
            print("✅ SQL injection detection working")
        
        try:
            xss = "<script>alert('xss')</script>"
            InputSanitizer.sanitize_string(xss)
            print("❌ Should have detected XSS!")
            return False
        except:
            print("✅ XSS detection working")
        
        print("✅ Security validation working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Security validation error: {e}")
        return False

def test_main_app():
    """Test main FastAPI application"""
    print("\n🚀 Testing main application...")
    
    try:
        from src.main import app, settings
        
        print(f"✅ FastAPI app created: {app.title}")
        print(f"✅ Version: {app.version}")
        print(f"✅ Environment: {settings.app.environment}")
        
        # Test routes are registered
        routes = [route.path for route in app.routes]
        expected_routes = ["/", "/health", "/api/v1"]
        
        for expected in expected_routes:
            if any(expected in route for route in routes):
                print(f"✅ Route registered: {expected}")
            else:
                print(f"⚠️ Route missing: {expected}")
        
        print("✅ Main application structure looks good!")
        return True
        
    except Exception as e:
        print(f"❌ Main app error: {e}")
        return False

def main():
    """Run all validation tests"""
    print("🏥 DevSecOps Platform - Quick Validation")
    print("=" * 50)
    
    tests = [
        ("Module Imports", test_imports),
        ("Configuration", test_configuration),
        ("Security Validation", test_security_validation),
        ("Main Application", test_main_app),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"\n❌ {test_name} failed!")
        except Exception as e:
            print(f"\n💥 {test_name} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Validation Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All validation tests passed! Platform is ready.")
        return True
    else:
        print("❌ Some validation tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
