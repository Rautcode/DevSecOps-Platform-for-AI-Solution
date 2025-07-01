#!/usr/bin/env python3
"""
DevSecOps Platform Startup Script
Quick start script for the DevSecOps Platform for AI Solutions
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def main():
    """Start the DevSecOps Platform"""
    print("🛡️  Starting DevSecOps Platform for AI Solutions")
    print("="*60)
    
    # Check if .env exists
    env_file = Path(".env")
    if not env_file.exists():
        print("⚠️  Warning: .env file not found!")
        print("   Please copy .env.example to .env and configure your settings")
        print("   cp .env.example .env")
        print()
    
    # Import and start the main application
    try:
        from src.main import main as app_main
        print("🚀 Starting application on http://localhost:8000")
        print("📊 Dashboard available at http://localhost:8000")
        print("📈 Metrics available at http://localhost:9090")
        print()
        print("Press Ctrl+C to stop the application")
        print("="*60)
        
        await app_main()
        
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        print("   Check your configuration and dependencies")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
