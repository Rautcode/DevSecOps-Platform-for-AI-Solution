#!/usr/bin/env python3
"""
Create Admin User Script
Initialize the first admin user for the DevSecOps Platform
"""

import asyncio
import getpass
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.core.production_config import ProductionSettings
from src.core.database import initialize_database_manager
from src.auth.auth_manager import AuthManager
from src.auth.models import UserCreate, UserRole


async def create_admin_user():
    """Create the initial admin user"""
    print("🚀 DevSecOps Platform - Admin User Setup")
    print("=" * 50)
    
    # Load settings
    settings = ProductionSettings()
    
    # Initialize database
    db_manager = initialize_database_manager(settings.database)
    await db_manager.initialize()
    
    # Initialize auth manager
    auth_manager = AuthManager(settings.security, settings.database)
    await auth_manager.initialize()
    
    try:
        # Collect user information
        print("\n📝 Please provide admin user details:")
        
        email = input("Email: ").strip()
        if not email:
            print("❌ Email is required")
            return False
        
        username = input("Username: ").strip()
        if not username:
            print("❌ Username is required")
            return False
        
        full_name = input("Full Name: ").strip()
        if not full_name:
            full_name = "System Administrator"
        
        # Get password securely
        while True:
            password = getpass.getpass("Password: ")
            if len(password) < 8:
                print("❌ Password must be at least 8 characters long")
                continue
            
            confirm_password = getpass.getpass("Confirm Password: ")
            if password != confirm_password:
                print("❌ Passwords do not match")
                continue
            
            break
        
        # Create user
        user_create = UserCreate(
            email=email,
            username=username,
            full_name=full_name,
            password=password,
            confirm_password=confirm_password,
            role=UserRole.ADMIN
        )
        
        print(f"\n🔧 Creating admin user '{username}'...")
        
        user = await auth_manager.create_user(user_create)
        
        if user:
            print(f"✅ Admin user created successfully!")
            print(f"   Email: {user.email}")
            print(f"   Username: {user.username}")
            print(f"   Role: {user.role.value}")
            print(f"   ID: {user.id}")
            
            # Update user to be verified and superuser
            from src.auth.models import UserUpdate
            user_update = UserUpdate(
                is_verified=True,
                is_superuser=True
            )
            
            updated_user = await auth_manager.update_user(
                user.id, user_update, updated_by=user.id
            )
            
            if updated_user:
                print(f"✅ Admin privileges granted")
            
            return True
        else:
            print("❌ Failed to create admin user (user may already exist)")
            return False
    
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False
    
    finally:
        await auth_manager.cleanup()
        await db_manager.cleanup()


def main():
    """Main function"""
    try:
        success = asyncio.run(create_admin_user())
        if success:
            print(f"\n🎉 Setup complete! You can now login to the platform.")
            print(f"🌐 Access the dashboard at: http://localhost:8000")
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n⏹️  Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
