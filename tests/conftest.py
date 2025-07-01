"""
pytest configuration file
"""

import pytest
import asyncio
import os
from pathlib import Path

# Set test environment variables
os.environ.update({
    "VAULT_ADDR": "http://localhost:8200",
    "VAULT_TOKEN": "test-token",
    "AWS_ACCESS_KEY_ID": "test-key",
    "AWS_SECRET_ACCESS_KEY": "test-secret",
    "AWS_REGION": "us-east-1",
    "SECRET_KEY": "test-secret-key",
    "DEBUG": "true",
    "LOG_LEVEL": "DEBUG"
})


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup test environment before each test"""
    # Add src to Python path
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in os.sys.path:
        os.sys.path.insert(0, str(src_path))
    
    yield
    
    # Cleanup after test if needed
