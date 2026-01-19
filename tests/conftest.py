"""Pytest configuration and fixtures."""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def test_data_dir():
    """Get test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture
def temp_env_file(tmp_path):
    """Create a temporary .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("""
ATS_ENV=testing
ATS_DEBUG=true
ATS_LOG_LEVEL=DEBUG
ATS_THREADS=10
""")
    return env_file


@pytest.fixture
def sample_module_config():
    """Sample module configuration."""
    return {
        "target": "example.com",
        "timeout": 30,
        "verbose": True
    }
