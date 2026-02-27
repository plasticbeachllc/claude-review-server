import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent / "scripts")


@pytest.fixture()
def scripts_on_path():
    """Temporarily add scripts/ to sys.path for build module imports."""
    sys.path.insert(0, SCRIPTS_DIR)
    yield
    sys.path.remove(SCRIPTS_DIR)


@pytest.fixture()
def rsa_key_pair(tmp_path):
    """Generate a temporary RSA key pair for testing JWT generation."""
    key_path = tmp_path / "test-key.pem"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(key_path), "2048"],
        capture_output=True, check=True, timeout=10,
    )
    return key_path
