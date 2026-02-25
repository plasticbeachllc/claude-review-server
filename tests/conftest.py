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
