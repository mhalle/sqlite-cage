import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import build


@pytest.fixture(scope="session")
def db(tmp_path_factory):
    """A built fixture database, shared across the session (read-only)."""
    path = tmp_path_factory.mktemp("cage") / "fixture.sqlite"
    return build(path)
