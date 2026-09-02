from pathlib import Path

import pytest

from .support import FIXTURES


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
