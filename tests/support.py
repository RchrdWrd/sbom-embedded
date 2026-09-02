"""Shared test constants."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

FIXTURES = Path(__file__).parent / "fixtures"

# Pinned so two runs over the same input produce byte-identical output.
FIXED_SERIAL = UUID("11111111-2222-3333-4444-555555555555")
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)
