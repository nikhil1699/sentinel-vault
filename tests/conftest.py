from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.security.logging import configure_logging


class LogCapture:
    """Captures every JSON log line our logging config emits."""

    def __init__(self) -> None:
        self.stream = io.StringIO()

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.text.splitlines() if line.strip()]


@pytest.fixture
def logs() -> Iterator[LogCapture]:
    cap = LogCapture()
    configure_logging("DEBUG", stream=cap.stream)
    yield cap
    configure_logging("WARNING")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data", secrets_dir=tmp_path / "secrets")


# Synthetic PHI used across leakage tests. None of these refer to real people.
PHI_SAMPLES: dict[str, str] = {
    "name": "Johnathan Q. Marlowe",
    "ssn": "123-45-6789",
    "ssn_compact": "123456789",
    "email": "j.marlowe@example-clinic.org",
    "phone": "(415) 555-0134",
    "dob": "1984-07-19",
    "mrn": "MRN: 00A-7781-22",
    "card": "4111 1111 1111 1111",
    "ip": "203.0.113.77",
}
