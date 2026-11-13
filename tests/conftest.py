from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import settings as hypothesis_settings

from sentinel_vault.config import Settings
from sentinel_vault.security.logging import configure_logging

# Hypothesis' default 200 ms per-example deadline flakes under load (coverage, busy host).
hypothesis_settings.register_profile("sv", deadline=None)
hypothesis_settings.load_profile("sv")

if TYPE_CHECKING:
    from sentinel_vault.privacy.detector import PiiDetector


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
    # Low Argon2 cost keeps tests fast; production defaults are tested in test_config.
    return Settings(data_dir=tmp_path / "data", secrets_dir=tmp_path / "secrets",
                    argon2_time_cost=1, argon2_memory_kib=8, argon2_parallelism=1)


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(scope="session")
def detector() -> PiiDetector:
    """Real Presidio + spaCy en_core_web_lg, loaded once per test session (~3 s)."""
    from sentinel_vault.privacy.detector import PiiDetector, build_presidio_analyzer

    return PiiDetector(build_presidio_analyzer(), 0.35)


@pytest.fixture
def app_deps(detector: PiiDetector) -> dict[str, object]:
    """Injectables for create_app() in tests that don't need the KMS."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from sentinel_vault.retrieval.embedder import HashEmbedder

    return {"service_key": Ed25519PrivateKey.generate(), "detector": detector,
            "embedder": HashEmbedder()}


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
