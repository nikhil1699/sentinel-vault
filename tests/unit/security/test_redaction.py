from __future__ import annotations

import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sentinel_vault.security.logging import get_logger
from sentinel_vault.security.redaction import REDACTED, redact_event, redact_text, redact_value
from sentinel_vault.security.sensitive import Sensitive
from tests.conftest import PHI_SAMPLES, LogCapture

PATTERN_SAMPLES = {k: v for k, v in PHI_SAMPLES.items() if k != "name"}


@pytest.mark.parametrize(("kind", "value"), PATTERN_SAMPLES.items())
def test_patterns_strip_phi_from_free_text(kind: str, value: str) -> None:
    out = redact_text(f"patient record note: {value} end")
    assert value not in out, kind
    assert "patient record note:" in out


@pytest.mark.parametrize(
    "secret",
    [
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----",
        "q8Vh3k2LmN9pR7sT1uW4xY6zA0bC5dE8fG2hJ4kL",
    ],
)
def test_patterns_strip_secrets(secret: str) -> None:
    assert secret not in redact_text(f"auth {secret}")


@given(st.from_regex(r"\d{3}-\d{2}-\d{4}", fullmatch=True))
def test_any_dashed_ssn_is_redacted(ssn: str) -> None:
    assert ssn not in redact_text(f"ssn is {ssn}.")


@given(
    st.from_regex(r"[a-z]{1,10}\.[a-z]{1,10}", fullmatch=True),
    st.from_regex(r"[a-z]{2,10}\.(com|org|net)", fullmatch=True),
)
def test_any_email_is_redacted(user: str, domain: str) -> None:
    email = f"{user}@{domain}"
    assert email not in redact_text(f"contact {email} now")


def test_sensitive_keys_dropped_whole_even_if_value_looks_safe() -> None:
    out = redact_value({"patient_name": "Johnathan Q. Marlowe", "password": "hunter2",
                        "note_text": "anything", "count": 3})
    assert out == {"patient_name": REDACTED, "password": REDACTED,
                   "note_text": REDACTED, "count": 3}


def test_nested_structures() -> None:
    value = {"meta": {"items": [{"ssn": "123-45-6789"}, "call (415) 555-0134"]}}
    out = redact_value(value)
    assert "123-45-6789" not in str(out)
    assert "555-0134" not in str(out)


def test_non_string_types() -> None:
    assert redact_value(Sensitive("x")) == "***"
    assert redact_value(b"\x00\x01") == "[BYTES]"
    assert redact_value(None) is None
    assert redact_value(1.5) == 1.5

    class Obj:
        def __str__(self) -> str:
            return "ssn 123-45-6789"

    assert "123-45-6789" not in redact_value(Obj())


def test_depth_limit() -> None:
    deep: dict[str, object] = {"a": "x"}
    for _ in range(20):
        deep = {"n": deep}
    assert REDACTED in str(redact_value(deep))


def test_safe_keys_kept() -> None:
    out = redact_event(None, "info", {"event": "request", "status": 200,
                                      "route": "/documents/{doc_id}", "duration_ms": 1.2})
    assert out["status"] == 200
    assert out["route"] == "/documents/{doc_id}"


def test_structlog_event_redacted_end_to_end(logs: LogCapture) -> None:
    get_logger("t").info("lookup for " + PHI_SAMPLES["ssn"], ssn=PHI_SAMPLES["ssn"],
                         extra={"email": PHI_SAMPLES["email"]})
    for v in (PHI_SAMPLES["ssn"], PHI_SAMPLES["email"]):
        assert v not in logs.text


def test_stdlib_logger_redacted_end_to_end(logs: LogCapture) -> None:
    logging.getLogger("thirdparty").warning("user %s called from %s",
                                            PHI_SAMPLES["email"], PHI_SAMPLES["phone"])
    assert PHI_SAMPLES["email"] not in logs.text
    assert PHI_SAMPLES["phone"] not in logs.text
    assert logs.records()[-1]["logger"] == "thirdparty"


def test_exception_traceback_redacted(logs: LogCapture) -> None:
    try:
        raise ValueError(f"bad record {PHI_SAMPLES['ssn']} for {PHI_SAMPLES['email']}")
    except ValueError:
        get_logger("t").exception("failed")
    assert "ValueError" in logs.text
    assert PHI_SAMPLES["ssn"] not in logs.text
    assert PHI_SAMPLES["email"] not in logs.text
