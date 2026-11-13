"""Unit tests for the egress layers that don't need a tenant key."""

from __future__ import annotations

import base64

import pytest

from sentinel_vault.privacy.egress import (
    SYSTEM_PROMPT,
    CleanPrompt,
    _ph,
    hard_findings,
    remove_encoded_blobs,
)

TOKEN = "<<US_SSN_0123456789abcdef>>"


@pytest.mark.parametrize(("text", "hit"), [
    ("ssn 123-45-6789", "US_SSN"),
    ("ssn 123 45 6789", "US_SSN"),
    ("mail a.b@example.org", "EMAIL"),
    ("call (415) 555-0134", "PHONE"),
    ("MRN: 00A-7781-22", "MRN"),
    ("mrn 77812", "MRN"),
    ("card 4111 1111 1111 1111", "DIGIT_RUN"),
    ("1 2 3 - 4 5 - 6 7 8 9", "DIGIT_RUN"),
    ("\uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19", "US_SSN"),  # full-width
])
def test_hard_findings(text: str, hit: str) -> None:
    assert hit in hard_findings(text)


@pytest.mark.parametrize("text", [
    f"patient {TOKEN} has kidney stones", "dose 500 mg twice daily", "N20.0 follow-up",
    "seen 2026-11-13", SYSTEM_PROMPT, "",
    f"mrn: {TOKEN}\nphone: {TOKEN}",       # regression: label + next label isn't an MRN
    "MRN: pending",
])
def test_hard_findings_clean(text: str) -> None:
    assert hard_findings(text) == []


def test_hard_findings_never_returns_values() -> None:
    assert all("6789" not in h for h in hard_findings("123-45-6789"))


def test_base64_and_hex_blobs_removed() -> None:
    secret = "SSN 123-45-6789 for John Smith"
    b64 = base64.b64encode(secret.encode()).decode()
    url = base64.urlsafe_b64encode(b"patient john smith ssn 123-45-6789").decode().rstrip("=")
    hx = secret.encode().hex()
    out, n = remove_encoded_blobs(f"a {b64} b {url} c {hx} d")
    assert n == 3 and b64 not in out and hx not in out and url not in out


def test_random_strings_kept() -> None:
    noise = base64.b64encode(bytes(range(0, 250, 7))).decode()  # not readable text
    text = f"value {noise} and supercalifragilisticexpialidocious"
    assert remove_encoded_blobs(text) == (text, 0)


def test_clean_prompt_cannot_be_forged() -> None:
    with pytest.raises(TypeError):
        CleanPrompt("s", ("ssn 123-45-6789",), "q", object())


def test_placeholders_unique() -> None:
    assert len({_ph(i) for i in range(1000)}) == 1000
