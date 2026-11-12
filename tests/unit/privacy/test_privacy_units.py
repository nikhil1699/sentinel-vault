"""Unit tests: normalization, PII detection, policy, tokens, chunking, embedder."""

from __future__ import annotations

import numpy as np
import pytest

from sentinel_vault.privacy.detector import DetectionUnavailableError, PiiDetector, Span, _merge
from sentinel_vault.privacy.normalize import normalize, normalize_with_map, to_original_span
from sentinel_vault.privacy.policy import DataPolicy, FieldAction
from sentinel_vault.retrieval.chunking import chunk_text, decode_chunk, encode_chunk
from sentinel_vault.retrieval.embedder import HashEmbedder
from sentinel_vault.service.tokenization import TOKEN_RE, make_token, normalize_value

# --- normalization ------------------------------------------------------------------------


def test_homoglyphs_zero_width_fullwidth() -> None:
    assert normalize("J\u043ehn Sm\u0456th") == "John Smith"           # Cyrillic о, і
    assert normalize("123\u200b-45-\u200b6789") == "123-45-6789"       # zero-width
    assert normalize("\uff11\uff12\uff13") == "123"                    # full-width digits


def test_span_maps_back_to_original() -> None:
    orig = "SSN 1\u200b23-45-6789 end"
    norm, idx = normalize_with_map(orig)
    s = norm.index("123-45-6789")
    o_start, o_end = to_original_span(idx, s, s + len("123-45-6789"))
    assert orig[o_start:o_end] == "1\u200b23-45-6789"


# --- detection (real Presidio) ------------------------------------------------------------

CASES = [
    ("Patient John Smith was seen today.", "John Smith"),
    ("DOB 1984-07-19", "1984-07-19"),
    ("MRN: 00A-7781-22", "00A-7781-22"),
    ("call (415) 555-0134", "555-0134"),
    ("SSN 123-45-6789", "123-45-6789"),
    ("SSN 078-05-1120", "078-05-1120"),                 # "invalid" SSN Presidio skips
    ("email j.marlowe@example-clinic.org", "j.marlowe@example-clinic.org"),
    ("member id XKZ-99812", "XKZ-99812"),
    ("NPI 1234567893", "1234567893"),
    ("ssn 1 2 3 - 4 5 - 6 7 8 9", "1 2 3 - 4 5 - 6 7 8 9"),  # spaced digits
    ("ssn 123\u200b-45-\u200b6789", "6789"),           # zero-width split
    ("patient J\u043ehn Sm\u0456th", "Sm\u0456th"),    # homoglyph name
    ("card 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("seen at 42 Elm Street, Springfield", "Elm Street"),
    ("Jordan called about the Paris trip", "Jordan"),  # ambiguous name/place
]


@pytest.mark.parametrize(("text", "secret"), CASES)
def test_detects(detector: PiiDetector, text: str, secret: str) -> None:
    spans = detector.detect_sync(text)
    covered = [text[s.start:s.end] for s in spans]
    assert any(secret in c for c in covered), covered


def test_empty_and_whitespace(detector: PiiDetector) -> None:
    assert detector.detect_sync("") == []
    assert detector.detect_sync("\u200b\u200b") == []


def test_fails_closed() -> None:
    class Broken:
        def analyze(self, text: str, language: str, score_threshold: float) -> list[object]:
            raise RuntimeError("model crashed")

    with pytest.raises(DetectionUnavailableError):
        PiiDetector(Broken(), 0.35).detect_sync("John Smith")


def test_merge_overlaps() -> None:
    merged = _merge([Span(0, 5, "A", 0.5), Span(3, 9, "B", 0.9), Span(20, 22, "C", 0.4)])
    assert merged == [Span(0, 9, "B", 0.9), Span(20, 22, "C", 0.4)]


# --- policy -------------------------------------------------------------------------------


def test_policy_default_drop_and_bad_names() -> None:
    p = DataPolicy(fields={"notes": FieldAction.SCAN})
    assert p.action_for("notes") == FieldAction.SCAN
    assert p.action_for("unknown") == FieldAction.DROP
    assert p.action_for("John Smith 123-45-6789") == FieldAction.DROP
    assert p.action_for("Notes") == FieldAction.DROP
    loose = DataPolicy(default_action=FieldAction.SCAN)
    assert loose.action_for("anything") == FieldAction.SCAN
    assert loose.action_for("bad name!") == FieldAction.DROP


# --- tokens --------------------------------------------------------------------------------

K1, K2 = bytes(32), bytes([1]) * 32


def test_token_deterministic_per_key_and_normalized() -> None:
    a = make_token(K1, "US_SSN", "123-45-6789")
    assert TOKEN_RE.fullmatch(a)
    assert make_token(K1, "US_SSN", "123 45 6789") == a
    assert make_token(K1, "PERSON", "John  Smith") == make_token(K1, "PERSON", "john smith")
    assert make_token(K1, "PERSON", "J\u043ehn Smith") == make_token(K1, "PERSON", "John Smith")
    assert make_token(K2, "US_SSN", "123-45-6789") != a   # other tenant
    assert make_token(K1, "PERSON", "123-45-6789") != a   # entity is domain-separated
    assert "6789" not in a and normalize_value("A-B c") == "abc"


# --- chunking / embedding --------------------------------------------------------------------


def test_chunking_respects_size_overlap_and_tokens() -> None:
    tok = "<<PERSON_0123456789abcdef>>"
    text = " ".join([f"word{i}" if i % 7 else tok for i in range(400)])
    chunks = chunk_text(text, 200, 40)
    assert all(len(c) <= 200 for c in chunks) and len(chunks) > 5
    for c in chunks:
        assert "<<" not in c.replace(tok, "")  # never split a token
    assert chunks[0].split()[-1] in chunks[1]  # overlap
    assert chunk_text("", 200, 40) == []
    assert all(len(c) <= 50 for c in chunk_text("x" * 120, 50, 10))


def test_chunk_payload_roundtrip() -> None:
    v = np.arange(8, dtype=np.float32)
    text, back = decode_chunk(encode_chunk("héllo", v))
    assert text == "héllo" and np.array_equal(v, back)
    with pytest.raises(ValueError):
        decode_chunk(b"XXXX")


async def test_hash_embedder() -> None:
    e = HashEmbedder(64)
    v = await e.embed(["kidney stones", "kidney stones", "broken arm"])
    assert v.shape == (3, 64)
    assert np.allclose(v[0], v[1]) and float(v[0] @ v[2]) < 0.99
    assert abs(float(np.linalg.norm(v[0])) - 1) < 1e-5
    assert (await e.embed([])).shape == (0, 64)
    assert np.allclose((await e.embed(["!!!"]))[0], 0)
