"""PII/PHI detection: Microsoft Presidio (spaCy NER + pattern recognizers) plus our own
recognizers for healthcare identifiers and obfuscated numbers.

Design rules:
- **Over-detect.** Low score threshold; every entity type Presidio reports is treated as
  sensitive. A wrongly tokenized word costs a little recall; a leaked SSN costs a breach.
- **Normalize first** (homoglyphs, zero-width, full-width) and map spans back.
- **Fail closed.** If the analyzer errors, the caller gets ``DetectionUnavailableError``
  and nothing is stored or sent.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol

from sentinel_vault.privacy.normalize import normalize_with_map, to_original_span
from sentinel_vault.security.errors import AppError
from sentinel_vault.security.logging import get_logger

log = get_logger(__name__)


class DetectionUnavailableError(AppError):
    status_code = 503
    code = "detection_unavailable"
    public_message = "Sensitive-data detection is unavailable; request not processed."


@dataclass(frozen=True, slots=True)
class Span:
    start: int  # in the ORIGINAL text
    end: int
    entity: str
    score: float


# (entity, regex, score). Broad on purpose; Presidio's own recognizers add precision.
CUSTOM_PATTERNS: tuple[tuple[str, str, float], ...] = (
    # Any 3-2-4 digit group, valid-looking or not (Presidio rejects "invalid" SSNs).
    ("US_SSN", r"\b\d{3}[-\s.]?\d{2}[-\s.]?\d{4}\b", 0.6),
    # Long digit runs with up to 3 separator chars between digits ("1 2 3 - 4 5 - ..."):
    # obfuscated SSNs, phones, account numbers.
    ("ID_NUMBER", r"(?<![\w])(?:\d[\s.\-]{0,3}){6,}\d(?![\w])", 0.5),
    ("MEDICAL_RECORD", r"(?i)\b(?:MRN|medical\s+record(?:\s+(?:number|no\.?))?)"
                       r"[\s:#-]*[A-Z0-9][A-Z0-9-]{3,}", 0.85),
    ("INSURANCE_ID", r"(?i)\b(?:member|policy|insurance|subscriber)\s*"
                     r"(?:id|no\.?|number|#)[\s:#-]*[A-Z0-9][A-Z0-9-]{4,}", 0.85),
    ("DATE_OF_BIRTH", r"(?i)\b(?:dob|d\.o\.b\.|date\s+of\s+birth|born(?:\s+on)?)[\s:]*"
                      r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}", 0.9),
    ("DATE_TIME", r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b", 0.6),
    ("NPI", r"(?i)\bNPI[\s:#-]*\d{10}\b", 0.9),
)


class Analyzer(Protocol):
    def analyze(self, text: str, language: str, score_threshold: float) -> list[object]: ...


def build_presidio_analyzer() -> Analyzer:
    """Load Presidio with spaCy ``en_core_web_lg`` and our recognizers (~3 s, once)."""
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

    engine = AnalyzerEngine()
    for entity, regex, score in CUSTOM_PATTERNS:
        engine.registry.add_recognizer(PatternRecognizer(
            supported_entity=entity, name=f"sv_{entity.lower()}",
            patterns=[Pattern(name=entity.lower(), regex=regex, score=score)]))
    return engine  # type: ignore[return-value]


def merge_spans(spans: list[Span]) -> list[Span]:
    """Union overlapping spans; keep the entity of the highest-scoring member."""
    out: list[Span] = []
    for s in sorted(spans, key=lambda x: (x.start, -x.end)):
        if out and s.start < out[-1].end:
            prev = out[-1]
            best = prev if prev.score >= s.score else s
            out[-1] = Span(prev.start, max(prev.end, s.end), best.entity, best.score)
        else:
            out.append(s)
    return out


def prefer_known(detected: list[Span], known: list[Span]) -> list[Span]:
    """Known values keep their exact span (so they map to the same token everywhere).
    Detected spans that overlap them are trimmed to the parts outside, never dropped,
    so no detected character is left uncovered."""
    known = merge_spans(known)
    out = list(known)
    for d in merge_spans(detected):
        pieces = [(d.start, d.end)]
        for k in known:
            nxt = []
            for a, b in pieces:
                if b <= k.start or a >= k.end:
                    nxt.append((a, b))
                else:
                    if a < k.start:
                        nxt.append((a, k.start))
                    if b > k.end:
                        nxt.append((k.end, b))
            pieces = nxt
        out += [Span(a, b, d.entity, d.score) for a, b in pieces if b > a]
    return sorted(out, key=lambda s: s.start)


class PiiDetector:
    def __init__(self, analyzer: Analyzer, threshold: float) -> None:
        self._analyzer = analyzer
        self._threshold = threshold

    def detect_sync(self, text: str) -> list[Span]:
        if not text:
            return []
        norm, idx = normalize_with_map(text)
        if not norm:
            return []
        try:
            results = self._analyzer.analyze(text=norm, language="en",
                                              score_threshold=self._threshold)
        except Exception as exc:
            log.error("pii_detector_failed", error_type=type(exc).__name__)
            raise DetectionUnavailableError from exc
        spans = []
        for r in results:
            start, end = int(r.start), int(r.end)  # type: ignore[attr-defined]
            if end <= start:
                continue
            o_start, o_end = to_original_span(idx, start, end)
            spans.append(Span(o_start, o_end, str(r.entity_type),  # type: ignore[attr-defined]
                              float(r.score)))  # type: ignore[attr-defined]
        return merge_spans(spans)

    async def detect(self, text: str) -> list[Span]:
        return await asyncio.to_thread(self.detect_sync, text)
