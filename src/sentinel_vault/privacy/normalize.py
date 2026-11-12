"""Text normalization before PII detection, with an index map back to the original.

Attackers hide PII from detectors with look-alike letters (Cyrillic "а" for Latin "a"),
zero-width characters inside numbers, and full-width digits. We detect on a normalized
copy, then map spans back so the *original* characters are the ones replaced.
"""

from __future__ import annotations

import unicodedata
from typing import Final

_ZERO_WIDTH: Final = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e")

# Small, high-value subset of Unicode confusables (Cyrillic/Greek -> Latin).
_CONFUSABLES: Final[dict[str, str]] = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Returns (normalized, idx) where ``idx[j]`` is the original index of normalized char j."""
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        for c in unicodedata.normalize("NFKC", ch):
            out.append(_CONFUSABLES.get(c, c))
            idx.append(i)
    return "".join(out), idx


def normalize(text: str) -> str:
    return normalize_with_map(text)[0]


def to_original_span(idx: list[int], start: int, end: int) -> tuple[int, int]:
    return idx[start], idx[end - 1] + 1
