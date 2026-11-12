"""Log redaction. Last line of defense: callers should not log sensitive data at all.

Two layers:
1. Key-based: values under sensitive keys (``password``, ``text``, ``ssn`` ...) are
   replaced whole, whatever they contain.
2. Pattern-based: every remaining string is scanned for PHI/PII and secret shapes.

The pattern list over-redacts on purpose. A log line with ``[SSN]`` where a harmless
9-digit number was is a fine trade for never logging a real one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from structlog.typing import EventDict

from sentinel_vault.security.sensitive import MASK, Sensitive

REDACTED: Final = "[REDACTED]"
_MAX_DEPTH: Final = 8

# Keys whose values are never logged. Matched on the lowercased key, by substring.
_SENSITIVE_KEY_PARTS: Final = (
    "password", "passwd", "secret", "token", "authorization", "cookie", "api_key",
    "apikey", "private", "dek", "plaintext", "ciphertext", "ssn", "dob", "email",
    "phone", "address", "mrn", "text", "body", "content", "prompt", "query", "chunk",
    "record", "payload", "value", "name", "embedding",
)

# Keys we emit ourselves whose values are known-safe. Exact match.
_SAFE_KEYS: Final = frozenset({
    "timestamp", "level", "logger", "request_id", "method", "route", "status",
    "duration_ms", "service", "error_code", "error_type", "tenant_id", "workspace_id",
    "doc_id", "chunk_id", "dek_id", "cmk_id", "count", "logger_name",
})

# Order matters: longer / more specific shapes first.
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("[BEARER]", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")),
    ("[PEM]", re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----")),
    ("[EMAIL]", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("[CARD]", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("[SSN]", re.compile(r"\b\d{3}[-\s.]?\d{2}[-\s.]?\d{4}\b")),
    ("[PHONE]", re.compile(r"(?:\+?1[-.\s]?)?\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("[MRN]", re.compile(r"(?i)\bMRN[:#\s-]*[A-Z0-9-]{4,}")),
    ("[IP]", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("[DATE]", re.compile(r"\b\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}\b")),
    ("[SECRET]", re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}")),
)


def redact_text(text: str) -> str:
    for label, pattern in _PATTERNS:
        text = pattern.sub(label, text)
    return text


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    if k in _SAFE_KEYS:
        return False
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


def redact_value(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Sensitive):
        return MASK
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return "[BYTES]"
    if isinstance(value, Mapping):
        return {
            str(k): (REDACTED if _is_sensitive_key(str(k)) else redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(v, depth + 1) for v in value]
    return redact_text(str(value))


# Values under safe keys are still checked: they must look like an id, route or timestamp.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:/{}+-]{0,128}")


def _safe_key_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str) and _SAFE_VALUE.fullmatch(value):
        return value
    return REDACTED


def redact_event(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor. Runs after exception formatting, before rendering."""
    out: EventDict = {}
    for key, value in event_dict.items():
        if key.startswith("_"):  # structlog internals (_record, _from_structlog)
            out[key] = value
        elif key in _SAFE_KEYS:
            out[key] = _safe_key_value(value)
        elif key == "exception":
            # Built by safe_exc_info from type names + code locations only (no messages).
            out[key] = str(value)
        elif key == "event":
            out[key] = redact_text(str(value))
        elif _is_sensitive_key(key):
            out[key] = REDACTED
        else:
            out[key] = redact_value(value)
    return out
