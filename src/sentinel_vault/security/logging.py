"""Structured JSON logging with redaction on every record.

Both structlog events and stdlib records (uvicorn, httpx, libraries) go through the
same processor chain, so no log path skips redaction. Uvicorn's access log is turned
off: it prints raw paths and query strings. Our middleware logs the route template.
"""

from __future__ import annotations

import logging
import sys
import traceback
from pathlib import Path
from typing import Any, TextIO

import structlog
from structlog.typing import EventDict, Processor

from sentinel_vault.security.redaction import redact_event

_MAX_FRAMES = 8
_MAX_CHAIN = 5


def describe_exception(exc: BaseException) -> str:
    """Exception type + code locations only. The message is never included.

    Exception messages are built from runtime data (``f"bad record {row}"``) and regex
    redaction can't reliably catch names or free text. Code locations come from our
    source, not from data, so they are safe to log and still enough to debug.
    """
    parts: list[str] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen and len(parts) < _MAX_CHAIN:
        seen.add(id(cur))
        frames = traceback.extract_tb(cur.__traceback__)[-_MAX_FRAMES:]
        where = " <- ".join(
            f"{Path(f.filename).name}:{f.lineno}:{f.name}" for f in reversed(frames)
        )
        parts.append(f"{type(cur).__module__}.{type(cur).__qualname__} at {where or '?'}")
        cur = cur.__cause__ or cur.__context__
    return " | from ".join(parts)


def safe_exc_info(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    """Replaces structlog's ``format_exc_info``: renders exceptions without messages."""
    event_dict.pop("stack_info", None)
    event_dict.pop("stack", None)
    exc_info = event_dict.pop("exc_info", None)
    exc: BaseException | None = None
    if exc_info is True:
        exc = sys.exc_info()[1]
    elif isinstance(exc_info, BaseException):
        exc = exc_info
    elif isinstance(exc_info, tuple) and len(exc_info) == 3:
        exc = exc_info[1]
    if exc is not None:
        event_dict["exception"] = describe_exception(exc)
    return event_dict


def _shared_processors() -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        safe_exc_info,
        redact_event,  # must stay last before rendering
    ]


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    shared = _shared_processors()
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "fastapi", "httpx", "httpcore"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    # httpx logs full outbound URLs at INFO; URLs can carry data in query strings.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    return structlog.stdlib.get_logger(name)
