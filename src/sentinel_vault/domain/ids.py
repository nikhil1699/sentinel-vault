"""Typed identifiers.

Each id kind is its own ``str`` subclass with a strict pattern, so mypy catches a
``DocumentId`` passed where a ``ChunkId`` is expected, and Pydantic rejects ids that
don't match (e.g. path traversal, SQL fragments, unicode look-alikes).

Generated ids carry a type prefix (``doc_``, ``chk_``, ``dek_``) so a value from one
kind can never parse as another.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, ClassVar, Self

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


class _PatternId(str):
    pattern: ClassVar[re.Pattern[str]]

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str) or not cls.pattern.fullmatch(value):
            raise ValueError(f"invalid {cls.__name__}")
        return super().__new__(cls, value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls, core_schema.str_schema(max_length=64),
            serialization=core_schema.to_string_ser_schema(),
        )


class TenantId(_PatternId):
    """Lowercase slug, 3–32 chars. ASCII only."""

    pattern = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")


class WorkspaceId(_PatternId):
    pattern = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")


class UserId(_PatternId):
    pattern = re.compile(r"[a-z][a-z0-9._-]{1,30}[a-z0-9]")


class _PrefixedId(_PatternId):
    prefix: ClassVar[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.pattern = re.compile(rf"{cls.prefix}_[0-9a-f]{{32}}")

    @classmethod
    def new(cls) -> Self:
        return cls(f"{cls.prefix}_{uuid.uuid4().hex}")


class DocumentId(_PrefixedId):
    prefix = "doc"


class ChunkId(_PrefixedId):
    prefix = "chk"


class DekId(_PrefixedId):
    prefix = "dek"


class SessionId(_PrefixedId):
    prefix = "ses"
