"""``Sensitive[T]``: a wrapper that refuses to show its value by accident.

``repr``, ``str``, f-strings, ``%`` formatting, Pydantic dumps and pickling all yield
``***`` or fail. The only way to read the value is an explicit ``.reveal()`` call,
which is easy to grep for in review.
"""

from __future__ import annotations

import copy
import hmac
from typing import Any, NoReturn, get_args

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

MASK = "***"


class Sensitive[T]:
    __slots__ = ("_value",)

    def __init__(self, value: T) -> None:
        self._value = value

    def reveal(self) -> T:
        return self._value

    def __repr__(self) -> str:
        return f"Sensitive({MASK!r})"

    def __str__(self) -> str:
        return MASK

    def __format__(self, format_spec: str) -> str:
        return MASK

    def __reduce__(self) -> NoReturn:
        raise TypeError("Sensitive values cannot be pickled")

    def __copy__(self) -> Sensitive[T]:
        return Sensitive(self._value)

    def __deepcopy__(self, memo: dict[int, Any]) -> Sensitive[T]:
        return Sensitive(copy.deepcopy(self._value, memo))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sensitive):
            return NotImplemented
        a, b = self._value, other._value
        if isinstance(a, str) and isinstance(b, str):
            return hmac.compare_digest(a.encode(), b.encode())
        if isinstance(a, bytes) and isinstance(b, bytes):
            return hmac.compare_digest(a, b)
        return bool(a == b)

    __hash__ = None  # type: ignore[assignment]

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        args = get_args(source)
        inner = handler.generate_schema(args[0] if args else Any)

        def unwrap(v: Any) -> Any:
            return v.reveal() if isinstance(v, Sensitive) else v

        return core_schema.no_info_before_validator_function(
            unwrap,
            core_schema.no_info_after_validator_function(cls, inner),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda _v: MASK, when_used="always"
            ),
        )
