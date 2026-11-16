"""Console output for the reviewer kit: colors, step headers, progress, highlighting.

Colors are on only when stdout is a terminal and ``NO_COLOR`` is unset (no-color.org).
Progress redraws one line on a terminal; when piped it prints a line every few items,
so logs and CI output stay readable.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from typing import Final, TextIO

_CODES: Final = {"dim": "2", "bold": "1", "red": "31", "green": "32", "yellow": "33",
                 "blue": "34", "magenta": "35", "cyan": "36"}
_TOKEN: Final = re.compile(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>")
_KEYID: Final = re.compile(r"\b(?:cmk|dek|doc|chk|job)_[0-9a-f]{32}\b")


def color_enabled(stream: TextIO | None = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(text: str, *styles: str, on: bool | None = None) -> str:
    if not (color_enabled() if on is None else on) or not styles:
        return text
    return f"\033[{';'.join(_CODES[s] for s in styles)}m{text}\033[0m"


def highlight(text: str, on: bool | None = None) -> str:
    """Tokens in magenta, key/record ids in cyan. Makes "what is a placeholder" obvious."""
    if not (color_enabled() if on is None else on):
        return text
    text = _TOKEN.sub(lambda m: paint(m.group(0), "magenta", on=True), text)
    return _KEYID.sub(lambda m: paint(m.group(0), "cyan", on=True), text)


def ok(msg: str) -> str:
    return f"{paint('[ok]', 'green')}   {msg}"


def fail(msg: str) -> str:
    return f"{paint('[fail]', 'red', 'bold')} {msg}"


def info(msg: str) -> str:
    return f"{paint('[..]', 'blue')}   {msg}"


class Progress:
    """``Progress("logins", 60, out)``; call ``tick()`` per item, ``done()`` at the end."""

    def __init__(self, label: str, total: int, out: Callable[[str], None] = print,
                 stream: TextIO | None = None, every: int = 10) -> None:
        self.label, self.total, self.n = label, total, 0
        self._out, self._stream = out, stream or sys.stdout
        self._tty = color_enabled(self._stream) and out is print
        self._every = max(1, every)

    def _line(self) -> str:
        return f"{paint('[..]', 'blue')}   {self.label} {self.n}/{self.total}"

    def tick(self, n: int = 1) -> None:
        self.n += n
        if self._tty:
            self._stream.write("\r" + self._line())
            self._stream.flush()
        elif self.n % self._every == 0 and self.n < self.total:
            self._out(self._line())

    def done(self, note: str = "") -> None:
        if self._tty:
            self._stream.write("\r\033[K")
        self._out(ok(f"{self.label} {self.n}/{self.total}{'  ' + note if note else ''}"))
