"""Readable view of the service logs: ``./run.sh logs`` (follows) or ``logs --no-follow``.

The JSON lines are already redacted by the services; this only reformats them::

    14:02:11  INFO   sentinel-api  request            method=POST route=/query status=200 …

Non-JSON lines (uvicorn startup banners) are shown dimmed.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from reviewer_kit.ui import paint

_LEVEL_STYLE: Final = {"debug": ("dim",), "info": ("green",), "warning": ("yellow",),
                       "error": ("red", "bold"), "critical": ("red", "bold")}
_SKIP: Final = {"event", "level", "timestamp", "logger"}


def format_line(service: str, raw: str, on: bool | None = None) -> str:
    raw = raw.rstrip("\n")
    try:
        rec: dict[str, Any] = json.loads(raw)
        if not isinstance(rec, dict):
            raise ValueError
    except ValueError:
        return paint(f"{'':8}  {'':6} {service:<13} {raw}", "dim", on=on)
    ts = str(rec.get("timestamp", ""))[11:19]
    level = str(rec.get("level", "info")).lower()
    extras = " ".join(f"{k}={v}" for k, v in rec.items() if k not in _SKIP)
    return (f"{ts:<8}  {paint(f'{level.upper():<6}', *_LEVEL_STYLE.get(level, ()), on=on)} "
            f"{paint(f'{service:<13}', 'cyan', on=on)} {str(rec.get('event', '')):<26} "
            f"{paint(extras, 'dim', on=on)}")


def _tail(path: Path, n: int) -> list[str]:
    if n <= 0:  # note: lines[-0:] would be ALL lines
        return []
    try:
        return path.read_text(errors="replace").splitlines()[-n:]
    except FileNotFoundError:
        return []


def follow(files: list[Path], lines: int, keep_following: bool,
           poll: float = 0.5) -> Iterator[str]:
    """Last ``lines`` per file, then new lines as they arrive. File positions are taken
    now (not on first ``next``), so nothing written after this call is missed."""
    head = [format_line(f.stem, raw) for f in files for raw in _tail(f, lines)]
    pos = {f: f.stat().st_size if f.exists() else 0 for f in files}
    return _follow(files, head, pos, keep_following, poll)


def _follow(files: list[Path], head: list[str], pos: dict[Path, int], keep_following: bool,
            poll: float) -> Iterator[str]:
    yield from head
    if not keep_following:
        return
    while True:
        for f in files:
            if not f.exists():
                continue
            size = f.stat().st_size
            if size < pos[f]:  # truncated / restarted
                pos[f] = 0
            if size > pos[f]:
                with f.open(errors="replace") as fh:
                    fh.seek(pos[f])
                    for raw in fh:
                        yield format_line(f.stem, raw)
                    pos[f] = fh.tell()
        time.sleep(poll)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="run.sh logs")
    p.add_argument("--dir", type=Path, default=Path(".run/logs"))
    p.add_argument("-n", "--lines", type=int, default=20)
    p.add_argument("--no-follow", action="store_true")
    a = p.parse_args(argv)
    files = sorted(a.dir.glob("*.log"))
    if not files:
        print("no logs yet — start the services with ./run.sh")
        return 1
    print(paint(f"logs: {', '.join(f.stem for f in files)}  (Ctrl-C to stop; "
                "already redacted: no PHI, tokens or keys)", "dim"))
    try:
        for line in follow(files, a.lines, not a.no_follow):
            print(line, flush=True)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
