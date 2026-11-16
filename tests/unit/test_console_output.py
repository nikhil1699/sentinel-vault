"""Reviewer-facing console output: colors, progress, log viewer."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from reviewer_kit import logview, ui

TOKEN = "<<US_SSN_0123456789abcdef>>"
CMK = "cmk_" + "a" * 32


def test_no_color_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert not ui.color_enabled()
    assert ui.paint("x", "red") == "x"


def test_force_color_and_highlight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ui.paint("x", "red") == "\033[31mx\033[0m"
    h = ui.highlight(f"ssn {TOKEN} key {CMK}")
    assert "\033[35m" + TOKEN in h and "\033[36m" + CMK in h
    assert ui.paint("x") == "x"


def test_piped_output_is_plain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert not ui.color_enabled(io.StringIO())
    assert ui.highlight(TOKEN, on=False) == TOKEN
    assert ui.ok("done") == "[ok]   done" and ui.fail("x").startswith("[fail]")
    assert ui.info("x").startswith("[..]")


def test_progress_non_tty_prints_milestones() -> None:
    lines: list[str] = []
    p = ui.Progress("logins", 25, lines.append, every=10)
    for _ in range(25):
        p.tick()
    p.done("ok")
    assert lines == ["[..]   logins 10/25", "[..]   logins 20/25", "[ok]   logins 25/25  ok"]


def test_progress_tty_redraws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    stream = io.StringIO()
    printed: list[str] = []
    p = ui.Progress("q", 3, print, stream=stream)
    monkeypatch.setattr("builtins.print", printed.append)
    p._out = printed.append  # keep tty mode, capture final line
    p.tick()
    p.tick(2)
    p.done()
    assert "\rq" not in stream.getvalue() and "q 3/3" in stream.getvalue()
    assert "q 3/3" in printed[-1]


# --- log viewer ----------------------------------------------------------------------------


def _rec(**kw: object) -> str:
    return json.dumps({"timestamp": "2026-11-16T14:02:11.123Z", "level": "info",
                       "logger": "access", "event": "request", **kw})


def test_format_json_line() -> None:
    out = logview.format_line("sentinel-api", _rec(route="/query", status=200), on=False)
    assert out.startswith("14:02:11  INFO   sentinel-api")
    assert "request" in out and "route=/query status=200" in out
    assert "logger=" not in out


def test_format_non_json_and_levels() -> None:
    assert "Started server" in logview.format_line("kms", "INFO: Started server", on=False)
    assert "[1, 2]" in logview.format_line("kms", "[1, 2]", on=False)
    err = logview.format_line("x", _rec(level="error"), on=True)
    assert "\033[31;1mERROR" in err


def test_follow_tails_and_picks_up_new_lines(tmp_path: Path) -> None:
    f = tmp_path / "sentinel-api.log"
    f.write_text("\n".join(_rec(n=i) for i in range(30)) + "\n")
    got = list(logview.follow([f, tmp_path / "missing.log"], 5, keep_following=False))
    assert len(got) == 5 and "n=29" in got[-1]

    it = logview.follow([f], 0, keep_following=True, poll=0)
    with f.open("a") as fh:
        fh.write(_rec(n=99) + "\n")
    assert "n=99" in next(it)
    f.write_text(_rec(n=7) + "\n")  # truncated (service restarted)
    assert "n=7" in next(it)


def test_logview_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert logview.main(["--dir", str(tmp_path), "--no-follow"]) == 1
    (tmp_path / "mock-llm.log").write_text(_rec(event="hello") + "\n")
    assert logview.main(["--dir", str(tmp_path), "--no-follow"]) == 0
    out = capsys.readouterr().out
    assert "already redacted" in out and "hello" in out
