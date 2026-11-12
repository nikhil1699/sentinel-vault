"""Async SQLite engine with safe defaults.

- DB file created 0600 before SQLite opens it (WAL/SHM files inherit the mode).
- ``BEGIN IMMEDIATE`` for every transaction: takes the write lock up front, so two
  writers (API + rotation worker, or two requests) can't deadlock on lock upgrade.
  ``busy_timeout`` makes the loser wait instead of failing.
- ``secure_delete`` overwrites deleted rows, so destroyed key material and revoked
  rows don't linger in free pages.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from sentinel_vault.security.files import ensure_private_dir, ensure_private_file

_PRAGMAS = (
    "journal_mode=WAL",
    "foreign_keys=ON",
    "secure_delete=ON",
    "busy_timeout=10000",
    "synchronous=NORMAL",
)


def create_sqlite_engine(path: Path) -> AsyncEngine:
    ensure_private_dir(path.parent)
    ensure_private_file(path)
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn: Any, _record: Any) -> None:
        dbapi_conn.isolation_level = None  # we issue BEGIN ourselves
        cur = dbapi_conn.cursor()
        for pragma in _PRAGMAS:
            cur.execute(f"PRAGMA {pragma}")
        cur.close()

    @event.listens_for(engine.sync_engine, "begin")
    def _on_begin(conn: Any) -> None:
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    return engine
