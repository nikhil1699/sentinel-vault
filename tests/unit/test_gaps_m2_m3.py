"""Close M2/M3 gaps: SQLite safety settings, scope checks, KMS operator CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends
from sqlalchemy import text

from customer_kms import cli
from customer_kms.directory import load_account, load_principal
from sentinel_vault.api.app import create_app
from sentinel_vault.api.deps import require_scope
from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Principal, Scope
from sentinel_vault.domain.ids import TenantId, UserId
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.security.sensitive import Sensitive
from tests.conftest import FakeClock
from tests.kms_env import pub_pem


async def test_sqlite_safety_pragmas(tmp_path: Path) -> None:
    db = tmp_path / "d" / "x.db"
    engine = create_sqlite_engine(db)
    async with engine.connect() as conn:
        got = {p: (await conn.execute(text(f"PRAGMA {p}"))).scalar()
               for p in ("journal_mode", "foreign_keys", "secure_delete", "busy_timeout")}
    await engine.dispose()
    assert got == {"journal_mode": "wal", "foreign_keys": 1, "secure_delete": 1,
                   "busy_timeout": 10000}
    assert db.stat().st_mode & 0o077 == 0
    assert db.parent.stat().st_mode & 0o077 == 0


async def test_transactions_take_write_lock_up_front(tmp_path: Path) -> None:
    """BEGIN IMMEDIATE: a second writer waits instead of deadlocking on lock upgrade."""
    import asyncio

    engine = create_sqlite_engine(tmp_path / "x.db")
    async with engine.begin() as conn:
        await conn.execute(text("create table t (n integer)"))

    async def writer(i: int) -> None:
        async with engine.begin() as conn:
            n = (await conn.execute(text("select count(*) from t"))).scalar_one()
            await asyncio.sleep(0.01)  # widen the read->write window
            await conn.execute(text("insert into t values (:n)"), {"n": n + i})

    await asyncio.gather(*(writer(i) for i in range(10)))
    async with engine.connect() as conn:
        assert (await conn.execute(text("select count(*) from t"))).scalar_one() == 10
    await engine.dispose()


async def test_require_scope(settings: Settings, clock: FakeClock,
                             app_deps: dict[str, Any]) -> None:
    app = create_app(settings, configure_logs=False, clock=clock, **app_deps)

    @app.get("/_t/admin-only")
    async def admin_only(p: Principal = Depends(require_scope(Scope.ADMIN))) -> dict[str, str]:  # noqa: B008
        return {"tenant": p.tenant_id}

    async with app.router.lifespan_context(app):
        svc = app.state.auth_service
        await svc.create_tenant(TenantId("acme"))
        pw = Sensitive("correct horse battery staple")
        await svc.create_user(TenantId("acme"), UserId("user"), pw, [Scope.QUERY])
        await svc.create_user(TenantId("acme"), UserId("boss"), pw, [Scope.ADMIN])
        t = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=t, base_url="http://t") as c:
            async def token(u: str) -> str:
                r = await c.post("/auth/login", json={"tenant_id": "acme", "username": u,
                                                      "password": pw.reveal()})
                return str(r.json()["token"])

            r = await c.get("/_t/admin-only",
                            headers={"authorization": f"Bearer {await token('user')}"})
            assert r.status_code == 403
            r = await c.get("/_t/admin-only",
                            headers={"authorization": f"Bearer {await token('boss')}"})
            assert r.status_code == 200 and r.json() == {"tenant": "acme"}


def test_kms_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                 capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "kms"
    monkeypatch.setenv("KMS_DATA_DIR", str(data))
    pub = tmp_path / "svc.pub.pem"
    pub.write_text(pub_pem(Ed25519PrivateKey.generate()))

    assert cli.main(["register-principal", "sentinel-svc", str(pub)]) == 0
    assert cli.main(["register-principal", "sentinel-svc", str(pub)]) == 0
    assert "present" in capsys.readouterr().out
    assert load_principal(data, "sentinel-svc") is not None

    other = tmp_path / "other.pub.pem"
    other.write_text(pub_pem(Ed25519PrivateKey.generate()))
    assert cli.main(["register-principal", "sentinel-svc", str(other)]) == 1
    assert "[fail]" in capsys.readouterr().err

    key_out = tmp_path / "customers" / "acme" / "admin.pem"
    assert cli.main(["create-account", "acme", "--admin-key-out", str(key_out)]) == 0
    assert key_out.stat().st_mode & 0o077 == 0
    assert load_account(data, "acme") is not None
    assert cli.main(["create-account", "acme", "--admin-key-out", str(key_out)]) == 1
