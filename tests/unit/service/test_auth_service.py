from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator

import pytest

from sentinel_vault.config import Settings
from sentinel_vault.domain.auth import Scope
from sentinel_vault.domain.ids import SessionId, TenantId, UserId
from sentinel_vault.persistence.auth_store import AuthStore
from sentinel_vault.persistence.sqlite import create_sqlite_engine
from sentinel_vault.security.errors import (
    AuthenticationError,
    ConflictError,
    InvalidInputError,
    NotFoundError,
    RateLimitedError,
    TenantFrozenError,
)
from sentinel_vault.security.sensitive import Sensitive
from sentinel_vault.service.auth_service import AuthService, hash_token
from tests.conftest import FakeClock

PW = Sensitive("correct horse battery staple")
ACME, BETA = TenantId("acme"), TenantId("beta")
ALICE, BOB = UserId("alice"), UserId("bob")


@pytest.fixture
async def svc(settings: Settings, clock: FakeClock) -> AsyncIterator[AuthService]:
    engine = create_sqlite_engine(settings.auth_db_path)
    store = AuthStore(engine)
    await store.create_schema()
    s = AuthService(store, settings, clock)
    for t in (ACME, BETA):
        await s.create_tenant(t)
        for u in (ALICE, BOB):
            await s.create_user(t, u, PW, [Scope.QUERY, Scope.INGEST])
    yield s
    await engine.dispose()


async def _login(svc: AuthService, t: TenantId = ACME, u: UserId = ALICE,
                 ip: str = "127.0.0.1") -> str:
    return (await svc.login(t, u, PW, ip)).token.reveal()


async def test_login_and_authenticate(svc: AuthService) -> None:
    res = await svc.login(ACME, ALICE, PW, "127.0.0.1")
    token = res.token.reveal()
    assert token.startswith("svs_")
    assert str(res.token) == "***"
    p = await svc.authenticate(token)
    assert (p.tenant_id, p.user_id, p.session_id) == (ACME, ALICE, res.session.session_id)
    assert p.has(Scope.QUERY) and not p.has(Scope.REIDENTIFY)


async def test_tenant_comes_only_from_session(svc: AuthService) -> None:
    pa = await svc.authenticate(await _login(svc, ACME))
    pb = await svc.authenticate(await _login(svc, BETA))
    assert pa.tenant_id == ACME and pb.tenant_id == BETA


@pytest.mark.parametrize("case", ["wrong_password", "unknown_user", "unknown_tenant"])
async def test_login_failures_look_identical(svc: AuthService, case: str) -> None:
    args = {
        "wrong_password": (ACME, ALICE, Sensitive("not the right password")),
        "unknown_user": (ACME, UserId("mallory"), PW),
        "unknown_tenant": (TenantId("nope"), ALICE, PW),
    }[case]
    with pytest.raises(AuthenticationError) as ei:
        await svc.login(*args, "127.0.0.1")
    assert ei.value.public_message == "Invalid or expired credentials."


async def test_token_never_stored(svc: AuthService, settings: Settings) -> None:
    token = await _login(svc)
    raw = settings.auth_db_path.read_bytes()
    for f in settings.data_dir.glob("auth.db*"):
        raw += f.read_bytes()
    assert token.encode() not in raw
    with sqlite3.connect(settings.auth_db_path) as db:
        hashes = [r[0] for r in db.execute("select session_hash from sessions")]
    assert hash_token(token) in hashes


async def test_password_not_stored_plain(svc: AuthService, settings: Settings) -> None:
    with sqlite3.connect(settings.auth_db_path) as db:
        rows = [r[0] for r in db.execute("select password_hash from users")]
    assert all(r.startswith("$argon2id$") for r in rows)
    assert all(PW.reveal() not in r for r in rows)


@pytest.mark.parametrize("bad", ["", "x", "svs_short", "svs_" + "A" * 43 + "!", "Bearer x",
                                 "svs_" + "A" * 43])
async def test_bad_tokens_rejected(svc: AuthService, bad: str) -> None:
    with pytest.raises(AuthenticationError):
        await svc.authenticate(bad)


async def test_tampered_token_rejected(svc: AuthService) -> None:
    token = await _login(svc)
    flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(AuthenticationError):
        await svc.authenticate(flipped)


async def test_idle_timeout(svc: AuthService, settings: Settings, clock: FakeClock) -> None:
    token = await _login(svc)
    clock.advance(settings.session_idle_seconds - 1)
    await svc.authenticate(token)  # touches: resets idle
    clock.advance(settings.session_idle_seconds - 1)
    await svc.authenticate(token)
    clock.advance(settings.session_idle_seconds + 1)
    with pytest.raises(AuthenticationError):
        await svc.authenticate(token)


async def test_absolute_timeout_even_when_active(svc: AuthService, settings: Settings,
                                                 clock: FakeClock) -> None:
    token = await _login(svc)
    step = settings.session_idle_seconds // 2
    elapsed = 0
    while elapsed + step < settings.session_absolute_seconds:
        clock.advance(step)
        elapsed += step
        await svc.authenticate(token)
    clock.advance(step)
    with pytest.raises(AuthenticationError):
        await svc.authenticate(token)


async def test_multiple_sessions_and_cap(svc: AuthService, settings: Settings,
                                         clock: FakeClock) -> None:
    tokens = []
    for _ in range(settings.max_sessions_per_user):
        tokens.append(await _login(svc))
        clock.advance(1)
    for t in tokens:
        await svc.authenticate(t)
    newest = await _login(svc)
    with pytest.raises(AuthenticationError):
        await svc.authenticate(tokens[0])  # oldest evicted
    for t in [*tokens[1:], newest]:
        await svc.authenticate(t)
    p = await svc.authenticate(newest)
    assert len(await svc.list_sessions(p)) == settings.max_sessions_per_user


async def test_logout_one_keeps_others(svc: AuthService) -> None:
    laptop, agent = await _login(svc), await _login(svc)
    await svc.logout(await svc.authenticate(laptop))
    with pytest.raises(AuthenticationError):
        await svc.authenticate(laptop)
    await svc.authenticate(agent)


async def test_logout_all(svc: AuthService) -> None:
    tokens = [await _login(svc) for _ in range(3)]
    other_user = await _login(svc, u=BOB)
    n = await svc.logout_all(await svc.authenticate(tokens[0]))
    assert n == 3
    for t in tokens:
        with pytest.raises(AuthenticationError):
            await svc.authenticate(t)
    await svc.authenticate(other_user)


async def test_list_sessions_marks_current_and_hides_tokens(svc: AuthService) -> None:
    a, b = await _login(svc), await _login(svc)
    sessions = await svc.list_sessions(await svc.authenticate(a))
    assert sum(s.current for s in sessions) == 1
    dumped = str([s.model_dump() for s in sessions])
    assert a not in dumped and b not in dumped
    assert hash_token(a) not in dumped


async def test_user_cannot_revoke_someone_elses_session(svc: AuthService) -> None:
    alice = await svc.authenticate(await _login(svc))
    bob_token = await _login(svc, u=BOB)
    bob = await svc.authenticate(bob_token)
    beta_token = await _login(svc, BETA, ALICE)
    beta = await svc.authenticate(beta_token)
    for victim in (bob.session_id, beta.session_id, SessionId.new()):
        with pytest.raises(NotFoundError):
            await svc.revoke_own_session(alice, victim)
    await svc.authenticate(bob_token)
    await svc.authenticate(beta_token)


async def test_revoke_own_other_session(svc: AuthService) -> None:
    a, b = await _login(svc), await _login(svc)
    pa, pb = await svc.authenticate(a), await svc.authenticate(b)
    await svc.revoke_own_session(pa, pb.session_id)
    with pytest.raises(AuthenticationError):
        await svc.authenticate(b)


async def test_freeze_tenant_kills_sessions_and_logins(svc: AuthService) -> None:
    acme_tokens = [await _login(svc, ACME, u) for u in (ALICE, BOB)]
    beta_token = await _login(svc, BETA)
    assert await svc.freeze_tenant(ACME) == 2
    for t in acme_tokens:
        with pytest.raises(AuthenticationError):
            await svc.authenticate(t)
    with pytest.raises(TenantFrozenError):
        await svc.login(ACME, ALICE, PW, "127.0.0.1")
    await svc.authenticate(beta_token)  # blast radius = one tenant
    await svc.unfreeze_tenant(ACME)
    await svc.authenticate(await _login(svc, ACME))
    for t in acme_tokens:  # old sessions stay dead after unfreeze
        with pytest.raises(AuthenticationError):
            await svc.authenticate(t)


async def test_frozen_tenant_wrong_password_still_401(svc: AuthService) -> None:
    await svc.freeze_tenant(ACME)
    with pytest.raises(AuthenticationError):  # don't reveal frozen state to bad passwords
        await svc.login(ACME, ALICE, Sensitive("wrong password here"), "127.0.0.1")


async def test_disabled_user(svc: AuthService) -> None:
    token = await _login(svc)
    await svc.disable_user(ACME, ALICE)
    with pytest.raises(AuthenticationError):
        await svc.authenticate(token)
    with pytest.raises(AuthenticationError):
        await svc.login(ACME, ALICE, PW, "127.0.0.1")


async def test_lockout_after_failures(svc: AuthService, settings: Settings,
                                      clock: FakeClock) -> None:
    bad = Sensitive("wrong password here")
    for _ in range(settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, ALICE, bad, "10.0.0.1")
    with pytest.raises(RateLimitedError):  # even with the right password
        await svc.login(ACME, ALICE, PW, "10.0.0.2")
    clock.advance(settings.login_lockout_base_seconds + 0.1)
    await svc.login(ACME, ALICE, PW, "10.0.0.2")


async def test_lockout_also_for_unknown_users(svc: AuthService, settings: Settings) -> None:
    ghost = UserId("ghost")
    for _ in range(settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, ghost, PW, "10.0.0.1")
    with pytest.raises(RateLimitedError):  # same behavior as a real user: no enumeration
        await svc.login(ACME, ghost, PW, "10.0.0.9")


async def test_ip_lockout_stops_password_spraying(svc: AuthService,
                                                  settings: Settings) -> None:
    bad = Sensitive("wrong password here")
    users = [UserId(f"user{i}") for i in range(settings.login_ip_max_failures)]
    for u in users:
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, u, bad, "10.6.6.6")
    with pytest.raises(RateLimitedError):
        await svc.login(ACME, ALICE, PW, "10.6.6.6")
    await svc.login(ACME, ALICE, PW, "10.0.0.1")  # other IPs fine


async def test_lockout_backoff_grows(svc: AuthService, settings: Settings,
                                     clock: FakeClock) -> None:
    bad = Sensitive("wrong password here")
    for _ in range(settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, BOB, bad, "10.0.0.1")
    clock.advance(settings.login_lockout_base_seconds + 0.1)
    with pytest.raises(AuthenticationError):
        await svc.login(ACME, BOB, bad, "10.0.0.3")
    clock.advance(settings.login_lockout_base_seconds + 0.1)  # now needs 2x base
    with pytest.raises(RateLimitedError):
        await svc.login(ACME, BOB, PW, "10.0.0.4")


async def test_success_resets_user_counter(svc: AuthService, settings: Settings) -> None:
    bad = Sensitive("wrong password here")
    for _ in range(settings.login_max_failures - 1):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, ALICE, bad, f"10.1.0.{_}")
    await svc.login(ACME, ALICE, PW, "10.1.1.1")
    for _ in range(settings.login_max_failures - 1):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, ALICE, bad, f"10.2.0.{_}")
    await svc.login(ACME, ALICE, PW, "10.2.1.1")


async def test_create_user_rules(svc: AuthService) -> None:
    with pytest.raises(InvalidInputError):
        await svc.create_user(ACME, UserId("carol"), Sensitive("short"), [Scope.QUERY])
    with pytest.raises(InvalidInputError):
        await svc.create_user(ACME, UserId("carol"), Sensitive("x" * 300), [Scope.QUERY])
    with pytest.raises(ConflictError):
        await svc.create_user(ACME, ALICE, PW, [Scope.QUERY])
    with pytest.raises(NotFoundError):
        await svc.create_user(TenantId("nope"), ALICE, PW, [Scope.QUERY])
    assert await svc.create_tenant(ACME) is False


async def test_overlong_password_login_fails_cleanly(svc: AuthService) -> None:
    with pytest.raises(AuthenticationError):
        await svc.login(ACME, ALICE, Sensitive("x" * 10_000), "127.0.0.1")


async def test_rehash_on_param_upgrade(svc: AuthService, settings: Settings,
                                       clock: FakeClock) -> None:
    import sqlite3 as sq

    from sentinel_vault.persistence.auth_store import AuthStore as Store

    stronger = settings.model_copy(update={"argon2_time_cost": 2})
    engine = create_sqlite_engine(settings.auth_db_path)
    svc2 = AuthService(Store(engine), stronger, clock)
    await svc2.login(ACME, ALICE, PW, "127.0.0.1")
    with sq.connect(settings.auth_db_path) as db:
        h = db.execute("select password_hash from users where user_id='alice' "
                       "and tenant_id='acme'").fetchone()[0]
    assert ",t=2," in h
    await engine.dispose()


async def test_concurrent_logins_ten_tenants(settings: Settings, clock: FakeClock) -> None:
    """10 tenants x 3 users x 2 sessions, all logging in and authenticating at once."""
    engine = create_sqlite_engine(settings.auth_db_path)
    store = AuthStore(engine)
    await store.create_schema()
    svc = AuthService(store, settings, clock)
    tenants = [TenantId(f"tenant-{i:02d}") for i in range(10)]
    users = [UserId(f"user{j}") for j in range(3)]
    for t in tenants:
        await svc.create_tenant(t)
        for u in users:
            await svc.create_user(t, u, PW, [Scope.QUERY])

    async def one(t: TenantId, u: UserId) -> tuple[TenantId, UserId, str]:
        return t, u, (await svc.login(t, u, PW, "127.0.0.1")).token.reveal()

    results = await asyncio.gather(*(one(t, u) for t in tenants for u in users for _ in range(2)))
    assert len({tok for *_, tok in results}) == 60
    principals = await asyncio.gather(*(svc.authenticate(tok) for *_, tok in results))
    for (t, u, _), p in zip(results, principals, strict=True):
        assert (p.tenant_id, p.user_id) == (t, u)
    for t in tenants:
        assert await store.count_live_sessions(t, clock(), clock() - 1800) == 6
    await engine.dispose()


async def test_concurrent_logins_respect_cap(settings: Settings, clock: FakeClock) -> None:
    capped = settings.model_copy(update={"max_sessions_per_user": 3})
    engine = create_sqlite_engine(settings.auth_db_path)
    store = AuthStore(engine)
    await store.create_schema()
    svc = AuthService(store, capped, clock)
    await svc.create_tenant(ACME)
    await svc.create_user(ACME, ALICE, PW, [Scope.QUERY])
    await asyncio.gather(*(svc.login(ACME, ALICE, PW, "127.0.0.1") for _ in range(12)))
    assert await store.count_live_sessions(ACME, clock(), clock() - 1800) == 3
    await engine.dispose()


async def test_one_user_lockout_does_not_lock_the_whole_ip(svc: AuthService,
                                                           settings: Settings) -> None:
    """Regression: users behind one IP (NAT, loopback) were all locked out by one
    user's typos, because the IP limit equalled the per-user limit."""
    bad = Sensitive("wrong password here")
    for _ in range(settings.login_max_failures):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, ALICE, bad, "10.9.9.9")
    with pytest.raises(RateLimitedError):
        await svc.login(ACME, ALICE, PW, "10.9.9.9")       # alice is locked
    await svc.login(ACME, BOB, PW, "10.9.9.9")             # bob on the same IP is not


async def test_failure_count_resets_after_quiet_window(svc: AuthService, settings: Settings,
                                                       clock: FakeClock) -> None:
    bad = Sensitive("wrong password here")
    for _ in range(settings.login_max_failures - 1):
        with pytest.raises(AuthenticationError):
            await svc.login(ACME, BOB, bad, "10.8.8.8")
    clock.advance(settings.login_failure_window_seconds + 1)
    with pytest.raises(AuthenticationError):               # count restarted at 1
        await svc.login(ACME, BOB, bad, "10.8.8.8")
    await svc.login(ACME, BOB, PW, "10.8.8.8")             # not locked


async def test_migrates_old_login_failures_table(settings: Settings) -> None:
    import sqlite3

    settings.data_dir.mkdir(parents=True, mode=0o700)
    with sqlite3.connect(settings.auth_db_path) as db:
        db.execute("create table login_failures (key varchar(128) primary key, "
                   "count integer not null, locked_until float not null)")
        db.execute("insert into login_failures values ('ip:1.2.3.4', 7, 0)")
    settings.auth_db_path.chmod(0o600)
    engine = create_sqlite_engine(settings.auth_db_path)
    store = AuthStore(engine)
    await store.create_schema()
    await store.create_schema()  # idempotent
    assert await store.record_failure("ip:1.2.3.4", 1e9, 20, 1.0, 900.0, 900.0) == 1
    await engine.dispose()
