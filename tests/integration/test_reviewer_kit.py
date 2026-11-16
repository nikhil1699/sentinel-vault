"""The reviewer kit (seed, simulate, attack, demo) runs end to end against the real apps."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.app import create_app as create_kms
from customer_kms.config import KmsSettings
from customer_kms.directory import register_principal
from mock_llm.app import create_app as create_llm
from reviewer_kit import attack, demo, seed, simulate
from reviewer_kit.common import Stack
from sentinel_vault.api.app import create_app
from sentinel_vault.config import Settings
from sentinel_vault.privacy.detector import PiiDetector
from sentinel_vault.retrieval.embedder import HashEmbedder
from tests.conftest import LogCapture
from tests.kms_env import SERVICE, pub_pem


@asynccontextmanager
async def stack_env(tmp_path: Path, settings: Settings,
                    detector: PiiDetector) -> AsyncIterator[Stack]:
    key = Ed25519PrivateKey.generate()
    kms_dir = tmp_path / "kms"
    register_principal(kms_dir, SERVICE, pub_pem(key))
    kms_app = create_kms(KmsSettings(data_dir=kms_dir), configure_logs=False)
    llm_app = create_llm(configure_logs=False)
    async with kms_app.router.lifespan_context(kms_app):
        kms = httpx.AsyncClient(transport=httpx.ASGITransport(app=kms_app),
                                base_url="http://kms")
        llm = httpx.AsyncClient(transport=httpx.ASGITransport(app=llm_app),
                                base_url="http://llm")
        app = create_app(settings, configure_logs=False, kms_http=kms, service_key=key,
                         detector=detector, embedder=HashEmbedder(), llm_http=llm)
        async with kms, llm, app.router.lifespan_context(app):
            api = httpx.AsyncClient(transport=httpx.ASGITransport(
                app=app, raise_app_exceptions=False), base_url="http://api")
            async with api:
                yield Stack(api, kms, llm, app.state.auth_service, kms_dir,
                            settings.data_dir, settings.secrets_dir, SERVICE, key)


@pytest.fixture
async def stack(tmp_path: Path, settings: Settings, detector: PiiDetector,
                logs: LogCapture) -> AsyncIterator[Stack]:
    async with stack_env(tmp_path, settings, detector) as s:
        yield s


async def test_seed_is_idempotent_and_private(stack: Stack) -> None:
    first = await seed.seed(stack, count=3, docs=2)
    assert [created for _, created in first] == [True] * 3
    again = await seed.seed(stack, count=3, docs=2)
    assert [created for _, created in again] == [False] * 3
    for c, _ in first:
        d = stack.secrets_dir / "customers" / c.tenant
        assert (d / "admin.pem").stat().st_mode & 0o077 == 0
        assert (d / "state.json").stat().st_mode & 0o077 == 0
    table = seed.credentials_table(first)
    assert first[0][0].passwords["admin"] in table


async def test_seeded_phi_is_not_on_disk(stack: Stack, settings: Settings) -> None:
    await seed.seed(stack, count=2, docs=2)
    blob = b"".join(p.read_bytes() for p in settings.data_dir.glob("*.db*"))
    for i in range(2):
        for v in seed.raw_values(i, 2):
            assert v.encode() not in blob, v


async def test_simulation_passes(stack: Stack) -> None:
    await seed.seed(stack, count=4, docs=2)
    r = await simulate.simulate(stack, count=4)
    assert r.failures == [] and r.sessions == 24


async def test_simulation_requires_seed(stack: Stack) -> None:
    r = await simulate.simulate(stack, count=2)
    assert r.failures


async def test_attack_runner_all_defended(stack: Stack) -> None:
    outcomes = await attack.run_attacks(stack)
    assert len(outcomes) == len(attack.CHECKS) >= 10
    failed = [o for o in outcomes if not o.defended]
    assert not failed, attack.report(outcomes)
    assert "attacks defended" in attack.report(outcomes)


async def test_attack_runner_reports_a_breach(stack: Stack) -> None:
    """If a defense were missing, the runner must say BREACHED (and exit non-zero)."""
    async def broken(_: attack.Ctx) -> tuple[bool, str]:
        return False, "simulated missing defense"

    attack.CHECKS.append(("A0 test", "always fails", broken))
    try:
        outcomes = await attack.run_attacks(stack)
    finally:
        attack.CHECKS.pop()
    assert not outcomes[-1].defended and "BREACHED" in attack.report(outcomes)


async def test_demo_runs_every_step(stack: Stack) -> None:
    lines: list[str] = []
    await demo.demo(stack, lines.append)
    text = "\n".join(lines)
    assert "=== 13." in text and "Demo complete." in text
    sent = text.split("=== 6.")[1].split("=== 7.")[0]
    for v in ("Marlowe", "123-45-6789", "555-0134", "maria.m@example.org"):
        assert v not in sent, v
    assert "tenant_key_unavailable" in text


# --- console output (what someone running the scripts sees) -------------------------------


async def test_seed_prints_one_line_per_customer(stack: Stack) -> None:
    lines: list[str] = []
    await seed.seed(stack, count=3, docs=1, out=lines.append)
    assert len(lines) == 3 and all(" onboarded + 2 records" in x for x in lines)
    assert {x.split()[1] for x in lines} == {"1/3", "2/3", "3/3"}
    again: list[str] = []
    await seed.seed(stack, count=3, docs=1, out=again.append)
    assert all("already seeded" in x for x in again)


async def test_attack_prints_legend_and_live_results(stack: Stack) -> None:
    lines: list[str] = []
    outcomes = await attack.run_attacks(stack, lines.append)
    text = "\n".join(lines)
    for actor, blurb in attack.ACTORS.items():
        if actor != "A0 test":
            assert actor in text and blurb in text
    assert text.count("DEFENDED") == len(outcomes) and "BREACHED" not in text


async def test_simulate_prints_progress(stack: Stack) -> None:
    await seed.seed(stack, count=2, docs=1)
    lines: list[str] = []
    r = await simulate.simulate(stack, count=2, out=lines.append)
    text = "\n".join(lines)
    assert r.failures == []
    assert "[ok]   logins 12/12" in text and "[ok]   queries 12/12" in text
    assert "logging out one" in text


async def test_demo_explains_each_step_and_can_pause(stack: Stack) -> None:
    lines: list[str] = []
    pauses: list[int] = []
    await demo.demo(stack, lines.append, pause=lambda: pauses.append(1))
    text = "\n".join(lines)
    assert text.count("what's happening:") == demo.TOTAL
    assert text.count("✔ proves:") == demo.TOTAL
    assert len(pauses) == demo.TOTAL - 1


async def test_tour_runs_every_chapter_and_all_checks_pass(stack: Stack) -> None:
    from reviewer_kit import tour

    lines: list[str] = []
    passed = await tour.run_tour(stack, lines.append, delay=0, tenants=2)
    text = "\n".join(lines)
    failed = [x for x in lines if "✘" in x]
    assert passed, "\n".join(failed)
    for n in range(1, 12):
        assert f"CHAPTER {n}/11" in text
    assert "SCOREBOARD" in text and "checks passed" in text
    llm_part = text.split("EVERYTHING the external LLM received")[1].split("✔ no raw PII")[0]
    for v in tour.RAW:
        assert v not in llm_part, v


async def test_cli_customer_and_password_helpers(stack: Stack) -> None:
    from reviewer_kit import cli

    msg = await cli.new_customer(stack, "my-clinic")
    assert "onboarded" in msg and "cmk_" in msg
    assert "already exists" in await cli.new_customer(stack, "my-clinic")
    pw = cli.password(stack, "my-clinic", "admin")
    assert pw and cli.password(stack, "nope-clinic", "admin") is None
    r = await stack.api.post("/auth/login", json={"tenant_id": "my-clinic",
                                                  "username": "admin", "password": pw})
    assert r.status_code == 200
    assert "rotated to v2" in await cli.key_action(stack, "rotate", "my-clinic")
    assert '"current_version": 2' in await cli.key_action(stack, "describe", "my-clinic")
    assert "DISABLED" in await cli.key_action(stack, "disable", "my-clinic")
    assert "refused" in await cli.key_action(stack, "rotate", "my-clinic")  # disabled key
    assert "enabled again" in await cli.key_action(stack, "enable", "my-clinic")
    audit = await cli.key_action(stack, "audit", "my-clinic")
    assert "RotateKey" in audit and "hash chain intact" in audit
    assert "no customer" in await cli.key_action(stack, "audit", "ghost-clinic")
