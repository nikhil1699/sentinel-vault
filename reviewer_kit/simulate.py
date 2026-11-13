"""Concurrent multi-tenant simulation against the seeded customers.

Every seeded tenant: 3 users × 2 sessions log in at once, then every session queries for
its tenant's canary word at once. Checks:

- every login and query succeeds,
- each answer's context holds the tenant's own canary and no other tenant's,
- the LLM received no raw seeded PHI (names, SSNs, emails, phones),
- logging out one session leaves the user's other session working.

Read-only for seeded data. Run: ``./run.sh simulate``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from reviewer_kit.common import Customer, Stack, live_stack, llm_received, load_customer
from reviewer_kit.seed import CANARIES, CUSTOMERS, raw_values


@dataclass
class SimResult:
    tenants: int
    sessions: int
    queries: int
    failures: list[str]


async def _session(stack: Stack, c: Customer, user: str) -> str:
    r = await stack.api.post("/auth/login", json={
        "tenant_id": c.tenant, "username": user, "password": c.passwords[user]})
    r.raise_for_status()
    return str(r.json()["token"])


async def simulate(stack: Stack, count: int = 10) -> SimResult:
    customers = [load_customer(stack, CUSTOMERS[i][0]) for i in range(count)]
    if any(c is None for c in customers):
        return SimResult(0, 0, 0, ["not seeded: run ./run.sh first"])
    cs = [c for c in customers if c is not None]
    failures: list[str] = []
    before = len(await llm_received(stack))

    pairs = [(i, c, u) for i, c in enumerate(cs) for u in c.passwords for _ in range(2)]
    tokens = await asyncio.gather(*(_session(stack, c, u) for _, c, u in pairs))

    async def ask(i: int, token: str) -> None:
        r = await stack.api.post("/query", headers={"authorization": f"Bearer {token}"},
                                 json={"question": "what is the canary word", "top_k": 3})
        if r.status_code != 200:
            failures.append(f"{cs[i].tenant}: query {r.status_code}")
            return
        ctx = r.json()["answer"].split("<question>")[0]
        if CANARIES[i] not in ctx:
            failures.append(f"{cs[i].tenant}: own canary missing")
        leaked = [w for j, w in enumerate(CANARIES[:count]) if j != i and w in ctx]
        if leaked:
            failures.append(f"{cs[i].tenant}: saw other tenants' canaries {leaked}")

    await asyncio.gather(*(ask(i, t) for (i, _, _), t in zip(pairs, tokens, strict=True)))

    # Two sessions of the same user: log out one, the other must keep working.
    a, b = tokens[0], tokens[1]
    await stack.api.post("/auth/logout", headers={"authorization": f"Bearer {a}"})
    if (await stack.api.get("/auth/me", headers={"authorization": f"Bearer {a}"})
            ).status_code != 401:
        failures.append("logged-out session still valid")
    if (await stack.api.get("/auth/me", headers={"authorization": f"Bearer {b}"})
            ).status_code != 200:
        failures.append("sibling session killed by logout")

    sent = "\n".join((await llm_received(stack))[before:])
    for i, c in enumerate(cs):
        marker = stack.secrets_dir / "customers" / c.tenant / "seeded"
        docs = int(marker.read_text()) if marker.is_file() else 0
        if any(v in sent for v in raw_values(i, docs)):
            failures.append(f"{c.tenant}: raw seeded PHI reached the LLM")
    return SimResult(len(cs), len(pairs), len(pairs), failures)


async def _main() -> int:
    async with live_stack() as stack:
        r = await simulate(stack)
    print(f"tenants={r.tenants} concurrent_sessions={r.sessions} concurrent_queries={r.queries}")
    for f in r.failures:
        print(f"[fail] {f}")
    if r.failures:
        return 1
    print("[ok]   simulation: every tenant saw only its own data; sessions independent")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
