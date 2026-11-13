"""Seed 10 synthetic customers, each with BYOK onboarding, 3 users and PHI-rich records.

Idempotent: a customer already in ``.secrets/customers/<tenant>/state.json`` is skipped.
All data is synthetic (``Faker`` with a fixed seed per tenant).

Run: ``python -m reviewer_kit.seed`` (``./run.sh`` does this for you).
"""

from __future__ import annotations

import asyncio
import random
import sys
from typing import Any, Final

from faker import Faker

from reviewer_kit.common import Customer, Stack, live_stack, load_customer, provision_customer
from sentinel_vault.security.files import write_exclusive

CUSTOMERS: Final[list[tuple[str, str]]] = [
    ("st-marys-hospital", "Hospital"), ("bluecross-mutual", "Insurer"),
    ("cornerstone-pharmacy", "Pharmacy"), ("lakeside-clinic", "Clinic"),
    ("northwind-labs", "Diagnostics lab"), ("harbor-dental", "Dental practice"),
    ("pinecrest-rehab", "Rehab center"), ("summit-cardiology", "Cardiology"),
    ("meadow-pediatrics", "Pediatrics"), ("riverbend-telehealth", "Telehealth"),
]
CANARIES: Final = ["apple", "banana", "cherry", "grape", "lemon", "mango", "olive", "peach",
                   "plum", "melon"]
DIAGNOSES: Final = [("N20.0", "kidney stones"), ("J45.9", "asthma"), ("E11.9", "type 2 diabetes"),
                    ("I10", "high blood pressure"), ("S52.5", "a wrist fracture"),
                    ("M54.5", "low back pain"), ("F41.1", "anxiety"), ("K21.9", "acid reflux")]


def synthetic_record(fake: Faker, rng: random.Random) -> dict[str, Any]:
    name = fake.name()
    code, dx = rng.choice(DIAGNOSES)
    phone, email = fake.numerify("(###) ###-####"), fake.email()
    mrn = fake.bothify("MRN-##??-####").upper()
    return {
        "fields": {
            "patient_name": name, "ssn": fake.ssn(), "dob": fake.date_of_birth().isoformat(),
            "mrn": mrn, "phone": phone, "email": email, "diagnosis_code": code,
            "visit_type": rng.choice(["new", "follow-up", "urgent"]),
            "notes": f"{name.split()[0]} reports symptoms of {dx}. Call back at {phone}.",
        },
        "text": f"{name} (DOB {fake.date_of_birth().isoformat()}, MRN: {mrn}) was seen for "
                f"{dx}. Lives at {fake.street_address()}, {fake.city()}. Contact {email}.",
    }


def records_for(idx: int, docs: int) -> list[dict[str, Any]]:
    """Deterministic per tenant (instance seed, safe under concurrency)."""
    fake = Faker()
    fake.seed_instance(idx)
    rng = random.Random(idx)  # noqa: S311 - synthetic data only
    return [synthetic_record(fake, rng) for _ in range(docs)]


def raw_values(idx: int, docs: int) -> list[str]:
    """Every PHI value seeded for a tenant (to prove none of it reaches the LLM)."""
    keys = ("patient_name", "ssn", "mrn", "phone", "email")
    return [str(r["fields"][k]) for r in records_for(idx, docs) for k in keys]


async def seed_customer(stack: Stack, idx: int, docs: int) -> tuple[Customer, bool]:
    tenant, _ = CUSTOMERS[idx]
    done = stack.secrets_dir / "customers" / tenant / "seeded"
    existing = load_customer(stack, tenant)
    if existing is not None and done.exists():
        return existing, False
    c = await provision_customer(stack, tenant)
    await c.login(stack, "loader")
    for rec in records_for(idx, docs):
        r = await stack.api.post("/documents", json=rec, headers=c.h("loader"))
        r.raise_for_status()
    # A canary only this tenant knows: the simulator checks it never shows up elsewhere.
    r = await stack.api.post("/documents", headers=c.h("loader"), json={
        "text": f"Ward supply note: the canary word is {CANARIES[idx]}."})
    r.raise_for_status()
    write_exclusive(done, str(docs).encode(), 0o600)
    return c, True


async def seed(stack: Stack, count: int = 10, docs: int = 8) -> list[tuple[Customer, bool]]:
    """Seed customers concurrently (exercises concurrent onboarding and ingest)."""
    return list(await asyncio.gather(*(seed_customer(stack, i, docs) for i in range(count))))


def credentials_table(results: list[tuple[Customer, bool]]) -> str:
    lines = [f"{'tenant':<24} {'user':<8} password", "-" * 60]
    for c, _ in results:
        for u, pw in c.passwords.items():
            lines.append(f"{c.tenant:<24} {u:<8} {pw}")
    return "\n".join(lines)


async def _main() -> int:
    async with live_stack() as stack:
        results = await seed(stack)
        new = sum(created for _, created in results)
        table = credentials_table(results)
        out = stack.secrets_dir / "reviewer-credentials.txt"
        out.unlink(missing_ok=True)
        write_exclusive(out, (table + "\n").encode(), 0o600)
    print(f"[ok]   seed: {new} new, {len(results) - new} already present "
          f"(logins in {out})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except Exception as exc:  # noqa: BLE001 - top-level CLI message
        print(f"[fail] seed: {type(exc).__name__} — see .run/logs/sentinel-api.log",
              file=sys.stderr)
        raise SystemExit(1) from None
