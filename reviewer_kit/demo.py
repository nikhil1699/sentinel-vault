"""Guided walkthrough of the whole system on a fresh demo tenant.

Steps: BYOK onboarding → Store → Retrieve → Process (what the LLM actually saw) →
customer rotates CMK + re-wrap → containment → customer revokes key (crypto-shred).

Run: ``./run.sh demo``.
"""

from __future__ import annotations

import asyncio
import textwrap
from collections.abc import Callable

from reviewer_kit.common import (
    Stack,
    disposable,
    jprint,
    live_stack,
    llm_received,
    provision_customer,
)

RECORD = {
    "fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789",
               "dob": "1984-07-19", "diagnosis_code": "N20.0", "visit_type": "follow-up",
               "notes": "Johnathan reports flank pain; call (415) 555-0134.",
               "insurance_carrier": "Acme Health"},
    "text": "Johnathan Q. Marlowe (MRN: 00A-7781-22) presented with kidney stones. "
            "Spouse Maria Marlowe can be reached at maria.m@example.org.",
}


async def _wait_job(stack: Stack, headers: dict[str, str], job: str) -> dict[str, object]:
    for _ in range(600):
        r = await stack.api.get(f"/tenant/jobs/{job}", headers=headers)
        if r.status_code == 200 and r.json()["state"] == "done":
            return dict(r.json())
        await asyncio.sleep(0.1)
    raise TimeoutError(job)


async def demo(stack: Stack, out: Callable[[str], None] = print) -> None:
    def step(n: int, title: str, body: object = "") -> None:
        out(f"\n=== {n}. {title} ===")
        if body != "":
            out(textwrap.indent(body if isinstance(body, str) else jprint(body), "    "))

    c = await provision_customer(stack, disposable("demo"))
    await c.login(stack, "analyst")
    step(1, "BYOK onboarding", {
        "tenant": c.tenant, "customer_cmk": c.cmk_id,
        "note": "customer created the CMK and granted us GenerateDataKey/Decrypt/ReEncrypt "
                "only for tenant_id=" + c.tenant + "; we probed it before accepting"})

    r = await stack.api.post("/documents", headers=c.h(), json=RECORD)
    doc = r.json()["doc_id"]
    step(2, "Store (insurance_carrier is not in the policy, so it is dropped)", r.json())

    tok = (await stack.api.get(f"/documents/{doc}", headers=c.h("analyst"))).json()
    step(3, "Retrieve, tokenized view (scope: query)", tok)
    orig = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(4, "Retrieve, original view (scope: reidentify)", orig.json())
    denied = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h("analyst"))
    step(5, "Original view without reidentify scope", f"HTTP {denied.status_code}")

    before = len(await llm_received(stack))
    q = await stack.api.post("/query", headers=c.h(), json={
        "question": "What did Johnathan Q. Marlowe present with?", "top_k": 2,
        "reidentify": True})
    sent = (await llm_received(stack))[before:]
    step(6, "Process: exactly what the external LLM received", "\n---\n".join(sent))
    step(7, "Process: answer after local re-identification", q.json())

    admin = c.kms_admin(stack)
    v = await admin.rotate_key(c.cmk_id)
    job = (await stack.api.post("/tenant/keys/rewrap", headers=c.h())).json()["job_id"]
    step(8, f"Customer rotates CMK to v{v}; we re-wrap every DEK (no downtime)",
         await _wait_job(stack, c.h(), job))
    still = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(9, "Old record still readable after rotation", f"HTTP {still.status_code}")

    job = (await stack.api.post("/tenant/contain", headers=c.h())).json()["job_id"]
    after = await stack.api.get("/auth/me", headers=c.h("analyst"))
    step(10, "Containment: tenant frozen, every session revoked",
         f"analyst session now HTTP {after.status_code}")
    for _ in range(600):
        try:
            await c.login(stack)
            break
        except Exception:  # noqa: BLE001 - frozen until the job ends
            await asyncio.sleep(0.1)
    step(11, "Containment done: new DEKs, new token key, data re-encrypted",
         await _wait_job(stack, c.h(), job))
    retok = (await stack.api.get(f"/documents/{doc}", headers=c.h())).json()
    step(12, "Same record, new tokens (old token key now matches nothing)",
         {"ssn_before": tok["fields"]["ssn"], "ssn_after": retok["fields"]["ssn"]})

    await admin.disable_key(c.cmk_id)
    await stack.api.post("/tenant/cache/flush", headers=c.h())
    gone = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(13, "Customer disables CMK + flush: data unreadable (crypto-shred)",
         f"HTTP {gone.status_code} {gone.json()['error']['code']}")
    out("\nDemo complete.")


async def _main() -> int:
    async with live_stack() as stack:
        await demo(stack)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
