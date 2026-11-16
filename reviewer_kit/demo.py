"""Guided walkthrough of the whole system on a fresh demo tenant.

Steps: BYOK onboarding → Store → Retrieve → Process (what the LLM actually saw) →
customer rotates CMK + re-wrap → containment → customer revokes key (crypto-shred).

Each step prints what is happening, the real API output, and what it proves.
Tokens like ``<<PERSON_…>>`` are shown in magenta, key and record ids in cyan.

Run: ``./run.sh demo`` (add ``--pause`` to wait for Enter between steps).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
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
from reviewer_kit.ui import highlight, paint

RECORD = {
    "fields": {"patient_name": "Johnathan Q. Marlowe", "ssn": "123-45-6789",
               "dob": "1984-07-19", "diagnosis_code": "N20.0", "visit_type": "follow-up",
               "notes": "Johnathan reports flank pain; call (415) 555-0134.",
               "insurance_carrier": "Acme Health"},
    "text": "Johnathan Q. Marlowe (MRN: 00A-7781-22) presented with kidney stones. "
            "Spouse Maria Marlowe can be reached at maria.m@example.org.",
}
TOTAL = 13


async def _wait_job(stack: Stack, headers: dict[str, str], job: str) -> dict[str, object]:
    for _ in range(600):
        r = await stack.api.get(f"/tenant/jobs/{job}", headers=headers)
        if r.status_code == 200 and r.json()["state"] == "done":
            return dict(r.json())
        await asyncio.sleep(0.1)
    raise TimeoutError(job)


async def demo(stack: Stack, out: Callable[[str], None] = print,
               pause: Callable[[], None] | None = None) -> None:
    def step(n: int, title: str, what: str, body: object, proves: str) -> None:
        if pause is not None and n > 1:
            pause()
        out("")
        out(paint(f"=== {n}. {title} ===", "bold") + paint(f"  [{n}/{TOTAL}]", "dim"))
        out(paint("    what's happening: ", "blue") + what)
        text = body if isinstance(body, str) else jprint(body)
        out(highlight(textwrap.indent(text, "    ")))
        out(paint("    ✔ proves: ", "green") + proves)

    out(paint("Sentinel Vault demo", "bold") + paint(
        " — a new customer goes from signup to crypto-shred. All output below is real.", "dim"))

    c = await provision_customer(stack, disposable("demo"))
    await c.login(stack, "analyst")
    step(1, "BYOK onboarding",
         "the customer creates a master key (CMK) in THEIR key vault and attaches a policy "
         "letting our service use it only for their tenant. We then test-drive the key.",
         {"tenant": c.tenant, "customer_cmk": c.cmk_id,
          "policy": f"sentinel-svc may GenerateDataKey/Decrypt/ReEncrypt "
                    f"only if tenant_id={c.tenant}"},
         "we never hold the master key; the customer can cut us off at any time")

    r = await stack.api.post("/documents", headers=c.h(), json=RECORD)
    doc = r.json()["doc_id"]
    step(2, "Store a patient record",
         "PII is found (fields + free text) and swapped for tokens; the original and the "
         "tokenized copy are encrypted with a data key wrapped by the customer's CMK. "
         "insurance_carrier is not on the tenant's allowlist, so it is dropped.",
         r.json(),
         "envelope encryption on write; unknown fields never reach the vector store")

    tok = (await stack.api.get(f"/documents/{doc}", headers=c.h("analyst"))).json()
    step(3, "Retrieve — tokenized view (analyst, scope: query)",
         "an analyst reads the record; every identifier is a per-tenant token",
         tok, "people without 'reidentify' only ever see tokens")
    orig = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(4, "Retrieve — original view (admin, scope: reidentify)",
         "the data key is unwrapped via the customer's KMS and the original is decrypted",
         orig.json(), "an authorized tenant gets its exact original record back")
    denied = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h("analyst"))
    step(5, "Original view without the reidentify scope",
         "the analyst asks for the raw record", f"HTTP {denied.status_code}",
         "raw PII needs an explicit permission")

    before = len(await llm_received(stack))
    q = await stack.api.post("/query", headers=c.h(), json={
        "question": "What did Johnathan Q. Marlowe present with?", "top_k": 2,
        "reidentify": True})
    sent = (await llm_received(stack))[before:]
    step(6, "Process — exactly what the external LLM received",
         "the question's name is tokenized, only this tenant's chunks are searched, and "
         "the egress guard re-scans everything before it leaves",
         "\n---\n".join(sent),
         "the LLM sees placeholders only — no names, SSNs, phones or emails")
    step(7, "Process — answer after local re-identification",
         "tokens in the answer are swapped back on OUR side, for this admin only",
         q.json(), "useful answers without the LLM ever seeing PHI")

    admin = c.kms_admin(stack)
    v = await admin.rotate_key(c.cmk_id)
    job = (await stack.api.post("/tenant/keys/rewrap", headers=c.h())).json()["job_id"]
    step(8, f"Customer rotates their CMK (now v{v}) → we re-wrap",
         "a background job asks the KMS to ReEncrypt every wrapped data key under the new "
         "version; plaintext keys never come to us",
         await _wait_job(stack, c.h(), job),
         "rotation without downtime; resumable if interrupted")
    still = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(9, "Old record after rotation", "reading the same record again",
         f"HTTP {still.status_code}", "old and new data stay readable through rotation")

    job = (await stack.api.post("/tenant/contain", headers=c.h())).json()["job_id"]
    after = await stack.api.get("/auth/me", headers=c.h("analyst"))
    step(10, "Containment starts (suspected key leak)",
         "the tenant is frozen, every session is revoked, and its data keys are marked "
         "compromised", f"analyst session now HTTP {after.status_code}",
         "blast radius is one tenant; other tenants keep working")
    for _ in range(600):
        try:
            await c.login(stack)
            break
        except Exception:  # noqa: BLE001 - frozen until the job ends
            await asyncio.sleep(0.1)
    step(11, "Containment done",
         "new data keys and a new token key; every document re-encrypted and re-embedded; "
         "old keys deleted; tenant unfrozen",
         await _wait_job(stack, c.h(), job), "a leaked old key now unlocks nothing")
    retok = (await stack.api.get(f"/documents/{doc}", headers=c.h())).json()
    step(12, "Same record, new tokens", "comparing the SSN token before and after",
         {"ssn_before": tok["fields"]["ssn"], "ssn_after": retok["fields"]["ssn"]},
         "the old token key can't be used to guess or link values")

    await admin.disable_key(c.cmk_id)
    await stack.api.post("/tenant/cache/flush", headers=c.h())
    gone = await stack.api.get(f"/documents/{doc}?view=original", headers=c.h())
    step(13, "Customer disables their CMK (+ cache flush)",
         "the customer pulls the plug in their own key vault",
         f"HTTP {gone.status_code} {gone.json()['error']['code']}",
         "crypto-shred: the ciphertext is still on our disk but nobody can read it")
    out("")
    out(paint("Demo complete.", "green", "bold") +
        paint("  See what the LLM got: curl -s 127.0.0.1:8200/v1/received", "dim"))


def _press_enter() -> None:
    try:
        input(paint("\n    ⏎ press Enter for the next step (Ctrl-C to quit) ", "dim"))
    except EOFError:
        pass


async def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="run.sh demo")
    p.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    a = p.parse_args(argv)
    pause = _press_enter if a.pause and sys.stdin.isatty() else None
    async with live_stack() as stack:
        await demo(stack, pause=pause)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
