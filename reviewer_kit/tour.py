"""Hands-free, end-to-end tour of the whole project. ``./run.sh tour``.

Runs on its own and narrates every step with the real API output, so a reviewer can sit
back and watch. Each step also *checks* what it claims; the tour ends with a scoreboard
and exits non-zero if any check failed. A plain-text transcript is written to
``.run/tour-<time>.log``.

Chapters
  1  Two new customers sign up (KMS account, master key, key policy, users, BYOK probe)
  2  Users log in; many sessions per user; logout; wrong password
  3  Store patient records (PII → tokens, envelope encryption) + what's on disk
  4  Retrieve (tokenized / original / denied / other tenant)
  5  Agentic query across the PHI boundary (+ KMS call counts and caching)
  6  The customer's view: KMS audit log, a denied cross-tenant call, chain check
  7  Customer rotates their master key → re-wrap with no downtime
  8  Containment after a suspected key leak (one tenant only)
  9  Customer revokes their key (crypto-shred) and restores it
 10  Four threat actors attack the live system
 11  Ten tenants, sixty sessions at the same time

Fresh tenants are created for every run; seeded data is only read.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import secrets
import sqlite3
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from customer_kms.client import KmsClient, KmsError
from customer_kms.directory import create_account
from reviewer_kit import attack, seed, simulate
from reviewer_kit.common import (
    CLINIC_POLICY,
    USERS,
    Customer,
    Stack,
    jprint,
    live_stack,
    llm_received,
    tenant_key_policy,
)
from reviewer_kit.ui import highlight, paint
from sentinel_vault.domain.ids import TenantId, UserId
from sentinel_vault.security.sensitive import Sensitive

_ANSI: Final = re.compile(r"\033\[[0-9;]*m")
ACTOR_STYLE: Final = {"customer": "yellow", "operator": "blue", "user": "cyan",
                      "sentinel": "green", "attacker": "red", "llm": "magenta", "kms": "yellow"}

PATIENTS: Final[list[dict[str, Any]]] = [
    {"fields": {"patient_name": "Rosalind Achebe", "ssn": "412-55-7301", "dob": "1979-03-02",
                "diagnosis_code": "J45.9", "visit_type": "follow-up",
                "notes": "Rosalind uses her inhaler twice daily. Call (646) 555-0142."},
     "text": "Rosalind Achebe (MRN: 77R-3310-08) was seen for asthma. "
             "Email r.achebe@example.org."},
    {"fields": {"patient_name": "Tobias Lindqvist", "ssn": "503-21-8846",
                "dob": "1990-11-23", "diagnosis_code": "N20.0", "visit_type": "urgent",
                "notes": "Tobias reports flank pain since Monday."},
     "text": "Tobias Lindqvist presented with kidney stones. Wife Ingrid Lindqvist "
             "can be reached at (917) 555-0183."},
    {"fields": {"patient_name": "Mei-Ling Okonkwo", "ssn": "611-40-2297",
                "dob": "1966-06-14", "diagnosis_code": "E11.9", "visit_type": "new",
                "insurance_carrier": "Acme Health",
                "notes": "Mei-Ling started metformin."},
     "text": "Mei-Ling Okonkwo has type 2 diabetes. Lives at 18 Harbor Lane, Portland."},
]
RAW: Final = ["Rosalind", "Achebe", "412-55-7301", "Tobias", "Lindqvist", "503-21-8846",
              "Okonkwo", "611-40-2297", "555-0142", "555-0183", "r.achebe@example.org",
              "77R-3310-08", "Ingrid", "Harbor Lane"]


@dataclass
class Tour:
    stack: Stack
    out: Callable[[str], None]
    delay: float
    checks: list[tuple[str, str, bool]] = field(default_factory=list)
    chapter_name: str = ""
    hospital: Customer | None = None
    insurer: Customer | None = None
    docs: list[str] = field(default_factory=list)

    # --- narration ---------------------------------------------------------------------

    async def pause(self, factor: float = 1.0) -> None:
        if self.delay > 0:
            await asyncio.sleep(self.delay * factor)

    async def chapter(self, n: int, title: str, why: str) -> None:
        self.chapter_name = f"{n}. {title}"
        self.out("")
        self.out(paint("━" * 78, "dim"))
        self.out(paint(f" CHAPTER {n}/11  {title}", "bold"))
        self.out(paint(f" {why}", "dim"))
        self.out(paint("━" * 78, "dim"))
        await self.pause(1.5)

    async def act(self, actor: str, text: str) -> None:
        tag = paint(f"{actor:>9}", ACTOR_STYLE.get(actor, "bold"), "bold")
        self.out(f"{tag} │ {highlight(text)}")
        await self.pause(0.6)

    def show(self, obj: Any, limit: int = 40) -> None:
        text = obj if isinstance(obj, str) else jprint(obj)
        lines = text.splitlines()
        if len(lines) > limit:
            lines = [*lines[:limit], f"… ({len(lines) - limit} more lines)"]
        for line in lines:
            self.out(paint("          │ ", "dim") + highlight(line))

    async def check(self, claim: str, passed: bool) -> bool:
        mark = paint("✔", "green", "bold") if passed else paint("✘ FAILED", "red", "bold")
        self.out(f"          {mark} {claim}")
        self.checks.append((self.chapter_name, claim, passed))
        await self.pause(0.4)
        return passed

    # --- helpers ---------------------------------------------------------------------------

    def _need(self, c: Customer | None) -> Customer:
        if c is None:  # pragma: no cover - chapters run in order
            raise RuntimeError("customer not created yet")
        return c

    async def _login(self, c: Customer, user: str) -> str:
        r = await self.stack.api.post("/auth/login", json={
            "tenant_id": c.tenant, "username": user, "password": c.passwords[user]})
        r.raise_for_status()
        return str(r.json()["token"])

    async def _audit_ops(self, c: Customer, since: int) -> list[dict[str, Any]]:
        return [e for e in await c.kms_admin(self.stack).list_audit(since_seq=since)
                if e["principal"] == self.stack.service_principal]

    async def _last_seq(self, c: Customer) -> int:
        entries = await c.kms_admin(self.stack).list_audit()
        return int(entries[-1]["seq"]) if entries else 0

    async def _job(self, c: Customer, job: str) -> dict[str, Any]:
        for _ in range(600):
            r = await self.stack.api.get(f"/tenant/jobs/{job}", headers=c.h())
            if r.status_code == 200 and r.json()["state"] == "done":
                return dict(r.json())
            await asyncio.sleep(0.1)
        raise TimeoutError(job)

    def _db(self, name: str) -> sqlite3.Connection:
        return sqlite3.connect(self.stack.sentinel_data_dir / name)

    # --- chapters -------------------------------------------------------------------------

    async def signup(self, label: str, kind: str) -> Customer:
        s = self.stack
        tenant = f"tour-{label}-{secrets.token_hex(2)}"
        await self.act("customer", f"{kind} '{tenant}' opens an account with its key vault "
                                   "provider and gets an admin signing key")
        admin_key = Ed25519PrivateKey.generate()
        create_account(s.kms_data_dir, tenant, admin_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        c = Customer(tenant, "", {u: secrets.token_urlsafe(18) for u in USERS}, admin_key)
        kms = c.kms_admin(s)
        c.cmk_id = await kms.create_key(f"{tenant} RAG master key")
        await self.act("customer", f"CreateKey → master key {c.cmk_id} (stays in THEIR vault)")
        policy = tenant_key_policy(tenant, s.service_principal)
        await kms.put_key_policy(c.cmk_id, policy)
        await self.act("customer", "PutKeyPolicy → lets our service use the key, but only "
                                   f"when the request says tenant_id={tenant}:")
        self.show(policy.model_dump(mode="json"))
        await self.act("operator", f"we create tenant {tenant} and its users "
                                   "(random passwords, Argon2id hashed):")
        await s.auth.create_tenant(TenantId(tenant))
        for u, scopes in USERS.items():
            await s.auth.create_user(TenantId(tenant), UserId(u), Sensitive(c.passwords[u]),
                                     scopes)
        self.show({u: sorted(x.value for x in sc) for u, sc in USERS.items()})
        await c.login(s)
        r = await s.api.put("/tenant/kms", headers=c.h(),
                            json={"kms_account": tenant, "cmk_id": c.cmk_id})
        await self.act("user", "tenant admin registers the master key with us: "
                               "PUT /tenant/kms")
        await self.act("sentinel", "probe: GenerateDataKey + Decrypt round trip through "
                                   f"the customer's vault → HTTP {r.status_code}")
        await self.check(f"{kind} onboarded with its own key (BYOK probe passed)",
                         r.status_code == 200)
        r = await s.api.put("/tenant/policy", headers=c.h(),
                            json=CLINIC_POLICY.model_dump(mode="json"))
        await self.act("user", "sets the data policy: which fields to tokenize, scan, keep "
                               "(anything else is dropped)")
        self.show({k: v.value for k, v in CLINIC_POLICY.fields.items()})
        return c

    async def ch1_customers(self) -> None:
        await self.chapter(1, "Two new customers sign up",
                           "Bring Your Own Key: each customer keeps the master key; we only "
                           "get permission to use it for their tenant.")
        self.hospital = await self.signup("hospital", "Hospital")
        self.insurer = await self.signup("insurer", "Insurer")
        bad = await self.stack.api.put("/tenant/kms", headers=self.insurer.h(), json={
            "kms_account": self.hospital.tenant, "cmk_id": self.hospital.cmk_id})
        await self.act("attacker", "insurer tries to register the HOSPITAL's master key "
                                   f"as its own → HTTP {bad.status_code}")
        await self.check("the hospital's key policy refuses the insurer", bad.status_code == 503)

    async def ch2_sessions(self) -> None:
        h = self._need(self.hospital)
        await self.chapter(2, "Users log in",
                           "Server-side sessions: many at once, each revocable on its own.")
        laptop = await self._login(h, "analyst")
        agent = await self._login(h, "analyst")
        await self.act("user", "analyst logs in from a laptop and from an AI agent runner "
                               "(two sessions)")
        r = await self.stack.api.get("/auth/sessions",
                                     headers={"authorization": f"Bearer {laptop}"})
        self.show([{k: s[k] for k in ("session_id", "expires_at", "current")} for s in r.json()])
        await self.check("both sessions are live", len(r.json()) == 2)
        await self.stack.api.post("/auth/logout", headers={"authorization": f"Bearer {laptop}"})
        a = await self.stack.api.get("/auth/me", headers={"authorization": f"Bearer {laptop}"})
        b = await self.stack.api.get("/auth/me", headers={"authorization": f"Bearer {agent}"})
        await self.act("user", f"logs out the laptop → laptop HTTP {a.status_code}, "
                               f"agent HTTP {b.status_code}")
        await self.check("logout ends one session, the other keeps working",
                         a.status_code == 401 and b.status_code == 200)
        bad = await self.stack.api.post("/auth/login", json={
            "tenant_id": h.tenant, "username": "analyst", "password": "not-the-password"})
        ghost = await self.stack.api.post("/auth/login", json={
            "tenant_id": h.tenant, "username": "nobody", "password": "not-the-password"})
        await self.act("attacker", f"wrong password → HTTP {bad.status_code}; "
                                   f"unknown user → HTTP {ghost.status_code}")
        await self.check("both look identical (no user enumeration)",
                         bad.status_code == ghost.status_code == 401
                         and bad.json()["error"]["message"] == ghost.json()["error"]["message"]
                         and bad.json()["error"]["code"] == ghost.json()["error"]["code"])
        h.tokens["analyst"] = agent
        await h.login(self.stack, "loader")
        assert self.insurer is not None  # noqa: S101
        await self.insurer.login(self.stack, "analyst")

    async def ch3_store(self) -> None:
        h = self._need(self.hospital)
        await self.chapter(3, "Store patient records",
                           "PII becomes tokens; everything is encrypted with a data key that "
                           "only the customer's master key can unlock.")
        for p in PATIENTS:
            r = await self.stack.api.post("/documents", headers=h.h("loader"), json=p)
            body = r.json()
            self.docs.append(body["doc_id"])
            await self.act("user", f"loader stores {p['fields']['patient_name'][:1]}. "
                                   f"(…) → {body['chunks']} chunk, "
                                   f"{sum(body['tokenized_entities'].values())} PII values "
                                   f"tokenized, {body['dropped_fields']} field dropped")
        self.show({"tokenized_entities (last record)": body["tokenized_entities"]})
        await self.check("3 records stored", len(self.docs) == 3)
        with self._db("keyring.db") as db:
            rows = db.execute("select dek_id, purpose, cmk_version, length(wrapped) from deks "
                              "where tenant_id=? order by purpose", (h.tenant,)).fetchall()
        await self.act("sentinel", "keyring.db holds only WRAPPED data keys (one per purpose):")
        self.show([{"dek_id": d, "purpose": p, "cmk_version": v, "wrapped_bytes": n}
                   for d, p, v, n in rows])
        blob = b"".join(f.read_bytes() for d in (self.stack.sentinel_data_dir,
                                                 self.stack.kms_data_dir)
                        for f in d.rglob("*.db*"))
        found = [v for v in RAW if v.encode() in blob]
        await self.act("attacker", f"a thief copies every database file "
                                   f"({len(blob) // 1024} KiB) and searches for the patients")
        await self.check("no name, SSN, phone, email or MRN is on disk in plain text",
                         not found)

    async def ch4_retrieve(self) -> None:
        h, ins = self._need(self.hospital), self._need(self.insurer)
        await self.chapter(4, "Retrieve", "Authorized users get the original; everyone "
                                          "else gets tokens, 403 or 404.")
        doc = self.docs[0]
        tok = (await self.stack.api.get(f"/documents/{doc}", headers=h.h("analyst"))).json()
        await self.act("user", "analyst reads record 1 (scope: query) → tokenized view:")
        self.show(tok["fields"])
        await self.check("analyst sees tokens, not the SSN", "412-55-7301" not in str(tok))
        orig = (await self.stack.api.get(f"/documents/{doc}?view=original",
                                         headers=h.h())).json()
        await self.act("user", "admin reads the original (scope: reidentify):")
        self.show({k: orig["fields"][k] for k in ("patient_name", "ssn", "dob")})
        await self.check("admin gets the exact original back",
                         orig["fields"] == PATIENTS[0]["fields"])
        d = await self.stack.api.get(f"/documents/{doc}?view=original", headers=h.h("analyst"))
        await self.act("user", f"analyst asks for the original → HTTP {d.status_code}")
        x = await self.stack.api.get(f"/documents/{doc}", headers=ins.h("analyst"))
        await self.act("attacker", f"insurer asks for the hospital's record → HTTP "
                                   f"{x.status_code} (same as 'does not exist')")
        await self.check("raw PII needs permission; other tenants see nothing",
                         d.status_code == 403 and x.status_code == 404)

    async def ch5_query(self) -> None:
        h = self._need(self.hospital)
        await self.chapter(5, "Agentic query across the PHI boundary",
                           "Search only this tenant, mask everything, check it twice, then "
                           "call the external LLM.")
        await self.stack.api.post("/tenant/cache/flush", headers=h.h())
        seq = await self._last_seq(h)
        before = len(await llm_received(self.stack))
        q = {"question": "What does Tobias Lindqvist have, and how do we reach his wife?",
             "top_k": 2, "reidentify": True}
        await self.act("user", f"admin asks: \"{q['question']}\"")
        r = await self.stack.api.post("/query", headers=h.h(), json=q)
        calls1 = len(await self._audit_ops(h, seq))
        sent = (await llm_received(self.stack))[before:]
        await self.act("llm", "this is EVERYTHING the external LLM received:")
        self.show("\n---\n".join(sent[1:]))
        leaked = [v for v in RAW if v in "\n".join(sent)]
        await self.check("no raw PII crossed the boundary", r.status_code == 200 and not leaked)
        await self.act("sentinel", "the answer, with tokens swapped back on OUR side:")
        self.show(r.json()["answer"])
        await self.check("re-identified answer names the right patient",
                         "Tobias Lindqvist" in r.json()["answer"])
        seq = await self._last_seq(h)
        await self.stack.api.post("/query", headers=h.h(), json={**q, "reidentify": False})
        calls2 = len(await self._audit_ops(h, seq))
        await self.act("kms", f"customer's vault was called {calls1}× for the first query "
                              f"(cold cache), {calls2}× for the second")
        await self.check("data-key cache: repeat queries need no KMS calls",
                         calls1 >= 1 and calls2 == 0)

    async def ch6_audit(self) -> None:
        h, ins = self._need(self.hospital), self._need(self.insurer)
        await self.chapter(6, "The customer's view of us",
                           "Every use of their key is in THEIR audit log — allowed or denied.")
        rogue = KmsClient(self.stack.kms, account=h.tenant,
                          principal=self.stack.service_principal,
                          private_key=self.stack.service_key)
        try:
            await rogue.generate_data_key(h.cmk_id, {"tenant_id": ins.tenant,
                                                     "purpose": "vector"})
            denied = False
        except KmsError as exc:
            denied = exc.code == "access_denied"
        await self.act("attacker", "a bug (or insider) in OUR service asks the hospital's "
                                   "key for a data key for the INSURER's tenant")
        await self.check("the customer's vault refuses it (policy condition)", denied)
        entries = await h.kms_admin(self.stack).list_audit()
        await self.act("customer", f"hospital reads its audit log ({len(entries)} entries), "
                                   "last 6:")
        self.show([{"op": e["operation"], "who": e["principal"], "result": e["outcome"],
                    "reason": e["reason"],
                    "tenant_id": e["encryption_context"].get("tenant_id", "")}
                   for e in entries[-6:]])
        await self.check("the denied attempt is on record", any(
            e["outcome"] == "deny" and e["encryption_context"].get("tenant_id") == ins.tenant
            for e in entries))
        await self.check("audit hash chain is intact", await h.kms_admin(self.stack).verify_audit())

    async def ch7_rotate(self) -> None:
        h = self._need(self.hospital)
        await self.chapter(7, "Customer rotates their master key",
                           "New key version; we re-wrap every data key inside the vault. "
                           "No downtime, nothing re-encrypted.")
        v = await h.kms_admin(self.stack).rotate_key(h.cmk_id)
        await self.act("customer", f"RotateKey → master key is now v{v} (v1 can still decrypt)")
        job = (await self.stack.api.post("/tenant/keys/rewrap", headers=h.h())).json()["job_id"]
        await self.act("user", f"admin starts the re-wrap job {job}")
        mid = await self.stack.api.get(f"/documents/{self.docs[1]}?view=original",
                                       headers=h.h())
        result = await self._job(h, job)
        self.show(result)
        with self._db("keyring.db") as db:
            versions = sorted({v for (v,) in db.execute(
                "select cmk_version from deks where tenant_id=?", (h.tenant,))})
        after = await self.stack.api.get(f"/documents/{self.docs[1]}?view=original",
                                         headers=h.h())
        await self.act("sentinel", f"wrapped data keys are now on master key version(s) "
                                   f"{versions}")
        await self.check("every data key moved to the new version", versions == [v])
        await self.check("records readable during and after rotation",
                         mid.status_code == after.status_code == 200)

    async def ch8_contain(self) -> None:
        h, ins = self._need(self.hospital), self._need(self.insurer)
        await self.chapter(8, "Containment after a suspected key leak",
                           "Freeze one tenant, new keys, re-encrypt everything, destroy the "
                           "old keys. Other tenants don't notice.")
        before = (await self.stack.api.get(f"/documents/{self.docs[0]}",
                                           headers=h.h())).json()["fields"]["ssn"]
        with self._db("keyring.db") as db:
            old = {d for (d,) in db.execute("select dek_id from deks where tenant_id=?",
                                            (h.tenant,))}
        job = (await self.stack.api.post("/tenant/contain", headers=h.h())).json()["job_id"]
        await self.act("user", f"admin reports a possible leak → POST /tenant/contain ({job})")
        me = await self.stack.api.get("/auth/me", headers=h.h("analyst"))
        other = await self.stack.api.post("/query", headers=ins.h("analyst"),
                                          json={"question": "anything"})
        await self.act("sentinel", f"hospital sessions revoked (analyst now HTTP {me.status_code});"
                                   f" insurer still served (HTTP {other.status_code})")
        await self.check("blast radius is one tenant",
                         me.status_code == 401 and other.status_code == 200)
        for _ in range(600):
            r = await self.stack.api.post("/auth/login", json={
                "tenant_id": h.tenant, "username": "admin", "password": h.passwords["admin"]})
            if r.status_code == 200:
                h.tokens["admin"] = r.json()["token"]
                break
            await asyncio.sleep(0.1)
        self.show(await self._job(h, job))
        with self._db("keyring.db") as db:
            now = {d for (d,) in db.execute("select dek_id from deks where tenant_id=?",
                                            (h.tenant,))}
        after = (await self.stack.api.get(f"/documents/{self.docs[0]}",
                                          headers=h.h())).json()["fields"]["ssn"]
        await self.act("sentinel", f"SSN token before: {before}")
        await self.act("sentinel", f"SSN token after:  {after}")
        await self.check("old data keys destroyed, new ones in use", not (old & now) and bool(now))
        await self.check("tokens changed (old token key now matches nothing)", before != after)
        ok = await self.stack.api.get(f"/documents/{self.docs[0]}?view=original", headers=h.h())
        await self.check("records still readable after containment", ok.status_code == 200)

    async def ch9_revoke(self) -> None:
        h, ins = self._need(self.hospital), self._need(self.insurer)
        await self.chapter(9, "Customer revokes their key",
                           "The customer's kill switch: disable the master key and the data "
                           "is unreadable — even though it is still on our disk.")
        await h.kms_admin(self.stack).disable_key(h.cmk_id)
        await self.act("customer", f"DisableKey {h.cmk_id}")
        f = await self.stack.api.post("/tenant/cache/flush", headers=h.h())
        await self.act("user", f"POST /tenant/cache/flush → dropped {f.json()['evicted']} "
                               "cached keys now (otherwise within 5 min)")
        gone = await self.stack.api.get(f"/documents/{self.docs[0]}?view=original",
                                        headers=h.h())
        q = await self.stack.api.post("/query", headers=h.h(), json={"question": "asthma"})
        await self.act("sentinel", f"read → HTTP {gone.status_code} "
                                   f"{gone.json()['error']['code']}; query → HTTP {q.status_code}")
        await self.check("crypto-shred: nothing readable while the key is disabled",
                         gone.status_code == 503 and q.status_code == 503)
        other = await self.stack.api.post("/query", headers=ins.h("analyst"),
                                          json={"question": "anything"})
        await self.check("other customers unaffected", other.status_code == 200)
        await h.kms_admin(self.stack).enable_key(h.cmk_id)
        back = await self.stack.api.get(f"/documents/{self.docs[0]}?view=original",
                                        headers=h.h())
        await self.act("customer", f"EnableKey → read HTTP {back.status_code}")
        await self.check("the customer stays in control: re-enable restores access",
                         back.status_code == 200)

    async def ch10_attacks(self) -> None:
        await self.chapter(10, "Four threat actors attack the live system",
                           "Each attack runs for real; the mock LLM obeys every injected "
                           "instruction.")
        outcomes = await attack.run_attacks(self.stack, self.out)
        await self.check(f"{sum(o.defended for o in outcomes)}/{len(outcomes)} attacks defended",
                         all(o.defended for o in outcomes))

    async def ch11_concurrency(self, tenants: int) -> None:
        await self.chapter(11, "Many tenants at the same time",
                           f"{tenants} seeded tenants × 3 users × 2 sessions, "
                           "all querying at once.")
        await seed.seed(self.stack, count=tenants, docs=1)
        r = await simulate.simulate(self.stack, count=tenants, out=self.out)
        for f in r.failures:
            self.out(paint(f"          ✘ {f}", "red"))
        await self.check("every tenant saw only its own data; sessions independent",
                         not r.failures)

    def scoreboard(self, seconds: float) -> bool:
        self.out("")
        self.out(paint("━" * 78, "dim"))
        self.out(paint(" SCOREBOARD", "bold"))
        self.out(paint("━" * 78, "dim"))
        chapters: dict[str, list[bool]] = {}
        for ch, _, passed in self.checks:
            chapters.setdefault(ch, []).append(passed)
        for ch, results in chapters.items():
            good = all(results)
            mark = paint("✔", "green", "bold") if good else paint("✘", "red", "bold")
            self.out(f"  {mark} {ch:<52} {sum(results)}/{len(results)} checks")
        n, total = sum(p for *_, p in self.checks), len(self.checks)
        self.out("")
        line = f"  {n}/{total} checks passed in {seconds:.0f}s"
        self.out(paint(line, "green" if n == total else "red", "bold"))
        for ch, claim, passed in self.checks:
            if not passed:
                self.out(paint(f"  ✘ {ch}: {claim}", "red"))
        return n == total


async def run_tour(stack: Stack, out: Callable[[str], None] = print, delay: float = 0.0,
                   tenants: int = 10) -> bool:
    t = Tour(stack, out, delay)
    start = time.monotonic()
    out(paint("Sentinel Vault — hands-free tour", "bold"))
    out(paint("BYOK envelope encryption + PHI protection for an agentic RAG system. "
              "Every line below is a real call to the running services.", "dim"))
    out("")
    out("  actors:  " + "  ".join(paint(a, s, "bold") for a, s in ACTOR_STYLE.items()
                                  if a != "kms") + paint("   (kms = the customer's vault)", "dim"))
    out(paint("  tokens look like <<PERSON_…>> (magenta); key / record ids are cyan", "dim"))
    await t.pause(2)
    await t.ch1_customers()
    await t.ch2_sessions()
    await t.ch3_store()
    await t.ch4_retrieve()
    await t.ch5_query()
    await t.ch6_audit()
    await t.ch7_rotate()
    await t.ch8_contain()
    await t.ch9_revoke()
    await t.ch10_attacks()
    await t.ch11_concurrency(tenants)
    return t.scoreboard(time.monotonic() - start)


async def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="run.sh tour")
    p.add_argument("--fast", action="store_true", help="no pauses between steps")
    p.add_argument("--delay", type=float, default=1.0, help="seconds per beat (default 1.0)")
    p.add_argument("--transcript-dir", type=Path, default=Path(".run"))
    a = p.parse_args(argv)
    a.transcript_dir.mkdir(parents=True, exist_ok=True)
    path = a.transcript_dir / f"tour-{time.strftime('%Y%m%d-%H%M%S')}.log"
    with path.open("w") as fh:
        def out(line: str) -> None:
            print(line, flush=True)
            fh.write(_ANSI.sub("", line) + "\n")
            fh.flush()

        async with live_stack() as stack:
            passed = await run_tour(stack, out, 0.0 if a.fast else max(a.delay, 0.0))
        out(paint(f"\n  transcript: {path}", "dim"))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(_main()))
    except KeyboardInterrupt:
        print("\ntour stopped")
        raise SystemExit(130) from None
    except Exception as exc:  # noqa: BLE001 - top-level CLI message
        print(paint(f"[fail] tour crashed: {type(exc).__name__} — see ./run.sh logs",
                    "red"), file=sys.stderr)
        raise SystemExit(1) from None
