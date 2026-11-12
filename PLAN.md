# Sentinel Vault — POC Plan (v2: BYOK for agentic RAG)

## 0. What changed from v1

v1 proved envelope encryption for generic records under a key we own.
v2 puts the same envelope scheme behind **customer-owned keys (BYOK)** and applies it to
the two hot spots in a RAG stack: the **vector store** (embeddings + chunk text) and the
**tokenization vault** (PII token -> original value).

Store / Retrieve / Process still exist, mapped to RAG:

| Required op | RAG form |
|---|---|
| Store | `POST /ingest` — chunk, embed, encrypt, write to vector store |
| Retrieve | `GET /documents/{id}` — authorized tenant gets original text back |
| Process | `POST /query` — retrieve top-k, decrypt, mask PII, send to (mock) LLM, re-identify answer |

## 1. Scope

**Hard requirement R0: one command to set up, one command to test.** A reviewer with only
Python 3.12 runs `./run.sh` and gets every service up, 10 tenants seeded, and a passing
smoke test. `./run.sh test` proves every claim below. Details in §18.

| # | Property | Depth |
|---|---|---|
| F1 | Tenant isolation + encryption context | Full. Per-tenant index + KMS policy condition + AAD |
| F2 | Key rotation without downtime | Full. Workspace DEK rotation + CMK rotation, resumable re-wrap |
| F3 | Compromise containment | Full. Customer revokes CMK = crypto-shred kill switch; we contain a leaked DEK |
| F4 | PHI/PII detection & scrubbing | Full. At ingest (tokenize) and at LLM egress (verify), fail closed |
| F5 | Leakage prevention | Full. Logs, errors, LLM/outbound calls |
| F6 | Persistence + key protection | Full. Vector store, vault and customer KMS are separate stores |
| X1 | Reversible tokenization vault | Extension, encrypted under the customer CMK |
| X2 | Audit trail | Extension. KMS side logs every call (like CloudTrail) so the customer can audit us |

Cut on purpose:
- **Real AWS KMS by default.** A simulated customer KMS ships as its own service. An
  `AwsKmsProvider` (cross-account key policy) is an optional adapter, not the test path.
- **Encrypted ANN search** (homomorphic / SSE). Research-grade, slow. See §5 for what we do instead.
- **A real vector DB product.** Once vectors are encrypted at rest, the DB can't search them.
  A typed SQLite store of encrypted blobs is honest about that.
- **Memory zeroing guarantees.** Python can't promise it. Best effort only (§6).
- Docker untested (not installed here). Native `make up` is the supported path.

## 2. Components and trust domains

```
 ┌──────── Customer trust domain (one per tenant) ────────┐
 │  Customer KMS (FastAPI, port 8100)                     │
 │   - CMK material (never leaves)                        │
 │   - Key policy (JSON, resource-based)                  │
 │   - Audit log of every GenerateDataKey / Decrypt       │
 └───────────────▲────────────────────────────────────────┘
                 │ signed request (service identity + encryption context)
 ┌───────────────┴──────── Our trust domain ──────────────┐
 │  Sentinel API (FastAPI, port 8000)                     │
 │   api/ -> service/ -> crypto/ (AES-GCM, DEK cache)     │
 │        -> privacy/ (Presidio, tokenizer, egress guard) │
 │        -> persistence/ (vector.db, vault.db)           │
 │   Mock LLM (port 8200) — the "external system"         │
 └────────────────────────────────────────────────────────┘
```

Separation of duties: our process holds **no** key material at rest. Steal `vector.db` +
`vault.db` and you have only ciphertext and DEKs wrapped by keys you can't reach.

## 3. Onboarding — the cross-account handshake (simulated)

1. Tenant admin calls customer KMS `CreateKey` -> `cmk_id`.
2. Tenant admin attaches a key policy:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "sentinel-ingest-svc",
    "Action": ["GenerateDataKey", "Decrypt"],
    "Condition": {"StringEquals": {"EncryptionContext:tenant_id": "acme"}}
  }]
}
```

3. Tenant registers `cmk_id` with us. We do a **probe**: GenerateDataKey + Decrypt round trip.
   Fail = onboarding rejected.
4. Our service identity = Ed25519 key pair. Every KMS call is signed over
   (method, path, body hash, timestamp, nonce). KMS rejects bad signature, skew > 60 s, or
   replayed nonce. This stands in for SigV4.

Why the `tenant_id` condition matters: even if a bug in our code sends tenant B's
wrapped DEK under tenant A's request, A's CMK policy refuses it. Isolation is enforced
**outside** our code.

## 4. Key hierarchy

```
Customer CMK (in customer KMS, per tenant, versioned)
  └─ Workspace DEK  (AES-256, one active per tenant+workspace, rotated by age/use count)
       └─ Chunk record = AES-GCM(text ‖ embedding), nonce 96-bit random
Customer CMK
  └─ Vault DEK      (separate DEK + separate context purpose="vault")
       └─ Token entry = AES-GCM(original PII value)
```

- **Encryption context** sent to KMS (bound into the wrapped DEK):
  `{tenant_id, workspace_id, purpose: "vector"|"vault", dek_id}`
- **AAD** on each chunk: `{tenant_id, workspace_id, doc_id, chunk_id, dek_id, schema_v}`
  Moving a chunk to another row, doc or tenant breaks decryption.
- Nonce reuse risk with a shared DEK: random 96-bit nonces are safe up to ~2^32 messages.
  We rotate the workspace DEK at **1M chunks or 24 h**, far below that bound.

Why workspace-level DEK, not per-chunk: 50 chunks per query = 1 KMS Decrypt instead of 50.
Same idea as S3 Bucket Keys. Cost: one DEK leak exposes a whole workspace epoch, not one chunk.
We accept that and contain it with rotation (§8).

## 5. Write path (ingest)

```
doc -> chunk -> PII tokenize (Presidio) -> embed (on tokenized text)
    -> get active workspace DEK (cache, or KMS GenerateDataKey)
    -> AES-GCM encrypt {text, embedding} with AAD
    -> write row {ids, dek_id, wrapped_dek_ref, nonce, ct}
    -> plaintext buffers wiped (best effort)
```

Decision: **tokenize before embedding.** The embedding and stored text never contain raw PII,
so even a decrypted chunk only shows `<PERSON_7f3a>`. Embedding inversion attacks recover
tokens, not names. Cost: semantic search on names is weaker. Accepted.

## 6. Read path (agent query)

The vector store can't rank encrypted vectors. So:

```
query -> authN -> tenant_id (from credential only)
  -> load that tenant's rows only (separate table/partition per tenant)
  -> group by dek_id -> one KMS Decrypt per distinct DEK (cache hit = zero calls)
  -> decrypt embeddings into a per-tenant in-memory index (numpy, cosine)
  -> top-k chunks -> decrypt text
  -> egress guard: re-scan for PII, fail closed -> mock LLM
  -> answer -> re-identify tokens only if caller has the "reidentify" scope
```

**DEK cache** (like the AWS Encryption SDK caching CMM):
- Key = `(tenant_id, dek_id)`. Value = plaintext DEK in a `bytearray`.
- Limits: TTL 5 min, max 10k uses, max entries per tenant. Whichever hits first evicts.
- Evict = overwrite the bytearray with zeros, then drop.
- The decrypted in-memory index shares the same TTL and is dropped with the DEK.
- **Revocation latency = cache TTL.** If the customer revokes, we keep working for up to 5 min.
  This is the core trade-off. TTL is a per-tenant setting so a strict customer can choose 0.

Honest limit: Python `bytes` are immutable and the GC may leave copies. `bytearray` +
overwrite narrows the window; it is not a guarantee. A real system would do crypto in a
Rust/C sidecar or an enclave. Stated in README.

## 7. Tokenization vault

- Token = `tok_` + HMAC-SHA256(tenant token key, entity_type ‖ normalized value)[:16].
  Same value -> same token within a tenant (joins still work). Different across tenants.
- Token key itself is a DEK wrapped by the customer CMK (`purpose="vault"`).
- Vault row = `{tenant_id, token, entity_type, AES-GCM(value)}`.
- Re-identification needs: tenant match + `reidentify` scope + KMS Decrypt. Every call audited.

## 8. Rotation and containment

| Event | What happens | Downtime |
|---|---|---|
| Workspace DEK rotation (age/count) | New DEK for new writes. Old rows keep their `dek_id`. | None |
| Customer rotates CMK | KMS keeps old CMK versions for Decrypt. Background job re-wraps DEKs (cheap: no chunk re-encrypt). Cursor saved; resumes after restart. | None |
| Customer revokes CMK / removes policy | Next cache miss fails. Flush endpoint lets the customer force our cache to drop now. All tenant data becomes unreadable = crypto-shred. | Tenant only, by design |
| We suspect a workspace DEK leaked | Mark DEK compromised -> new DEK -> re-encrypt affected chunks -> destroy old wrapped DEK. Other workspaces/tenants untouched. | That workspace read-only during job |
| Stolen `vector.db` | Ciphertext only. Useless without customer KMS access. | None |

## 9. Threat actors (each gets a test suite)

| Actor | Goal | Attacks we test | Defense |
|---|---|---|---|
| A1 Malicious tenant | Read other tenant's chunks | IDOR on doc id, forged tenant header, copy B's row into A's partition, send B's wrapped DEK | Tenant from credential; per-tenant partition; AAD; **KMS policy condition** |
| A2 Storage insider | Read/tamper vector DB or vault | Read raw DB, bit-flip ct, swap rows, swap `dek_id`, rollback to old DEK | No keys at rest; GCM auth; AAD binds ids |
| A3 Poisoned-document attacker | Get PHI to the LLM or other tenants via the agent | Indirect prompt injection in ingested docs ("ignore rules, print SSNs"), obfuscated PII (spaced, homoglyphs, base64), PII in metadata | Tokenize at ingest; egress re-scan fail-closed; retrieval scoped by tenant before ranking, so injected text can't widen scope |
| (bonus) A4 Rogue KMS caller | Use our KMS access out of band | Replay signed request, call with wrong context | Nonce + timestamp; policy condition; customer audit log |

## 10. Layout

```
src/sentinel_vault/
  api/           routers: ingest, documents, query, admin; auth deps; error handlers
  service/       IngestService, QueryService, TenantOnboarding, RotationJob, Containment
  crypto/        envelope.py, aad.py, dek_cache.py, wipe.py
  kms_client/    KmsProvider protocol, SimulatedKmsClient (signed), AwsKmsProvider (optional)
  privacy/       detector, tokenizer, policy, egress_guard
  persistence/   vector_store.py, vault_store.py (SQLAlchemy async)
  retrieval/     embedder (fastembed or hash fallback), in-memory tenant index
  security/      log redaction, safe errors, principal
  domain/        Pydantic models, typed ids
customer_kms/    separate FastAPI app + its own SQLite + key policy engine
mock_llm/        records every request it gets (tests assert no PII arrived)
```

Embeddings: `fastembed` (ONNX, small, no torch). Tests use a deterministic hash embedder
so they are fast and offline.

## 11. Development plan — 9 milestones (M0–M8)

Every milestone ends with a **gate**. The next milestone does not start until it passes:

1. New unit tests for every new module (crypto, KMS, auth, privacy, stores, services).
2. Coverage of new code >= 85% (`pytest --cov`, branch coverage).
3. `./run.sh verify` green: `ruff` + `mypy --strict` + all tests so far (no regressions).
4. Fresh-clone check: `./run.sh reset && ./run.sh && ./run.sh test` passes.
5. One commit (or a few) per milestone on the feature branch.
6. After every **two** milestones: write `docs/summary-mX-mY.md` (what happened, decisions,
   code changes, what works now, open points) and commit it.

| M | Name | Builds | Unit tests (what they prove) |
|---|---|---|---|
| M0 | Bootstrap | `run.sh` (setup/test/verify/stop/reset), Makefile, settings (pydantic-settings), `.secrets/` key generation, health endpoints | Settings load + reject bad values; key files created 0600; `run.sh` twice = no change |
| M1 | Foundation | Domain models + typed ids, `Sensitive[T]` wrapper, log redaction processor, safe error handler, correlation ids | Redactor strips PHI from logs; `repr(Sensitive)` = `***`; forced exception with PHI gives generic body + no PHI in logs |
| M2 | Auth + sessions | `auth.db`, Argon2id users, login/logout/logout-all/list, idle + absolute expiry, 10-session cap, backoff, tenant principal dependency | Hash-only token storage; expiry; cap evicts oldest; logout one keeps others; tampered/expired/revoked = same 401; concurrent logins (asyncio.gather) |
| M3 | Customer KMS | Separate FastAPI app; per-customer DB + root key; CreateKey, PutKeyPolicy, GenerateDataKey, Decrypt, ReEncrypt, RotateKey, DisableKey, ScheduleDeletion, audit log; Ed25519 request signing | Policy engine allow/deny incl. `tenant_id` condition; bad sig / replayed nonce / clock skew rejected; wrong context fails Decrypt; old version decrypts after rotate; disabled key refuses all; every call audited (A4) |
| M4 | Envelope crypto | AES-256-GCM envelope, canonical AAD, DEK cache (TTL/uses/zeroing), `KmsProvider` protocol + signed client, `deks` table, per-workspace lock | Round trip; bit-flip in ct/nonce/tag fails; AAD swap (tenant/doc/chunk/dek_id) fails; cache hit = 0 KMS calls; TTL + use-count eviction zeroes buffer; concurrent first-writes make one DEK (A2) |
| M5 | Ingest + vault | Chunker, PII detector (Presidio + custom recognizers), tokenizer (HMAC), vault store, hash + fastembed embedders, vector store (per-tenant partition), `POST /ingest`, `GET /documents/{id}` | Detects names/SSN/MRN/DOB/phone/email in text + structured fields; unknown fields dropped; same value = same token per tenant, different across tenants; stored chunk has no raw PII; tenant B can't read A's doc by id or row copy (A1) |
| M6 | Query + egress | Per-tenant in-memory index, `POST /query`, egress guard, mock LLM, re-identify with scope | Retrieval never returns other tenant's chunks; obfuscated PII (spaced, homoglyph, base64, nested JSON) caught or request fails closed; prompt-injection doc can't widen scope; mock LLM log has zero PII; re-identify needs scope (A3) |
| M7 | Rotation + containment | Rotation worker (DEK roll, CMK re-wrap via ReEncrypt, cursor), containment (freeze, re-encrypt, revoke sessions), cache flush, revoke/crypto-shred | Old + new records readable mid-rotation; kill worker mid-batch, restart, resumes and finishes; CAS prevents double re-wrap; compromised DEK gone after re-encrypt; disabled CMK = data unreadable; other tenants unaffected |
| M8 | Simulation + reviewer kit | Seed 10 customers (personas, Faker docs, users), concurrent simulator, `./run.sh attack` report, `./run.sh demo`, `scripts/client.py`, README (scope, decisions, threat model, migration, AI usage, claim→test map), Dockerfile + compose | Seed idempotent; 10 tenants × 3 users × 2 sessions concurrent ingest/query with no cross-tenant reads; attack runner exits non-zero on any failed defense |

Test layout:

```
tests/
  unit/<module>/test_*.py      fast, no I/O beyond temp SQLite, no network
  integration/test_*.py        ASGI in-process clients, KMS + API + mock LLM wired together
  attacks/test_a1..a4_*.py     one file per threat actor
  conftest.py                  temp dirs, random ports, hash embedder, seeded tenants
```

Integration tests start at M3 (KMS app) and grow each milestone. Attack tests land in the
milestone that builds the defense (A4 in M3, A2 in M4, A1 in M5, A3 in M6).

## 12. Least-sure calls

1. **DEK cache TTL vs revocation.** 5 min default means a revoked customer is not cut off at once.
   Mitigated by the flush endpoint and per-tenant TTL. Still a real gap.
2. **Decrypt-then-rank in memory.** Fine for 10 tenants x thousands of chunks. Does not scale to
   millions without per-tenant sharded workers holding hot indexes, which widens the plaintext window.
3. **Tokenize-before-embed** hurts recall on name-based queries.

## 13. Services

| Service | Port | Owner | Job |
|---|---|---|---|
| Sentinel API | 8000 | Us | Login, sessions, ingest, query, get document, admin |
| Rotation worker | — | Us | Re-wrap / re-encrypt jobs. Resumes after a crash |
| Customer KMS | 8100 | Customer | CMKs, key policy, audit log |
| Mock LLM | 8200 | External | Records every request it gets |
| Customer simulator | CLI | Test | Plays the 10 customers |
| Attacker suite | pytest | Test | Plays the 3 attackers |

| Store | Owner | Holds |
|---|---|---|
| `vector.db` | Us | Encrypted chunks, wrapped DEKs, rotation cursors |
| `vault.db` | Us | Encrypted token -> PII entries |
| `auth.db` | Us | Users (password hashes), sessions (token hashes) |
| `kms_<customer>.db` + root key file | Customer | CMKs, policy, audit log |

Our process never reads customer KMS files.

## 14. Customer simulation

One Customer KMS process hosts one **account per customer**. Each account has its own DB
file and its own root key file (mode 0600).

Identities per customer:

| Identity | Can do |
|---|---|
| Customer admin key (Ed25519) | CreateKey, PutKeyPolicy, RotateKey, DisableKey, ScheduleDeletion, ReadAudit |
| Our service key (Ed25519) | Only what that customer's policy allows: GenerateDataKey, Decrypt, ReEncrypt |
| Tenant users (password login) | Sentinel API with scopes `ingest`, `query`, `reidentify`, `admin` |

Seed: 10 customers (hospital, insurer, pharmacy, bank, law firm, ...), ~50 synthetic
documents each with PHI/PII from `Faker`, 2–5 users per customer.

Customer personas:

| Persona | Behavior |
|---|---|
| Normal | Ingest + query |
| Strict | DEK cache TTL = 0 |
| Rotator | Rotates its CMK mid-run |
| Leaver | Disables its CMK = crypto-shred |

The simulator runs all 10 at once, with several users per customer logged in at the same
time. Tests assert one customer's rotate or revoke never affects another.

## 15. Customer KMS operations

Every call passes the same gate:

```
verify signature -> timestamp skew <= 60 s + unused nonce -> policy (principal, action, EncryptionContext:tenant_id)
  -> key enabled -> do work -> append audit entry
```

| Op | Does | Returns to caller |
|---|---|---|
| `CreateKey` | 32 random bytes = CMK v1, stored wrapped by the account root key | `cmk_id` |
| `GenerateDataKey(cmk, ctx)` | New random 32-byte DEK, AES-GCM sealed under active CMK version, AAD = canonical `ctx` | plaintext DEK + wrapped blob |
| `Decrypt(blob, ctx)` | Reads version from blob, opens it. Wrong `ctx` fails | plaintext DEK |
| `ReEncrypt(blob, ctx)` | Opens with old version, seals with active version, inside KMS | new wrapped blob (no plaintext) |
| `RotateKey` | Adds version N+1 as active. Old versions stay decrypt-only | new version |
| `DisableKey` | All further calls fail | — |
| `ScheduleDeletion(7d)` | Destroys key material after window | — |

Wrapped blob = `{cmk_id, cmk_version, nonce, ciphertext}`. `ctx` =
`{tenant_id, workspace_id, purpose, dek_id}`.

`ReEncrypt` lets us rotate without the plaintext DEK ever visiting our process.

## 16. Our DEK lifecycle and rotation

Table `deks` in `vector.db`:

```
dek_id | tenant | workspace | purpose | wrapped_blob | cmk_version | uses | created | state
                                                                         active | retired | compromised
```

Write:

```
active DEK for (tenant, workspace)?
  ├─ none, or > 1M uses / 24 h -> GenerateDataKey -> insert row -> cache plaintext
  └─ found -> cache hit ? use : Decrypt -> cache
AES-GCM encrypt chunk, AAD = {tenant, workspace, doc, chunk, dek_id}
insert chunk with dek_id
```

A per-(tenant, workspace) asyncio lock stops two concurrent ingests creating two DEKs.

Read:

```
load this tenant's chunks -> distinct dek_ids (usually 1–2)
  -> one Decrypt per dek_id (0 on cache hit)
  -> decrypt embeddings -> rank -> decrypt top-k text -> PII egress check -> LLM
```

Cache: key `(tenant, dek_id)`, evict at 5 min or 10k uses, whichever first. Evict =
zero the `bytearray`. Customer flush endpoint clears it at once.

Rotation cases:

| Case | Trigger | Steps | Chunks rewritten? |
|---|---|---|---|
| DEK roll | 1M uses or 24 h | New DEK; old DEK `retired`; old chunks keep old `dek_id` | No |
| Customer rotates CMK | `RotateKey` | Worker finds DEKs with old `cmk_version` -> `ReEncrypt` -> `UPDATE ... WHERE wrapped_blob = old` | No |
| DEK compromised | Admin marks `compromised` | Freeze workspace writes -> new DEK -> decrypt + re-encrypt each chunk -> delete old wrapped DEK | Yes |
| Customer leaves | `DisableKey` | Next cache miss fails; flush makes it immediate; data is crypto-shredded | No |

Crash safety: every row change is one compare-and-swap. A cursor is saved per batch.
On restart the worker resumes from the cursor and skips rows already done. Reads work
throughout because each row names its own `dek_id` and `cmk_version`.

Test: kill the worker mid-batch, restart, every chunk still decrypts, job completes.

## 17. Users, login and concurrent sessions

Requirement: many users, across tenants, log in at the same time and each can hold
several live sessions (e.g. laptop + agent runner).

Design: **server-side opaque sessions**, not JWTs, because we need instant revocation
(logout, tenant freeze, compromise).

| Item | Choice |
|---|---|
| Password storage | Argon2id (`argon2-cffi`) |
| Login | `POST /auth/login` -> session token (32 random bytes, base64url) |
| Token at rest | Only SHA-256(token) stored in `auth.db`. Stolen DB can't replay sessions |
| Session row | `{session_hash, user_id, tenant_id, scopes, created, last_seen, expires, revoked}` |
| Lifetime | Idle timeout 30 min, absolute 12 h |
| Concurrency | Up to 10 live sessions per user. 11th login evicts the oldest |
| Logout | `POST /auth/logout` (this session), `POST /auth/logout-all` (all of the user's) |
| List | `GET /auth/sessions` — user sees their own sessions |
| Revocation hooks | Tenant freeze, user disable, or containment -> revoke all tenant sessions |
| Brute force | Per-user + per-IP failed-login backoff; generic "invalid credentials" error |
| Transport | `Authorization: Bearer <token>`; never logged (redaction processor) |

Tenant identity comes **only** from the session row. Any `tenant_id` in a path, body or
header is ignored or must match, else 404 (not 403, so ids aren't confirmed to exist).

Tests:
- 10 tenants × 3 users × 2 sessions each, all running ingest/query concurrently.
- Session of tenant A can never read tenant B data.
- Logout of one session leaves the user's other sessions working.
- Tenant freeze kills all that tenant's sessions; other tenants unaffected.
- Expired / revoked / tampered tokens rejected with the same generic 401.

## 18. Reviewer experience (R0)

Goal: a reviewer clones the repo, runs one command, and can see and test everything.

Only prerequisite: **Python 3.12** (macOS or Linux). No Docker, AWS account, or API keys.

| Command | What it does | Time target |
|---|---|---|
| `./run.sh` | Setup (if needed) + seed + start all services + smoke test + print login info | < 5 min first run, < 20 s after |
| `./run.sh test` | Full test suite incl. all attacker suites, no services needed | < 2 min |
| `./run.sh attack` | Runs A1–A4 against the live services, prints a pass/fail report | < 1 min |
| `./run.sh demo` | Guided walkthrough: ingest, query, rotate, revoke, contain, with output per step | < 1 min |
| `./run.sh stop` | Stops all services | — |
| `./run.sh reset` | Stops services, deletes all DBs, keys and seed data, keeps the venv | — |
| `./run.sh verify` | `ruff` + `mypy --strict` + full tests (what CI would run) | < 3 min |

`make <same-name>` targets wrap `run.sh` for people who prefer make.

What `./run.sh` does, in order:

```
check python3.12 -> create .venv (uv if present, else venv+pip) -> install pinned deps
  -> download spaCy model (once, cached) -> generate service + customer keys into .secrets/ (0600)
  -> create 10 customer KMS accounts + CMKs + key policies -> onboarding probe per tenant
  -> create users -> ingest synthetic docs -> start KMS :8100, mock LLM :8200, API :8000, worker
  -> wait for /health on each -> run smoke test -> print table of tenants, users, passwords, URLs
```

Rules that make it work:
- **Idempotent.** Running `./run.sh` twice changes nothing and does not reseed.
- **Pinned deps.** `requirements.lock` generated from `pyproject.toml`; install uses it.
- **Offline tests.** Tests use a hash embedder and in-process ASGI clients, temp dirs and
  random ports. No network, no shared state, safe to run in parallel.
- **No secrets in the repo.** All keys generated locally on first run into `.secrets/`
  (gitignored). Seed passwords are random and printed once, plus written to
  `.secrets/reviewer-credentials.txt`.
- **Loopback only.** Every service binds `127.0.0.1`.
- **Clear failures.** Each step prints `[ok]` or `[fail] <what> — <how to fix>`. Logs in
  `.run/logs/<service>.log`.
- **Explore by hand.** Swagger UI at `http://127.0.0.1:8000/docs` and `:8100/docs`.
  `scripts/client.py` is a tiny CLI (`login`, `ingest`, `query`, `rotate`, `revoke`).
- **Claim → test map.** README table links every security claim to the test that proves it.

Optional second path: `docker compose up` (Dockerfile + compose shipped). Not tested on
the author's machine (no Docker), stated in README. The native path is the supported one.

Acceptance check for R0: on a fresh clone in a new folder, `./run.sh && ./run.sh test &&
./run.sh attack` passes with no manual steps.
