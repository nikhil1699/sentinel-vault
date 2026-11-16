# Sentinel Vault

A multi-tenant security layer for agentic RAG. Customers keep their own master key (BYOK).
We store their documents, embeddings and PII vault encrypted under that key, retrieve them
for authorized users, and send only de-identified context to an external LLM.

## Quick start

Only prerequisite: **Python 3.12** (macOS or Linux). No Docker, AWS account or API keys.

```bash
./run.sh            # install, start 3 services, seed 10 tenants, smoke test (~2 min first run)
./run.sh customer new my-clinic   # then follow docs/TRY-IT-YOURSELF.md (copy-paste curl)
./run.sh tour       # the whole project end to end, narrated + checked; Enter between chapters
                    #   --auto hands-free, --fresh starts from zero (setup included), --fast no pauses
./run.sh demo       # 13-step walkthrough: BYOK → store → retrieve → query → rotate → contain → revoke
./run.sh attack     # 4 threat actors, 11 live attacks, pass/fail table; exits 1 on any breach
./run.sh simulate   # 10 tenants × 3 users × 2 sessions querying at once; checks isolation
./run.sh test       # 398 tests (unit, integration, attack suites), no services needed
./run.sh verify     # ruff + mypy --strict + tests + coverage gate (≥ 85%, currently ~97%)
./run.sh logs       # follow all service logs, readable (already redacted)
./run.sh stop       # stop services        ./run.sh reset   # delete all data and keys
```

Output: every setup step is numbered with elapsed time (`[3/8] Python packages (+12s)`),
long steps show a spinner, the demo explains each step ("what's happening" / "✔ proves")
and `./run.sh demo --pause` waits for Enter between steps — good for presenting.
Add `--verbose` to any command for full pip / spaCy / pytest output. Colors turn off
when output is piped or `NO_COLOR=1` is set.

Logins for the seeded tenants: `.secrets/reviewer-credentials.txt`.
Swagger: [API](http://127.0.0.1:8000/docs) · [Customer KMS](http://127.0.0.1:8100/docs) ·
[Mock LLM](http://127.0.0.1:8200/docs). Everything binds `127.0.0.1` only.

Try it by hand (replace the password from the credentials file):

```bash
TOKEN=$(curl -s localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"tenant_id":"st-marys-hospital","username":"admin","password":"<pw>"}' | jq -r .token)
curl -s localhost:8000/query -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"question":"Who was seen for asthma?","reidentify":true}' | jq
curl -s localhost:8200/v1/received | jq   # what the "external" LLM actually got
```

## 1. What I built, and what I cut

| Built | Depth |
|---|---|
| Tenant isolation + encryption context | Tenant only from the session; every store query tenant-scoped; AAD binds tenant/doc/chunk/DEK; the **customer's** key policy enforces `tenant_id` |
| Key rotation without downtime | Customer rotates CMK → resumable `ReEncrypt` job (CAS + cursor); survives crash + restart; reads work throughout |
| Compromise containment | Freeze tenant → re-key → re-tokenize → re-encrypt + re-embed → destroy old keys; resumable; one tenant only |
| PHI/PII detection and scrubbing | Presidio + custom recognizers on normalized text; per-tenant field allowlist; tokenize before embedding; fails closed |
| Leakage prevention | Message-free exception logs, key + pattern log redaction, fixed error bodies, 3-layer egress guard, sealed `CleanPrompt` type |
| Persistence + key protection | 4 separate SQLite stores (0600, `secure_delete`), keys only in the customer KMS; no key material at rest on our side |
| Extensions | Reversible tokenization vault · hash-chained KMS audit log · multi-session login · BYOK onboarding probe |

| Cut | Why |
|---|---|
| Real HSM / AWS KMS | Reviewers must run it with no account. The `KmsProvider` protocol is the seam for an AWS adapter |
| Encrypted ANN search | Research-grade and leaks access patterns. We decrypt one tenant's vectors in memory and rank there |
| Semantic embeddings by default | Default hash embedder is offline and fast. `SV_EMBEDDER=fastembed` switches to `bge-small` |
| Per-tenant cache TTL | Global `SV_DEK_CACHE_TTL_SECONDS` (0 = no cache). Per-tenant would be a policy field |
| Docker | Services refuse non-loopback binds by design; a container needs `0.0.0.0`. I chose the stricter default and a native one-command setup over an untested container |
| Memory-zeroing guarantees | Python can't promise it. `bytearray` + `memset` is best effort (see §3) |
| Public signup API | Tenants/users are created by an operator path, like a real B2B onboarding |

## 2. Architecture

```
 Customer trust domain (one account per customer)            External (untrusted)
 ┌──────────────────────────────────────────┐                ┌──────────────────┐
 │ Customer KMS :8100                       │                │ Mock LLM :8200   │
 │  CMK versions (sealed by account root)   │                │ records every    │
 │  key policy  · audit chain · nonces      │                │ request it gets  │
 └──────────▲───────────────────────────────┘                └────────▲─────────┘
            │ Ed25519-signed GenerateDataKey / Decrypt / ReEncrypt     │ CleanPrompt only
            │ + encryption context {tenant_id, workspace, purpose, dek}│
 ┌──────────┴──────────────────── Our trust domain ───────────────────┴─────────┐
 │ Sentinel API :8000                                                           │
 │  api/ (authz boundary) → service/ → crypto/ (AES-GCM, DEK cache) → persistence│
 │  privacy/ (detector, policy, egress guard)   retrieval/ (chunk, embed)        │
 │  auth.db   keyring.db (wrapped DEKs, jobs)   vector.db (ciphertext)   vault.db│
 └──────────────────────────────────────────────────────────────────────────────┘
```

**Store:** record → field policy → detect PII (normalized) → tenant HMAC tokens →
vault (encrypted originals) → original + tokenized doc (DOCUMENT DEK) → chunk tokenized
text → embed → encrypt chunks (VECTOR DEK) → one transaction.

**Retrieve:** session → tenant → tenant-scoped row → KMS Decrypt (or cache) → AES-GCM open
with AAD. Original view needs scope `reidentify`.

**Process:** tokenize PII in the question → load **only this tenant's** chunks → one Decrypt
per DEK → rank in memory → egress guard → LLM → optional local re-identification.

### Key hierarchy

```
Customer account root key (file 0600, KMS only)
 └─ CMK v1..vN            sealed at rest, never leaves the KMS
     └─ DEK per (tenant, workspace, purpose)   wrapped by CMK, context-bound, rolled at 1M uses / 24 h
         ├─ document: original + tokenized JSON   AAD {tenant, ws, dek, doc, kind}
         ├─ vector:   tokenized chunk + embedding AAD {..., chunk, seq}
         ├─ vault:    token → original value      AAD {..., token, entity}
         └─ tokenkey: HMAC key for tokens (stable; replaced only on containment)
```

Workspace-level DEKs work like S3 Bucket Keys: 50 chunks cost one KMS call, a warm query
costs zero. The price is a bigger blast radius per DEK, which rotation and containment bound.

## 3. Key decisions

| Decision | Reason |
|---|---|
| BYOK with an encryption-context **policy condition** | Even a bug in our code can't unwrap tenant B's DEK with tenant A's request: the customer's KMS refuses |
| `ReEncrypt` for rotation | DEKs move to the new CMK version without plaintext keys reaching us |
| Tokenize **before** embedding | Embedding-inversion attacks recover tokens, not names |
| Deterministic per-tenant tokens (HMAC) | Same person → same token, so retrieval and joins work; no linkage across tenants |
| Three egress layers, last one **blocks** | NER is probabilistic; an independent regex backstop turns a miss into a refused request, not a leak |
| Opaque server-side sessions, hash-only storage | Instant revocation for logout, freeze and containment; stolen `auth.db` can't be replayed |
| Same 404 for "not yours" and "doesn't exist" | No cross-tenant existence oracle |
| Never log exception messages | Messages carry data; regex can't spot names. Type + `file:line` is enough to debug (it found the M5 bug) |

**How this compares to large providers.** AWS KMS runs one shared, HSM-backed multi-tenant
service: a shared domain key protects per-key backing keys, and tenants are separated by
account, key policy and encryption context. Our simulated KMS gives each customer its own
folder, root key and DB, closer to a dedicated store (CloudHSM / External Key Store).
Our own side follows the shared model, like Slack EKM: one data store, partitioned per
tenant, encrypted under each customer's key.

**Least sure about:**

1. **DEK cache TTL vs revocation.** Default 5 min means a customer's disable bites after up
   to 5 minutes unless they call `/tenant/cache/flush`. Strict customers want 0; that
   costs a KMS call per request.
2. **Decrypt-then-rank in memory.** Fine at POC scale. At millions of chunks you'd keep hot
   per-tenant indexes, which widens the plaintext window.
3. **Over-redaction.** Presidio tags "120/80" and "2 weeks" as dates. Answers get vaguer,
   never leakier; I chose that trade.

## 4. Threat model

| Actor | Goal | What we tested (`./run.sh attack` + `tests/attacks/`) | Defense |
|---|---|---|---|
| **A1** malicious tenant | Read another tenant's data | IDOR, header/query/body tenant override, onboard with victim's CMK, query for victim data, use victim tokens | Tenant from session only; tenant-scoped SQL; same 404; customer key policy |
| **A2** storage insider (our DBs, not the KMS) | Read or silently alter data | Raw DB scan, bit flips, ciphertext swap, original↔tokenized swap, wrong DEK, vault swap, relabel rows to own tenant | No keys at rest; AES-GCM + AAD; KMS context check |
| **A3** data smuggler / poisoned doc | Get PHI to the LLM or across tenants | Prompt injection to an LLM that **obeys**, spaced / zero-width / full-width / homoglyph PII, base64, hex, PII in an `allow` field, PII in the question, a foreign token, a blind detector | Tokenize at ingest; tenant scope before ranking; 3-layer egress guard; re-identify only this request's tokens |
| **A4** rogue KMS caller | Abuse access to a customer key | Replay (also after KMS restart), clock skew, body/path swap, forged principal, impersonate customer admin, cross-tenant context, version downgrade | Signed requests, persisted nonces, admin-only management, policy conditions, audited denials |

**Residual risk I accept:**

- Whoever runs our process **and** has live KMS access can decrypt that tenant: that is
  BYOK's trust model; the customer's lever is disable/delete plus the audit log.
- Plaintext lives briefly in Python memory; zeroing is best effort.
- Up to TTL (5 min) of access after a customer revokes, unless they flush.
- NER can miss PII in **free text** that matches no hard pattern (e.g. an unusual name).
  If that value is declared in a tokenized field anywhere in the tenant, a vault
  blind-index lookup still catches it at ingest, in questions and at egress. A name that
  appears **only** in free text and that NER misses can still reach the LLM.
- Simulated KMS root keys sit in plain files (no HSM, no multi-party control, no rotation).
- Plaintext DEKs cross loopback HTTP between our service and the KMS; production needs TLS.

## 5. Claim → test map

| Claim | Proven by |
|---|---|
| Tenant can't read another tenant's data | `tests/attacks/test_a1_malicious_tenant.py`, `test_query_api.py::test_retrieval_is_tenant_scoped` |
| Tampering is detected, never served | `tests/attacks/test_a2_storage_insider.py`, `tests/integration/test_keyring.py` |
| No raw PHI at rest (ours and KMS) | `test_ingest_api.py::test_nothing_raw_at_rest`, `test_reviewer_kit.py::test_seeded_phi_is_not_on_disk` |
| No raw PHI to the LLM, even if it obeys injections | `tests/attacks/test_a3_data_smuggler.py`, `test_query_api.py` |
| No PHI in logs or error bodies | `tests/integration/test_http_leakage.py`, `test_*::test_no_phi_in_logs*` |
| KMS abuse blocked and audited | `tests/attacks/test_a4_rogue_kms_caller.py`, `tests/integration/test_kms_api.py` |
| Rotation with no downtime, resumes after crash + restart | `tests/integration/test_rotation.py` |
| Containment re-keys one tenant; old keys match nothing | `test_rotation.py::test_containment_*`, `test_old_token_key_matches_nothing_after_containment` |
| Customer revoke = crypto-shred | `test_keyring.py::test_customer_disables_key`, `test_kms_api.py::test_scheduled_deletion_crypto_shreds` |
| Fail closed (KMS, detector, LLM down) | `test_keyring.py::test_kms_down_fails_closed`, `test_ingest_api.py::test_detector_outage_fails_closed`, `test_query_api.py::test_llm_down_fails_closed` |
| Many users, many sessions, many tenants at once | `test_auth_service.py::test_concurrent_logins_ten_tenants`, `./run.sh simulate` |

## 6. Production evolution

**Migrating an existing system with unencrypted records, without disruption:**

1. **Dual-read first.** Ship a read path that accepts both a plaintext row and an envelope
   row (row-level format marker). No behavior change yet.
2. **Encrypt new writes.** Turn on envelope encryption for writes behind a per-tenant flag.
   Old rows still read through the plaintext branch.
3. **Backfill in the background**, exactly like the rotation job here: batches, a saved
   cursor, a compare-and-swap per row (`WHERE version = old`), throttled, resumable. Run
   detection + tokenization in the same pass so vectors get rebuilt from tokenized text.
4. **Verify** with a scan that every row is in envelope format and decrypts, plus checksums
   compared against the plaintext before deletion.
5. **Remove plaintext**: drop the old columns, `VACUUM` with `secure_delete`, rotate
   backups out of retention, then remove the plaintext read branch.
6. **BYOK per customer** later: start on our own KMS key, then let a customer register a
   CMK; the rewrap job moves their DEKs onto it with `ReEncrypt`. No data re-encryption.

**Introducing PHI controls without breaking customers:** run the egress guard in
**shadow mode** first (log entity names and counts, block nothing), tune per-tenant policies
with each customer, then enforce tenant by tenant. Field policies default to `drop`, so
roll out with a tenant-approved allowlist rather than flipping the default on live tenants.

## 7. AI usage

An AI coding agent (Kiro) scaffolded most of the code and tests from a plan we agreed on
first (`PLAN.md`), one or two milestones at a time with a test gate after each
(`docs/summary-*.md`).

| Where it helped | Where it was wrong, and how it was caught |
|---|---|
| Boilerplate: FastAPI layers, SQLAlchemy stores, Pydantic models | Logged a **patient name** inside an exception message; the leakage test caught it → exception messages are never logged |
| Wide test matrices (tamper positions, attack variants) | DEK cache with TTL 0 shared one key buffer between concurrent callers; the second got a zeroed key. Caught in review, pinned by a regression test |
| Wiring the KMS policy semantics after AWS KMS | Spaced-digit SSNs slipped past the detector; a probe script showed it → recognizer widened |
| Writing the attack suites | A `zip(strict=True)` bug broke 22 ingest tests; the message-free traceback (`ingest.py:155`) pointed straight at it |
| | The egress MRN regex matched the **label** "mrn:" followed by the next field name and blocked every simulator query; found by `./run.sh simulate` |
| | End-to-end curl run: spaCy missed the rare name "Zelda Quint", so it reached the LLM. Fixed with a known-value sweep and a vault blind-index lookup; regression tests in the A3 suite |
| | `./run.sh verify` first let lint failures pass (`a && b` under `set -e`); fixed when a red step printed `[ok]` |
| | A fresh-clone check once ran in parallel with the commit it was meant to test; re-run strictly after |

Rule I kept: every claim in this README has a test, and every milestone had to pass from a
fresh clone before the next one started.

## Layout

```
src/sentinel_vault/  api/ service/ crypto/ kms_client/ privacy/ persistence/ retrieval/ security/ domain/
customer_kms/        simulated customer KMS (separate process + data dir)
mock_llm/            the external system
reviewer_kit/        seed, demo, attack, simulate (same code runs live and in tests)
tests/               unit/ integration/ attacks/
docs/                milestone summaries        PLAN.md   design plan
```
