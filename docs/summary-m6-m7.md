# Summary: M6 (Query + egress guard) + M7 (Rotation + containment)

Branch `feat/byok-rag` · code commit `1a42a24`, plus the commit adding this doc.

## 1. What happened

| Step | Result |
|---|---|
| Session resumed | Re-confirmed state from git: clean tree at `e3195f3` |
| M6 built | Mock LLM, `EgressGuard` + `LlmClient`, `QueryService`, `POST /query` |
| M6 first run | 41 pass, 3 fail. All three were **test design**, not product bugs: lexical embedder tied on the word "with"; the question itself echoed the test word; NER tagged `marker00` as a person |
| M7 built | Jobs table, CAS re-wrap, containment migration, `RotationService`, admin endpoints, resume on startup |
| M7 tests | 9 pass on the first run |
| First full `verify` | **1 flaky failure**, not reproduced in 5 more runs. `run.sh verify` now prints failing test names (`-rf`). Best guess: Hypothesis's 200 ms per-example deadline under coverage load; deadline disabled |
| Gate | ruff ✅ · mypy `--strict` ✅ · **369 tests** ✅ · **96.8%** coverage |
| Fresh-clone gate | Up in 115 s, re-run idempotent, 369 pass |

## 2. Decisions

### M6: Process across the PHI boundary

| Decision | Why |
|---|---|
| Tokenize PII in the **question** with the tenant key | Names in a question map to the same token as in documents, so retrieval still works and the LLM never sees the name |
| Load only the caller's tenant + workspace chunks, then rank | Scope is fixed before ranking; a poisoned document can't widen it |
| Group chunks by DEK → one KMS Decrypt per DEK | Cold query ≤ 3 KMS calls; warm query 0 (tested) |
| Egress layer 1: cut decodable base64 / hex blobs holding readable text | Encodings can't be scanned, so they never leave |
| Egress layer 2: second-pass Presidio on outbound text, tokenize hits | Catches ingest misses and PII in fields a tenant marked `allow` |
| Egress layer 3: hard regex check (SSN, email, phone, MRN, 9+ digit runs) → **block** | Independent of NER. Tested with a "blind" detector: request blocked, nothing sent |
| Our tokens masked with private-use placeholders during scanning | Tokens aren't re-scanned or mistaken for blobs; attacker PUA chars are stripped first |
| `LlmClient` only accepts `CleanPrompt`, which only the guard can build | Can't send unguarded text by mistake; it also re-checks the exact JSON bytes |
| Context wrapped in `<context>` tags; system prompt says it's untrusted | Helps, but **not relied on**: tests use an LLM that obeys every injection |
| Re-identify only with `reidentify` scope, only tokens seen in **this** request | A token planted from another tenant resolves to nothing (tested) |
| Detector or LLM down → 503, nothing sent | Fail closed |

### M7: Rotation and containment

| Decision | Why |
|---|---|
| Re-wrap with KMS `ReEncrypt` | DEKs move to the new CMK version without plaintext reaching us; payloads untouched |
| Compare-and-swap on `wrapped` + cursor saved per batch | Crash anywhere is safe; resume skips rows already at the new version |
| Jobs stored in `keyring.db`, resumed on API startup | Survives restarts (tested with a crash, then a fresh KMS + API on the same data) |
| One running job per tenant | No two jobs fighting over the same rows |
| Containment = freeze → mark + record compromised set (one transaction) → new keys → re-tokenize vault → re-encrypt + re-embed each doc → delete old vault rows + wrapped DEKs → unfreeze | A leaked old DEK or old token key matches nothing stored afterwards (tested) |
| Recorded compromised set used on resume | Keys made during containment are never re-marked |
| Token key **replaced** in containment | A leaked HMAC key would allow dictionary attacks on SSNs; replacing it breaks that |
| Sessions stay dead after unfreeze | Whoever held a session during the compromise must log in again |
| Customer cache-flush endpoint | Revocation takes effect now, not after the 5-min TTL |

## 3. Code changes

```
mock_llm/app.py                                 POST /v1/complete, GET /v1/received, modes
src/sentinel_vault/privacy/egress.py            EgressGuard, CleanPrompt, LlmClient, hard checks
src/sentinel_vault/service/query.py             QueryService
src/sentinel_vault/service/rotation.py          RotationService: rewrap, containment, resume
src/sentinel_vault/service/keyring.py           store property, rewrap()
src/sentinel_vault/persistence/keyring_store.py jobs table, CAS rewrap, start_containment, delete
src/sentinel_vault/persistence/vector_store.py  documents_on_deks, replace_document
src/sentinel_vault/persistence/vault_store.py   rows_on_deks, delete_on_deks
src/sentinel_vault/api/routes/query.py          /query, /tenant/keys/rewrap, /tenant/contain,
                                                /tenant/jobs/{id}, /tenant/cache/flush
src/sentinel_vault/api/app.py                   LLM client, query + rotation wiring, job resume
src/sentinel_vault/config.py                    query, LLM and job settings
run.sh                                          verify names failing tests
tests/                                          egress units, query API, rotation, A3 suite
```

## 4. What works now

| Check | Status |
|---|---|
| `./run.sh` fresh clone | ✅ 115 s |
| `./run.sh verify` | ✅ 369 tests, 96.8% |
| Query answers from tokenized context; LLM log has no raw PHI | ✅ |
| Re-identify locally with scope; refused without | ✅ |
| 10 tenants × 3 concurrent queries, no cross-tenant context | ✅ |
| Customer revokes CMK + flush → query 503 | ✅ |
| **A3**: prompt injection, spaced / zero-width / full-width / homoglyph PII, base64, hex, PII in `allow` field, PII in question, foreign token, NER miss | ✅ all kept from the LLM or blocked |
| Customer rotates CMK → rewrap job → all DEKs on new version, reads work during it | ✅ |
| Rewrap crash → restart → resumes and finishes | ✅ |
| Containment: one tenant re-keyed, old DEKs gone, old tokens dead, beta untouched | ✅ |
| Containment crash → still frozen → resume finishes | ✅ |
| A1, A2, A4 (earlier milestones) | ✅ |
| Seeded tenants, `./run.sh attack`, `./run.sh demo`, README | ⏳ M8 |

## 5. Open points

- **Whole-field tokens don't link to text tokens.** `patient_name` gets a `FIELD_PATIENT_NAME`
  token; the same name in free text gets a `PERSON` token. A query by name matches the text
  mention only.
- **Query decrypts all of a tenant's chunks** per request. Fine for thousands; at millions
  you'd hold hot per-tenant indexes, which widens the plaintext window.
- **Containment holds the tenant frozen** for the whole migration. That's the cost of a
  clean cut.
- **Over-detection at egress** adds tokens for things like "2 weeks". Answers get vaguer,
  never leakier.
- **One flaky test seen once**, cause not confirmed. Watch for it in M8 runs.

## 6. Next: M8 (seed 10 tenants, simulator, `./run.sh attack` / `demo`, README)
