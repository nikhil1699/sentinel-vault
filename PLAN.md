# Sentinel Vault — POC Plan

## 1. Scope

Built (6 of 6 listed features, plus 2 extensions):

| # | Property | Depth |
|---|---|---|
| F1 | Tenant isolation + encryption context (AAD) | Full |
| F2 | Key rotation without downtime (resumable re-wrap) | Full |
| F3 | Compromise containment (tenant kill-switch + forced rotate + revoke DEK) | One full path |
| F4 | PHI/PII detection & scrubbing (structured + free text) | Full, fail-closed |
| F5 | Leakage prevention (logs, errors, outbound) | Full |
| F6 | Persistence + key protection (split stores) | Full |
| X1 | Audit trail (hash-chained, no plaintext) | Extension |
| X2 | Reversible tokenization (per-tenant HMAC tokens) | Extension |

Cut on purpose (owned in README):
- Real HSM / FIPS. A local KMS stands in. An `AwsKmsProvider` stub shows the swap.
- Searchable encryption. Leaks access patterns; not worth it for a POC.
- Multi-region, HA, rate limiting beyond a simple in-process limiter.
- Training an NER model. Presidio + spaCy + custom recognizers only.
- Docker. Not installed on this Mac. `make up` runs it natively; a Dockerfile is shipped untested.

## 2. Architecture (layers kept separate)

```
src/sentinel_vault/
  api/          FastAPI routers, auth dependency, error handlers   (HTTP only)
  service/      RecordService, ProcessService, KeyAdminService     (business rules)
  crypto/       envelope.py (AES-256-GCM), aad.py, kms/ (provider interface)
  kms/          LocalKms: own SQLite file, own master key           (separate trust domain)
  privacy/      detector (Presidio), policy, transformer, egress guard
  persistence/  data store (records), audit store                   (no keys here)
  security/     log redaction, safe errors, authn/authz
  domain/       Pydantic models, typed ids
```

Data flow:

```
client --API key--> [AuthN] -> Principal(tenant_id)  # tenant never taken from body/path
   |
 Store:   record -> DEK(random) -> AES-GCM(AAD) -> wrap DEK via KMS(tenant KEK vN) -> data.db
 Retrieve: data.db -> check tenant -> KMS unwrap(AAD) -> decrypt -> record
 Process: retrieve -> classify fields by policy -> Presidio scan -> transform
          -> re-scan output (verify) -> EgressGuard -> external (mock LLM)
```

## 3. Key hierarchy

```
Root key (KMS process only; from file/env, never in data.db)
  └─ Tenant KEK v1..vN   (wrapped by root, stored in keys.db, state: active|decrypt-only|revoked)
       └─ Record DEK     (random 256-bit, wrapped by KEK, stored next to ciphertext)
            └─ Record ciphertext (AES-256-GCM, 96-bit nonce)
```

- AAD = canonical JSON of `{tenant_id, record_id, kek_version, schema_version, alg}`.
  Bound into both the DEK wrap and the payload. Swapping any of them fails auth.
- KMS API is the only path to unwrap. It checks `tenant_id` of the caller against the KEK owner.
- Separation of duties: `data.db` holds ciphertext + wrapped DEKs. `keys.db` + root key file
  live in a different directory with different file perms. Steal one, get nothing.
- Library: `cryptography` (AESGCM). No hand-rolled crypto.

## 4. Rotation (F2)

1. `rotate(tenant)`: create KEK vN+1 = active; vN -> decrypt-only. New writes use vN+1.
2. Background re-wrap job: re-wraps DEKs only (payload untouched). Cursor saved per batch
   in `keys.db`. Restart resumes from cursor. Idempotent: skip rows already at vN+1.
3. Reads work at all times: each row names its KEK version.
4. When no rows reference vN, it can be retired.

Test: kill the job mid-batch, restart, all records still readable, job finishes.

## 5. Compromise containment (F3)

Path: "tenant KEK suspected leaked".
1. `POST /admin/tenants/{id}/contain` -> freeze tenant (reads/writes 423), rotate KEK,
   mark old KEK `compromised`, run full **re-encrypt** (new DEK + new ciphertext, not just re-wrap).
2. Blast radius = one tenant. Other tenants keep working (test proves it).
3. Unfreeze after job done. Audit log records each step.

Also: single record compromise -> re-encrypt that record with a new DEK.

## 6. PHI/PII handling (F4)

- Policy per tenant: per field `allow | mask | tokenize | drop`. Default for unknown
  fields = **drop** (allowlist, not denylist).
- Free text: Presidio analyzer (spaCy) + custom recognizers (MRN, US SSN variants,
  DOB, NPI, insurance id). Replace with typed placeholders `<PERSON_1>` or tokens.
- Ambiguous inputs (e.g. "Jordan" name vs place, low-score hits): threshold low, treat as PII.
  Over-redact by design.
- Detection failure: second pass on output with regex safety net. Any hit -> request fails
  closed (422, no body sent outbound). Analyzer crash -> fail closed.
- Tokenization: HMAC-SHA256(tenant token key, value) -> stable per tenant, not across tenants.

## 7. Leakage prevention (F5)

- structlog processor redacts known fields + runs regex scrubber on every log event.
- Global exception handler: generic error body + correlation id. No stack, no input echo.
- Pydantic `SecretStr` / custom `Sensitive[T]` wrapper with `__repr__ = "***"`.
- EgressGuard wraps the only httpx client allowed to call outside. Scans body before send.
- Tests: force exceptions with PHI in input; assert caplog + response contain none of it.

## 8. Tenants and threat actors (synthetic)

- 10 tenants seeded (clinics, insurer, pharmacy...). Concurrency test: 10 tenants x N writes in parallel.
- Evil actors (tested as attack suites):

| Actor | Goal | Attacks we test |
|---|---|---|
| A1 Malicious tenant | Read other tenant data | IDOR on record id, swap tenant header, replay other tenant ciphertext/wrapped DEK into own row |
| A2 Storage insider (has data.db) | Read or tamper data | Read raw DB, flip ciphertext bits, swap rows, roll back KEK version field, swap AAD metadata |
| A3 Data smuggler | Get PHI past the LLM boundary | Obfuscated PHI (spaced SSN, "j o h n"), PHI in field names, unicode homoglyphs, PHI in nested JSON, prompt injection in text |

## 9. Milestones

1. Skeleton, config, domain models, logging redaction.
2. Crypto envelope + LocalKms + keys.db. Unit tests (tamper, AAD swap).
3. Data store + Store/Retrieve API + authN/authZ. A1/A2 tests.
4. Rotation + resumable job. Restart test.
5. Privacy pipeline + egress guard. A3 tests.
6. Containment path + audit chain.
7. Seed script, README (threat model, migration, AI usage).

## 10. Open calls (least sure)

- Local KMS vs real AWS KMS. Local = easy to run; weaker key protection. Provider interface keeps the swap cheap.
- Fail-closed on any residual detection hit may block useful records. Chosen: safety over utility.
