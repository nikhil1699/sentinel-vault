# Summary: M2 (Auth + sessions) + M3 (Customer KMS)

Branch `feat/byok-rag` · code commit `cd18654`, plus the commit adding this doc.

## 1. What happened

| Step | Result |
|---|---|
| Shared pieces | `security/files.py` (private files), `persistence/sqlite.py` (safe async SQLite), lifespan support in the app builder |
| M2 built | Users, sessions, login throttling, auth dependency, `/auth/*` API |
| M2 tests | 46 passed on the first run |
| M3 built | KMS protocol, policy engine, blob crypto, identity directory, per-account store, service, HTTP API, client SDK, operator CLI |
| M3 tests | 79 passed on the first run (unit + integration + A4 attacker suite) |
| First `verify` | 3 lint findings (generic syntax, 2 false-positive "hardcoded password" hits). Fixed / annotated |
| Coverage gaps | SQLite pragmas, scope checks, KMS CLI untested. Added `test_gaps_m2_m3.py` |
| Gate | ruff ✅ · mypy `--strict` ✅ · **221 tests** ✅ · **97.1%** branch coverage |
| Fresh-clone gate | First try was invalid: the clone ran **in parallel with the commit** and tested old code. Re-ran after the commit: up in 95 s, re-run idempotent, 221 pass |

## 2. Decisions

### M2: Auth + sessions

| Decision | Why |
|---|---|
| Opaque server-side sessions, not JWT | Logout, tenant freeze and containment must take effect at once |
| Store only SHA-256(token) | A copied `auth.db` can't be replayed as live sessions (tested by scanning raw DB bytes) |
| Token = `svs_` + 32 random bytes | Prefix lets secret scanners and our log redactor spot leaks |
| Argon2id (RFC 9106 params), re-hash on param upgrade | Vetted KDF; cost can rise without forcing password resets |
| Same 401 for: no header, wrong scheme, garbage, expired, revoked, wrong password, unknown user, unknown tenant | No account or session enumeration |
| Dummy Argon2 verify for unknown users | Login time doesn't reveal whether a user exists |
| Frozen tenant + **wrong** password still → 401, not 423 | Frozen state shown only to someone who knows the password |
| Backoff per attempted user **and** per IP; applies to nonexistent users too | Stops brute force and password spraying without enumeration |
| Success clears the user counter, not the IP counter | An attacker can't reset IP throttling by logging into their own account |
| 10 live sessions per user; 11th evicts oldest, in one transaction | Supports laptop + agent runners; bounded |
| Idle 30 min + absolute 12 h; `last_seen` written at most every 15 s | Limits stolen-token lifetime; avoids a write per request |
| Freeze revokes all tenant sessions in the same transaction as the flag | No window where a frozen tenant still has live sessions; unfreeze doesn't revive them |
| Users can revoke only their own sessions; others' → 404 | Owner-scoped SQL `WHERE`, not a check after the fact |
| Tenant comes only from the session row | Path/query/header `tenant_id` ignored (tested) |
| SQLite `BEGIN IMMEDIATE` on every transaction | Two writers (API + future worker) can't deadlock on lock upgrade; tested with 10 racing writers |
| `secure_delete=ON` | Revoked/destroyed rows overwritten on disk |

### M3: Customer KMS

| Decision | Why |
|---|---|
| Separate process, own settings (`KMS_*`), own data dir | Separate trust domain, as in real BYOK |
| One folder per customer account: own root key (0600) + own DB | One customer's compromise or deletion can't touch another |
| Ed25519 request signing over method, path, account, principal, time, nonce, body hash | Stands in for SigV4. Body/path swaps break the signature |
| ±60 s clock skew; nonces **persisted** in the account DB | Replays rejected, including right after a KMS restart (tested) |
| Account admin vs external principal; external names can't end in `-admin` | Our service can't impersonate a customer admin |
| Management ops admin-only and **not grantable** in a key policy | Customer can't hand key admin to us by mistake, or lock themselves out |
| Policy: default deny, explicit deny wins, exact principals, no `*` | Small, auditable subset of AWS key policy semantics |
| Context conditions: `encryption_context_equals` + `encryption_context_keys` | `tenant_id` check is enforced by the **customer**, outside our code |
| New CMK starts with an empty policy | We get nothing until the customer explicitly grants it |
| Blob = header (account, CMK id, version) + nonce + ciphertext; AAD = header + canonical context | Swapping account, key, version or context fails decryption; version downgrade tested |
| CMK material sealed by the account root key; AAD binds account, CMK, version | Stolen `kms.db` alone gives no key material |
| `ReEncrypt` | Rotation re-wraps without the plaintext DEK leaving the KMS; needs its own grant |
| Old CMK versions stay decrypt-only after rotate | No downtime on rotation |
| Disable = instant kill switch; Enable restores | Customer control |
| Scheduled deletion 7–30 days, then versions deleted = crypto-shred; cancel → Disabled | Same safety window as AWS KMS |
| Unknown key / foreign-account blob → `access_denied` | Doesn't reveal which keys exist |
| Any decrypt failure → one `invalid_ciphertext` error | No oracle on which check failed |
| Every call audited, allow **and** deny, with reason and context; hash-chained | Customer can see every attempt we make; tampering detected (tested) |
| Plaintext DEKs returned as `bytearray` in the client | Lets M4 zero them after use |

## 3. Code changes

```
src/sentinel_vault/security/files.py         private dir/file helpers (moved from bootstrap)
src/sentinel_vault/persistence/sqlite.py     async engine: WAL, BEGIN IMMEDIATE, secure_delete, 0600
src/sentinel_vault/persistence/auth_store.py tenants, users, sessions, login_failures
src/sentinel_vault/domain/auth.py            Scope, Principal, SessionInfo
src/sentinel_vault/service/auth_service.py   login, authenticate, logout(-all), freeze, throttling
src/sentinel_vault/api/deps.py               get_principal, require_scope (authorization boundary)
src/sentinel_vault/api/routes/auth.py        /auth/login, /me, /logout, /logout-all, /sessions
src/sentinel_vault/api/app.py                lifespan wiring
src/sentinel_vault/config.py                 Argon2 + throttling settings
src/sentinel_vault/security/errors.py        RateLimitedError, InvalidInputError
customer_kms/protocol.py                     signing, context validation, base64 helpers
customer_kms/policy.py                       key policy model + evaluator
customer_kms/crypto.py                       root key, CMK sealing, DEK blob wrap/unwrap
customer_kms/directory.py                    accounts + external principals
customer_kms/store.py                        keys, versions, nonces, audit chain
customer_kms/service.py                      all KMS operations
customer_kms/app.py                          POST /v1/<Operation>
customer_kms/client.py                       signed async client (SDK)
customer_kms/cli.py                          register-principal, create-account
customer_kms/config.py                       KmsSettings
run.sh                                       registers our service principal with the KMS on setup
tests/                                       +5 test files, kms_env helper, FakeClock
```

## 4. What works now

| Check | Status |
|---|---|
| `./run.sh` fresh clone (now also registers `sentinel-svc` with the KMS) | ✅ 95 s |
| `./run.sh` re-run | ✅ idempotent |
| `./run.sh verify` | ✅ 221 tests, 97.1% |
| Login, many concurrent sessions per user, 10 tenants × 3 users × 2 sessions at once | ✅ |
| Logout one / all, revoke own session, cap eviction, idle + absolute expiry | ✅ |
| Lockout (user, IP, nonexistent user), backoff growth | ✅ |
| Tenant freeze kills sessions, blocks login, other tenants unaffected | ✅ |
| BYOK handshake: create CMK → grant policy → GenerateDataKey → Decrypt | ✅ |
| Customer policy blocks wrong-tenant context even from our own service | ✅ |
| Rotate (old blobs readable), ReEncrypt, disable/enable, scheduled deletion + shred | ✅ |
| 10 accounts × 5 concurrent data-key round trips | ✅ |
| A4 attacks: replay (incl. after restart), skew, body/path swap, forged principal, admin impersonation, cross-account blob, version downgrade | ✅ all blocked and audited |
| Audit chain verify + tamper detection | ✅ |
| Seeded tenants/users for manual testing in `/docs` | ⏳ M8 |

## 5. Open points

- **Plaintext DEK over loopback HTTP.** Fine for a local POC. Production needs TLS (or a
  Unix socket) between our service and the KMS.
- **Throttling is per process DB, keyed by client IP.** Behind a proxy the IP would need to
  come from a trusted header. Not relevant on loopback.
- **Nonce table grows until rows expire** (2 min). Purged on every insert; fine at POC load.
- **KMS identity directory is a JSON file** read on each request. Simple and correct; would be
  a real IAM in production.
- **Process lesson:** never run a fresh-clone check in the same parallel batch as the commit
  it is meant to test.

## 6. Next: M4 (envelope crypto + DEK cache) and M5 (ingest + token vault)
