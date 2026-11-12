# Summary: M4 (Envelope crypto + DEK cache) + M5 (Ingest + token vault)

Branch `feat/byok-rag` · commits `05da07d` (M4), `abd0dcf` (M5), plus the commit adding this doc.

## 1. What happened

| Step | Result |
|---|---|
| M4 built | AES-GCM envelope, key wiping, DEK cache, signed KMS provider, `keyring.db`, Keyring service |
| Bug caught while writing M4 | With cache TTL 0, concurrent callers shared one key buffer; the first caller wiped it before the second used it. Fixed (no single flight when caching is off) and pinned by a regression test |
| M4 tests | 38 passed; committed `05da07d` |
| Detector probe (`scripts/probe_detector.py`) | Found every planted value except a **spaced SSN** (`1 2 3 - 4 5 - 6 7 8 9`). Widened the digit-run recognizer; re-probe caught it |
| M5 built | Normalization, Presidio detector, data policy, tokenizer + vault, chunking, embedder, vector store, Store/Retrieve + onboarding + policy API |
| M5 first run | 22 failures, all from one bug: a `zip(strict=True)` between scanned fields and texts that also held the free-text body. Found from the **message-free traceback** (`ingest.py:155`), which validated the M1 logging design |
| After fix | 69 M5 tests pass |
| Gate | ruff ✅ · mypy `--strict` ✅ · **316 tests** ✅ · **96.8%** coverage |
| Fresh-clone gate | Run strictly after the commit this time: up in 113 s (API now loads Presidio + on-disk service key), re-run idempotent, 316 pass |

## 2. Decisions

### M4: Envelope crypto and keys

| Decision | Why |
|---|---|
| AES-256-GCM from `cryptography`, random 96-bit nonce | Vetted AEAD; nonce space far beyond our DEK roll limit |
| Keyring **adds** `tenant_id`, `workspace_id`, `dek_id`, `purpose`, `alg`, `v` to every AAD; callers can't override them | Binding can't be forgotten by a caller |
| One active DEK per (tenant, workspace, purpose) | Like S3 Bucket Keys: 50 chunks = 1 KMS call (tested) |
| Separate purposes: `document`, `vector`, `vault`, `tokenkey` | A leaked vector DEK doesn't expose originals or the vault |
| DEK roll at `dek_max_uses` (1M) or `dek_max_age` (24 h); old DEK → `retired`, still decrypts | Bounds GCM nonce use and blast radius per DEK |
| Token HMAC key never rolls | Rolling it would break token joins; it is still re-wrapped on CMK rotation |
| KMS encryption context `{tenant_id, workspace_id, purpose, dek_id}` | Customer's key policy enforces `tenant_id` outside our code |
| DEK cache: TTL 5 min, 10k uses, single flight, zero on evict, per-tenant flush | Read-path latency; revocation latency = TTL (tested both: after TTL, and TTL 0 = immediate) |
| Keys used only inside a **synchronous** callback | No `await` while holding a key, so no other task can evict/zero it mid-use |
| Provider fails closed: revoked → 503 `tenant_key_unavailable`; tampered → 500 `integrity_error`; outage → retry ×2 then 503 | Never serve data we can't verify; never hang |
| Onboarding probe: GenerateDataKey + Decrypt before accepting a CMK | Wrong key or missing grant is caught at signup, not at first read |
| `keyring.db` separate from `vector.db` / `vault.db` | Stealing the data stores doesn't even yield wrapped DEKs |
| Best-effort wiping via `ctypes.memset` on `bytearray` | Honest limit documented: Python/OpenSSL may hold copies |

### M5: Ingest, PII, vault

| Decision | Why |
|---|---|
| Presidio + spaCy `en_core_web_lg`, threshold 0.35, **every** reported entity treated as sensitive | Over-detect; a wrongly tokenized word is cheap, a leaked SSN isn't |
| Custom recognizers: MRN, insurance/member id, DOB, NPI, any 3-2-4 SSN, obfuscated digit runs, ISO/US dates | Presidio skips "invalid" SSNs like `078-05-1120` and misses healthcare ids |
| Detect on a normalized copy (NFKC, Cyrillic/Greek look-alikes, zero-width removed), map spans back | Homoglyph and zero-width tricks caught; the *original* characters get replaced |
| Detector failure → 503, nothing stored | Fail closed (tested: zero documents written) |
| Structured fields: per-tenant allowlist (`allow` / `tokenize` / `scan` / `drop`), default **drop** | Unknown fields never reach chunks or embeddings |
| Field names must be snake_case identifiers, else dropped | PHI can't ride in as a key (tested with `"John Smith 078-05-1120"`) |
| Token = `<<ENTITY_16hex>>`, HMAC-SHA256 of entity + normalized value, per-tenant key | Same value → same token in a tenant; no cross-tenant linkage; spacing/case/homoglyph variants map together |
| Vault = token → AES-GCM(original), AAD (token, entity) | Swapping vault rows is detected (tested) |
| **Tokenize before embedding** | Embedding inversion recovers tokens, not names |
| Store original + tokenized document, both encrypted, AAD has `kind` | Retrieve returns the original; swapping original into the tokenized slot is detected (tested) |
| Original view needs `reidentify` scope; tokenized needs `query` | Least privilege for raw PII |
| Every store method takes `tenant_id` and filters by it | No API can read across tenants; AAD + KMS policy are the backstops |
| Document + chunks in one transaction; vault written first (idempotent) | No half-ingested documents; a crash leaves only harmless orphan vault rows |
| Hash embedder by default; fastembed optional | Offline, fast reviewer setup. Lexical only; semantic quality isn't the security claim |

## 3. Code changes

```
M4
src/sentinel_vault/crypto/envelope.py          AES-GCM seal/open, canonical AAD
src/sentinel_vault/crypto/wipe.py              best-effort zeroing
src/sentinel_vault/crypto/dek_cache.py         TTL/uses cache, single flight, flush
src/sentinel_vault/kms_client/provider.py      KmsProvider protocol, SignedKmsProvider, error mapping
src/sentinel_vault/persistence/keyring_store.py tenant_keys, deks, policies
src/sentinel_vault/service/keyring.py          onboarding probe, DEK lifecycle, encrypt/decrypt
src/sentinel_vault/config.py                   KMS, embedder, PII, chunk, limit settings

M5
src/sentinel_vault/privacy/normalize.py        normalization with index map
src/sentinel_vault/privacy/detector.py         Presidio + custom recognizers, fail closed
src/sentinel_vault/privacy/policy.py           DataPolicy / FieldAction
src/sentinel_vault/service/tokenization.py     HMAC tokens, vault store/reidentify
src/sentinel_vault/persistence/vault_store.py  vault_entries
src/sentinel_vault/persistence/vector_store.py documents, chunks
src/sentinel_vault/retrieval/embedder.py       HashEmbedder, FastEmbedEmbedder
src/sentinel_vault/retrieval/chunking.py       whitespace chunker, chunk payload codec
src/sentinel_vault/service/ingest.py           IngestService, PolicyService
src/sentinel_vault/api/routes/documents.py     PUT /tenant/kms, GET/PUT /tenant/policy, POST/GET /documents
src/sentinel_vault/api/app.py                  full wiring, all collaborators injectable
scripts/probe_detector.py                      dev aid: what the detector finds
tests/                                         keyring_env, app_env, 6 new test files incl. A1 + A2 suites
```

## 4. What works now

| Check | Status |
|---|---|
| `./run.sh` fresh clone, API boots with Presidio + service key | ✅ 113 s |
| `./run.sh verify` | ✅ 316 tests, 96.8% |
| BYOK onboarding via API (`PUT /tenant/kms`), bad/foreign CMK rejected | ✅ |
| Store: PII tokenized in fields + text; unknown fields dropped | ✅ |
| Retrieve original (with `reidentify`) and tokenized view | ✅ |
| 50 chunks → 1 KMS call; cache hit → 0 calls | ✅ |
| Customer disables CMK → unreadable after flush / TTL; other tenants fine | ✅ |
| KMS down / 5xx → retried, then 503 | ✅ |
| No raw PHI anywhere at rest (all `.db` files scanned, ours and KMS) | ✅ |
| No raw PHI in logs or responses | ✅ |
| 10 tenants ingesting concurrently | ✅ |
| **A1** malicious tenant: IDOR (same 404 as missing), header/query/body override, victim's CMK, relabeled rows, victim tokens | ✅ all blocked |
| **A2** storage insider: raw read, bit flips, ciphertext swap, original↔tokenized swap, wrong DEK, vault swap, stolen DBs + revoked CMK | ✅ all detected / useless |
| **A4** rogue KMS caller (from M3) | ✅ |
| Query path + egress guard + LLM (A3) | ⏳ M6 |
| Seeded tenants for manual testing | ⏳ M8 |

## 5. Open points

- **Over-redaction is real.** Presidio tags `120/80` (blood pressure) and `2 weeks` as
  `DATE_TIME`. We accept that; it costs answer quality, not safety.
- **Detection is probabilistic.** NER can miss unusual names. M6 adds a second, independent
  check at the LLM boundary (fail closed), so one miss isn't a leak.
- **Ingest is CPU-bound** (spaCy runs in a worker thread). Fine for the POC; production
  would run detection in a separate worker pool.
- **Vault and document writes aren't one transaction** (different DB files). Order makes it
  safe: vault first, idempotent.
- **Hash embedder is lexical.** Switch with `SV_EMBEDDER=fastembed` for semantic search.

## 6. Next: M6 (query + egress guard + mock LLM, A3) and M7 (rotation + containment)
