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

## 11. Milestones

1. Domain models, settings, log redaction, safe errors.
2. Customer KMS service: CreateKey, PutKeyPolicy, GenerateDataKey, Decrypt, Rotate, Disable, audit. Signed requests.
3. Envelope crypto + DEK cache + KMS client. Tamper/AAD/policy tests (A2, A4).
4. Ingest path + vector store + tokenization vault. Tenant isolation tests (A1).
5. Query path + in-memory index + egress guard + mock LLM. Poisoned-doc tests (A3).
6. Rotation job (resumable) + containment + revoke/crypto-shred tests.
7. Seed 10 tenants + concurrent load test; README (threat model, migration, AI usage).

## 12. Least-sure calls

1. **DEK cache TTL vs revocation.** 5 min default means a revoked customer is not cut off at once.
   Mitigated by the flush endpoint and per-tenant TTL. Still a real gap.
2. **Decrypt-then-rank in memory.** Fine for 10 tenants x thousands of chunks. Does not scale to
   millions without per-tenant sharded workers holding hot indexes, which widens the plaintext window.
3. **Tokenize-before-embed** hurts recall on name-based queries.
