# Summary: M0 (Bootstrap) + M1 (Foundation)

Branch `feat/byok-rag` · commits `715037a` (code) and the commit adding this doc.

## 1. What happened

| Step | Result |
|---|---|
| M0 built | `run.sh`, Makefile, settings, private key bootstrap, `/health` on all 3 services |
| M1 built | Typed ids, `Sensitive[T]`, JSON log redaction, safe error bodies, request-id middleware |
| First test run | 1 failure: a **patient name leaked into logs** inside an exception message |
| Second run | Request ids over-redacted; IPs half-redacted as dates; `deepcopy` of `Sensitive` broke |
| First `verify` | Lint and type errors **did not fail the gate** (`a && b` hides failures under `set -e`) |
| After fixes | `./run.sh verify` green: ruff, mypy `--strict`, 92 tests, 96.6% branch coverage |
| Fresh-clone gate | Clean clone → `./run.sh` up in 88 s → second run changes nothing → `./run.sh test` 92 pass → `./run.sh stop` |

## 2. Decisions

| Decision | Why |
|---|---|
| **Never log exception messages.** Log type + `file:line:function` only | Messages are built from data (`f"bad {row}"`). Regex can't catch names. Code locations come from source, not data |
| Two-layer log redaction: sensitive **keys** dropped whole, then **patterns** on all strings | Keys catch what patterns miss (names, free text). Patterns catch PHI in messages |
| Over-redact by design | A harmless 9-digit number shown as `[SSN]` beats a real SSN in a log |
| "Safe" log keys must still look like an id/route/timestamp | A safe key name alone is not proof the value is safe |
| Uvicorn access log off; our middleware logs the **route template** | Raw paths and query strings can carry PHI |
| `httpx` logger at WARNING | It logs full outbound URLs at INFO |
| Error bodies are fixed text: `{code, message, request_id}` | Never built from exception text or input |
| Validation errors return field location + type, never input or message | FastAPI's default echoes the input. PHI-shaped field names shown as `<field>` |
| Cross-tenant access will use 404, not 403 | Don't confirm that someone else's id exists |
| Inbound `x-request-id` accepted only if it is a UUID | Stops log injection |
| `Sensitive[T]`: masked in repr/str/format/Pydantic dump; pickling refused; `.reveal()` is the only way out | Makes accidental exposure hard, and every real use easy to grep |
| Prefixed typed ids (`doc_`, `chk_`, `dek_`, `ses_`) with strict patterns | A doc id can never parse as a chunk id; blocks traversal, SQL fragments, look-alike letters |
| All binds must be loopback (validated in settings) | Reviewer machines never expose a port |
| Keys in `.secrets/` (0700 dir, 0600 file), refuse to start if group/other can read | Same rule as OpenSSH; written via O_EXCL temp file + atomic rename |
| Customer KMS has its own settings (`KMS_` prefix, own data dir) | Separate trust domain from day one |
| `requirements.lock` pins 98 packages; spaCy model fetched by `spacy download` | Reproducible installs; the model isn't on PyPI |
| `run.sh` written for bash 3.2 (macOS default) and Linux | Reviewers shouldn't need a newer bash |

## 3. Code changes

```
run.sh                                   one-command setup/up/test/verify/stop/status/reset
Makefile                                 wraps run.sh
requirements.lock                        pinned deps
pyproject.toml                           deps, ruff (+ test ignores), mypy strict, pytest config
src/sentinel_vault/config.py             Settings (SV_*), loopback check, bounds
src/sentinel_vault/bootstrap.py          private dirs + Ed25519 service key, idempotent
src/sentinel_vault/domain/ids.py         TenantId, WorkspaceId, UserId, DocumentId, ChunkId, DekId, SessionId
src/sentinel_vault/security/sensitive.py Sensitive[T]
src/sentinel_vault/security/redaction.py key + pattern redaction, structlog processor
src/sentinel_vault/security/logging.py   JSON logging, message-free exception rendering
src/sentinel_vault/security/errors.py    AppError family + handlers
src/sentinel_vault/security/middleware.py request id, security headers, access log
src/sentinel_vault/security/http.py      shared app skeleton + /health
src/sentinel_vault/api/app.py            Sentinel API factory
customer_kms/app.py                      KMS factory + KmsSettings
mock_llm/app.py                          mock LLM factory
tests/                                   conftest (log capture, PHI samples) + 6 test files
```

## 4. What works now

| Check | Status |
|---|---|
| `./run.sh` from a fresh clone (venv, deps, spaCy, keys, 3 services, smoke) | ✅ 88 s first run |
| Re-running `./run.sh` | ✅ no change, services detected as running |
| `./run.sh test` | ✅ 92 tests pass in ~3 s |
| `./run.sh verify` (ruff + mypy strict + coverage ≥ 85%) | ✅ 96.6% |
| `./run.sh stop` / `status` / `reset` | ✅ |
| PHI in an unhandled exception → no PHI in body or logs | ✅ tested |
| PHI in validation errors, malformed JSON, unknown routes, query strings | ✅ tested |
| Non-loopback bind, bad config, world-readable keys rejected | ✅ tested |
| `./run.sh attack` / `demo` | ⏳ M8 (prints a clear message today) |

## 5. Open points

- Third-party stdlib log messages are only pattern-redacted. A library that logs a bare
  name would get through. Mitigation today: library loggers kept at WARNING. Tracked for README.
- The service private key is protected by file mode only, not a passphrase. Fine for a local
  POC; production would use a secrets manager.
- Docker path not built yet (M8).

## 6. Next: M2 (auth + sessions) and M3 (Customer KMS)
