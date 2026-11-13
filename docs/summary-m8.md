# Summary: M8 (Seed, simulator, attack runner, demo, README)

Branch `feat/byok-rag` · code commit `9dad4fa`, plus the commit adding this doc.
M8 is the last milestone, so this summary covers one milestone.

## 1. What happened

| Step | Result |
|---|---|
| Built | `reviewer_kit/` (common, seed, simulate, attack, demo), mock LLM `PUT /v1/mode`, `run.sh demo/attack/simulate`, seed on startup, README |
| First kit test run | 6 pass, 1 fail: the simulator's 24 queries all **blocked by the egress final check** |
| Root cause | The MRN hard pattern matched the label `mrn:` followed by the *next field name* (`phone`) once tokens were stripped. Found by logging which rule fired (names only) |
| Fix | MRN value must contain a digit and stay on one line; placeholder stripping made exact. Regression tests added |
| Live run (dev machine) | Seed 10 tenants in 26 s · attack **11/11 defended** · simulate 60 concurrent sessions clean · demo 13 steps complete |
| Gate | ruff ✅ · mypy `--strict` ✅ · **379 tests** ✅ · **95.7%** coverage |
| **R0 acceptance** (fresh clone) | `./run.sh` 126 s → re-run idempotent → `attack` 11/11 → `simulate` ok → `demo` complete → `test` 379 pass |

## 2. Decisions

| Decision | Why |
|---|---|
| One `Stack` abstraction; same kit code runs live and in-process | Tests prove what reviewers will run |
| Demo and attack create **fresh disposable tenants** each run | Seeded data is never mutated; runs can repeat |
| Simulator is read-only on seeded tenants | Safe to run any number of times |
| Tenants/users created by an operator path, not a public API | B2B onboarding; no self-signup attack surface |
| Random seeded passwords, written once to `.secrets/` (0600) | No secrets in the repo |
| Canary word per tenant | Cross-tenant leakage is checkable with one string match |
| Attack runner treats any runner crash as BREACHED, exits 1 | A broken check can't look like a pass |
| Docker cut | Our services refuse non-loopback binds; a container needs `0.0.0.0`. Stricter default wins |
| Small client CLI cut | Swagger UI + `curl` examples in README cover it |

## 3. What works now (whole project)

| Command | Result |
|---|---|
| `./run.sh` | Setup + 3 services + 10 seeded tenants + logins table |
| `./run.sh demo` | BYOK → store → retrieve → query → rotate → contain → crypto-shred |
| `./run.sh attack` | A1–A4, 11 live attacks, all defended |
| `./run.sh simulate` | 10 tenants × 3 users × 2 sessions, isolated |
| `./run.sh verify` | 379 tests, ~96% coverage |

## 4. Open points

- Simulator branch coverage is 66% (its failure branches only fire when isolation breaks).
- Hash-embedder scores can tie or be 0; retrieval quality isn't a security claim.
- Everything in README §4 "Residual risk".
