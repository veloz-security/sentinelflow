# SentinelFlow Implementation Readiness

[한국어](./IMPLEMENTATION_READINESS.ko.md)

Last updated: 2026-07-20

## 1. Readiness statement

SentinelFlow has moved from architecture readiness into integrated implementation and release stabilization. The Gateway-first data plane, control-plane services, database, administrator UI, dispatcher/executor boundary, recovery/export/observability tooling, and test harnesses exist in the shared workspace. This is not yet a complete v0.1 release claim.

Tasklist completion remains stricter than code presence. Only `M0-001`, `M0-002`, `M0-009`, `M0-015`, `M0-017`, and `M0-019` currently satisfy all deliverables and prerequisites. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520` is a published baseline and an external clean clone passed `make check`; the post-repair CI rerun is still pending, M0 is not complete, and therefore downstream M1–M10 checkboxes remain open even where local implementation evidence is strong.

## 2. Frozen implementation baseline

- `cmd/gateway` is the primary HTTP sensor and reverse proxy for one fixed private upstream.
- `gateway-http-v1`, `auth-event-v1`, source health, sender checkpoints, and the retry-safe `event-batch-v1` envelope are the v0.1 input contracts.
- Internal requests bind the endpoint and bounded sender header in HMAC; Gateway and auth producers each expose loss, and record time outside +60 seconds/-5 minutes is non-enforcing.
- Nginx/Syslog/firewall-log adapters, raw packet sensing, and `http-deny-v1` are post-v0.1 work.
- The request path is independent of PostgreSQL, GPT-5.6, policy validation, administrator approval, and nftables.
- GPT uses explicit `gpt-5.6-sol` through the Responses API with strict Structured Outputs and no tools.
- AI output remains untrusted and the accepted `nft-blacklist-v1` exact-artifact HIL path remains the only adaptive enforcement path.
- The Gateway has no `NET_ADMIN`; only a namespace-sharing executor owns it, and a minimal non-AI dispatcher with a restricted authorized-operation view may authorize typed add, revoke, or read-only inspect artifacts over a private UDS.
- Executor bootstrap owns only `inet sentinelflow`, preserves foreign tables, verifies an exact existing schema without TTL refresh, and fails closed without repair on partial, extra, duplicate, or drifted owned state.
- Dispatcher capabilities, executor-signed results, protected-range/live-schema contracts, HIL snapshots, and demo-history manifests use separate Ed25519 keys where applicable, RFC 8785/JCS bytes, golden vectors, and replay-safe two-phase journaling.
- The asserted demo profile stages signed history through distinct five-minute PostgreSQL importer and activator leases. Migration pins only distinct analysis/validation capability digests; one-shot services commit `NOLOGIN`/password-null/epoch-expired fencing before terminating peer sessions; the atomic consumer pair lasts exactly one hour and cannot be refreshed.
- Analysis and validation mount only their respective raw 32-byte capability and may attach/use only the exact unexpired activation. Expiry, partial state, drift, or wrong capability fails closed; recovery after expiry requires complete disposable profile/volume reset and a newly sealed run.
- Recovery reads back indeterminate state and never re-adds or refreshes a relative TTL; manual removal is a separate deterministic `nft-revoke-v1` artifact.
- Lifecycle inspection is a separately signed read-only `nft-inspect-v1` operation; native expiry remains a bounded real-time Linux gate.
- HIL challenges bind the exact session, operation, resource/version, validation snapshot, and artifact digests. The NFC-normalized reason and `reason_digest` first enter the consumed decision, not the challenge.
- Artifact-content digests are integrity values and non-unique lookup keys, not row, lifecycle, or authorization identities. Identical add or inspect bytes in a later workflow require fresh evidence-bound candidate, policy, validation, challenge, decision, authorization, schedule/action, and capability IDs.
- The management API distinguishes a successful HIL-authorizing validation snapshot from a typed terminal `latest_validation_attempt`. A migration-owned security-definer projection is executable only by the API role; raw attempt tables and prepared/terminal JSON remain denied, and claim/result mismatch fails closed through a generic `503` response.
- Migration 33 completes a queued analysis as audited `analysis_superseded` before provider claim/dead letter only when immutable history proves that version existed and the current incident advanced. It leaves the current incident unchanged; a truly missing aggregate remains unresolved `analysis_incident_missing` evidence.
- Incident detail binds `latest_analysis` to the evidence version captured by its base read, orders attempts only within that version, and preserves the captured binding across later statements so concurrent evidence advance cannot substitute a newer analysis.
- The frontend uses a CSP-safe static API-error decoder. Deployment pins one exact CSP without `'unsafe-eval'`; verification parses that header, scans every emitted production JavaScript chunk for dynamic code generation, and runs the built application in Chromium under the same header.
- Frontend/UI/UX implementation remains a separate workstream from Gateway, backend, AI, policy, executor, and infrastructure work.

Normative detail lives in [PRD.md](./PRD.md), [ADR.md](./ADR.md), and [TDD.md](./TDD.md). Work order and evidence-bound completion live in [TASKLIST.md](./TASKLIST.md) and [WBS.md](./WBS.md).

## 3. Implemented repository baseline

| Area | Implemented artifacts | Current evidence status |
| --- | --- | --- |
| Workflow and configuration | `AGENTS.md`, `.gitignore`, `.env.example`, typed safe configuration | Present; secret-bearing local files remain ignored and outside documentation evidence |
| Contracts | AI input/prompt/output, events, HIL/JCS, protected IPv4, nft base/live schema, UDS, capability/result, journal, history, and vectors | Contract-vector gate passed |
| Backend and data plane | Go `1.25.12`; Gateway, API, worker, detector, validator, dispatcher, executor, simulator, lifecycle, retention, recovery, export, metrics, and smoke commands | Backend format/vet/staticcheck/test/build gate passed across 88 `cmd`/`internal` packages |
| Database | PostgreSQL roles, SQL query sources/sqlc configuration, 33 up migrations, staged demo-history activation, repeated-content-digest identity, API-only validation-attempt projection, stale-analysis supersession, and verification fixtures | Final root PostgreSQL 17.10 33-migration/72-table verifier passed fresh/restart-noop, `33→24→33`, ACL, sqlc, digest-identity, projection, raw-access-denial, and supersession checks |
| Frontend | React/TypeScript/Vite/MUI administrator investigation, HIL, lifecycle, revocation, SSE, failure states, and strict production CSP | Final root verification reports 39 Vitest files/363 tests and deployment-CSP Chromium 1/1; release-level browser certification remains pending |
| Deployment | Application images, Compose topology with one-shot history importer/handoff/activator and isolated analysis/validation capability volumes, isolated networks/UDS/volumes, Prometheus | RUN25 fast covered the mutation/outage/restart path; a later macOS `--run-browser-qa` execution passed active/revoked browser QA using a fixed 61-second revoked-phase pre-hash login-window wait without login retry or limit change; default native-expiry and native host-ruleset evidence remain open |
| Operations | Backup/restore, minimized export, retention, observability, threshold report, performance harness | Recovery, export, observability, threshold, and performance-smoke evidence passed |
| Documentation | README plus strict English/`.ko.md` PRD, ADR, TDD, Tasklist, WBS, and readiness pairs | Updated from integrated evidence; documentation gates must be rerun after this change |

The AI contracts align with the official [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). This is contract evidence, not a live API result.

## 4. Verified local evidence

The following evidence was observed on 2026-07-18–19 from the current shared workspace:

| Gate | Observed result | Qualification boundary |
| --- | --- | --- |
| Host/toolchain | `Darwin 24.6.0 arm64`; Go `1.25.12`; Node `24.13.0`; npm `11.6.2`; Docker client/server `29.4.0`; Compose `5.1.2` | Development host, not the native Linux release host |
| Backend | Formatting, vet, staticcheck, tests, and all `cmd` builds passed across 88 packages; the published baseline's clean clone passed `make check` | The post-repair GitHub Actions CI run is pending |
| Contracts/security | Contract vectors, secret scan, `govulncheck`, and npm audit passed | Does not replace runtime lifecycle or Compose mutation E2E |
| Database | Final root PostgreSQL 17.10 verifier passed 33 migrations and 72 tables, including fresh/restart-noop, `33→24→33`, ACL, sqlc, recurring-content/fresh-authority, API-only terminal-attempt projection, raw-table denial, mismatch fail-closed behavior, and queued stale-analysis provider-free supersession/true-missing dead-letter cases; the published baseline's clean clone passed `make check` | The post-repair GitHub Actions CI run is pending |
| Recovery/export/observability | Backup/restore passed in 63.742s; minimized export, Prometheus configuration/runtime, and alert checks passed | Does not replace full Compose lifecycle E2E |
| nftables | Disposable namespace preflight plus executor targeted unit/race/integration/security checks passed; foreign-state preservation and verify-only restart behavior have evidence | macOS Docker VM evidence does not certify native host-nft invariance or the default real-expiry release run |
| Performance | Fixed five-second `500 RPS` smoke mode and outage correctness passed | The five-minute 4 GB reference-host release gate is unqualified on this 24 GB macOS host |
| Frontend local | Final root verification reports 39 Vitest files/363 tests and the production-CSP Chromium gate passing 1/1, including CSP-safe error decoding, exact deployment-header validation, and every-production-chunk dynamic-code-generation scan | The macOS fast Compose browser runner passed active/revoked action states, but complete release-level browser certification and screenshots are pending; frontend remains separate from backend/API completion |
| E2E harness | Root rerun passed demo helper 39/39 and shell-contract 6/6 (46 combined tests), including migrated-PostgreSQL evidence-SQL parse/zero-row preflight before the long coverage wait | Static/helper evidence does not replace native Linux release qualification |
| Supply chain | Full third run passed static 18/18, reproducible source SBOM with 354 packages/354 relationships, reproducible backend/PostgreSQL/Web images, runtime fail-fast probes, frozen Trivy/SPDX/evidence bindings for all four shipped images with zero CRITICAL findings, PostgreSQL fresh/migrate/restart/wrong-owner-fail-closed lifecycle, and cleanup; the published baseline's clean clone passed `make check` | The post-repair GitHub Actions CI run is pending |
| OpenAI smoke | Disabled and missing-key paths fail closed without a network request | No billable live request, provider response, model access, or live Structured Output is claimed |
| Compose E2E | RUN25 fast (log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`) passed pinned-image start/health, authority/private-origin isolation, exact 305-second coverage, all five scenarios, stable bindings, exact HIL add/inspect/revoke, digest-mismatch rejection, outage forwarding, restart/reconciliation, and cleanup; a later macOS `--run-browser-qa` execution passed active/revoked browser QA after a fixed 61-second pre-hash login-window wait in the revoked phase | `--fast` intentionally revokes the action and runs on macOS, so native kernel expiry and host-ruleset invariance remain unqualified; clean-checkout/CI remains pending |

The existing ignored local credential and generated demo-secret paths were not printed, copied into docs, or used for a billable call.

## 5. Remaining release inputs and blockers

| Input or gate | Needed for | Current state |
| --- | --- | --- |
| Committed clean baseline and CI rerun | `M0-006`, `M0-008`, downstream reproducibility, final merge train | Published commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`; an external clean clone was clean before/after and `make check` passed. The post-repair CI rerun remains pending |
| Live OpenAI opt-in result | `M0-005` callable-model/runtime evidence | Command exists and fails closed when disabled/missing; no live call was made |
| Dedicated 4 GB Linux runner or VM | Native host-nft diff, real kernel expiry, capability/recovery proof, five-minute performance | Not selected or verified |
| Compose mutation E2E | Exact signed-history activation → challenge/HIL → dispatcher → add/inspect/revoke/expiry lifecycle | RUN25 fast proves add, signed inspect, exact revoke, outage forwarding, restart/reconciliation, and cleanup; the later macOS browser runner proves active/revoked UI states. The default native-expiry run remains pending because the fast mode revokes instead of waiting for kernel expiry |
| Clean-input preflight | `scripts/check-clean-input.sh` copies tracked plus unignored candidate inputs into an external temporary snapshot before invoking its gate | Latest full run copied 905 candidate source files, recorded manifest SHA-256 `2c395c3c5e3d28e908513e3304f5896ac7ae1eebe9a88dc80c543fe8baa73150`, and passed `make check`; it is source-only pre-commit evidence, not committed-checkout, CI, Linux, or release evidence |
| Reusable isolated worktree pool | `M0-018` leaf reproducibility | Not established; the swarm used a shared workspace with scoped ownership |
| Live screenshots/submission/clean rehearsal | M9 packaging and release decision | Not produced or claimed |
| TLS certificate/key | Optional Gateway TLS mode | Intentionally absent |

These blockers must not be bypassed by weakening the accepted contracts or treating smoke evidence as release evidence.

## 6. Current implementation wave

The active wave is release stabilization after RUN25. Final root backend, PostgreSQL 17.10 33-migration/72-table, frontend CSP/unit/browser, contract-vector, and E2E helper/shell gates have targeted evidence; the published baseline also has clean-clone `make check` evidence. The next goals are the post-repair CI rerun, a serialized default native-expiry run on Linux, host-ruleset/performance qualification, release screenshots, and release packaging; fast Compose evidence does not certify native expiry. The detailed roster, wave ledger, ownership, and final gates are in [WBS.md](./WBS.md).

The current release classification is **Still implementing**. No branch, commit, push, pull request, tag, deployment, billable OpenAI call, or external submission is authorized by this document.

## 7. Verification commands

Implemented local gates:

```bash
make check-backend
make check-contracts
make check-database
make check-frontend
npm --prefix web run test:browser:functional:linux
npm --prefix web run test:browser:csp
make check-security
make check-observability
make check-export
make check-recovery
make check-nft-namespace
SENTINELFLOW_GATEWAY_PERF_MODE=smoke make check-gateway-performance
make check-docs
```

Pending release-sensitive gates:

```bash
make check-supply-chain
./scripts/check-demo-e2e.sh --fast
./scripts/check-demo-e2e.sh
make check-gateway-performance
```

The default performance command is the fixed five-minute release mode and must run on the documented 4 GB reference host. `--fast` skips only native TTL expiry and is not a release substitute. The OpenAI probe is intentionally omitted from automatic gates because it is billable and requires explicit opt-in.
