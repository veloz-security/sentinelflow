# SentinelFlow Implementation Readiness

[한국어](./IMPLEMENTATION_READINESS.ko.md)

Last updated: 2026-07-20

## Published research release (2026-10-07)

[v0.1.0-rc.1](https://github.com/veloz-security/sentinelflow/releases/tag/v0.1.0-rc.1) is published as an experimental research prerelease from `1ae56b965355bd82d051a4794db26c72d2bb704d`. [Exact-source hosted CI](https://github.com/veloz-security/sentinelflow/actions/runs/37592532654) passed all 11 jobs, including backend, database, frontend, recovery, fresh image security evidence, and deterministic packaging. The five uploaded asset digests and sizes match local verified outputs. M9-010, M9-011, M9-012, M9-013, and M9-014 are complete for this separate publication/maintenance scope. Full implementation-qualified v0.1 P0 prerequisites, final acceptance/performance rehearsal and release-capture obligations remain open; July runtime results have not been relabeled as fresh October qualification.

## Public research distribution checkpoint (2026-10-07)

SentinelFlow is owned by Veloz (벨로즈), whose official site is [sec.veloz.kr](https://sec.veloz.kr); the owner supplied [security@veloz.kr](mailto:security@veloz.kr) as the security contact. The owner requested public restructuring and release publication. `v0.1.0-rc.1` is an experimental research distribution, separate from the implementation-qualified v0.1 release. No production, customer, certification, or CVP approval claim is made. Runtime and enforcement contracts are unchanged.

Implementation checkpoint `b125adec66864c87f5d37f15049514381dd9e4f3` already committed migration 34 and the v2 expiry repair; [CI run 29709922172](https://github.com/veloz-security/sentinelflow/actions/runs/29709922172) passed all ten shards for that commit. Earlier references below to “current-tree” results describe the July 2026 snapshot, not a fresh October rerun. The release record must identify its own exact commit and verification. Existing P0 prerequisites and full v0.1 acceptance gates remain open until independently satisfied. See [release guide](./RELEASE.md), [research evidence](./RESEARCH.md), ADR-015, and M9-010.

Patch maintenance for public distribution follows ADR-016: Go `1.25.13`, `golang.org/x/text` `v0.39.0`, and same-major frontend dependency fixes require fresh backend (M9-011) and independent frontend (M9-012) verification. Existing safety contracts and the full release gates remain unchanged.

October verification: M9-011 passed the patched 88-package backend gate, fresh govulncheck, infrastructure contract 25/25, backend image build and an unprivileged read-only/no-network runtime probe. M9-012 passed npm audit (zero findings), 39 Vitest files/363 tests, CSP 1/1, 88 real browser tests, and Linux visual 4/4 after normalizing the optional npm peer. These standalone P1 maintenance tasks do not complete the original P0 prerequisite graph. M9-013 transfer and M9-010 experimental publication are verified.

Release image evidence refresh is tracked by M9-014 under ADR-016. The 2026-10-07 immutable scanner database replaces the expired July snapshot, while seven-day freshness, critical-vulnerability rejection, digest/metadata verification and image binding remain required. Leaf 3 owns only scripts/check-images.sh and scripts/supply-chain-policy{,.test}.mjs for this package; ROOT owns canonical documentation and final publication.

## 1. Readiness statement

SentinelFlow has moved from architecture readiness into integrated implementation and release stabilization. The Gateway-first data plane, control-plane services, database, administrator UI, dispatcher/executor boundary, recovery/export/observability tooling, and test harnesses exist in the shared workspace. This is not yet a complete v0.1 release claim.

Tasklist completion remains stricter than code presence. Within the original P0 graph, only `M0-001`, `M0-002`, `M0-009`, `M0-015`, `M0-017`, and `M0-019` currently satisfy all deliverables and prerequisites. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520` is a published baseline and an external clean clone passed `make check`; hosted CI run `29696139988` passed all ten shards for implementation checkpoint `5ef870155bc59e6ac3c30279a7cd8be8d0249887`, but `M0-006` and `M0-008` remain unchecked because `M0-003` and `M0-007` are unchecked prerequisites. M0 is not complete, and therefore original downstream P0 M1–M10 checkboxes remain open even where local implementation evidence is strong.

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
- The previously recorded lifecycle repair adds `execution-result-v2`: executor-signed millisecond `readback_started_at`/`readback_completed_at` form read-back lower/upper expiry bounds. Migration `000034_execution_result_v2_expiry_bounds` stores the bounds separately, preserves v1 historical records, rejects result/bound reuse, and binds only the original active read-back so later inspection cannot refresh TTL. Focused recovery-bundle and migration-chain tests verify signed v2 bracket/bound equality, exact replay without a second lifecycle mutation, and crash recovery of a persisted v2 terminal result; the backup preflight also validates v1/v2 shape and bounds. Current-tree Linux native v6 E2E additionally exited `0` with real kernel expiry, signed absent inspection, audit/recovery/forwarding convergence, and unchanged semantic host nftables after cleanup. This is runtime evidence, not a release authorization.
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
| Backend and data plane | Go `1.25.13`; Gateway, API, worker, detector, validator, dispatcher, executor, simulator, lifecycle, retention, recovery, export, metrics, and smoke commands | Backend format/vet/staticcheck/test/build gate passed across 88 `cmd`/`internal` packages |
| Database | PostgreSQL roles, SQL query sources/sqlc configuration, 34 up migrations including `000034_execution_result_v2_expiry_bounds`, staged demo-history activation, repeated-content-digest identity, API-only validation-attempt projection, stale-analysis supersession, and verification fixtures | The published final root PostgreSQL 17.10 33-migration/72-table verifier passed fresh/restart-noop, `33→24→33`, ACL, sqlc, digest-identity, projection, raw-access-denial, and supersession checks. The current M34 database-chain test passes its v2 bounds/no-reuse contract; it is not a native release result |
| Frontend | React/TypeScript/Vite/MUI administrator investigation, HIL, lifecycle, revocation, SSE, failure states, and strict production CSP | Final root verification reports 39 Vitest files/363 tests and deployment-CSP Chromium 1/1; release-level browser certification remains pending |
| Deployment | Application images, Compose topology with one-shot history importer/handoff/activator and isolated analysis/validation capability volumes, isolated networks/UDS/volumes, Prometheus | Current-tree Linux native v6 E2E exited `0` with real TTL expiry, signed absence, audit/recovery/forwarding convergence, and semantic host nftables unchanged after cleanup; fast browser QA exited `0` with sanitized active/revoked screenshots, which remain non-release UI evidence |
| Operations | Backup/restore, minimized export, retention, observability, threshold report, performance harness | Recovery, export, observability, threshold, and performance-smoke evidence passed; a current-tree five-minute 4 GB Linux performance gate exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage overhead `436us` |
| Documentation | README plus strict English/`.ko.md` PRD, ADR, TDD, Tasklist, WBS, and readiness pairs | Updated from integrated evidence; documentation gates must be rerun after this change |

The AI contracts align with the official [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). This is contract evidence, not a live API result.

## 4. Verified local evidence

The following evidence was observed on 2026-07-18–19 from the current shared workspace:

| Gate | Observed result | Qualification boundary |
| --- | --- | --- |
| Host/toolchain | `Darwin 24.6.0 arm64`; Go `1.25.12`; Node `24.13.0`; npm `11.6.2`; Docker client/server `29.4.0`; Compose `5.1.2` | Development host, not the native Linux release host |
| Backend | Formatting, vet, staticcheck, tests, and all `cmd` builds passed across 88 packages; the published baseline's clean clone passed `make check`; hosted CI run `29696139988` passed the backend shard | Native Linux release-host qualification remains separate |
| Contracts/security | Contract vectors, secret scan, `govulncheck`, and npm audit passed | Does not replace runtime lifecycle or Compose mutation E2E |
| Database | Final root PostgreSQL 17.10 verifier passed 33 migrations and 72 tables, including fresh/restart-noop, `33→24→33`, ACL, sqlc, recurring-content/fresh-authority, API-only terminal-attempt projection, raw-table denial, mismatch fail-closed behavior, and queued stale-analysis provider-free supersession/true-missing dead-letter cases; the published baseline's clean clone passed `make check`; hosted CI run `29696139988` passed the database shard | Native Linux release-host qualification remains separate |
| Recovery/export/observability | Backup/restore passed in 63.742s; minimized export, Prometheus configuration/runtime, and alert checks passed. A focused v2 recovery-bundle test verifies signed read-back brackets against persisted bounds, and backup preflight validates their v1/v2 representation | Does not replace full Compose lifecycle E2E or a full v2 backup/restore runtime qualification |
| nftables | Disposable namespace preflight plus executor targeted unit/race/integration/security checks passed; current-tree Linux native v6 E2E exited `0` after real TTL expiry and signed absence, with semantic host nftables unchanged after cleanup | This runtime evidence does not itself authorize release or replace current-SHA CI |
| Performance | Fixed five-second `500 RPS` smoke mode and outage correctness passed; current-tree five-minute 4 GB Linux release gate exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage overhead `436us` | This runtime evidence does not itself authorize release or replace current-SHA CI |
| Frontend local | Final root verification reports 39 Vitest files/363 tests and the production-CSP Chromium gate passing 1/1, including CSP-safe error decoding, exact deployment-header validation, and every-production-chunk dynamic-code-generation scan; fast browser QA exited `0` with sanitized active/revoked captures | Captures are non-release UI evidence; complete release-level browser certification/screenshots remain pending and frontend remains separate from backend/API completion |
| E2E harness | Root rerun passed demo helper 39/39 and shell-contract 6/6 (46 combined tests), including migrated-PostgreSQL evidence-SQL parse/zero-row preflight before the long coverage wait. The current bounded diagnostic reports redacted lifecycle state/result/audit evidence before cleanup | Static/helper evidence and the new diagnostic do not replace a rerun and passing native Linux release qualification |
| Supply chain | Full third run passed static 18/18, reproducible source SBOM with 354 packages/354 relationships, reproducible backend/PostgreSQL/Web images, runtime fail-fast probes, frozen Trivy/SPDX/evidence bindings for all four shipped images with zero CRITICAL findings, PostgreSQL fresh/migrate/restart/wrong-owner-fail-closed lifecycle, and cleanup; the published baseline's clean clone passed `make check`; hosted CI run `29696139988` passed the supply-chain shard | Native Linux release-host qualification remains separate |
| OpenAI smoke | Disabled and missing-key paths fail closed without a network request; one explicit billable, synthetic, non-mutating `openai_responses`/`gpt-5.6-sol` attempt returned `status=ok` with one evidence reference and schema-valid command digests | The probe has no persistence, HIL, dispatcher, or executor path and does not by itself authorize release |
| Compose E2E | RUN25 fast remains fast-path evidence. Current-tree Linux native v6 E2E exited `0` and proved real kernel expiry, signed absent inspection, audit/recovery/forwarding convergence, and semantic host nftables unchanged after cleanup. Fast browser QA exited `0` with sanitized active/revoked captures | Fast browser captures remain non-release UI evidence; current-SHA clean-checkout/CI, final release captures/submission evidence, and release decision remain open |

The existing ignored local credential and generated demo-secret paths were not printed, copied into docs, or used for a billable call.

## 5. Remaining release inputs and blockers

| Input or gate | Needed for | Current state |
| --- | --- | --- |
| Committed clean baseline and CI | `M0-006`, `M0-008`, downstream reproducibility, final merge train | Published commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`; an external clean clone was clean before/after and `make check` passed. Hosted CI run `29696139988` passed all ten shards for `5ef870155bc59e6ac3c30279a7cd8be8d0249887`; Tasklist prerequisite completion remains separate |
| Live OpenAI opt-in result | `M0-005` callable-model/runtime evidence | One explicit billable, synthetic, non-mutating `openai_responses`/`gpt-5.6-sol` call returned `status=ok`; `M0-005` remains open because its `M0-004` prerequisite is unchecked |
| Dedicated 4 GB Linux runner or VM | Native host-nft diff, real kernel expiry, capability/recovery proof, five-minute performance | Current-tree native v6 E2E and five-minute performance gate both exited `0`; v6 proves bounded v2 expiry/signed absence/recovery/forwarding/audit plus semantic host invariance, and performance reports `GATE_VERDICT=pass`, p95 `533us`, outage `436us` |
| Compose mutation E2E | Exact signed-history activation → challenge/HIL → dispatcher → add/inspect/revoke/expiry lifecycle | Current-tree native v6 E2E exited `0` and proved expiry plus signed absence, audit/recovery/forwarding convergence and semantic host invariance; this does not replace final clean-checkout/CI or release decision |
| Clean-input preflight | `scripts/check-clean-input.sh` copies tracked plus unignored candidate inputs into an external temporary snapshot before invoking its gate | Latest full run copied 905 candidate source files, recorded manifest SHA-256 `2c395c3c5e3d28e908513e3304f5896ac7ae1eebe9a88dc80c543fe8baa73150`, and passed `make check`; it is source-only pre-commit evidence, not committed-checkout, CI, Linux, or release evidence |
| Reusable isolated worktree pool | `M0-018` leaf reproducibility | Not established; the swarm used a shared workspace with scoped ownership |
| Live screenshots/submission/clean rehearsal | M9 packaging and release decision | Fast QA produced sanitized active/revoked screenshots only; final release screenshots, submission evidence, and release decision are not produced or claimed |
| TLS certificate/key | Optional Gateway TLS mode | Intentionally absent |

These blockers must not be bypassed by weakening the accepted contracts or treating smoke evidence as release evidence.

## 6. Current implementation wave

The active wave is release stabilization after RUN25. Final root backend, published PostgreSQL 17.10 33-migration/72-table, frontend CSP/unit/browser, contract-vector, and E2E helper/shell gates have targeted evidence; the previously recorded M34/v2 implementation adds bounded expiry persistence/diagnostics with passing focused unit, contract, and database-chain tests. The published baseline also has clean-clone `make check` evidence and hosted CI run `29696139988` passed all ten shards for `5ef870155bc59e6ac3c30279a7cd8be8d0249887`. A serialized Linux native v6 rerun passed native expiry, host-ruleset invariance, and the 4 GB performance qualification; a one-attempt billable live `openai_responses`/`gpt-5.6-sol` probe returned `status=ok` without control-plane mutation. Remaining goals are current-SHA clean-checkout/CI, release screenshots/submission evidence, and release packaging/decision. Fast Compose browser evidence remains non-release UI proof. The detailed roster, wave ledger, ownership, and final gates are in [WBS.md](./WBS.md).

Full implementation-qualified v0.1 remains **Still implementing**; experimental research distribution follows ADR-015. No branch, commit, push, pull request, tag, deployment, billable OpenAI call, or external submission is authorized by this document.

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
