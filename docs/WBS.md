# SentinelFlow Five-Day Gateway-First Leaf-Agent Swarm WBS

**English** | [한국어](WBS.ko.md)

> Execution window: 2026-07-18 through 2026-07-22 (Asia/Seoul)
>
> Target: implementation-complete single-node Gateway-first hybrid SentinelFlow v0.1 release candidate
>
> Canonical completion source: [TASKLIST.md](./TASKLIST.md)
>
> Execution state: release stabilization in progress; Tasklist completion remains evidence- and prerequisite-bound

## 1. Rebaseline decision

The 2026-07-18 Gateway-first queue superseded the unexecuted 2026-07-17 log-first queue. The Gateway-first swarm has since produced an integrated implementation and local verification evidence in the shared workspace. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520` is a published baseline and an external clean clone passed `make check`; hosted CI run `29696139988` then passed all ten shards for implementation checkpoint `5ef870155bc59e6ac3c30279a7cd8be8d0249887`. Existing Syslog/parser Task IDs retain their meanings as P2 optional adapters; they do not enter this five-day queue or any release gate.

The release builds an inline but unprivileged reverse-proxy data plane in front of one fixed private upstream. It observes HTTP requests directly, emits privacy-minimized events asynchronously, accepts a narrow authenticated application-auth event, and preserves the existing deterministic detection, evidence-bound AI command, ordered validation, exact-artifact administrator HIL, and isolated nftables executor model. It is not a general-purpose origin server, raw-packet IPS, or adaptive L7 enforcement system.

This is an implementation schedule, not another planning exercise. The result must be runnable code, tests, browser evidence, recovery/security evidence, and synchronized documentation. A scaffold, mock-only UI, synthetic shortcut, or smaller demo MVP does not satisfy the release contract.

## 2. Concurrency and continuous relay

The runtime has four slots:

- `ROOT`: one long-running orchestration, contract ownership, integration, documentation, and release-control slot;
- leaf workers: three concurrent slots, always filled with dependency-ready, non-overlapping implementation, independent-certification, or repair packages;
- queue: six waves per day × three workers × five days = exactly 90 initial leaves (`A001`~`A090`): 75 Tasklist-completion leaves and 15 support/attack-corpus/repair leaves that never complete a Tasklist ID by themselves;
- leaf duration: one to four hours; split or replace any leaf that cannot hand off a reviewable increment within four hours;
- relay duration: continue 18–24 hours per day when runtime continuity permits, checkpointing every accepted integration;
- extension: failures create `Axxx-Rn` or `A091+` repair leaves and extend the calendar rather than reducing P0 scope.

`ROOT` keeps `READY`, `RUNNING`, `REVIEW`, `RETRY`, `BLOCKED`, and `DONE` queues, prepares the next prompts before a wave ends, reviews every diff, integrates in dependency order, and reruns the affected shard. Agent status is never completion evidence.

### 2.1 Current execution checkpoint

Snapshot: 2026-07-20 (Asia/Seoul). The 90-leaf table remains the dependency and ownership plan; runtime repair/certification leaves may use descriptive names after their original wave. The current four-slot roster is:

| Slot | Active package | Ownership | Current status |
| --- | --- | --- | --- |
| `ROOT` | Orchestration, integration, release control | Shared contracts, final gates, cross-package decisions | Running; validates every handoff and retains publish authority |
| Leaf 1 | `compose_browser_qa` | Local-only Compose browser runner and exact active/revoked action-state evidence | Fast browser QA exited `0` and produced sanitized active/revoked captures. It remains non-release UI evidence; final release certification/screenshots remain pending |
| Leaf 2 | `clean_checkout_gate` | Clean checkout and CI reproducibility; no publication authority | Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520` was externally cloned into a clean temporary directory; status was clean before/after and `make check` passed. Hosted CI run `29696139988` passed all ten shards for `5ef870155bc59e6ac3c30279a7cd8be8d0249887`; Linux and release gates remain open |
| Leaf 3 | `expiry_bounds_v2_repair` | Executor result contract, dispatcher persistence, migration 34, bounded lifecycle diagnostics; frontend excluded | Current-tree Linux native v6 E2E exited `0`: bounded v2 TTL expiry, signed absence, audit/recovery/forwarding convergence, and unchanged semantic host nftables after cleanup are observed; release remains open |

The completed `docker_none_semantics_review` independently constrained the compatibility rule used by `RUN4`: a running `network_mode:none` container is acceptable only when its endpoint ID is exactly bound to membership in Docker's built-in `none` network and address, MAC, DNS, alias, and IPAM state are all inert. This review is a precondition for the repair, not E2E success evidence.

Execution waves now stand as follows:

| Wave | State | Integrated evidence / remaining boundary |
| --- | --- | --- |
| Contract and implementation waves | Published baseline plus current local repair and hosted CI | Gateway-first contracts, backend/control plane, published 33 migrations including provider-free stale queued-analysis supersession, staged signed-history activation, repeated-content-digest identity, and API-only projections, UI, dispatcher/executor, recovery, export, observability, and test harnesses exist. The current uncommitted M34 repair adds `execution-result-v2` signed read-back bounds, no reuse/no TTL refresh persistence, and bounded diagnostics with focused tests passing; current-tree native v6 E2E exited `0` with real expiry, signed absence, recovery/forwarding/audit convergence, and semantic host invariance. `d66c4b8a4842ad4226cb741e35331ba5b9068520` has older clean-clone/CI evidence, not current-SHA CI |
| Frontend contract certification | Final root and hosted CI passed | Final root rerun reports 39 Vitest files/363 tests and deployment-CSP Chromium 1/1. The CSP-safe error decoder, exact header parser, and all-production-chunk dynamic-code-generation scan exist. A later macOS runner passed active/revoked browser QA, and hosted CI run `29696139988` passed functional-browser and pinned Linux visual-baseline gates; full frontend state/accessibility and release-screenshot evidence remain pending |
| Backend and safety certification | Published final root reruns passed; M34 focused checks passed | The backend 88-package gate and published PostgreSQL 17.10 33-migration/72-table verifier passed final root reruns, including fresh/restart-noop, `33→24→33`, ACL, sqlc, repeated-content identity, API projection, and stale-analysis supersession checks. M34 v2 bounds/no-reuse database-chain and focused contract/unit checks pass, but native Linux and release-duration conditions remain open |
| Compose E2E repair/certification | Current-tree native v6 and fast browser QA passed; release qualification open | Native v6 exited `0` with real TTL expiry, signed absent inspection, audit/recovery/forwarding convergence, and semantic host nftables unchanged after cleanup. Fast browser QA exited `0` with sanitized active/revoked captures, but remains non-release UI evidence |
| Supply chain and final release | Prior full supply-chain, clean-clone, and hosted-CI evidence retained; final release open | The current-tree five-minute 4 GB Linux performance gate exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage `436us`; a one-attempt billable `openai_responses`/`gpt-5.6-sol` synthetic probe returned `status=ok` without control-plane mutation. Remaining goals are current-SHA clean-checkout/CI, final release captures/submission evidence, and release decision |

Tasklist checkboxes remain stricter than this wave ledger. Only `M0-001`, `M0-002`, `M0-009`, `M0-015`, `M0-017`, and `M0-019` are complete. Hosted CI now provides the independent quality-gate deliverables for `M0-006` and `M0-008`, but their unchecked `M0-003` and `M0-007` prerequisites keep the Tasklist items open. `M0-005` now has a successful live OpenAI result but remains open because `M0-004` is unchecked; current-SHA clean-checkout/CI, final release evidence, and decision remain incomplete. Therefore the current release classification is **Still implementing**.

The prior full supply-chain gate completed and cleaned up before Docker-mutating E2E work. The next default native-expiry rerun must capture a fresh global baseline, emit the bounded redacted v2 lifecycle diagnostic before cleanup, and remain serialized from any other Docker-mutating gate.

## 3. Frozen implementation contracts

### 3.1 Gateway data plane

- Protected application traffic reaches the Gateway directly. Cleartext accepts only origin-form HTTP/1.1; optional TLS terminates there and advertises/accepts only ALPN `http/1.1`, with HTTP/2/h2c and every other target form rejected. There is no Nginx identity hop, and trusted proxy chains are post-v0.1.
- One startup-fixed `http://` upstream, configured non-broad RFC 1918 origin CIDRs, and a normalized ASCII host allowlist are supported. Every DNS result and dialed address must be IPv4 inside those CIDRs; public, loopback, link-local, metadata, IPv6, mixed, and rebinding answers fail closed, environment proxies are disabled, and the origin is unreachable from the public/client network.
- The socket peer is the canonical client identity. Inbound forwarding and SentinelFlow request/trace headers are discarded; the Gateway regenerates forwarding headers plus `X-SentinelFlow-Request-ID` and `X-SentinelFlow-Trace-ID`, propagates both IDs to `demo-app`, and emits those same IDs once in `gateway-http-v1`.
- `gateway-http-v1` uses fixed `protocol: HTTP/1.1`. Exact path data exists only in a bounded transient classifier; persistence and AI receive only `route_label`, `path_catalog_version=path-catalog-v1`, and one fixed `suspicious_path_id`, never query strings, bodies, cookies, Authorization values, exact paths, or raw credentials.
- Limits are header `32 KiB`, body `10 MiB`, header timeout `5s`, upstream timeout `30s`, and idle timeout `60s`. Go `net/http` parser tests and a byte-crafted differential raw-socket origin-observation harness must prove that rejection and origin interpretation cannot desynchronize.
- Gateway and `demo-app` event producers each own a health-only durable checkpoint, random 128-bit per-boot sender epoch, monotonic sequence, and authenticated `source-health-v1`; it is not an event spool. Delivery uses queue capacity `10,000`, batch maximum `100`/`256 KiB`, flush `100ms`, and endpoint-bound `POST /internal/v1/gateway-events` or `/auth-events`. Retry preserves exact body/epoch/batch/sequence. Control-plane outage forwards otherwise-valid traffic, creates no new block, and exposes gaps/degradation/loss that cannot support enforcement.
- Exact `X-Sentinel-Sender-ID` must match the body sender and endpoint/key mapping. Both endpoints use an endpoint-bound Base64 HMAC key decoding to at least 32 random bytes, an exact 128-bit unpadded-Base64url nonce, and asymmetric event skew of at most `+60s` future or `5m` past. Bounded syntax/sender/endpoint/time/body checks and constant-time HMAC verification precede atomic authenticated nonce insertion and the all-or-nothing `202`; invalid auth consumes no replay capacity. Auth binding lasts at most `5m` and requires request ID, trace ID, canonical IP, exact `service_label=demo-app`, and login-route agreement.
- The Gateway has no database credential/reachability and never receives `NET_ADMIN`; only the executor sidecar that shares its network namespace receives namespace-local `CAP_NET_ADMIN`.

### 3.2 Detection and lifecycle defaults

- path scan: `8` distinct suspicious paths per canonical source IP in `60s`;
- request burst: `120` requests per source IP in `10s`;
- brute force: `10` login-route `401/403` responses per source IP in `60s`;
- credential stuffing: `20` failures and `8` distinct keyed account hashes per source IP in `5m`;
- correlation: canonical source IP in `5m`; close after `15m` quiet and reopen within `30m`;
- retention: all normalized events/evidence `7d`, incidents/AI outputs/policies `30d`, audit `90d`.

### 3.3 AI, HIL, and executor defaults

- OpenAI: `gpt-5.6-sol` Responses API, immutable checked-in schema and prompt, strict Structured Outputs, `store: false`, reasoning `medium`, no tools, at most `50` stable sorted-unique evidence refs/`12 KiB` deterministic input, `2,048` output tokens, `30s` timeout, concurrency `2`, and at most two attempts with one retry only for classified `408/409/429/5xx`. Overflow or missing evidence fails before a call; it is never truncated, dropped, or reordered. The configurable demo daily operator budget USD `10` fails closed when exhausted.
- Command and digests: exactly one `nft-blacklist-v1` candidate targets `inet sentinelflow blacklist_ipv4`; structured `ttl_seconds` is `60..86400` default `1800`, candidate TTL is `[1-9][0-9]*(s|m|h)`, and canonical output uses the largest exact unit. Policy, sorted evidence, validation, normalized non-empty reason, and HIL authorization use versioned RFC 8785 JCS plus domain-separated lowercase `sha256:` digests and byte-exact vectors. Artifact-content digests are non-unique integrity/lookup values rather than row/lifecycle/authority identities; repeated command or inspect bytes require fresh evidence-bound IDs, authorization, and capability. Validation validity is `5m` and impact lookback is `24h`.
- Investigation projection: a successful HIL-authorizing validation snapshot and a terminal fail-closed `latest_validation_attempt` are distinct API contracts. Only the API role may execute the bounded typed projection; raw attempt tables and prepared/terminal JSON remain denied, and claim/result mismatch fails closed as a generic `503` rather than leaking inconsistent state. Frontend presentation is a separate dependent workstream.
- History: any verified, pending, or untrusted successful auth, source-loss interval, or insufficient history blocks approval. Only the asserted demo/test profile accepts signed JCS `demo-history-v1` bound to exact `demo-app` dataset rows/IDs, record count/digest, source-health digest, `path-catalog-v1`, and deterministic 24-hour coverage. Distinct five-minute importer and activator PostgreSQL leases are committed to inert two-phase role/session fences; one atomic pair gives analysis and validation separate digest-bound capabilities for exactly one hour. Consumers attach/use only, no refresh exists, and expiry requires full disposable profile/volume reset and reseal. Production rejects the entire mechanism.
- Protected target: versioned `protected-ipv4-v1` and its digest reject unspecified, loopback, private, link-local, CGNAT, benchmarking, documentation, multicast, reserved, origin/Gateway/executor, management/current-administrator-path targets, and every IPv6 address. `PROTECTED_CIDRS` is additive. An isolated demo may allow only RFC 5737 after namespace and host-ruleset-diff assertions; the exact digest binds validation, HIL, and capability.
- Administrator: Argon2id PHC minimum memory `64 MiB`, time `3`, parallelism `2`, salt `16` bytes, key `32` bytes; opaque server-side session max `8h`/idle `30m`; independent `authenticated_at`; rotation never refreshes it; password step-up is required after `15m`. Origin-checked synchronizer CSRF and a random session/operation/exact-artifact-bound, single-use challenge valid at most `5m` protect approve/reject/revoke, with idempotency and limit `5/min/session`.
- Authority bridge: only minimal non-AI `cmd/dispatcher` reads the restricted approved-outbox view and Ed25519 dispatch key. Add, revoke, and read-only inspect use ≤`60s` single-use RFC 8785 JCS capabilities and separately signed results. The private UDS permits exactly one 4-byte unsigned big-endian length-prefixed request and one response, each at most `16 KiB` with `2s` deadlines, then closes; strict schemas/vectors reject zero, short, oversized, second, trailing, unknown, duplicate, non-canonical, replayed, or invalidly signed input.
- Executor bootstrap and journal: before Gateway traffic, executor alone installs byte-exact `nft-base-chain-v1`, verifies raw SHA-256 `2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488` plus a separately pinned canonical live read-back digest, and exposes readiness. Before mutation, the checksummed length/version-delimited full-request `started` record stores exact capability/signature/artifact bytes and fsyncs file plus parent directory; signed terminal results are fsynced. Torn/corrupt tails or fsync uncertainty fail readiness without truncation. Duplicates and recovery use signed read-only inspect only, never invoke add again or refresh TTL; `nft-revoke-v1` has separate authorization and deletes only.
- Time: deterministic application time may drive fixtures, history, validation, and approval tests, but the minimum `60s` nftables timeout must expire under actual kernel/monotonic time. No fake clock or time namespace may be used as kernel-expiry evidence.

## 4. Leaf contract and ownership

Every leaf receives a base commit, exclusive writable paths, frozen input contracts, Tasklist IDs, deliverable, positive/negative test command, stop condition, and handoff target. It returns a focused commit or explicit no-change finding, changed paths, exact test output, failure-path evidence, compatibility impact, and remaining risk.

| Domain | Owned paths and boundary |
| --- | --- |
| `FOUNDATION` | Go module, commands, config, build/CI; one dependency-lock owner |
| `CONTRACT` | `gateway-http-v1`, `auth-event-v1`, OpenAPI, AI/policy/command/HIL/executor schemas; `ROOT` approves changes |
| `GATEWAY` | Reverse proxy, peer identity, header policy, async emitter; never AI, UI, policy, or `NET_ADMIN` |
| `DATA` | `db/`, migrations, repositories, retention, outbox; one migration owner |
| `DETECT` | Aggregation, detector, correlation, state machine; fixed-clock contracts |
| `AI` | Compact input and untrusted structured analysis/command candidate; no validation, approval, execution, or UI |
| `POLICY` | Parser, AST, canonical bytes/digests, protected targets, impact, validation snapshots |
| `EXECUTOR` | Isolated authenticated transport, fixed nft invocation, read-back, expiry/recovery |
| `API` | Admin auth, REST/SSE, HIL endpoints, health/degradation DTOs; no frontend implementation |
| `FRONTEND` | `web/` only: IA, components, client state, accessibility, and browser tests; no backend/domain changes |
| `OPS-QA` | Compose/network isolation, benchmark, security, recovery, browser, supply-chain, release evidence |
| `DOCS` | README and bilingual documents, updated only from integrated evidence |

The merge train is `contract → data/migration → Gateway/producer/domain → API/SSE → frontend → Compose/integration → independent security/recovery/browser certification → evidence/docs`. Backend and frontend leaves never share ownership; integration leaves verify both without completing missing work for either.

## 5. Release gates

1. **Day 1:** scope and ADR-012/ADR-013 architecture, build/contract foundations, sender/checkpoint/HMAC/skew and request/trace contracts, storage/outbox/auth-event boundaries, Linux/nft raw/live-schema and administrator challenge contracts, fixed-upstream proxy core, and independent frontend shell are reviewable; no later leaf ran before its prerequisite.
2. **Day 2:** asynchronous Gateway/`demo-app` events, source health, private-origin and Go-parser/differential-raw-socket protocol/security/load gates, all four deterministic detectors, simulator primitives, and immutable-schema/prompt/no-truncation AI adapter/provenance pass.
3. **Day 3:** AI degradation/adversarial/golden checks and the complete ordered policy pipeline through JCS policy/evidence/validation digests, `protected-ipv4-v1`, staged non-renewable signed history, immutable snapshot, and bypass tests pass; merge-train, worktree, migration-recovery, and evidence-ledger foundations are integrated.
4. **Day 4:** challenge/password-step-up exact HIL, hardened administrator session, executor-only base-chain bootstrap, strict-UDS add/revoke/inspect, full torn-record-safe journal, signed read-only recovery, real-kernel expiry, audit, safety-path E2E, investigation/SSE API, and contract-backed frontend review states pass; the Gateway still has no executor privilege.
5. **Day 5:** real frontend integration, concrete-history simulators, Compose, private-origin/control-plane-outage E2E, contract/security/recovery/real-expiry/load/soak/browser suites, operational hardening, clean-checkout commands, evidence, and release regression pass. Any failed P0 extends the relay.

Canonical expanded gates include `UT-017~019`, `CT-009~010`, `IT-014~015`, `E2E-011~012`, `SEC-012~014`, and `REC-009~010` in addition to the existing suites.

## 6. Ninety-leaf implementation queue

The waves are dependency targets, not fixed wall-clock starts. Cross-leaf prerequisites must be completed in an earlier wave. Multiple Tasklist IDs inside one leaf execute strictly left to right and share one owner; a same-wave sibling is never a prerequisite. `ROOT` may pull a later independent leaf forward, but it may not run a dependent leaf early or let two leaves own the same path.

Support leaves have no Tasklist completion IDs. They prepare bounded corpora, independent checks, or repair-ready evidence from already frozen inputs; they cannot satisfy a prerequisite, certify their own production code, or replace the canonical completion leaf.

### Day 1 — Baseline, contracts, storage, and proxy foundation

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D1-W1` | `A001` — `M0-001` → `M0-002`; freeze scope, then architecture decisions (`CONTRACT`, `DOCS`) | `A002` — read-only repository/decision inventory and conflict report; support only (`OPS-QA`) | `A003` — toolchain, PostgreSQL, browser, Linux namespace, and nft capability preflight; support only (`OPS-QA`) |
| `D1-W2` | `A004` — `M0-003` → `M0-006`; backend skeleton, then backend quality gate (`FOUNDATION`) | `A005` — `M0-009`; leaf queue and exclusive path ownership (`OPS-QA`) | `A006` — `M0-007` → `M0-008`; independent frontend skeleton, then browser/a11y quality gate (`FRONTEND`) |
| `D1-W3` | `A007` — `M0-017` → `M0-019`; measurable budgets, then Gateway boundary/defaults (`CONTRACT`) | `A008` — `M0-004` → `M0-005`; safe config, then callable-model preflight (`FOUNDATION`, `AI`) | `A009` — `M0-010`; shared schemas, mocks, and invalidation registry (`CONTRACT`) |
| `D1-W4` | `A010` — `M1-001` → `M1-009`; normalized Gateway/`demo-app` schemas, generated IDs, checkpoint/source-health, sender/endpoint HMAC/skew vectors (`CONTRACT`) | `A011` — `M0-013` → `M0-016`; Linux/nft probe, then raw/live-schema, strict-UDS, grammar/TTL contract (`EXECUTOR`, `OPS-QA`) | `A012` — `M0-015`; Argon2id/session/independent-reauth/challenge/CSRF/rate contract (`API`, `CONTRACT`) |
| `D1-W5` | `A013` — `M1-002` → `M1-003` → `M1-007`; migration, repository, and least-privilege DB roles (`DATA`) | `A014` — `M0-014`; transactional outbox/topology decision (`DATA`, `CONTRACT`) | `A015` — `M2-010` → `M2-011`; fixed-upstream proxy, regenerated request/trace IDs, direct-peer/header policy (`GATEWAY`) |
| `D1-W6` | `A016` — `M1-006`; transactional outbox, lease, retry, and dead letter (`DATA`) | `A017` — `M2-014`; `demo-app` auth-event HMAC ingest, checkpoint/source health, exact binding, keyed account hash (`API`) | `A018` — `M7-008`; independent design system and application shell (`FRONTEND`) |

### Day 2 — Gateway completion, deterministic detection, and frozen AI handoff

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D2-W1` | `A019` — `M2-012` → `M2-013`; same request/trace IDs, minimized observation, bounded async sender-ID/endpoint HMAC delivery and source health (`GATEWAY`) | `A020` — `M2-015`; private-origin network and direct-bypass proof (`OPS-QA`) | `A021` — `M0-011`; root merge train and sharded CI gates (`OPS-QA`) |
| `D2-W2` | `A022` — `M3-001`; fixed-window aggregation and exact detector defaults (`DETECT`) | `A023` — `M2-016` → `M2-017`; Go-parser/differential raw-socket desync suite, then `500 RPS` availability/load gate (`GATEWAY`, `OPS-QA`) | `A024` — `M1-005`; `7d`/`30d`/`90d` retention and restricted-value deletion (`DATA`) |
| `D2-W3` | `A025` — `M3-003`; brute-force detector boundary suite (`DETECT`) | `A026` — `M3-004`; path-scan taxonomy and detector (`DETECT`) | `A027` — `M3-005`; request-burst detector (`DETECT`) |
| `D2-W4` | `A028` — `M3-002` → `M3-006`; credential stuffing, then source-IP/`5m` Gateway/auth correlation (`DETECT`) | `A029` — `M8-001`; normal Gateway/`demo-app` checkpoint/source-health baseline simulator (`OPS-QA`) | `A030` — `M9-004`; MIT/public-notice verification (`DOCS`) |
| `D2-W5` | `A031` — `M4-001` → `M4-002`; immutable schema/prompt, stable evidence, no-truncation input, inspected Responses request/retry (`AI`) | `A032` — `M8-002` → `M8-005`; credential-stuffing, then brute-force simulator (`OPS-QA`) | `A033` — `M8-003`; path-scan simulator (`OPS-QA`) |
| `D2-W6` | `A034` — `M4-003` → `M4-004` → `M4-009`; strict analysis/command schema, provenance, and evidence-bound candidate (`AI`) | `A035` — `M8-004`; request-burst simulator (`OPS-QA`) | `A036` — `M3-007`; suppression and false-positive reasons (`DETECT`) |

### Day 3 — AI assurance and ordered policy validation

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D3-W1` | `A037` — `M5-001` → `M5-002`; constrained policy, then versioned RFC 8785 JCS/domain-separated digest and state (`POLICY`) | `A038` — `M3-008`; durable detector/correlator worker (`DETECT`) | `A039` — `M4-006`; injection and invented-evidence corpus (`AI`, `OPS-QA`) |
| `D3-W2` | `A040` — `M5-003` → `M5-005`; schema gate, then strict parser/AST/canonical bytes (`POLICY`) | `A041` — `M4-007`; versioned model/schema/grammar/operator budgets (`AI`) | `A042` — `M10-002`; threshold comparison and false-positive tuning (`DETECT`, `OPS-QA`) |
| `D3-W3` | `A043` — `M5-011` → `M5-004`; consistency, then versioned/digest-bound `protected-ipv4-v1` gate (`POLICY`) | `A044` — `M0-012`; reproducible leaf handoff and evidence ledger (`OPS-QA`) | `A045` — `M0-018`; recyclable worktrees and deterministic integration harness (`OPS-QA`) |
| `D3-W4` | `A046` — `M5-006` → `M5-007`; owned-set `nft --check`, then concrete signed `demo-app` dataset/`24h` impact gate (`POLICY`, `DATA`) | `A047` — `M1-008`; migration and backup/restore recovery (`DATA`, `OPS-QA`) | `A048` — `M3-009`; close `15m`/reopen `30m` state machine (`DETECT`) |
| `D3-W5` | `A049` — `M5-008` → `M5-010`; ordered audit, then JCS evidence/validation digests and immutable `5m` snapshot (`POLICY`) | `A050` — `M4-005`; typed AI outage/budget degradation (`AI`) | `A051` — `M4-008`; deterministic golden corpus and opt-in live smoke (`AI`, `OPS-QA`) |
| `D3-W6` | `A052` — `M5-009`; bypass, mutation, timeout, and TOCTOU negatives (`POLICY`, `OPS-QA`) | `A053` — parser/command mutation corpus and canonical-byte oracle; support only (`POLICY`, `OPS-QA`) | `A054` — protected-target/CIDR/impact edge corpus and expected-decision oracle; support only (`POLICY`, `OPS-QA`) |

### Day 4 — Exact HIL, isolated enforcement, API, and contract-backed UI

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D4-W1` | `A055` — `M6-001` → `M6-002` → `M6-014`; independent `authenticated_at`, challenge/reauth API, JCS reason/HIL authorization binding (`API`) | `A056` — challenge/reauth/concurrency/replay/rate/digest-swap vectors; support only (`API`, `OPS-QA`) | `A057` — strict UDS framing/schema/key/digest-mutation adversarial corpus; support only (`EXECUTOR`, `OPS-QA`) |
| `D4-W2` | `A058` — `M6-003` → `M6-009`; executor-only base-chain bootstrap/raw-live digests, strict-UDS signed add/revoke/inspect (`EXECUTOR`) | `A059` — `M6-013`; Argon2id/session/reauth/challenge/CSRF/replay/rate negatives (`API`, `OPS-QA`) | `A060` — administrator challenge/abuse-state model and typed failure-code oracle; support only (`API`, `OPS-QA`) |
| `D4-W3` | `A061` — `M6-004` → `M6-010` → `M6-005`; full fsynced journal, signed inspect/read-back, raw-live proof, real-kernel expiry/revoke (`EXECUTOR`) | `A062` — namespace/host diff, signed inspect, actual-`60s` expiry/revoke failure-injection harness; support only (`EXECUTOR`, `OPS-QA`) | `A063` — audit/full-journal torn-record/fsync/crash/recovery oracle; support only (`DATA`, `OPS-QA`) |
| `D4-W4` | `A064` — `M6-006` → `M6-011`; full JCS-digest/add-revoke-inspect lifecycle audit, then audit-write integrity (`DATA`, `API`) | `A065` — permission/reauth/challenge/loading/empty/error/success frontend fixtures; support only (`FRONTEND`) | `A066` — unauthorized SSE, replay-gap, and reconnect contract probes; support only (`API`, `OPS-QA`) |
| `D4-W5` | `A067` — `M7-001` → `M7-004`; reauth/challenge/inspect lifecycle API, then authorized SSE replay (`API`) | `A068` — `M6-007` → `M6-012`; signed read-only inspect reconciliation, then recovery/dead-letter alerts (`EXECUTOR`) | `A069` — cross-layer ID/JCS/digest/schema/contract drift auditor; support only (`CONTRACT`, `OPS-QA`) |
| `D4-W6` | `A070` — `M6-008`; challenge/HIL/strict-UDS/full-journal/inspect/real-expiry safety-path E2E (`OPS-QA`) | `A071` — `M7-011` → `M7-015` → `M7-012`; digest review, inert command preview, challenge/password-step-up decision UX (`FRONTEND`) | `A072` — `M7-009` → `M7-010`; incident list, then Gateway/auth/AI evidence detail (`FRONTEND`) |

### Day 5 — Integrated UI, simulation, operations, and release

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D5-W1` | `A073` — `M8-006`; staged importer/handoff/activator, separate one-hour consumer activations, executor bootstrap, strict UDS/full journal, real-kernel-expiry Compose integration (`OPS-QA`) | `A074` — `M7-003`; integrated exact-command/challenge review flow (`FRONTEND`) | `A075` — `M7-002` → `M7-007`; real-contract investigation, then SSE reconnect/gap UX (`FRONTEND`) |
| `D5-W2` | `A076` — `M9-001` → `M10-003` → `M10-007`; deployment, executor-bootstrap/real-expiry soak, torn-journal/DB restore proof (`OPS-QA`) | `A077` — `M7-013` → `M7-005`; signed-inspect/journal/audit components, then integrated lifecycle (`FRONTEND`) | `A078` — `M8-011`; raw-socket, AI-no-truncation, challenge/JCS/UDS/journal/expiry security suite (`OPS-QA`) |
| `D5-W3` | `A079` — `M7-006` → `M7-014`; complete UI states/a11y, then independent browser/visual/contract QA (`FRONTEND`, `OPS-QA`) | `A080` — `M8-007` → `M9-002`; full Gateway/HIL/inspect/real-expiry acceptance, then clean-checkout commands (`OPS-QA`, `DOCS`) | `A081` — `M8-009`; byte-exact HMAC, AI, JCS digest, UDS, journal, history, add/revoke/inspect compatibility (`CONTRACT`, `OPS-QA`) |
| `D5-W4` | `A082` — `M9-003`; sanitized current screenshots and topology (`FRONTEND`, `DOCS`) | `A083` — `M8-008` → `M10-006`; performance gate, then frontend performance/a11y/visual hardening (`FRONTEND`, `OPS-QA`) | `A084` — `M10-001` → `M10-004`; lifecycle observability, then retention/export operations (`DATA`, `OPS-QA`) |
| `D5-W5` | `A085` — `M9-005` → `M9-006` → `M10-005`; security evidence, status reconciliation, then supply-chain hardening (`OPS-QA`, `DOCS`) | `A086` — `M8-010`; full merge-train regression (`OPS-QA`) | `A087` — independent secret/license/evidence/README-claim audit; support only and any finding opens a repair leaf (`DOCS`, `OPS-QA`) |
| `D5-W6` | `A088` — `M9-009` → `M9-007` → `M9-008`; convergence audit, submission evidence, and release decision (`OPS-QA`, `DOCS`) | `A089` — security-failure reproduction and repair standby; support only, never a release approval (`OPS-QA`) | `A090` — browser/recovery/doc-parity reproduction and repair standby; support only, never a release approval (`FRONTEND`, `DOCS`, `OPS-QA`) |

The queue is topologically valid under the conservative rule that same-wave siblings are concurrent. `A088` is the only release-decision leaf and executes its three IDs left to right after every external prerequisite completed by `D5-W5`. `A089` and `A090` cannot approve the release; a reproduced defect invalidates the decision and creates `A091+` repair work.

## 7. Coverage and exclusions

- The queue maps each of the 120 P0 Tasklist IDs exactly once.
- The 17 P2 tasks—`M1-004`, `M2-001~009`, and `M11-001~007`—are not mapped and cannot affect the release decision.
- Frontend/UI work is confined to explicit `FRONTEND` leaves; backend, Gateway, policy, executor, and data leaves do not implement UI.
- `http-deny-v1`, trusted proxy chains, and a raw-packet sensor remain separate future work. They do not share the nftables HIL artifact or Gateway privilege boundary.

## 8. Stop and recovery rules

| Trigger | Required response |
| --- | --- |
| Baseline uncommitted or worktrees diverged | Stop code leaves, establish one reviewed baseline, recycle worktrees |
| Contract drift or overlapping edit | Freeze affected leaves, let `ROOT` select the canonical contract, respawn narrower owners |
| Model contract unavailable | Continue offline deterministic work, keep live-AI release gate blocked, preserve secret hygiene |
| Gateway blocks on control plane, accepts spoofed identity, or origin is public | Stop downstream release work and prioritize Gateway/security repair |
| Validation/HIL bypass or digest mutation | Disconnect executor, keep only contract-mocked frontend work running, repair and independently retest |
| Gateway obtains `NET_ADMIN` or host nftables changes | Stop enforcement work, restore isolation, capture evidence, require independent security review |
| P0 failure or unreproducible evidence on Day 5 | Do not release or reduce scope; continue `A091+` repairs until complete or genuinely blocked |

## 9. Evidence and release decision

Each accepted leaf records date, leaf ID, base/result commit, paths, commands, exact results, traceability IDs, remaining risk, and next package. `ROOT` reruns integrated gates, and an independent leaf certifies security, recovery, browser, and release-sensitive behavior.

The final evidence bundle must include sender/header/skew and source-health vectors, raw-socket origin observations, deterministic no-truncation AI request capture, JCS policy/evidence/validation/reason/HIL vectors, `protected-ipv4-v1` plus raw/live base-chain digests, challenge/re-auth negative cases, strict UDS framing, full/torn-journal recovery, signed read-only inspect, and a wall-clock record of actual kernel expiry. A mock, agent report, or deterministic application clock cannot substitute for these integrated artifacts.

Final classification is one of:

- **Complete v0.1:** all 120 P0 completion criteria and five daily gates have reproducible integrated evidence.
- **Still implementing:** at least one release-blocking package remains; continue the relay.
- **Blocked:** an external prerequisite prevents progress and no safe in-scope alternative exists.

There is no “demoable MVP” success class. Passing this WBS prepares but does not authorize a Git tag, push, publication, or submission.
