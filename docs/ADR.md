# SentinelFlow Architecture Decision Record (ADR)

**English** | [한국어](ADR.ko.md)

| Field | Value |
| --- | --- |
| Document status | Draft |
| Source of record | [`README.md`](../README.md) |
| Target scope | SentinelFlow v0.1 single-node reference implementation / experimental research release |
| Date | 2026-07-19 |
| Related documents | [`PRD.md`](PRD.md) · [`TDD.md`](TDD.md) · [`TASKLIST.md`](TASKLIST.md) · [`IMPLEMENTATION_READINESS.md`](IMPLEMENTATION_READINESS.md) |

> "SentinelFlow is an explainable AI security gateway that observes web traffic through an inline reverse proxy, correlates structured evidence, and applies temporary response actions only after strict validation and administrator HIL approval."
>
> Source: [README](../README.md)

## Published research release (2026-10-07)

[v0.1.0-rc.1](https://github.com/veloz-security/sentinelflow/releases/tag/v0.1.0-rc.1) is published as an experimental research prerelease from `1ae56b965355bd82d051a4794db26c72d2bb704d`. [Exact-source hosted CI](https://github.com/veloz-security/sentinelflow/actions/runs/37592532654) passed all 11 jobs, including backend, database, frontend, recovery, fresh image security evidence, and deterministic packaging. The five uploaded asset digests and sizes match local verified outputs. M9-010, M9-011, M9-012, M9-013, and M9-014 are complete for this separate publication/maintenance scope. Full implementation-qualified v0.1 P0 prerequisites, final acceptance/performance rehearsal and release-capture obligations remain open; July runtime results have not been relabeled as fresh October qualification.

## Public research distribution checkpoint (2026-10-07)

SentinelFlow is owned by Veloz (벨로즈), whose official site is [sec.veloz.kr](https://sec.veloz.kr); the owner supplied [security@veloz.kr](mailto:security@veloz.kr) as the security contact. The owner requested public restructuring and release publication. `v0.1.0-rc.1` is an experimental research distribution, separate from the implementation-qualified v0.1 release. No production, customer, certification, or CVP approval claim is made. Runtime and enforcement contracts are unchanged.

Implementation checkpoint `b125adec66864c87f5d37f15049514381dd9e4f3` already committed migration 34 and the v2 expiry repair; [CI run 29709922172](https://github.com/veloz-security/sentinelflow/actions/runs/29709922172) passed all ten shards for that commit. Earlier references below to “current-tree” results describe the July 2026 snapshot, not a fresh October rerun. The release record must identify its own exact commit and verification. Existing P0 prerequisites and full v0.1 acceptance gates remain open until independently satisfied. See [release guide](./RELEASE.md), [research evidence](./RESEARCH.md), ADR-015, and M9-010.

## 1. Purpose and status semantics

This document collects the design principles, trust boundaries, and architecture described in `README.md` plus explicit project-owner decisions recorded here. The project now has an integrated prototype, while some release commands and environment-specific evidence remain unverified. Therefore, **Accepted** means a product or safety decision is frozen for implementation; it does not by itself mean release or operational verification is complete.

Statuses are interpreted as follows:

- **Accepted — implementation verification required**: the README or an explicit project-owner decision freezes a principle, contract, or trust boundary. Code and tests must demonstrate compliance.
- **Proposed**: the README uses language such as `planned`, `intended`, `expected`, or `target`. The implementation may change.
- **Open**: the README does not provide enough evidence to select an implementation detail.
- **Superseded**: a later ADR replaces all or a named portion of this decision. ADR-010 supersedes only the command-generation boundary in ADR-003 and ADR-004; ADR-011 supersedes log-first primary-ingress assumptions without removing optional adapters or shared normalization; ADR-012 supersedes only the named executor-authority and recovery-reapplication mechanics in ADR-006, ADR-010, and ADR-011, while narrowing or completing their compatible edge and delivery contracts; ADR-014 narrows only the expiry-time interpretation and result-attestation version used by ADR-012 lifecycle reconciliation.

## 2. Decision index

| ID | Decision | Status | Related requirements |
| --- | --- | --- | --- |
| [ADR-001](#adr-001-run-deterministic-detection-before-ai-analysis) | Deterministic detection first | Accepted — implementation verification required | FR-005~FR-007, FR-025~FR-026, NFR-008 |
| [ADR-002](#adr-002-normalize-to-a-shared-schema-and-retain-minimized-evidence) | Normalization and minimized evidence retention | Accepted — source priority updated by ADR-011; path representation narrowed by ADR-012 | FR-001~FR-004, FR-024, FR-026, NFR-014 |
| [ADR-003](#adr-003-constrain-the-role-and-trust-boundary-of-gpt-56) | Constrained GPT-5.6 role | Accepted — command-generation boundary superseded by ADR-010 | FR-008~FR-010, FR-021, FR-024~FR-025, NFR-004~NFR-005, NFR-014 |
| [ADR-004](#adr-004-use-constrained-policies-and-a-validation-pipeline) | Structured policy and validation | Accepted — command-generation boundary superseded by ADR-010 | FR-011~FR-012, FR-021, NFR-001~NFR-002 |
| [ADR-005](#adr-005-require-administrator-approval-before-enforcement) | Human approval | Accepted — implementation verification required | FR-013, FR-021, NFR-001~NFR-002, NFR-006 |
| [ADR-006](#adr-006-make-nftables-enforcement-temporary-reversible-and-isolated) | Temporary nftables and isolation | Accepted — named execution/recovery mechanics superseded by ADR-012 | FR-014~FR-016, NFR-001~NFR-003, NFR-006~NFR-009 |
| [ADR-007](#adr-007-use-a-go-and-react-stack-with-explicit-process-and-module-boundaries) | Technology stack and module boundaries | Accepted — implementation evidence present; release verification incomplete | FR-001~FR-026, NFR-002, NFR-010~NFR-014 |
| [ADR-008](#adr-008-use-sse-as-the-administrator-state-delivery-mechanism) | Server-Sent Events | Accepted — implementation verification required | FR-017~FR-018, FR-025, NFR-009 |
| [ADR-009](#adr-009-audit-the-full-lifecycle-and-treat-logs-and-secrets-as-untrusted) | Audit and security controls | Accepted — implementation verification required | FR-003, FR-008~FR-016, FR-021, FR-024~FR-026, NFR-001~NFR-007, NFR-014 |
| [ADR-010](#adr-010-allow-evidence-bound-ai-generated-nftables-blacklist-command-candidates-under-hil) | AI-generated nftables blacklist command candidates under HIL | Accepted — named executor/recovery mechanics superseded by ADR-012 | FR-011~FR-016, FR-021, NFR-001~NFR-009 |
| [ADR-011](#adr-011-adopt-a-gateway-first-hybrid-architecture-with-separated-data-and-control-planes) | Gateway-first hybrid data/control-plane split | Accepted — edge/delivery mechanics refined and executor-authority clause superseded by ADR-012 | FR-022~FR-026, NFR-001~NFR-002, NFR-012~NFR-014 |
| [ADR-012](#adr-012-freeze-gateway-edge-delivery-and-once-only-enforcement-protocols) | Gateway edge, delivery integrity, exact AI/HIL contracts, and once-only enforcement protocols | Accepted — implementation evidence present; integrated release verification incomplete | FR-008~FR-016, FR-020~FR-026, NFR-001~NFR-003, NFR-006~NFR-009, NFR-012~NFR-014 |
| [ADR-013](#adr-013-stage-and-expire-demo-history-authority-without-renewable-worker-privilege) | Staged, non-renewable signed demo-history authority | Accepted — targeted implementation evidence present; release verification incomplete | FR-012, FR-020, NFR-001~NFR-002, NFR-006, NFR-008~NFR-011 |
| [ADR-014](#adr-014-bind-expiry-lifecycle-to-a-signed-read-back-interval) | Signed read-back interval and bounded expiry lifecycle | Accepted — implementation and release verification required | FR-014~FR-016, NFR-001~NFR-003, NFR-006~NFR-009 |
| [ADR-015](#adr-015-publish-experimental-research-distributions-separately-from-full-v01-qualification) | Experimental research distribution | Accepted — experimental distribution published | FR-021, NFR-005, NFR-010, NFR-011 |
| [ADR-016](#adr-016-refresh-vulnerable-dependencies-before-public-distribution) | Refresh vulnerable dependencies before public distribution | Accepted — dependency and image regression verified | FR-021~FR-026, NFR-002, NFR-005, NFR-010, NFR-011 |

FR/NFR ranges are inclusive; for example, `FR-005~FR-007` means every consecutive ID from both endpoints.

---

## ADR-001: Run deterministic detection before AI analysis

### Status

**Accepted — implementation verification required.** Deterministic-first processing remains a safety principle and the v0.1 thresholds and incident lifecycle are now frozen.

### Context

Individual events from different logs may appear low risk. Sending every raw log directly to a model would make measurable evidence and reproducible processing difficult to guarantee.

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> Source: [README](../README.md)

### Decision

The accepted principles are:

1. First calculate measurable signals from minimized Gateway and authenticated application events by canonical source IP.
2. Run deterministic event-time rules before model analysis: path scan at 8 distinct configured suspicious paths in 60 seconds; burst at 120 requests in 10 seconds; brute force at 10 `401`/`403` responses on configured authentication routes in 60 seconds; credential stuffing at 20 failures across at least 8 account hashes in 5 minutes.
3. Correlate on canonical source IP with a 5-minute overlap, close after 15 minutes idle, and reopen for matching evidence within 30 minutes after closure.
4. Keep observed signals separate from AI explanation so detection evidence never depends solely on model output.

Duplicate, late-event, and order semantics must be deterministic and tested at exact boundaries. Configured suspicious paths and authentication routes are versioned inputs; changing them does not alter the frozen numeric defaults without a reviewed decision.

### Alternatives

- **Send all raw logs directly to AI**: explicitly inconsistent with the README principle.
- **Use only learned baselines**: outside MVP; rule-based thresholds are a documented limitation and organization-specific baselines are roadmap work.
- **Provide only manual correlation**: inconsistent with the intended automated detection and correlation flow.

The README provides no quantitative comparison among these alternatives.

### Consequences

- Signals and detection results must be reproducible for identical input and configuration.
- GPT-5.6 failure does not remove the underlying detection evidence.
- Rule maintenance and tuning are required, and limited rules may miss attacks or create false positives.
- This decision does not guarantee detection of every attack.

---

## ADR-002: Normalize to a shared schema and retain minimized evidence

### Status

**Accepted — source priority updated by ADR-011 and path representation narrowed by ADR-012; implementation verification required.** Shared normalization and evidence traceability remain accepted. ADR-011 makes Gateway metadata the primary source and moves Nginx/Syslog receivers to optional P2/post-v0.1 adapters; ADR-012 implements the minimization principle by forbidding exact-path persistence.

### Context

Gateway traffic, authenticated application events, and optional future log adapters use different formats. Shared fields are needed for counting and correlation, but raw HTTP content would create avoidable secret, privacy, storage, and prompt-injection exposure.

### Decision

The v0.1 decision is:

1. The Gateway directly emits a versioned normalized request/response event; the authenticated application adapter emits a versioned auth event. Optional source-specific parsers may later map Nginx and Syslog/firewall records into the same envelope.
2. `gateway-http-v1` evidence is limited to schema/event/request/trace/idempotency identifiers, start/end times, canonical TCP-peer source IP, allowlisted host/service label, method, normalized path without query string, fixed `HTTP/1.1` protocol, response status, request/response byte counts, and latency. `auth-event-v1` adds a known Gateway request binding when available, configured route, outcome, and a stable nonreversible HMAC account hash; an unknown binding remains untrusted and cannot support enforcement.
3. Query strings, request/response bodies, cookies, `Authorization`, and raw secret-bearing headers are never persisted or sent to AI. The system does not retain raw HTTP evidence merely because it traversed the proxy.
4. PostgreSQL stores normalized events, incidents, AI/policy artifacts, and audit data with retention of 7 days for events/evidence, 30 days for incidents/AI/policies, and 90 days for audit.
5. Parse, validation, duplicate, and drop outcomes remain traceable without retaining prohibited content.

Schema versioning, timestamp normalization, deduplication keys, masking, access control, indexing, and partitioning remain implementation contracts, not permission to expand collected data.

**Refinement note (2026-07-18):** the `normalized path` phrase in historical Decision 2 does not authorize an exact-path field. ADR-012 narrows the current representation to `route_label`, `path_catalog_version`, and `suspicious_path_id`, which strengthens rather than replaces ADR-002's normalization and minimization decision.

### Alternatives

- **Store only source-specific formats**: not selected by the cross-source aggregation model.
- **Retain full HTTP requests and responses**: rejected because it violates minimization and unnecessarily exposes secrets and personal data.
- **Use a different store**: OpenSearch is roadmap work; PostgreSQL is the selected v0.1 store. No benchmark superiority claim is made.

### Consequences

- Detection and correlation can be decoupled from source-specific formats.
- An incident can link normalized values to minimized source evidence and its provenance.
- Some forensic detail is intentionally unavailable because prohibited content was never retained.
- Migrations and API contracts cannot be considered complete until the selected schema and retention behavior are implemented and verified.

---

## ADR-003: Constrain the role and trust boundary of GPT-5.6

### Status

**Accepted — command-generation boundary superseded by ADR-010.** Compact input, untrusted-log handling, no direct authority, and fail-safe behavior remain accepted. ADR-010 expands the model output from policy-only recommendation to an evidence-bound nftables command candidate.

### Context

Contextual reasoning helps explain incidents and false positives, but logs may contain prompt-injection text and a model may hallucinate. Giving the model firewall authority could turn an incorrect correlation or explanation into an operational change.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> Source: [README](../README.md)

### Decision

The accepted principles are:

1. `gpt-5.6-sol` runs asynchronously after deterministic detection and incident correlation through the Responses API.
2. It receives a compact, versioned incident summary with no more than 50 evidence references and 12 KiB of input. Query strings, bodies, cookies, `Authorization`, and raw secret-bearing headers cannot enter the summary.
3. Its role includes summarization, classification, evidence explanation, uncertainty and false-positive analysis, a constrained policy proposal, and—under ADR-010—an evidence-bound nftables blacklist command candidate.
4. Log content is untrusted data and never becomes model instruction.
5. The model receives neither shell access nor direct firewall authority. Its command candidate remains untrusted data and cannot replace validation or HIL approval.
6. The request uses reasoning `medium`, `store: false`, strict Structured Outputs `text.format`, no tools, and a maximum of 2,048 output tokens. One attempt has a 30-second timeout and only one retry for classified `408`/`409`/`429`/`5xx` transient errors is allowed. Worker concurrency defaults to two analyses and the configurable demo operator budget defaults to USD 10 per UTC day; this is an operator guardrail, not an API price claim.
7. Refusal, incomplete output, exhausted timeout/retry, schema failure, invalid evidence references, or operator-budget exhaustion produces the sole non-enforcing `analysis_failed` state with a typed reason such as `budget_exhausted`. Deterministic evidence remains available and no failed analysis may advance an enforcement artifact.

The request/response and schema versions are compatibility boundaries. A model, prompt, schema, limit, timeout, or retry change requires contract tests and documentation updates. The implementation follows the official [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). The opt-in smoke command has one verified billable, non-mutating result from `openai_responses`/`gpt-5.6-sol` for synthetic `path_scan`; it remains only a bounded contract probe, not authorization to enforce.

### Alternatives

- **Send every raw log to the model**: explicitly excluded by the README.
- **Grant shell or firewall access to the model**: conflicts with the Safety Model.
- **Use no AI**: preserves detection but removes the contextual explanation and constrained recommendation central to the product.
- **Use another or local model**: not selected for v0.1; substitution requires an explicit model-contract decision and revalidation.

### Consequences

- Model output must be displayed as interpretation and recommendation, separate from observed facts.
- Model or schema failure must fail safely and never bypass the enforcement pipeline.
- Structured input limits attack surface and cost but may omit some context.
- GPT-5.6 analysis requires network access and API credentials and is not a detection guarantee.

---

## ADR-004: Use constrained policies and a validation pipeline

### Status

**Accepted — command-generation boundary superseded by ADR-010.** The prohibition on unrestricted shell commands and the ordered validation stages remain accepted. ADR-010 replaces the policy-only/deterministic-translation assumption with a strictly parsed AI-generated nftables command candidate.

### Context

Executing natural-language or model-generated shell commands could produce overly broad rules or block protected networks. Policy intent, target, exclusions, action, duration, and approval requirement must be machine-verifiable.

### Decision

The accepted principles are:

1. AI response proposals use a constrained policy and, under ADR-010, a schema-bounded nftables command candidate rather than unrestricted shell.
2. A policy/command pair passes structured-output/schema validation, command parsing/canonicalization, policy/evidence/command consistency, protected-network checks, owned-set nftables syntax validation, and historical-impact analysis in that order. Missing, stale, failed, timed-out, or ambiguous results fail closed.
3. A validation failure stops the policy from reaching enforcement.
4. A valid policy/command pair still requires HIL approval of the exact artifact by binding its policy, generated/canonical command, and evidence/validation snapshot digests under ADR-005 and ADR-010.

The v0.1 policy accepts only `block_ip` for one canonical IPv4 source. TTL is at least 1 minute, defaults to 30 minutes, and is at most 24 hours. Validation is valid for at most 5 minutes. Historical impact uses a 24-hour lookback; successful authentication evidence associated with the target is blocking, and insufficient or ambiguous evidence fails closed. Future actions, including Gateway-local `http-deny-v1`, require a separate artifact contract and follow-up ADR; nftables approval cannot authorize them.

### Alternatives

- **Execute an unparsed model-generated command or invoke it through a shell**: explicitly excluded by the Safety Model and ADR-010.
- **Approve and execute free-form natural language**: cannot satisfy schema and syntax validation.
- **Require administrators to author nftables manually**: possible as an external operation, but not a replacement for SentinelFlow's selected validation flow.

### Consequences

- A testable contract separates model output from firewall representation.
- Target, exclusions, action, and duration can be rejected before enforcement.
- Responses outside the schema cannot be expressed in MVP.
- Schema, command parser/canonicalizer, validators, impact analysis, HIL binding, and executor contract must be versioned and tested together.

---

## ADR-005: Require administrator approval before enforcement

### Status

**Accepted — implementation verification required.** The final enforcement decision remains under administrator control.

### Context

Incorrect correlation, hallucination, false positives, or overly broad rules can block legitimate traffic or lock out administrators. The README provides no evidence that automated checks alone can account for organization-specific impact.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> Source: [README](../README.md)

### Decision

The accepted principles are:

1. Present the immutable evidence snapshot, proposed policy, generated and canonical commands, all relevant digests, validation results, expected impact, and validity to an administrator.
2. Do not apply a rule before explicit approval.
3. Let the administrator approve or reject the exact artifact through HIL by binding the policy version/digest, generated and canonical command digests, evidence/validation snapshot digest, actor, reason, and validity; the model never makes the final enforcement decision.
4. Disable automatic production enforcement by default.
5. Approval cannot override failed command grammar, schema, protected-network, syntax, consistency, or impact validation. Any command, policy, validator, configuration, analysis input, or evidence mutation invalidates approval.
6. v0.1 has one administrator identity. Its Argon2id PHC hash is injected through environment configuration with minimum memory 64 MiB, time cost 3, parallelism 2, salt 16 bytes, and key 32 bytes. The password itself never enters repository configuration.
7. Authentication creates an opaque server-side session with an 8-hour absolute and 30-minute idle lifetime, rotated at login and privilege actions. The cookie is HttpOnly and SameSite=Strict and is Secure whenever TLS is used. State-changing requests use synchronizer-token CSRF protection.
8. Approve, reject, and revoke operations are rate-limited to 5 per minute per session and require reauthentication when session age exceeds 15 minutes. A decision consumes a single-use nonce bound to the session, exact artifact digests, and 5-minute validation window and supplies `Idempotency-Key`, expected policy version/digests, decision, and nonempty reason. An identical idempotent retry returns the original result; conflicting reuse, stale session, nonce replay, or artifact mismatch fails closed and is audited. Optimistic concurrency permits one final HIL decision per artifact version.

The validation snapshot has `valid_until` no later than 5 minutes after validation. An approval has `decision_valid_until = min(validation.valid_until, decision_time + 5m)`. Execution and recovery require both timestamps to remain in the future, so approval never extends validation validity.

Multiple administrators, roles, separation of duties, external identity providers, notifications, and SLA remain post-v0.1 work. They cannot be claimed from the single-admin reference implementation.

### Alternatives

- **Automatically enforce after validation**: conflicts with the default Safety Model.
- **Let AI self-approve**: violates the human-control and trust-boundary principles.
- **Remove enforcement and provide recommendations only**: a safer reduced scope, but not the intended approval-to-temporary-enforcement demo.

### Consequences

- A human can review business context and false positives before impact.
- Actor, time, policy, and decision must be audit-linked.
- Human wait time is added; unattended response is not the MVP default.
- Approval UI without verified authentication and authorization is not a complete safety boundary.

---

## ADR-006: Make nftables enforcement temporary, reversible, and isolated

### Status

**Accepted — implementation verification required.** Temporary rules, automatic expiry, and isolated demo enforcement remain frozen but unverified. ADR-012 supersedes only Decision 6's direct executor-delivery mechanics, Decision 7's privilege topology, and the recovery-reapplication sentence below; the fixed-binary, shell-free, read-back, lifetime, isolation, and audit principles remain accepted.

### Context

Blocking rules can disrupt legitimate traffic and management access. A demo that changes the host firewall could damage the development environment, so scope and lifetime must be limited.

> "The default demo keeps the upstream private and runs nftables enforcement only inside an isolated container or network namespace."
>
> Source: [README](../README.md)

### Decision

The accepted principles are:

1. v0.1 enforcement targets the pre-created `inet sentinelflow blacklist_ipv4` set and every applied rule has a finite lifetime of at least 1 minute, 30 minutes by default, and at most 24 hours.
2. Temporary rules expire automatically and retain an auditable lifecycle from application through removal.
3. Default demo enforcement runs in a container or network namespace that does not modify the host firewall.
4. Enforcement accepts only canonical global-unicast IPv4. It rejects unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, configured management CIDRs, Gateway/upstream/executor addresses, the current administrator path, and all IPv6. Built-in protection cannot be removed by `PROTECTED_CIDRS`; that configuration only adds ranges.
5. Host-level production enforcement is not the default and must not be enabled without reviewing implementation, privileges, protected networks, rollback, and audit configuration.
6. The executor runs only the HIL-approved canonical command artifact through a fixed `nft` binary and fixed arguments without a shell, then reads back the actual rule and timeout.
7. The Gateway, API, AI adapter, and general workers have no `NET_ADMIN`; only the isolated executor receives the minimum required capability.

RFC 5737 documentation ranges are protected in normal profiles. An isolated demo/test profile may explicitly allow only those documentation ranges after namespace isolation and before/after host-ruleset assertions pass. Atomic application, failed-expiry retries, rule conflicts, and concurrent approvals remain implementation details constrained by the exact-artifact gate. Initial execution and any recovery reapplication must recheck current digests, both 5-minute validity timestamps, protected configuration, owned-set schema, and remaining TTL. Roadmap policy rollback is not treated as implemented.

**Supersession note (2026-07-18):** the preceding historical text is retained as the record of ADR-006. Implementations must follow ADR-012: a restricted dispatcher mints the exact signed capability, only the executor has namespace-local `NET_ADMIN`, and a relative-timeout add is never reapplied during recovery.

### Alternatives

- **Permanent rules**: inconsistent with temporary and reversible action.
- **Modify host nftables in the default demo**: contrary to the explicit isolation requirement.
- **Observation-only demo**: safer and smaller, but does not demonstrate the intended approval-to-enforcement lifecycle.
- **Other firewall or cloud WAF enforcement**: outside MVP.

### Consequences

- The duration of a bad block is bounded and the host demo risk is reduced.
- Automatic expiry and failed cleanup require time-based integration tests.
- A successful isolated demo does not prove production host safety.
- A least-privilege boundary is required between the executor and the API/AI components.

---

## ADR-007: Use a Go and React stack with explicit process and module boundaries

### Status

**Accepted — implementation evidence present; release verification incomplete.** The v0.1 stack and top-level process/module boundaries are implemented. Current-tree Linux native v6 E2E exited `0` with real kernel expiry, signed absent inspection, audit/recovery/forwarding convergence, and unchanged semantic host nftables after cleanup. The current-tree five-minute 4 GB Linux performance gate also exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage overhead `436us`; fast browser QA exited `0` with sanitized active/revoked captures. A one-attempt billable live `openai_responses`/`gpt-5.6-sol` synthetic `path_scan` probe returned `status=ok` without control-plane mutation. Current-SHA committed clean-checkout/CI, final release captures/submission evidence, and release decision remain open.

### Context

Gateway proxying, event publication, storage, detection, correlation, AI, validation, approval, enforcement, simulation, and UI have different availability and privilege requirements. Explicit code and process boundaries make parallel implementation, outage testing, and security review possible.

### Decision

The v0.1 decision is:

1. Use Go `1.25.12` and `net/http` for the inline Gateway and backend services; use `github.com/go-chi/chi/v5` `v5.3.1`, `github.com/jackc/pgx/v5` `v5.9.2`, SQL query sources with a sqlc configuration, PostgreSQL, and the OpenAI Responses API in the control plane.
2. Use React `19.2.7`, TypeScript `6.0.2`, Vite `8.1.5`, and MUI `7.3.8` on the frontend.
3. Use Docker, Docker Compose, Linux, and nftables for the isolated reference deployment. Nginx and Syslog are optional P2/post-v0.1 adapters, not primary runtime dependencies.
4. Keep distinct entry points under `cmd/gateway`, `cmd/api`, `cmd/worker`, `cmd/dispatcher`, `cmd/executor`, `cmd/simulator`, and focused validation, lifecycle, retention, recovery, observability, export, history, and smoke commands; any `cmd/ingestor` work is optional P2.
5. Keep domain boundaries under `internal/gateway`, `ai`, `api`, `correlation`, `detection`, `enforcement`, `events`, `ingestion`, `policy`, `repository`, and `validation`, plus focused adapters around those domains. Gateway code cannot import AI, database, approval, or executor capabilities into the request path.
6. Keep database migrations/queries/schema, web, deployment, samples, scripts, and documentation as separate top-level areas.
7. Keep React/TypeScript/Vite/MUI frontend implementation in `web/`, consuming frozen REST/SSE contracts. Frontend/UI tasks remain separate from backend, AI, data, validation, enforcement, and infrastructure tasks and cannot redefine authorization or enforcement behavior.
8. Keep the executor process and IPC contract isolated from Gateway/API/AI/general workers; only the executor receives minimal nftables capability, while Gateway and control-plane processes run without `NET_ADMIN`.

ADR-011 fixes the asynchronous data/control-plane boundary, one fixed private upstream, and no `NET_ADMIN` in the Gateway. Internal APIs, transaction/job implementation, configuration mechanics, migration mechanics, frontend state, and detailed container topology must remain within these selected boundaries and be proven by tests.

### Alternatives

- **Single-process, single-package application**: not selected because it would collapse the required data/control/executor boundaries.
- **Other backend or frontend frameworks**: not selected for v0.1; no comparative benchmark claim is made.
- **OpenSearch- or SIEM-centered storage**: roadmap work, not the MVP plan.

These alternatives are outside the selected v0.1 baseline, not technologies claimed inferior by benchmark evidence.

### Consequences

- Selected package names expose responsibilities and trust boundaries.
- Multiple entry points and separate database/web builds may increase deployment and integration complexity.
- Directory existence alone does not prove compliance with the selected module and process boundaries.
- Material boundary changes should be recorded in a later ADR.

---

## ADR-008: Use SSE as the administrator state-delivery mechanism

### Status

**Accepted — implementation verification required.** SSE is the v0.1 administrator state-delivery mechanism. This fixes a contract for implementation but is not proof that the endpoint, replay, browser, or recovery behavior works.

### Context

Incident creation, source degradation, AI completion/failure, policy validation, approval, application, and expiry change over time. The administrator needs timely updates, but this notification channel must not become a command or safety-decision channel.

### Decision

1. `GET /api/v1/events/stream` returns authenticated `text/event-stream` records with `id`, `event`, `data`, and heartbeat comments.
2. Event types are `incident.created|updated`, `analysis.completed|failed`, `policy.validation_updated`, `approval.recorded`, `enforcement.updated`, and `source.degraded|recovered`.
3. Payloads contain only event/resource IDs, time, version, trace ID, and a minimal summary. They do not carry raw HTTP content, secrets, executable command bytes, or approval authority.
4. Clients reconnect with `Last-Event-ID`. When the replay window cannot cover the gap, the client reloads an authorized REST snapshot and treats that snapshot as current state.
5. Delivery is at-least-once notification: clients deduplicate by event/resource version and never create incidents, approvals, or enforcement from an SSE message.
6. SSE is never a command channel. Approval/rejection/revocation remains an authenticated, CSRF/replay-protected REST operation, and enforcement remains behind exact-artifact HIL.

### Alternatives

- **Periodic polling:** workable fallback, but selected only for REST snapshot recovery rather than primary state delivery.
- **WebSocket:** unnecessary for one-way administrator notifications and would add a bidirectional channel not required in v0.1.
- **Manual refresh:** insufficient for visible degradation and lifecycle transitions in the reference demo.

### Consequences

- Authentication, replay-gap, deduplication, and browser lifecycle behavior require contract, recovery, and end-to-end tests.
- REST remains the authoritative state and mutation interface; SSE loss cannot authorize or silently change a policy.
- Proxy buffering must be disabled for the stream in the reference topology, and resource/connection bounds remain required operational configuration.
- State delivery cannot bypass approval or enforcement safety boundaries.

---

## ADR-009: Audit the full lifecycle and treat logs and secrets as untrusted

### Status

**Accepted — implementation verification required.** Auditability, minimization, and the core security controls are fixed for the single-node reference. Production-grade audit and compliance remain roadmap work.

### Context

The MVP considers malformed proxy input, forwarding-header spoofing, request smuggling, prompt injection in evidence, incorrect correlation, AI hallucination, false-positive blocking, administrator lockout, broad rules, API-key leakage, telemetry drops, and privileged-container abuse. Without lifecycle and degradation evidence, the cause of a bad action or missing incident cannot be reconstructed.

### Decision

The accepted principles are:

1. Treat Gateway metadata, application auth events, optional logs, and all evidence as untrusted data; never interpret embedded text as model instruction.
2. Keep API keys and credentials outside the repository, logs, model context, and audit output.
3. Never persist or send query strings, request/response bodies, cookies, `Authorization`, or raw secret-bearing headers to AI. Record event drops and degradation without prohibited content.
4. Preserve layered defenses: constrained policy/command schema, canonicalization, policy/evidence/command consistency, protected CIDRs, owned-set syntax validation, impact analysis, exact-artifact HIL approval, temporary rules, automatic expiry, and isolation.
5. Link normalized minimized evidence, model analysis, command candidate, canonical command and digest, policy proposal, validation results, HIL approval/rejection, application, failure, and expiry in an audit trail.
6. Distinguish observed fact, model interpretation, human decision, enforcement outcome, and data-plane degradation.

Before execution, the durable enforcement job and required pre-application audit record must commit together or enforcement fails closed. After an nftables apply attempt, an audit persistence failure leaves the result `indeterminate`, blocks further transitions, raises an alert, and is recovered through the durable outbox plus ruleset read-back; it is never silently marked successful. Events/evidence are retained 7 days, incidents/AI/policies 30 days, and audit 90 days. Tamper-resistant external archival, compliance export, and multi-party audit controls remain roadmap work.

### Alternatives

- **Record only final firewall state**: does not satisfy an auditable proposal-to-expiry lifecycle.
- **Treat raw log text as model instruction**: conflicts with Threat Model mitigations.
- **Store secrets in the repository or ordinary logs**: explicitly excluded.
- **Delegate all audit to an external SIEM**: SIEM integration is roadmap work, not an MVP dependency.

### Consequences

- Incident and policy IDs must reconstruct the full timeline from evidence through expiry.
- Audit data can itself contain sensitive IP, account, path, and evidence data and needs access control and masking.
- Safety-control or pre-application audit failure stops enforcement; post-attempt audit failure enters durable reconciliation and remains release-blocking until recovered.
- MVP auditability does not automatically satisfy production compliance or immutability requirements.

---

## ADR-010: Allow evidence-bound AI-generated nftables blacklist command candidates under HIL

### Status

**Accepted — implementation verification required.** This decision was explicitly approved on 2026-07-17. It supersedes only the policy-only/deterministic command-generation boundary in ADR-003 and ADR-004. ADR-012 in turn supersedes only the direct executor-delivery and recovery-reapplication mechanics in Decision 8 and Decision 9 below. The AI candidate, compact-input, untrusted-data, no-direct-authority, validation, HIL, expiry, and audit requirements remain in force.

### Context

The product must let AI convert its evidence-based incident analysis into the actual nftables blacklist command that an administrator can inspect. A policy-only proposal hides the exact executable artifact until a later translator runs, while direct model-to-shell execution would make command injection, overbroad changes, and approval drift unacceptable.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> Source: [README](../README.md)

### Decision

1. GPT-5.6 runs only after deterministic detection and correlation and receives a compact structured incident summary with stable evidence references.
2. Its structured output contains the explanation, uncertainty, false-positive analysis, constrained `block_ip` policy, and an evidence-bound nftables blacklist command candidate.
3. The command family is `nft-blacklist-v1`. A v0.1 candidate may add exactly one canonical global-unicast IPv4 source address to the pre-created `inet sentinelflow blacklist_ipv4` set with a timeout of at least 1 minute, 30 minutes by default, and at most 24 hours. IPv6 evidence remains detectable but cannot produce a v0.1 enforcement candidate. The candidate may not create, delete, flush, rename, or modify tables, chains, rules, or other sets.
4. The candidate is untrusted text. A strict parser rejects additional statements, unsupported tokens, variables, include operations, shell metacharacters, redirection, pipelines, command substitution, comments used to hide tokens, missing timeouts, unexpected table/set names, and multiple addresses.
5. The parser produces a typed AST and serializes one canonical UTF-8 command with LF line endings without inventing a different action. Consistency requires every cited evidence ID to belong to the immutable incident/analysis-input snapshot, every cited source address to equal the policy target, policy and command to use the same evidence set and target, and timeout to match the policy plus configured bounds. The server calculates SHA-256 generated and canonical command digests.
6. One immutable artifact must pass structured-output/schema validation, command grammar/canonicalization and policy/evidence/command consistency, protected-network checks, isolated `nft --check -f -` against an identical pre-created owned-set schema, and 24-hour historical-impact analysis in that order. Successful authentication evidence associated with the target is blocking. Missing, stale, failed, timed-out, insufficient, or ambiguous results fail closed.
7. The validation snapshot digest commits the policy digest, incident/evidence snapshot digest, analysis input/version, generated-candidate digest, canonical bytes/digest, grammar/parser/validator versions, protected-range configuration, owned-set schema, nft binary version, impact inputs/results, and `valid_until` no later than 5 minutes after validation. The administrator sees the evidence, generated/canonical diff, TTL, exclusions, impact, and digests. HIL binds that snapshot plus policy version/digest, generated/canonical digests, actor, reason, and `decision_valid_until` no later than the validation expiry or 5 minutes after decision; any dependent change requires full revalidation and reapproval.
8. The model cannot approve, enqueue, or execute the candidate. The isolated executor receives canonical bytes plus the HIL-approved digest, recomputes the digest, invokes a fixed `nft` binary with fixed arguments, and passes only those bytes through standard input without a shell.
9. Immediately before initial execution or recovery reapplication, the executor rechecks policy and analysis versions, all command/evidence/validation digests, HIL identity and both validity timestamps, protected-range and owned-set-schema configuration, and remaining TTL. It reads back the applied rule and timeout; a mismatch is failure, never success. The reconciler may repair missing state only through this same gate and never from a stale or expired approval.
10. Audit records preserve the evidence snapshot, model/prompt/schema versions, generated candidate digest, canonical bytes/digest, validation snapshot, HIL actor/reason/time/validity, executor result, read-back, expiry, revocation, and recovery outcome.

**Supersession note (2026-07-18):** Decision 8's direct delivery to the executor and Decision 9's recovery reapplication are historical. ADR-012 requires dispatcher-signed single-use capability delivery over private UDS and read-back-only crash resolution that never re-adds a relative-timeout artifact.

The canonical v0.1 shape is `add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }`. Normal profiles protect RFC 5737 documentation ranges along with unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, configured management, Gateway/upstream/executor, and current-administrator paths. An isolated demo/test profile may allow only RFC 5737 targets after namespace and host-ruleset-diff assertions; `PROTECTED_CIDRS` may add protection but never remove built-ins. Any future IPv6 family requires a follow-up ADR.

### Alternatives

- **Keep deterministic command generation only**: preserves a smaller model boundary but does not satisfy the selected product behavior in which AI generates the administrator-reviewed nftables command.
- **Execute the model response directly through a shell**: rejected because it bypasses grammar enforcement, digest binding, least privilege, and HIL integrity.
- **Let the administrator manually author the command**: keeps human control but removes the intended AI-generated, evidence-bound response artifact and makes repeatability weaker.
- **Automatically execute after machine validation**: rejected because it removes the required HIL decision.

### Consequences

- Administrators can review exactly what would execute, including its evidence and impact, before deciding.
- The AI output schema, command grammar, canonicalizer, validator versions, approval record, executor protocol, and audit chain become one compatibility boundary.
- Command injection, policy/command mismatch, post-validation mutation, stale approval, replay, and read-back mismatch require dedicated negative and recovery tests.
- AI command generation still does not constitute firewall authority; only the independently validated and HIL-approved canonical artifact can reach the isolated executor.
- The allowed nftables capability is intentionally narrow and is not a general firewall-management interface.

---

## ADR-011: Adopt a Gateway-first hybrid architecture with separated data and control planes

### Status

**Accepted — implementation verification required.** Approved on 2026-07-18. This decision changes the primary v0.1 sensor from external Nginx/Syslog ingestion to an inline Gateway while preserving authenticated application auth events and retaining legacy log adapters as optional P2/post-v0.1 work. ADR-012 supersedes only Decision 8's direct executor-delivery/privilege mechanics. It narrows or completes the compatible origin, protocol, exact-path, batch-authentication, and auth-binding details in Decision 2 through Decision 6 without replacing the Gateway-first selection, direct-peer identity, asynchronous separation, performance gate, hybrid-source position, or scope.

### Context

A log-first prototype must wait for external formatting, transport, parsing, and delivery before it can observe a request. Building a general-purpose origin server would instead assume responsibility for application hosting. An inline reverse proxy can observe HTTP at a consistent boundary while forwarding to the existing application, but it becomes availability- and protocol-security-sensitive and therefore cannot share failure or privilege boundaries with AI, persistence, approval, or firewall execution.

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> "Raw packet capture and analysis are not part of v0.1."
>
> Source: [README](../README.md)

### Decision

1. **Primary data plane:** v0.1 adds a Go `SentinelFlow Gateway` as an inline reverse proxy before exactly one fixed private upstream. One configured host is allowlisted. The Gateway is not a general origin server, static-file host, arbitrary forward proxy, dynamic service router, or production WAF. The upstream is unpublished and reachable only inside the reference network.
2. **Identity and origin trust:** `canonical_source_ip` is the canonicalized TCP peer address in v0.1. The Gateway strips every incoming `Forwarded` and `X-Forwarded-*` header, validates the allowlisted `Host`, and regenerates forwarding headers from trusted local state. It never selects an upstream from request input. Protected application traffic reaches the Gateway directly, and optional TLS terminates there; Nginx is not an upstream identity hop in v0.1, trusted proxy chains are post-v0.1, and the admin UI may use a separate endpoint.
3. **Protocol bounds:** maximum headers are 32 KiB, maximum request body is 10 MiB, header-read timeout is 5 seconds, upstream/request timeout is 30 seconds, and idle timeout is 60 seconds. Protocol-invalid, oversized, and timed-out requests may be rejected by deterministic server-safety controls; these controls are not AI adaptive enforcement.
4. **Minimized event contract:** after a response or terminal proxy outcome, the Gateway asynchronously emits `gateway-http-v1` with only schema/event/request/trace/idempotency identifiers, start/end times, canonical source IP, allowlisted host/service label, method, normalized path without query string, fixed `HTTP/1.1` protocol, response status, request/response byte counts, and latency. Query strings, bodies, cookies, `Authorization`, and raw secret-bearing headers are neither persisted nor sent to AI.
5. **Bounded delivery:** the default in-memory queue holds 10,000 events, batches at most 100 records, and flushes within 100 ms; sender backoff is bounded from 100 ms to 5 seconds and v0.1 has no durable disk spool. `event-batch-v1` carries sender/batch IDs, monotonic per-sender sequence, sent time, and at most 100 typed records or 256 KiB. Endpoint-scoped senders use HMAC-SHA256 over timestamp, nonce, and body digest. Receivers verify in constant time, permit at most ±60 seconds clock skew, and retain nonces for 5 minutes. Retries keep body, batch ID, and sequence stable but use fresh authentication values. Receivers deduplicate batches/records, reject a reused batch ID with different bytes, and treat sequence gaps as incomplete evidence that cannot support enforcement. Queue depth, lag, rejected batches, sequence gaps, and event drops are observable.
6. **Required auth semantics:** an authenticated application auth-event adapter remains P0 because a proxy cannot safely infer account identity or login outcome semantics. Its allowlisted `auth-event-v1` contains schema/event/Gateway-request/trace/idempotency identifiers, occurred time, canonical source IP derived from sanitized Gateway forwarding, configured service/route labels, outcome, and a stable nonreversible HMAC account hash. Raw usernames and credentials are forbidden; an unknown Gateway request binding remains untrusted and cannot support enforcement. The adapter uses the authenticated, replay-resistant batch contract above.
7. **Asynchronous isolation:** Gateway forwarding never waits for PostgreSQL, deterministic workers, GPT-5.6, validation, the administrator, or the executor. During their outage or queue saturation, otherwise-valid traffic continues, no new adaptive block is generated, existing approved nftables rules expire normally, and degradation or drops are reported. Recovery cannot invent missing evidence.
8. **Privilege split:** the Gateway has no `NET_ADMIN`, shell, approval, policy-validation, or executor capability. The API, AI adapter, and general workers also have no executor privilege. Only the separate isolated executor may receive HIL-approved canonical bytes plus digest under ADR-010.
9. **Performance gate:** on the 4 GB single-node reference host at 500 requests/second, Gateway-added p95 latency is at most 5 ms and event drops are zero. Saturation outside the target must remain observable and must not block valid traffic.
10. **Hybrid sources:** Nginx access-log and TCP/UDP Syslog/firewall-log receivers/parsers retain their existing requirements and IDs but move to optional P2/post-v0.1 adapters. They cannot change Gateway-derived canonical identity or block the v0.1 release.
11. **Scope boundary:** raw packet capture/analysis is not part of v0.1. Any eBPF/XDP or packet sensor must be a separate least-privilege component with its own privacy, capacity, and failure ADR. Adaptive Gateway-local `http-deny-v1` is also future work and requires a distinct typed artifact, validator, digest/HIL binding, and ADR; an nftables approval cannot authorize it.
12. **Release position:** v0.1 is an implementation-complete, single-node reference and demo, not a production WAF, managed origin server, high-availability proxy, or claim of production TLS operations. Production TLS ownership, certificate rotation, horizontal scaling, failover, and HA require follow-up evidence and decisions.

**Supersession and refinement note (2026-07-18):** Decision 8's direct executor-authority wording remains visible as superseded history. Decision 2 through Decision 6 remain accepted at the architectural level, while ADR-012 is the narrower implementation authority for the private origin, HTTP edge, path minimization, batch/HMAC/checkpoint, and pending-auth binding contracts.

### Alternatives

- **Keep log/Syslog analysis as the primary sensor:** less intrusive, but retains source-format, delivery, and latency dependencies and weakens the direct demo path.
- **Build a general-purpose origin web server:** rejected because application hosting, framework behavior, and origin migration are outside the security product's scope.
- **Put AI or database decisions in the request path:** rejected because control-plane latency and outage would become application availability failures.
- **Perform raw-packet analysis inside the Gateway:** rejected for v0.1 because HTTP proxying and packet sensing have different privilege, privacy, performance, and failure boundaries.
- **Let the Gateway directly apply L7 or nftables blocks:** rejected because it collapses the exact-artifact HIL and least-privilege boundaries.

### Consequences

- HTTP request evidence is immediate, structured, reproducible, and easier to demonstrate than external log parsing.
- The Gateway becomes availability-critical and therefore requires protocol-security, backpressure, upstream-failure, and load evidence before release.
- Account-aware credential-stuffing still requires an authenticated application contract; the proxy does not invent usernames or authentication semantics.
- Data minimization deliberately reduces forensic depth to avoid collecting secrets and unnecessary personal data.
- Optional legacy adapters preserve hybrid extensibility without controlling the v0.1 critical path.
- This architecture does not by itself establish production WAF efficacy, HA, TLS operations, or raw-packet visibility.

---

## ADR-012: Freeze Gateway edge, delivery, and once-only enforcement protocols

### Status

**Accepted — implementation evidence present; integrated release verification incomplete.** Approved by the project owner on 2026-07-18 as part of the final recommended architecture and implementation-readiness request. Current-tree native v6 E2E and the five-minute 4 GB performance gate exited `0`; v6 proves bounded lifecycle expiry/signed absence/recovery/forwarding/audit plus semantic host invariance, and performance reports `GATE_VERDICT=pass`, p95 `533us`, outage `436us`. Fast browser QA exited `0` with sanitized captures but is non-release UI evidence. A one-attempt billable live `openai_responses`/`gpt-5.6-sol` probe returned `status=ok` without control-plane mutation. Current-SHA clean-checkout/CI, final release evidence, and decision remain open. This ADR supersedes only the explicitly named executor-authority and recovery-reapplication mechanics in ADR-006, ADR-010, and ADR-011. Its edge, origin, minimization, delivery, and auth-binding clauses narrow or complete compatible earlier contracts; it does not replace their product goals, trust boundaries, validation order, HIL requirement, Gateway-first selection, or optional-adapter position.

### Context

ADR-006, ADR-010, and ADR-011 selected temporary isolated nftables enforcement, an exact AI-generated artifact under HIL, and a Gateway-first split. Their original wording still left implementation-sensitive ambiguity: a worker could appear to deliver directly to the executor; recovery could appear to reapply a relative timeout; a timeout set could exist without a hooked rule; an exact path could enter persistence; and batch, origin, protocol, and crash behavior lacked byte-exact interoperability contracts. Those ambiguities cross privilege and recovery boundaries and therefore require an accepted decision rather than an implementation-local convention.

### Decision

1. **Supersession and refinement scope:** only the former direct executor-authority and recovery-reapplication mechanics are superseded. ADR-012 otherwise narrows or completes the compatible Gateway edge, origin, minimization, event-batch authentication, and auth-binding contracts and is the implementation authority for dispatcher/executor, namespace, replay, TTL, and revocation mechanics. ADR-006 continues to govern temporary, reversible, isolated enforcement; ADR-010 continues to govern the evidence-bound AI candidate, validation order, exact HIL binding, and no model authority; ADR-011 continues to govern the Gateway-first data/control-plane split, direct-peer identity, non-blocking request path, hybrid source position, and release scope.
2. **HTTP edge and fixed private origin:** cleartext accepts only origin-form HTTP/1.1 and optional TLS advertises only `http/1.1`. Go `net/http` is the sole framing parser; no middleware raw pre-parser is permitted. `http.Server.MaxHeaderBytes=32768` is a configured parser bound, not a byte-exact raw-wire claim, and the selected Go version is pinned by raw-socket differential tests proving rejected or safely normalized input becomes at most one origin request. HTTP/1.0, HTTP/2/h2c, unsupported target/upgrade/trailer/`Expect` forms, and non-allowlisted ASCII Host values are rejected. Inbound forwarding and SentinelFlow request/trace IDs are removed; fresh request and trace IDs are supplied to the private application. The one `http://` origin is resolve/dial constrained to configured non-broad RFC 1918 IPv4 CIDRs, and environment proxy selection is disabled.
3. **Exact-path minimization:** an observed exact raw, normalized, or decoded path exists only transiently inside the bounded Gateway classifier. Persistence, AI input, ordinary logs, traces, audit payloads, screenshots, and captured fixtures receive only configured `route_label`, `path_catalog_version=path-catalog-v1`, and one `suspicious_path_id`. Reviewed synthetic exact paths are allowed only in versioned parser/catalog test inputs. The fixed IDs are `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, and `backup_archive`; every non-match is `none`.
4. **Atomic authenticated event delivery:** every process boot creates a random 128-bit `sender_epoch`; sequence starts at one. Retry preserves exact body/epoch/batch/sequence. `X-Sentinel-Sender-ID` is 1–64 lowercase ASCII matching `[a-z0-9][a-z0-9._-]{0,63}` and selects a sender/endpoint-scoped Base64 key of at least 32 random bytes before reading the body. The signature is `hex(HMAC-SHA256(key, endpoint_path + "\n" + sender_id + "\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(raw_body))))`; after constant-time verification the body sender must byte-equal the header. Nonce insertion and whole-batch persistence/ack commit atomically. Gateway and auth producers each own a non-spooling checkpoint and may emit endpoint-scoped `source-health-v1`; loss remains incomplete. HMAC request skew is ±60 seconds. Record time beyond 60 seconds future or 5 minutes past receipt is persisted as untrusted and cannot support detection, analysis, validation, or enforcement.
5. **Pending application-auth binding:** the Gateway removes inbound request/trace IDs and gives the private application fresh `X-SentinelFlow-Request-ID` and `X-SentinelFlow-Trace-ID`. The demo application's HTTP listener binds only its origin-network address while its authenticated producer also joins the ingest network and reaches the API's ingest-only address; neither exposes a host port. An auth event may remain pending for five minutes and verifies only on exact request ID, trace ID, source IP, `demo-app` service, and route. Only a verified failure supports detection; mismatch/expiry is untrusted and any pending/untrusted success blocks impact validation.
6. **Single authority bridge:** only minimal non-AI `cmd/dispatcher` may read the restricted authorized-operation view and dispatch private key. It may mint `add` only from an exact approved job, `revoke` only from separate administrator authorization, and `inspect` only from a lifecycle/reconciliation row bound to an existing action; inspect is read-only and cannot inherit mutation authority. The executor has only verification/result keys, replay journal, private UDS, and namespace-local nft capability. Other components have none of those privileges. Dispatcher verifies every separately signed result.
7. **Canonical signed messages and transport:** strict checked-in schemas define every capability/result/envelope field, type, enum, nullable value, timestamp, digest, nonce, and signature encoding. Policy, sorted-unique evidence snapshot, validation snapshot, NFC-normalized administrator reason, HIL authorization, capability, result, protected-range configuration, and demo-history manifest use RFC 8785/JCS and lowercase `sha256:` digests. An artifact-content digest proves bytes and may be a non-unique lookup key; it is not a database-row, lifecycle, or authorization identity. Repeating command or inspect bytes therefore requires fresh evidence-bound candidate, policy, validation, challenge, decision, authorization, schedule/action, and capability identities. Evidence arrays must be strictly ascending, duplicate-free, and byte-identical across analysis/policy/command; invalid order is rejected without repair. The private UDS carries one request and one response per connection using a 4-byte unsigned big-endian length followed by at most 16 KiB of strict UTF-8 JSON, with 2-second I/O deadlines and unpadded Base64url byte/signature fields. Unknown/duplicate fields, malformed/oversized frames, non-canonical bytes, signature failure, or trailing frames fail closed before mutation.
8. **Namespace and owned blocking schema:** only the executor sidecar shares the Gateway network namespace; Gateway has zero capabilities and executor alone has namespace-local `NET_ADMIN`. The executor's sole Compose dependency object is normalized against `gateway` as `condition: service_started`, `required: true`, and `restart: true`; this is an exact startup/restart ordering edge, not a health assertion or privilege grant. Executor bootstrap is the sole privileged provisioner. It inventories the complete stateless namespace ruleset before and after bootstrap, verifies the raw `nft_base_chain_v1.nft` SHA before loading, then reads back and JCS-digests the separate canonical live-structure contract for its owned table, timeout set, input hook/priority/policy, protected port, and drop expression. Foreign tables are never adopted, rewritten, or normalized and their canonical state must remain unchanged. Steady-state verification reads only the owned `inet sentinelflow` table. An exact existing schema on restart is verify-only and never refreshes an element TTL; a partial, extra, duplicated, or drifted owned schema fails closed without automatic repair. Validator and dispatcher bind both digests. Host rules remain byte-for-byte unchanged. The versioned protected-IPv4 contract is likewise JCS-digested; configuration may only add ranges, while the isolated demo exception may remove exactly the three RFC 5737 ranges after namespace/host invariance proof.
9. **Exact TTL serialization:** structured `ttl_seconds` is an integer from 60 through 86,400 inclusive. A candidate token matches `[1-9][0-9]{0,4}[smh]` with one lowercase unit; checked arithmetic converts it to seconds, and the result must equal policy `ttl_seconds`. Canonical output uses the largest exact unit: hours when divisible by 3,600, otherwise minutes when divisible by 60, otherwise seconds. The command token, policy value, validation snapshot, capability-bound artifact, and read-back expectation must agree exactly.
10. **Two-phase once-only replay journal:** journal lookup precedes freshness or mutation. Before any mutation, executor appends a checksummed `started` record containing exact capability JCS bytes, detached signature, exact canonical artifact bytes, all capability/artifact digests, operation, target, schema, receive/deadline times, and monotonic journal sequence, then fsyncs the file and containing directory. Terminal stores exact signed result bytes likewise. Startup validates checksums, sequence continuity, signatures, digests, and canonical bytes; a torn/corrupt tail fails closed and cannot be truncated automatically. A started-only record has enough persisted authority to perform read-back and classify without invoking add again. Duplicate/restart/reconciliation never refreshes TTL; a new add requires a new candidate, validation, HIL authorization, and capability.
11. **Separate mutation and observation operations:** `nft-revoke-v1` is independently administrator-authorized, binds action/target/original digest/reason, and can only delete. `nft-inspect-v1` is a separately signed JCS artifact produced only for an existing action lifecycle row and maps only to fixed `nft --json list set inet sentinelflow blacklist_ipv4` read-back. It can report active/absent/mismatch/indeterminate but never add, delete, extend, or synthesize approval. Native timeout provides automatic expiry; a bounded real-time Linux test verifies kernel expiry. Early disappearance or unexpected residue fails and alerts; no automatic re-add occurs.
12. **Golden interoperability evidence:** checked-in byte-exact vectors include `event-batch-hmac-v1`, `capability-add-v1`, `capability-revoke-v1`, `capability-inspect-v1`, applied/recovered/revoked/inspect execution results, UDS frames, `demo-history-v1`, and `ttl-canonical-v1`. Public test-only keys and deterministic bytes pin JCS, digests, signatures, framing, nullable fields, authentication order, journal recovery, and TTL conversions. Generated Go/TypeScript fixtures derive from the same bundle and a repository check regenerates or verifies it.
13. **HIL challenge contract:** the API issues a five-minute single-use challenge bound to session digest, operation, resource/version, validation snapshot, and exact artifact digests. Password step-up is required when independently persisted `authenticated_at` is older than 15 minutes; successful step-up updates it, while session-token rotation alone never does. Decision/revocation consumes the challenge atomically with CSRF, origin, idempotency, normalized reason, and final optimistic transition.
14. **Exact AI request contract:** checked-in `sentinelflow_analysis_input_v1` and system-prompt artifacts are digest-pinned with the output schema. The builder includes every enforcement-eligible signal reference for one incident version, sorts by stable ASCII reference ID, and never silently truncates or repairs. A signal reference expands server-side to the complete immutable event set, allowing a 120-event burst without 120 model references. The sorted-unique server-side expansion is limited to 1,000,000 event IDs; exceeding it fails as `input_too_large` without sampling. Duplicate, out-of-order, over-50, or over-12-KiB model input likewise fails typed and creates no policy.
15. **Demo-history and clock boundary:** the signed demo manifest binds one checked-in canonical synthetic dataset by dataset schema/version/digest, record count, source-health digest, import ID, coverage interval, path-catalog version, and run profile. Production rejects it. Injected application time covers deterministic event, retention, validation, and authorization tests only; native nft timeout/expiry is verified on a bounded real-time Linux run.

### Alternatives

- **Let a general worker call the executor with a shared HMAC secret:** rejected because it gives an AI/job process both database breadth and execution authority and cannot provide asymmetric result attestation.
- **Re-add a missing relative-timeout artifact after crash:** rejected because it silently refreshes the approved duration and cannot distinguish “never applied” from “applied, then disappeared.”
- **Use a timeout set without a protected-port input-chain rule:** rejected because set membership alone does not demonstrate that Gateway traffic is blocked.
- **Persist normalized paths or durable event records for convenience:** rejected because it violates exact-path minimization or turns the health checkpoint into an undeclared sensitive-data spool.
- **Permit general HTTP versions, request-selected origins, or public/mixed DNS results:** rejected because it expands proxy and SSRF behavior outside the frozen v0.1 security boundary.
- **Reuse the dispatch key for executor results:** rejected because the dispatcher could forge success and separation of authority would be unverifiable.
- **Add a second raw HTTP parser before Go:** rejected because parser disagreement would create the smuggling boundary the design is meant to remove; the pinned Go parser and end-to-end raw-socket tests are the authority.
- **Let the browser create its own HIL nonce or let inspection reuse add approval:** rejected because neither proves server-side exact-artifact freshness and inspection must remain independently signed and non-mutating.

### Consequences

- Crash recovery favors bounded authority and explicit `indeterminate`/failed outcomes over availability; an administrator may need to create and approve a new action.
- JCS schemas, asymmetric keys, a restricted DB view, a private UDS, a two-phase journal, and golden vectors add implementation and operational work, but make authorization and result provenance independently testable.
- The no-spool Gateway preserves request-path availability at the cost of explicit evidence gaps that suppress new enforcement.
- Exact-path minimization reduces forensic detail by design; route and suspicious-path classifications must be sufficient for v0.1 detectors.
- A namespace demo proves only the frozen reference topology. It does not authorize host enforcement or a production WAF claim.
- The larger checked-in contract pack and real-time Linux expiry gate add work, but remove implementer-dependent serialization, sender lookup, HIL, recovery, and lifecycle interpretations.

---

## ADR-013: Stage and expire demo-history authority without renewable worker privilege

### Status

**Accepted — integrated database evidence present; release verification incomplete.** The architecture is frozen for the asserted v0.1 demo profile. The PostgreSQL 17.10 verifier passes 33 migrations and 72 tables, including fresh/restart-noop and `33→24→33`; the staged activation and recovery evidence remain intact. Current-tree native v6 E2E exited `0` with real expiry, signed absence, audit/recovery/forwarding convergence, and semantic host invariance, while the five-minute 4 GB performance gate exited `0` with `GATE_VERDICT=pass`, p95 `533us`, outage `436us`. A one-attempt billable live `openai_responses`/`gpt-5.6-sol` probe returned `status=ok` without control-plane mutation. Current-SHA clean-checkout/CI, final release evidence, and decision remain pending. This ADR narrows ADR-012's demo-history clause; it does not authorize signed fixtures in production.

### Context

RUN6 proved Gateway/auth coverage readiness and all simulator scenarios but failed before HIL because every attack analysis saw `history_incomplete`. A signed manifest alone is insufficient: a long-running worker able to import, activate, refresh, or substitute history could turn a deterministic fixture into renewable enforcement authority. PostgreSQL login roles are cluster-global, so a database-local grant without session fencing could also survive across databases or race a transaction commit.

The demo needs a short, auditable bridge from one freshly sealed public proof to two least-privilege consumers. It must fail closed after a bounded run rather than grow into a production history-assertion service.

### Decision

1. **Demo-only and disposable:** this mechanism exists only in the asserted isolated demo profile. Production rejects the fixture key, deterministic-clock manifest, activation capability, importer role, and activator role. One SentinelFlow demo profile owns one isolated PostgreSQL cluster authority lifecycle.
2. **Distinct secrets and digest-only persistence:** demo preparation generates two different nonzero 32-byte capabilities, one for analysis and one for validation. The handoff exposes only their lowercase `sha256:` digests to migration/bootstrap authority. Raw capability bytes remain in separate read-only volumes and are never stored in PostgreSQL, logs, output, or the other consumer.
3. **Five-minute staged database leases:** `sentinelflow_demo_importer` and `sentinelflow_demo_activator` are cluster-global `NOINHERIT`, non-superuser, non-owner roles with connection limit two and exact per-database timeouts. They are normally `NOLOGIN`, password-null, and epoch-expired. Bootstrap may open only the current stage with a SCRAM credential and `VALID UNTIL` no later than five minutes; the other role remains inert.
4. **Fresh import before activation:** migration pins the two capability digests and importer lease atomically. The one-shot history importer connects first, verifies the exact run-scoped Ed25519/JCS envelope, fixed dataset locator and digests, 24-hour coverage, import ID, source-health proof, and immutable imported rows, then either creates that one import or attaches only its exact completed recovery state. General workers lose all legacy import and validation-binding grants.
5. **Committed two-phase fencing:** after every success or authenticated failure, phase one commits the applicable role or roles as `NOLOGIN`, password-null, epoch-expired with exact attributes. Only after that commit may phase two terminate and verify all other importer/activator sessions. The sole caller is then closed. This ordering prevents a login from racing the last session scan and transaction commit. If connection setup never succeeds, the five-minute `VALID UNTIL` is the outer bound.
6. **Atomic one-hour consumer pair:** after importer fencing, a narrow handoff verifies the pinned digests and inert importer before briefly opening only the activator. `cmd/demoactivator` re-verifies the exact public proof, reads both raw capabilities, and within five minutes of manifest issue creates exactly one analysis activation and one validation activation with the same claims, activation time, and expiry. The pair expires exactly one hour after activation; partial creation, mismatched claims, a second pair, or extension is rejected.
7. **Attach and use, never create or refresh:** long-running analysis and validation processes mount only their own capability. They may attach only the byte-exact existing unexpired activation and record append-only use against one job and aggregate version. No worker can import history, create a pair, renew expiry, exchange consumer identity, silently repair order/digests, or continue on missing/expired activation.
8. **Fail-closed recovery:** exact completed import recovery and exact pair reattachment are idempotent; failed, importing, drifted, partially activated, stale, or expired state is not repaired in place. After the one-hour expiry, the operator must stop the profile, remove the entire disposable demo state and volumes, generate a new run and capabilities, and migrate/import/activate from a fresh cluster. Partial reseal, database reuse, or activation-only restart is unsupported.
9. **Cluster-wide migration guard:** migration startup, downgrade, and production transition normalize both roles across the PostgreSQL cluster, terminate retained sessions, reject memberships/elevated attributes, and verify zero peer sessions. The migration owner is the session superuser for fixed-name fencing functions; `PUBLIC` and unrelated roles receive no execution grant. Evidence-bearing activations or uses block downgrade.
10. **Independent evidence requirement:** targeted unit and PostgreSQL integration tests cover wrong capability, expired lease/activation, role-attribute drift, retained sessions, two databases sharing one cluster, failure before and after handoff, exact ACLs, empty down/up, downgrade guard, and no secret leakage. Static Compose policy must prove exact commands, dependency objects, environment owners, complete mount inventories, source-level `bind.create_host_path: false` for every approved fixed or dynamic bind, a digest-pinned OCI-capable BuildKit builder, and no authority-volume alias or writable leak. A Compose normalizer may omit an explicit false as `{}` in its runtime representation, but an explicit true remains invalid. RUN25 and hosted CI run `29696139988` cover fast mutation/outage/restart and portable CI evidence; neither substitutes for the default native-expiry, native host-ruleset, performance, or final release gates.

### Alternatives

- **Let the general worker import and validate signed history:** rejected because a long-running AI/validation process would retain database write authority and could renew its own enforcement evidence.
- **Mount one shared activation secret:** rejected because analysis and validation would no longer be independently attributable or least-privilege consumers.
- **Store raw capabilities in PostgreSQL or environment output:** rejected because a database reader or diagnostic path could impersonate either consumer.
- **Fence roles and scan sessions in one transaction:** rejected because a new authentication can race before the role change commits.
- **Renew an expired activation in place:** rejected because the original five-minute proof freshness and disposable run boundary cannot be reconstructed safely from old state.
- **Use one PostgreSQL cluster for unrelated concurrent demo profiles:** rejected for v0.1 because login roles and `VALID UNTIL` are cluster-global.

### Consequences

- The demo gains a bounded, independently testable evidence bridge without giving long-running workers import or activation authority.
- Startup has more one-shot services, capability volumes, role transitions, and failure gates; any ambiguity prevents analysis or validation from becoming enforcement-eligible.
- A demo run is intentionally limited to one hour after activation. Expiry recovery is operationally heavier because safety requires a full disposable reset and reseal.
- PostgreSQL cluster reuse and rolling renewal are not supported. A production-grade attestation service, rotation, revocation, and multi-database tenancy require OQ-015 and a follow-up ADR.
- Targeted database and static-policy evidence validates this boundary independently, and RUN25 supplies fast mutation/browser/outage evidence; release status remains **Still implementing** until native expiry and the remaining release gates pass.

---

## ADR-014: Bind expiry lifecycle to a signed read-back interval

### Status

**Accepted — implementation and native verification evidence present; release verification incomplete.** A default native Linux expiry run observed a lifecycle failure after an otherwise successful add/restart path: the stored one-point expiry expectation could precede the real kernel expiry. The corrective v2 contract is implemented, and current-tree native v6 E2E subsequently exited `0` with real expiry, signed absence, audit/recovery/forwarding convergence, and semantic host invariance. The five-minute 4 GB performance gate also exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage `436us`; final release gates remain open.

### Context

The legacy `execution-result-v1` records an outer execution interval (`started_at` through `completed_at`) and a positive integer `remaining_ttl_seconds`. It does not attest when the fixed nftables read-back began or ended. nftables JSON exposes the remaining timeout as an integer-second observation rather than an exact expiry instant. Deriving an expiry from the pre-mutation start time can therefore schedule reconciliation before the kernel element may legitimately disappear. A legitimate active element then looks late, while an absent element near the projected boundary can look early; either false result is unsafe and caused the native lifecycle gate to fail closed.

The corrective design must preserve the existing properties: the executor alone observes nftables, HIL never grants a renewal, the scheduler never re-adds or extends an element, and missing or ambiguous evidence remains fail closed.

### Decision

1. **Versioned result attestation:** new executor output MUST use [`execution-result-v2`](../contracts/enforcement/execution_result_v2.schema.json), separately signed under `Ed25519("sentinelflow execution-result-v2\\n" || SHA256(JCS(payload)))`. The v2 result retains all v1 identity, capability, artifact, operation, classification, read-back-state, TTL, schema-digest, journal-sequence, and error fields, and adds required millisecond UTC `readback_started_at` and `readback_completed_at`. They bracket only the fixed nft JSON read-back and MUST satisfy `started_at <= readback_started_at <= readback_completed_at <= completed_at`. v1 remains parseable only for historical fixtures/records and cannot supply a new expiry-classification boundary.
2. **Bounded, not guessed, expiry:** for a signed active read-back with positive `remaining_ttl_seconds`, lifecycle derives an inclusive uncertainty interval: `lower = readback_started_at + remaining_ttl_seconds`; `upper = readback_completed_at + remaining_ttl_seconds + 1 second`. The upper one-second allowance is solely for nftables' integer-second projection. The persisted lifecycle representation and scheduler MUST retain both bounds (or an equivalent lossless representation), not collapse them into an invented exact kernel-expiry timestamp.
3. **Conservative classification:** an `absent` read-back is `missing_early` only when its signed completion is strictly before `lower`; it is `expired` only when its signed start is at or after `upper`. An `active` read-back is `late_active` only when its signed start is at or after `upper`. An observation overlapping either boundary, a missing/invalid v2 bracket, an unavailable/mismatched read-back, or impossible time order is `indeterminate`; it creates no success transition and follows the existing alert/fail-closed handling. An action remains active while a valid active observation starts before `upper`.
4. **No recovery authority from time ambiguity:** neither bound permits reapplication, timeout refresh, scheduler mutation, or administrator override of failed validation. `missing_early`, `late_active`, and `indeterminate` remain failure/audit outcomes as applicable; a later legitimate block needs a new candidate, validation snapshot, HIL decision, capability, and once-only add.
5. **Migration and compatibility discipline:** the database change MUST be a new forward migration that preserves applied migration history, stores/validates the exact v2 signed bytes and digest, rejects v1 for new lifecycle scheduling, and atomically moves any schedule from an unsafe one-point expectation to the bounded contract. It MUST not rewrite a historical signed result, synthesize read-back timestamps, or silently repair a failed action.
6. **Required proof before release:** unit/contract tests must reject missing, reversed, out-of-execution-interval, non-millisecond, and wrong-domain v2 attestations. PostgreSQL integration tests must prove legitimate active, true early-missing, true expiry, late-active, overlapping-boundary indeterminate, restart, duplicate, and crash paths without a second add or TTL increase. The default real-time Linux run must then prove native expiry plus host-ruleset invariance; it is not replaced by fast Compose, fixture-clock, or static evidence.

### Alternatives

- **Use `started_at + ttl_seconds` as exact expiry:** rejected because mutation can occur after `started_at` and read-back returns an integer projection, producing false lifecycle failures.
- **Use `completed_at + remaining_ttl_seconds` as exact expiry:** rejected because completion is after the observation and still loses both read-back duration and integer projection uncertainty.
- **Add only a larger generic reconciliation grace period:** rejected because it hides the ordering error, weakens detection of true early disappearance, and does not provide signed evidence for the selected boundary.
- **Treat uncertain absence as expired:** rejected because a boundary-overlapping absence cannot prove native expiry.
- **Re-add when state is uncertain or missing:** rejected because it refreshes TTL and bypasses the exact new authority chain.

### Consequences

- Lifecycle storage and schedules gain an explicit bounded expiry contract and a result-schema migration.
- The native failure is retained as evidence of an unmet release condition; no documentation claim changes it into a passing expiry test.
- The correction increases executor/result and database compatibility work, but keeps expiry, recovery, and alert decisions evidence-bound rather than dependent on a locally guessed timestamp.

---

## ADR-015: Publish experimental research distributions separately from full v0.1 qualification

### Status

**Accepted — experimental distribution published.** The owner requested public restructuring and release publication on 2026-10-07 and confirmed Veloz ownership, official website, and security contact.

### Decision

Publish `v0.1.0-rc.1` as an explicitly experimental GitHub prerelease for authorized research evaluation. Keep the module path, runtime boundaries, migration order, MIT author notice, and all full v0.1 acceptance gates unchanged. Public documentation identifies Veloz ownership and separates implemented behavior, historical evidence, fresh release verification, and unresolved work.

Distribute only committed source and reproducible Linux build artifacts with checksums and exact commit/toolchain provenance. A release must identify checks actually run and any failures or unavailable checks. Fresh CI and packaging checks are required before publication. An artifact checksum proves byte integrity, not publisher identity or security certification. This work is M9-010 and supports NFR-005, NFR-010, NFR-011 without completing M9-008 or weakening FR-021.

### Consequences

The prerelease is a public record of defensive security work; it does not guarantee CVP admission, production readiness, or customer usage. Full implementation qualification remains governed by PRD section 12 and the existing Tasklist dependencies. Any future promotion to a stable version requires those gates and a separate release decision.

---

## ADR-016: Refresh vulnerable dependencies before public distribution

### Status

**Accepted — dependency and image regression verified.** Fresh release checks on 2026-10-07 found seven reachable Go vulnerability reports and eight high-severity npm dependency findings. Publishing the existing binaries would fail the established security gate.

### Decision

Supersede only the Go patch pin in ADR-007: use Go `1.25.13` and `golang.org/x/text` `v0.39.0`, with the corresponding digest-pinned backend build image and resolved module checksums. Upgrade vulnerable frontend dependencies within their existing major versions, preserving exact direct pins and the committed npm lockfile. Root owns all dependency locks; frontend verification remains a separate task from backend patch verification. No HTTP protocol limits, authorization, evidence, signing, HIL, or enforcement contract changes are authorized.

Before distribution rerun backend unit/framing/recovery tests, frontend unit/build/browser checks, live dependency advisories, contract vectors, and deterministic packaging on the patched commit. Refresh the immutable image-scanner database for publication and retain the existing maximum seven-day snapshot age; a dependency scan does not substitute for an image scan. Record this release prerequisite as M9-011 (backend) and M9-012 (frontend), and do not suppress failing advisories to publish.

The same maintenance also refreshes unavailable Alpine runtime package revisions to `ca-certificates=20260909-r0` and `tzdata=2026e-r0`, while preserving exact pins and `nftables=1.1.6-r1`. Linux npm resolves the optional `@emnapi/runtime` peer explicitly in the lockfile; existing package versions remain unchanged by that normalization.

M9-014 refreshes the scanner database to the official `2026-10-07T07:38:55.515026687Z` snapshot, OCI digest `sha256:a7ace06d6bb43a23fab1b9cae2a02c0b3e856006f2de75bb0c9661e655e3b74e`, and trivy.db SHA-256 `5f4b978a55284b1997dc31e9f2fc3f4f1abae80829f51451ade221d5675a69b9`. Scanner version, immutable acquisition, byte/metadata verification, freshness rejection, image evidence binding, and critical-vulnerability gates remain unchanged. Add a stale-snapshot negative regression and rerun all shipped-image scans before publication.

### Consequences

Historical July test evidence remains valid only for its recorded toolchain. New artifacts require fresh verification. This patch maintenance preserves FR-021~FR-026, NFR-002, NFR-005, NFR-010, NFR-011, and the pinned-parser negative-test obligations.

---

## 3. Frozen v0.1 decisions and follow-up ADR triggers

Detection thresholds and lifecycle, Gateway identity and protocol bounds, minimized event delivery, AI model/request/failure behavior, single-admin authentication, retention, nftables grammar/TTL/digest, validation/approval validity, protected-target policy, impact lookback, dispatcher/executor separation and recovery, non-renewable demo-history activation, bounded expiry interpretation, and performance targets are frozen in ADR-001 through ADR-014. Schema field mechanics, migration layout, queue implementation, UI composition, and test harness details must implement those decisions and are not unresolved permission to change them.

Only these product-level post-v0.1 triggers remain open:

1. **Production TLS and HA:** TLS ownership, certificate lifecycle, horizontal scaling, failover, and production availability claims require a follow-up ADR and operational evidence.
2. **Adaptive `http-deny-v1`:** any Gateway-local adaptive denial requires a distinct artifact, validator, exact digest/HIL binding, authorization model, negative tests, and follow-up ADR. An nftables approval does not authorize it.
3. **Raw-packet sensor:** any eBPF/XDP/raw-packet component requires a separate least-privilege process and follow-up ADR covering privacy, retention, capacity, protocol interpretation, and failure isolation.
4. **Production or renewable history attestation:** any reusable, renewable, cross-database, or production history authority requires a separate identity, rotation, revocation, recovery, and audit ADR. The demo-only importer/activator roles and activation capabilities cannot be promoted into that service.

Roadmap items require separate approval and are not part of the current decisions. These ADRs describe accepted intent and implementation contracts. Current verification evidence and its release limitations are recorded separately in [Implementation Readiness](./IMPLEMENTATION_READINESS.md); local implementation evidence never changes an ADR status by itself.
