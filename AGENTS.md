# SentinelFlow Repository Instructions

## Scope

This file applies to the entire repository.

SentinelFlow is an experimental, Veloz-owned open-source defensive security gateway developed and maintained by Veloz Security Research. Its v0.1 primary sensor is an inline Go HTTP reverse proxy in front of one fixed private upstream. It emits minimized request/response events, correlates them with authenticated application events, and produces constrained, reviewable response policies. Nginx, Syslog, firewall-log, and raw-packet sensors are not v0.1 release requirements.

Do not infer that a planned component exists merely because it appears in the README or design documents. Inspect the repository and tests before describing functionality as implemented or verified.

## Read before changing the project

For any non-trivial change, read the relevant parts of:

1. `README.md` for public product status, supported workflows, setup, demos, and limitations.
2. `docs/PRD.md` for product requirements and acceptance criteria.
3. `docs/ADR.md` for accepted, proposed, and open architecture decisions.
4. `docs/TDD.md` for technical contracts, component boundaries, and test design.
5. `docs/TASKLIST.md` for dependencies, priority, completion criteria, and current work status.
6. `docs/WBS.md` for the active time-boxed delivery schedule, staffing assumptions, and daily gates.
7. `docs/IMPLEMENTATION_READINESS.md` for the frozen implementation baseline, local preflight evidence, and remaining external inputs.

Read the corresponding `.ko.md` files whenever documentation is being changed. They are not summaries; they are semantically equivalent translations.

## Sources of truth and conflict handling

Use each source for its own purpose:

- Current code, tests, migrations, and verified runtime behavior establish what actually exists.
- `docs/PRD.md` establishes intended product requirements.
- `docs/ADR.md` establishes architecture decisions and their status.
- `docs/TDD.md` establishes the current technical design.
- `docs/TASKLIST.md` establishes planned order and evidence-based completion status.
- `docs/WBS.md` selects and schedules Tasklist work for the current delivery window; it does not weaken requirements or completion criteria.
- `docs/IMPLEMENTATION_READINESS.md` records preparation evidence and blockers; it never marks implementation tasks complete by itself.
- `README.md` is the public-facing summary and must reflect verified reality.

Observed code is evidence of current behavior, not automatic approval of that behavior. If implementation conflicts with an accepted requirement or decision, do not silently rewrite the documents to legitimize the code. Identify the conflict, then either fix the implementation or record an explicitly approved decision change.

When documents disagree:

1. Recheck the current implementation and available verification evidence.
2. Distinguish current behavior from intended behavior.
3. Resolve product scope in the PRD, material decisions in an ADR, and resulting contracts in the TDD.
4. Update the Tasklist and README to match the resolved state.
5. Update English and Korean document pairs in the same change.

Do not mark a proposal as accepted or a planned feature as implemented without evidence or an explicit decision.

## Required change workflow

For implementation, refactoring, security, infrastructure, or product changes:

1. Inspect the working tree and preserve unrelated user changes.
2. Identify affected `FR-*`, `NFR-*`, `ADR-*`, TDD test IDs, and `M*-*` tasks.
3. Confirm whether the work follows an accepted decision or requires a new or superseding ADR.
4. Implement the smallest coherent change without weakening a safety invariant.
5. Add or update tests in proportion to risk.
6. Verify actual behavior, including failure behavior for safety-sensitive changes.
7. Update all affected English and Korean documents in the same change.
8. Mark Tasklist items complete only when their stated completion criteria have evidence.
9. Recheck README claims, commands, limitations, and project status.
10. Run documentation, link, traceability, and whitespace checks before handoff.

Documentation synchronization is part of the implementation, not a later cleanup task.

## LLM subagent swarm execution

For a multi-component implementation, use the maximum safe subagent concurrency available at runtime. Keep one root agent as the long-running orchestrator and integration owner; fill every other available slot with a short, bounded leaf implementation package. When a leaf finishes, validate or integrate it and immediately refill the slot so the swarm can continue for the full delivery window.

Do not equate maximum concurrency with uncontrolled delegation:

1. Resolve contracts and file ownership before spawning implementation workers.
2. Give each subagent one narrow leaf package with explicit inputs, permitted paths, Tasklist IDs, deliverables, tests, and completion evidence. Target packages that can finish in roughly one to four hours.
3. Do not let two active agents edit the same owned file or migration sequence.
4. Assign cross-cutting contracts, generated clients, shared schema, and migration ordering to a single owner.
5. Keep frontend/UI/UX agents separate from backend, data, AI, security, enforcement, and infrastructure agents.
6. Continuously rotate dedicated integration, security, recovery, browser-QA, and documentation leaf agents through available slots; implementation agents do not self-certify final completion.
7. Have the root agent inspect every result, reconcile conflicts, run the appropriate gate, and update the canonical documents.
8. Merge or integrate in dependency order. A downstream agent may work from a frozen mock or contract, but cannot silently redefine it.
9. If an agent discovers a contract or architecture change, stop that package at the boundary and route the change through the owning task and required ADR/TDD updates.
10. Never use parallelism to bypass review, negative tests, safety gates, bilingual parity, or secret handling.

Subagents share the working environment unless the runtime explicitly provisions isolated worktrees. In a shared workspace, use a written ownership manifest and non-overlapping path scopes. Only the root/integration owner may resolve overlapping edits, change shared dependency locks, reorder migrations, mark canonical Tasklist items complete, or publish Git changes.

Prefer many short-lived specialist leaf agents operating under one long-running root orchestration session. A leaf agent should implement and test one coherent package, hand off a focused commit and evidence, then release its slot. The root should immediately spawn the next dependency-safe package and keep the available worker slots saturated for as long as implementation work remains. Agent status is not evidence: only integrated output and rerun verification can complete a task.

The active agent roster, dependency waves, ownership map, merge train, and daily gates belong in `docs/WBS.md` and `docs/WBS.ko.md`.

## Frontend and UI/UX task isolation

Frontend and UI/UX implementation is always a separate task from backend, domain, AI, data, security, enforcement, and infrastructure implementation.

When a feature spans both server and user interface work:

1. Create separate Tasklist IDs before implementation.
2. Complete or freeze the server/API/data contract in the backend or contract task.
3. Make the frontend/UI/UX task depend on that explicit contract task.
4. Give each task its own deliverable, completion criteria, tests, and verification evidence.
5. Use a later integration or end-to-end task only to verify the layers together; do not hide unfinished implementation for either layer inside the integration task.

Backend and contract tasks own domain behavior, persistence, authorization, safety gates, API/DTO schemas, server-side errors, and server tests. They must not implement screens, client state, interaction behavior, styling, or accessibility in `web/`.

Frontend and UI/UX tasks own information architecture, user flows, visual hierarchy, components, client state, interaction and feedback states, responsive behavior, accessibility, and browser verification. They must not silently add or change backend domain, authorization, or enforcement behavior. A required contract change becomes a separate backend/contract task first.

Shared schemas, generated clients, mock payloads, and fixtures may cross the boundary only as the agreed handoff contract. Keep the contract source in the appropriate backend/contract task and consumption in the frontend task.

If delegation or parallel execution is used, assign frontend/UI/UX work as a distinct task. Do not give one delegated task joint ownership of backend implementation and frontend/UI/UX implementation.

Frontend/UI/UX completion requires frontend-focused tests and real browser verification of the affected flow, including loading, empty, error, disabled, success, and permission-denied states where applicable. Backend completion does not imply frontend completion, and frontend completion does not imply end-to-end feature completion.

## Bilingual documentation policy

English files are canonical, and Korean translations use the same basename with `.ko.md`:

- `docs/PRD.md` ↔ `docs/PRD.ko.md`
- `docs/ADR.md` ↔ `docs/ADR.ko.md`
- `docs/TDD.md` ↔ `docs/TDD.ko.md`
- `docs/TASKLIST.md` ↔ `docs/TASKLIST.ko.md`
- `docs/WBS.md` ↔ `docs/WBS.ko.md`
- `docs/IMPLEMENTATION_READINESS.md` ↔ `docs/IMPLEMENTATION_READINESS.ko.md`

Maintain strict semantic parity between every pair:

- Preserve the same section structure and ordering.
- Preserve all requirements, decisions, design logic, safety boundaries, examples, limitations, and open questions.
- Preserve identifiers, priorities, prerequisites, status values, checkboxes, and completion criteria.
- Do not translate code, commands, paths, schema fields, enum values, API fields, or identifiers.
- Do not make one language a summary of the other.
- Do not add normative content to only one language.
- Preserve the strength of terms such as `MUST` and `SHOULD`, and the distinction between Accepted, Proposed, Open, and Superseded.

Allowed differences are natural-language translation, the language-switch link, and links that intentionally point to the corresponding language file.

If a translation conflict is found, use the English file only as the canonical comparison point. Recheck the actual project decision and implementation before synchronizing both files; do not hide a substantive disagreement by blindly overwriting the Korean file.

New normative project documentation under `docs/` should follow the same English-plus-`.ko.md` convention unless the user explicitly exempts it.

`AGENTS.md` is an operational instruction file outside `docs/` and does not require a translated pair unless explicitly requested.

## Documentation responsibilities

Update documents according to the type of change:

| Change | Required documentation action |
| --- | --- |
| Public feature, supported source, setup, command, demo, limitation, or status | Update `README.md` |
| Product scope, user journey, requirement, priority, acceptance criterion, or non-goal | Update both PRD files |
| Material architecture, dependency, trust boundary, irreversible choice, or replacement of an earlier decision | Add or update an ADR in both languages |
| Component boundary, data/API/SSE contract, state machine, failure behavior, security design, deployment, or test strategy | Update both TDD files |
| Work dependency, deliverable, priority, completion evidence, or progress | Update both Tasklist files |
| Delivery schedule, staffing assumption, daily gate, or time-boxed scope | Update both WBS files and keep their Tasklist mappings current |
| Frozen implementation baseline, local preflight, or external readiness input | Update both Implementation Readiness files without overstating code completion |
| Feature spanning backend and frontend/UI/UX implementation | Create separate backend/contract and frontend/UI/UX Tasklist IDs with an explicit dependency |
| Repository-wide agent workflow or maintenance convention | Update `AGENTS.md` |

For a cross-cutting change, update every affected row, section, and traceability reference rather than only the most obvious document.

## Identifier and status discipline

The current traceability system is:

- Product requirements: `FR-001` through `FR-026`
- Non-functional requirements: `NFR-001` through `NFR-014`
- Architecture decisions: `ADR-001` through `ADR-012`
- TDD tests: `UT-*`, `CT-*`, `IT-*`, `E2E-*`, `SEC-*`, and `REC-*`
- Work items: milestones `M0` through `M11` and task IDs such as `M5-003`

When extending these sets:

- Add new stable IDs monotonically; do not renumber or reuse existing IDs for unrelated meaning.
- Update all cross-references in PRD, ADR, TDD, and Tasklist pairs.
- Keep the same ID, meaning, status, priority, and dependencies in both languages.
- Record a superseding ADR instead of rewriting decision history as though the former decision never existed.
- Check a Tasklist box only after its deliverable and completion criteria are satisfied and verified.
- If a task is only partially complete, leave it unchecked and describe the verified partial state without overstating it.

## Security and safety invariants

These invariants must not be weakened implicitly:

1. Deterministic signals and rules run before AI analysis.
2. GPT receives a compact, structured incident summary, not a synchronous request, unrestricted raw-log stream, request/response body, query string, cookie, authorization header, or raw header map.
3. HTTP metadata, application events, optional logs, retained evidence, and model output are untrusted data. Embedded text never becomes model instruction.
4. Observed facts, deterministic conclusions, AI interpretation, human decisions, and enforcement outcomes remain distinguishable and traceable.
5. Model output is constrained by a schema. It may contain an evidence-bound, single-IP nftables blacklist command candidate, but never unrestricted shell or arbitrary firewall commands.
6. The model has no direct firewall authority. Its command candidate is untrusted data until it is strictly parsed, canonicalized, validated, and approved through HIL.
7. Enforcement follows this ordered hard-gate path:

   `structured-output and command-grammar parsing/canonicalization → policy-evidence-command consistency → protected-network checks → nftables syntax validation against the owned-set schema → historical-impact analysis → administrator HIL approval of the exact artifact by digest → isolated shell-free temporary enforcement → automatic expiry and audit`

8. Missing, stale, failed, timed-out, or ambiguous validation fails closed.
9. Administrator approval cannot override failed safety validation and must bind the exact policy version/digest, generated and canonical command digests, immutable evidence/validation snapshot, actor, reason, and validity. Any dependent mutation requires revalidation and reapproval.
10. Default demo enforcement runs only in the Gateway network namespace through a separate `CAP_NET_ADMIN` executor sidecar. The executor is the only privileged bootstrap provisioner: it verifies the pinned raw base-chain contract SHA before loading it, then verifies the separate canonical live-structure digest. The owned input chain must reference the timeout set on the protected Gateway port, and host nftables must remain unchanged.
11. Every applied block has a finite lifetime, native automatic expiry, and an auditable lifecycle. An add artifact is applied once; a checksummed two-phase journal fsyncs the complete signed request and canonical artifact before mutation and an executor-signed terminal result after invocation/read-back. Duplicate or crash recovery may reverify persisted bytes and read back state but must never refresh TTL or invoke add again; torn/corrupt records fail closed and reapplication requires a new validation and HIL decision.
12. Secrets stay outside the repository, fixtures, logs, model context, screenshots, and audit payloads.
13. General API, AI, and worker components do not receive executor privileges or signing keys. Only a minimal non-AI dispatcher with a restricted authorized-operation database view may sign a short-lived, single-use exact-artifact capability. The executor verifies it, recomputes the canonical digest, uses a fixed `nft` binary and fixed arguments without a shell, and signs a digest-bound `execution-result-v1` with a separate Ed25519 key over a private UDS. The UDS accepts one bounded length-prefixed request and response with strict schemas, unpadded base64url bytes, two-second deadlines, and no TCP listener. Signed JSON uses RFC 8785/JCS and golden vectors.
14. The Gateway request path never waits for GPT, PostgreSQL, a policy validator, administrator approval, or nftables. Control-plane failure continues forwarding, exposes degradation, and cannot create a new adaptive block.
15. The v0.1 canonical client IP is the direct TCP peer after canonical parsing. The Gateway removes inbound `Forwarded` and `X-Forwarded-*`, regenerates forwarding headers from trusted connection state, accepts only allowlisted hosts, and routes only to the startup-configured private upstream.
16. The Gateway persists only the minimized `gateway-http-v1` contract. Observed exact paths, query strings, bodies, cookies, authorization/session material, account names, and unrestricted headers must not enter persistence, prompts, ordinary logs, audit payloads, screenshots, or captured fixtures; only versioned route/path classifications may persist. Reviewed synthetic exact paths are allowed only inside versioned parser/catalog test inputs that cannot be confused with observed traffic.
17. The Gateway never receives `CAP_NET_ADMIN`, raw-socket access, OpenAI credentials, executor authority, or a request-selected upstream. Raw packet sensing remains a separate future privilege and failure domain.
18. Deterministic protocol, size, and timeout controls may reject invalid or out-of-contract HTTP traffic without HIL. Any AI-derived adaptive action still requires its exact grammar, validation, digest, and HIL contract. Approval of `nft-blacklist-v1` never implicitly approves a future `http-deny-v1` action.
19. Manual removal uses a separate deterministic `nft-revoke-v1` artifact bound to an active action, original digest, administrator, and reason. It cannot add a rule or inherit authority from the AI-generated add artifact.
20. Event-batch restart, epoch, sequence-gap, and atomic-ack behavior must make loss explicit without blocking Gateway forwarding. Every Gateway and auth producer has its own checkpoint and may emit endpoint-scoped source health. `X-Sentinel-Sender-ID` and the endpoint path are included in the HMAC input; the bounded header selects an endpoint-scoped base64 key of at least 32 random bytes before the body is read, and the authenticated body sender must match. Nonces are bounded 128-bit random base64url values and enter the replay cache only after sender, endpoint, time, body digest, and constant-time signature checks. Incomplete or unknown coverage cannot support enforcement.
21. The Gateway removes inbound SentinelFlow request/trace headers and sends fresh `X-SentinelFlow-Request-ID` and `X-SentinelFlow-Trace-ID` values to the private application. Exact auth binding uses those values, canonical source, service, and route. Record times beyond 60 seconds future or 5 minutes past receipt remain traceable but are untrusted and cannot enforce.
22. Go `net/http` is the sole request-framing parser. Do not add a second raw pre-parser or claim a byte-exact wire limit that `http.Server.MaxHeaderBytes` does not provide. Pin the Go toolchain and use raw-socket end-to-end differential tests to prove rejected or safely normalized framing reaches the fixed origin as at most one normalized request.
23. Policy, evidence, validation, normalized reason, HIL authorization, capability, result, protected-range, and demo-history digests use versioned RFC 8785/JCS bytes and lowercase `sha256:` encoding. Evidence references are strictly sorted, duplicate-free, and byte-identical across AI output levels; mismatch or out-of-order input is rejected without silent repair.
24. Lifecycle `inspect` is a separately signed, typed, read-only executor operation derived from an existing action. It may execute only the fixed nftables read-back command and can never add, delete, extend, or reuse HIL mutation authority. Manual removal remains `nft-revoke-v1`.

Any proposed change to this sequence or trust model requires explicit PRD/TDD updates, a reviewed ADR, matching Korean translations, threat analysis, and failure-path tests.

## Planned architecture is not current implementation

The documents currently propose:

- Go `net/http`/`httputil.ReverseProxy`, chi, pgx, sqlc, PostgreSQL, and the OpenAI Responses API
- React, TypeScript, Vite, and MUI
- Docker, Docker Compose, Linux, nftables, and an isolated enforcement namespace
- Entry points under `cmd/gateway`, `cmd/api`, `cmd/worker`, `cmd/dispatcher`, `cmd/executor`, and `cmd/simulator`; `cmd/ingestor` is reserved for optional post-v0.1 adapters
- Domain packages under `internal/gateway`, `ai`, `api`, `correlation`, `detection`, `enforcement`, `events`, `ingestion`, `policy`, `repository`, and `validation`

Treat these as proposed until the corresponding files, builds, tests, and ADR status demonstrate adoption. Do not create large portions of the target tree merely to make the repository resemble the diagram; create only what the current task requires and preserve clear component boundaries.

When code is added, keep the Gateway data plane isolated from the control plane and keep privileged enforcement isolated from the Gateway, ingestion, API, AI, and general worker code. Prefer typed event and artifact contracts, strict nftables command parsing/canonicalization, digest binding, fixed upstream routing, minimized metadata, and fixed shell-free execution over string interpolation or request-controlled routing.

## Gateway implementation boundaries

The Gateway implementation must preserve these frozen v0.1 contracts unless an explicit superseding decision changes them:

- one startup-configured private-HTTP upstream and an allowlisted public host; origin CIDRs are non-broad RFC 1918 ranges and every resolved/dialed address is revalidated with public, metadata, IPv6, mixed, and rebinding answers rejected;
- direct TCP peer as canonical client identity, with inbound forwarding and SentinelFlow request/trace headers removed and fresh forwarding, request-ID, and trace-ID headers generated for the private application;
- origin-form HTTP/1.1 only, optional-TLS ALPN restricted to `http/1.1` with Go HTTP/2 auto-configuration disabled, deterministic rejection of unsupported target/upgrade/trailer/Expect forms and ambiguous encoding, normalized ASCII Host matching, no automatic compression transformation, configured `http.Server.MaxHeaderBytes=32768` verified against the pinned Go parser rather than treated as a raw-wire byte promise, `4 KiB` request-target/`2 KiB` classification-path limits, `10 MiB` request-body limit, `5s` header-read timeout, `30s` request/upstream timeout, and `60s` idle timeout;
- bounded asynchronous event delivery that never blocks request forwarding; queue or sink degradation is metered, alerted, and never interpreted as evidence for a block;
- `event-batch-v1` internal Gateway/auth envelopes containing endpoint/key-bound stable `sender_id`, per-boot `sender_epoch`, stable `batch_id`, monotonic per-epoch `sequence`, `sent_at`, and 1–100 typed records within 256 KiB; HMAC-SHA256 uses a base64-encoded key of at least 32 random bytes and covers endpoint path, bounded `X-Sentinel-Sender-ID`, timestamp, a 128-bit random base64url nonce, and raw-body digest with constant-time comparison and ±60-second request-auth skew; header/body sender equality is mandatory; nonce insertion occurs atomically only after sender/endpoint lookup, time check, and valid signature, then remains in a five-minute replay cache; retries preserve exact body/epoch/batch/sequence, receivers acknowledge a whole batch atomically, every producer owns a durable health checkpoint/source-health stream, and record-time trust is +60 seconds/-5 minutes relative to receipt; default queue 10,000, batch 100, flush 100 ms;
- no exact path, query, body, cookie, authorization, session, raw account, or unrestricted header persistence; `path-catalog-v1` emits only configured route labels and one of eight built-in suspicious-path IDs or `none`;
- fixed detector defaults of all 8 versioned suspicious-path IDs/60s, 120 requests/10s, 10 exact `/login` route `401`/`403` responses/60s, and 20 verified failed authentication events across 8 account hashes/5m;
- same-source incident overlap of 5 minutes, close after 15 minutes idle, and reopen within 30 minutes;
- explicit `gpt-5.6-sol` Responses API calls with immutable checked-in input schema, system prompt, and `contracts/ai/sentinelflow_analysis_v1.schema.json` strict output contract; all enforcement-eligible signal references for one incident version are stable-ID sorted and included without silent truncation, while duplicate/out-of-order/over-50/over-12-KiB input fails typed and output evidence arrays must be sorted, unique, and byte-identical; `reasoning.effort: medium`, `store: false`, no tools, 2,048 output tokens, a 30-second timeout, one classified transient retry, concurrency two, and a configurable USD 10/UTC-day demo budget use versioned operator rates plus atomic conservative reservation that fails closed when missing or exhausted;
- `inet sentinelflow blacklist_ipv4` plus its owned protected-port input chain; the executor alone bootstraps the raw-SHA-pinned contract and verifies a distinct canonical live-structure digest; integer `ttl_seconds` `60..86400` must equal the parsed command timeout, which canonicalizes to the largest exact `h` or `m` unit or otherwise integer `s`; command bytes are UTF-8 with one trailing LF and SHA-256; validation/approval validity is five minutes, historical impact lookback is 24 hours, execution uses RFC 8785/JCS dispatcher-signed one-shot capabilities and separate executor-signed results, inspect is separately signed/read-only, and revocation is a separate deterministic artifact;
- only canonical global-unicast IPv4 enforcement targets under the checked-in versioned protected-IPv4 contract; built-in unspecified, loopback, private, link-local, CGNAT, benchmarking, documentation, multicast, reserved, management, current-administrator-path, and IPv6 protection cannot be disabled by configuration; only the three RFC 5737 ranges may be removed by the isolated demo exception with namespace and host-diff evidence;
- event/evidence retention of 7 days, incident/AI/policy retention of 30 days, and audit retention of 90 days;
- one Argon2id-backed administrator with an opaque server-side session capped at 8 hours/30 minutes idle, rotation at login and privileged actions without changing independent `authenticated_at`, synchronizer CSRF, password step-up after 15 minutes, five-minute single-use session/artifact-bound decision challenges, five HIL decisions per minute per session, and pre-hash login limits of 5/minute/source plus 20/minute globally without persistent account lockout;
- a p95 Gateway overhead target of at most 5 ms at 500 RPS on the 4 GB reference environment.

If an implementation package needs to change one of these values, stop at the contract boundary and route the change through PRD/ADR/TDD and both language pairs before implementation continues.

## Testing and verification

Use the most relevant implemented checks. The README currently labels setup and test commands as planned, so do not claim they pass until the corresponding code and configuration exist.

For documentation-only changes, at minimum:

1. Run `git diff --check`.
2. Run the repository traceability validator:

   `node scripts/validate-docs.mjs`

3. Verify all checked-in schemas, JCS digests, public test keys, HMAC/Ed25519 signatures, UDS frames, demo-history binding, and golden vectors:

   `node scripts/generate-contract-vectors.mjs --check`

4. Run Markdown lint with the known compatible command:

   `npx --yes markdownlint-cli --disable MD013 MD024 -- README.md AGENTS.md docs/*.md`

5. Validate every local Markdown path and anchor.
6. Confirm every README quotation is exact and links to the correct section.
7. Compare English/Korean heading order and identifier sets.
8. Compare PRD requirement priority, ADR state, TDD test IDs, and Tasklist checkbox/priority/prerequisite values across languages.

For code changes, also run all relevant unit, contract, integration, end-to-end, security, and recovery tests defined by the implemented project. Safety-sensitive work requires negative and failure-path tests, not only a happy path.

If a command cannot run because the implementation or dependency does not exist, report it as unverified. Do not rewrite documentation to imply success.

## Secrets, fixtures, and evidence

- Never commit `.env`, API keys, database passwords, tokens, session data, or real credentials.
- Use documentation-safe example addresses and synthetic identities.
- Do not place real request/response content, authentication events, account identifiers, or log data into fixtures unless it has been reviewed, irreversibly sanitized, and required by an explicit test contract. Reviewed synthetic exact paths may appear only in versioned parser/path-catalog test inputs; never copy an observed path into a fixture.
- Preserve useful failure evidence while redacting secrets and unnecessary personal data.
- Treat screenshots and demo recordings as potential secret-bearing artifacts and review them before inclusion.
- Keep OpenAI credentials outside model prompts and outside executor configuration.

## Git and change hygiene

- Preserve unrelated working-tree changes.
- Stage only files that belong to the requested change.
- Do not commit or push unless explicitly requested.
- Do not rewrite history or discard user changes.
- Keep generated files and dependency artifacts out of Git unless the project explicitly adopts them.
- Before handoff, summarize files changed, verification performed, unverified items, and any documentation or implementation conflict that remains.

## Repository license

The root `LICENSE` and README identify the project as MIT-licensed. Keep public documentation and submission metadata aligned with that file. Any future license change requires explicit owner approval and a repository-wide notice review.

## Definition of done

A change is complete only when all applicable conditions hold:

- The requested behavior or document change is implemented.
- Relevant positive, negative, and failure-path verification passes.
- Security invariants remain intact.
- Current behavior and intended behavior are not conflated.
- Affected README, PRD, ADR, TDD, Tasklist, WBS, and Implementation Readiness content is synchronized.
- Backend and frontend/UI/UX implementation is represented by separate tasks with independent evidence.
- English and Korean document pairs are semantically equivalent.
- Traceability IDs and task dependencies remain consistent.
- No secret or unrelated change is included.
- Remaining limitations and unverified claims are stated explicitly.
