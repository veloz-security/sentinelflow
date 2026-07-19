# SentinelFlow Product Requirements Document (PRD)

**English** | [한국어](PRD.ko.md)

| Field | Value |
| --- | --- |
| Document status | Draft |
| Source of record | [`README.md`](../README.md) |
| Target release | SentinelFlow v0.1 single-node reference implementation / experimental research release |
| Last updated | 2026-07-19 |
| Product category | Explainable AI security gateway / Developer Tools |

> "SentinelFlow is an explainable AI security gateway that observes web traffic through an inline reverse proxy, correlates structured evidence, and applies temporary response actions only after strict validation and administrator HIL approval."
>
> — [`README.md`](../README.md)

## 1. Purpose and interpretation

This document turns the product intent in `README.md` into requirements that can be implemented and verified. The v0.1 target is an implementation-complete, single-node reference release: real code, persistence, REST/SSE, browser UI, OpenAI adapter, isolated nftables enforcement, recovery, performance, and security evidence must work together. It is not a claim of production readiness, high availability, multi-tenancy, or host-firewall deployment. The implementation now exists, but the remaining release gates in Section 12 still prevent a complete-release claim. Requirements in this document use the following interpretation:

- **Evidence**: a short, direct quotation from the README supports each major requirement area.
- **MUST**: required for the v0.1 implementation-complete release candidate.
- **SHOULD**: desirable for the release, but may be deferred only through an explicit product decision that updates this PRD and the public limitations.
- **Design proposal**: implementation detail not fixed by the README and subject to review.
- **Open question**: a decision that must be made by the product owner or through implementation evidence.

Example commands, screenshots, and deployment details in the README are treated as completed functionality only to the extent identified by current implementation and rerun evidence. A smoke result does not satisfy a stricter release condition.

The repository and README identify the project under the MIT [`LICENSE`](../LICENSE). Final submission metadata and dependency notices must remain consistent with that file.

## 2. Product summary

SentinelFlow is a Gateway-first hybrid security system. Its v0.1 primary HTTP sensor is an inline Go reverse proxy placed before one fixed private upstream; it is not a general-purpose origin web server. The Gateway derives sanitized request/response metadata directly from traffic and publishes normalized events asynchronously. An authenticated application auth-event adapter supplies account-aware evidence required for credential-stuffing analysis. Nginx access-log and Syslog/firewall-log adapters remain compatible post-v0.1 inputs, but are optional P2 work rather than primary ingress.

Deterministic detectors and correlation run before asynchronous GPT-5.6 analysis. GPT-5.6 explains likely behavior and uncertainty and generates an evidence-bound blacklist policy plus one constrained nftables command candidate. The candidate remains untrusted data until strict parsing, canonicalization, evidence consistency, safety validation, and administrator Human-in-the-Loop (HIL) approval bind the exact artifact by digest. Only a separate isolated executor may receive the canonical bytes, recompute the digest, and apply the temporary rule without a shell. The Gateway itself has no `NET_ADMIN` capability.

### 2.1 Product flow

`Client → SentinelFlow Gateway → fixed private upstream` and, asynchronously, `sanitized Gateway metadata + authenticated application auth events → normalized events → deterministic detection → source-IP correlation → GPT-5.6 explanation and constrained nftables blacklist command candidate → command grammar/canonicalization and policy-evidence-command consistency → protected-network, owned-set syntax, and impact validation → administrator HIL approval of the exact artifact by digest → isolated shell-free temporary nftables enforcement`

The HTTP request path never waits for GPT-5.6, PostgreSQL, or administrator approval. This sequence is a safety boundary: implementations must not omit control-plane stages, grant GPT-5.6 direct execution authority, or give the Gateway firewall privileges.

## 3. Problem statement

Security operators need to connect a source IP's path scans, repeated authentication failures, multi-account attempts, and abnormal request bursts without depending on delayed, heterogeneous, or incomplete external logs. A log-only architecture adds parser and delivery complexity before the product can observe the request that matters. An inline Gateway can produce a consistent event at the request boundary while the authenticated application adapter contributes account semantics that an HTTP proxy cannot safely infer.

The product addresses seven core problems:

1. A protected application needs consistent, immediate HTTP evidence without adopting a new origin server.
2. Client identity and forwarding headers are unsafe unless the Gateway owns their normalization boundary.
3. Individual request and authentication events do not expose a correlated attack sequence.
4. AI explanation is useful, but untrusted evidence, hallucination, and disproportionate response remain risks.
5. Firewall actions can lock out administrators, block legitimate users, or create overly broad rules.
6. An inline data plane must keep forwarding during control-plane, database, AI, or approval outages.
7. Normal and attack traffic must be reproducible for demos, security tests, and regression tests.

## 4. Goals and non-goals

### 4.1 v0.1 implementation goals

- Run an inline Go reverse proxy before one allowlisted, private, fixed upstream without becoming an origin-server framework.
- Strip incoming forwarding headers, derive canonical client identity from the TCP peer, regenerate trusted forwarding headers, and emit minimized request/response metadata asynchronously.
- Keep traffic forwarding independent of PostgreSQL, AI, administrator decisions, and a bounded event queue; expose degradation and event loss without blocking valid traffic.
- Accept authenticated application auth events for account-aware credential-stuffing evidence.
- Detect path scanning, request bursts, brute-force login, and credential stuffing with frozen deterministic thresholds and correlate incidents by canonical source IP.
- Use `gpt-5.6-sol` through the Responses API to produce evidence-linked explanations, uncertainty, possible false positives, a constrained policy, and one evidence-bound nftables command candidate.
- Parse and canonicalize the command, verify immutable evidence membership and policy/evidence/command consistency, then validate protected networks, nftables syntax against the owned-set schema, and historical impact.
- Let the single v0.1 administrator review and explicitly approve or reject the exact artifact through HIL.
- Apply approved blocks temporarily in an isolated environment, expire them automatically, and audit the lifecycle.
- Reproduce normal, attack, outage, backpressure, protocol-security, approval, and expiry scenarios through repeatable simulations and tests.

### 4.1.1 Current implementation goals (2026-07-19)

The current delivery goal is to turn the integrated implementation into a release-qualified, reproducible v0.1 baseline while preserving the accepted safety boundaries:

1. Keep the Gateway data plane non-blocking and unprivileged, with deterministic detection before AI, exact-artifact HIL, isolated shell-free enforcement, bounded TTL, read-only inspection, and fail-closed recovery.
2. Preserve the independent backend/control-plane and frontend/UI/UX workstreams, and synchronize every verified status change across the English and Korean documents.
3. Reproduce the complete mutation path from signed demo history through add, inspect, revoke, outage, restart, audit, and cleanup; RUN25 fast evidence covers this path, while native expiry remains open.
4. Obtain independent Linux evidence for native kernel expiry, host-ruleset invariance, and the five-minute 500-RPS/4-GB performance gate.
5. Reproduce the gates from a committed clean checkout, and run a live OpenAI smoke only as an explicit, billable opt-in; deterministic stub mode remains the default.
6. Prepare the final release evidence, screenshots, commands, limitations, and decision without claiming completion until every release-blocking prerequisite has evidence.

### 4.2 Non-goals

- Guaranteeing detection of every attack or zero false positives.
- Operating as a general-purpose origin web server, production WAF, high-availability proxy, or multi-tenant service.
- Raw packet capture, payload inspection below HTTP, eBPF/XDP sensing, or an in-process packet analyzer.
- Learned behavioral baselines or multi-node operation in v0.1.
- Enforcement through systems other than nftables.
- Direct firewall modification, self-approval, or arbitrary shell execution by AI. AI command generation does not grant execution authority.
- Direct adaptive L7 denial by the Gateway. A future `http-deny-v1` action requires a separate artifact contract and ADR.
- Host-level production enforcement as the default workflow.
- Nginx access-log, Syslog/firewall-log, Traefik, Apache, SSH, raw-packet, OpenSearch, SIEM, or cloud WAF adapters as v0.1 completion criteria.

> "Raw packet capture and analysis are not part of v0.1."
>
> — [`README.md`](../README.md)

## 5. Users and core jobs

### 5.1 Security analyst

- Investigate a correlated incident across Gateway and authenticated application events.
- Review quantitative signals and retained minimized evidence.
- Evaluate the AI explanation, uncertainty, and false-positive hypotheses.

### 5.2 Security administrator / approver

- Review the target, evidence, excluded CIDRs, duration, canonical nftables command, command digest, and estimated impact.
- Approve or reject the exact validated command through HIL and record a reason.
- Verify application, automatic expiry, failures, and audit history.

### 5.3 Developer / demo operator

- Start an isolated demo with Docker Compose.
- Place a private demo upstream behind the Gateway and run reproducible normal and attack simulations.
- Execute automated proxy, protocol-security, event, detection, correlation, policy, and enforcement tests.

## 6. Scope

### 6.1 Input sources and boundaries

- **Primary v0.1 sensor:** SentinelFlow Gateway request/response metadata from one allowlisted host and one fixed private upstream
- **Required v0.1 enrichment:** authenticated application auth events with pseudonymous account hashes
- **Optional P2/post-v0.1 adapters:** Nginx access logs, Syslog over TCP/UDP, and Linux firewall/nftables syslog
- **Excluded from v0.1:** raw packet capture or analysis and direct adaptive L7 enforcement

### 6.2 Detection scenarios

| Scenario | Primary signals | Expected outcome |
| --- | --- | --- |
| Credential stuffing | At least 20 failed authenticated app events across at least 8 account hashes from one canonical source IP within 5 minutes | Multi-account attack-candidate incident |
| Brute-force login | At least 10 Gateway `401`/`403` responses on configured authentication routes from one canonical source IP within 60 seconds | Brute-force candidate incident |
| Automated path scanning | At least 8 distinct configured suspicious paths from one canonical source IP within 60 seconds | Path-scan candidate incident |
| Abnormal request burst | At least 120 Gateway requests from one canonical source IP within 10 seconds | Automated-abuse or application-layer DoS candidate |

Incidents correlate on canonical source IP with a 5-minute overlap, close after 15 minutes without a related event, and reopen when matching evidence arrives within 30 minutes after closure.

## 7. Functional requirements

### 7.1 Optional legacy ingestion and shared normalization

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-001 | SHOULD | A post-v0.1 adapter should receive Syslog over TCP and UDP without becoming a dependency of the Gateway request path. | P2 adapter fixtures from both transports are processed with source and receive time; malformed messages do not stop the Gateway or control plane. |
| FR-002 | SHOULD | Post-v0.1 source-specific parsers should support Nginx access logs and Linux/nftables events; authenticated application events are implemented separately under FR-026. | Normal, edge, malformed, and redaction fixtures pass for each implemented optional adapter without changing the canonical Gateway identity contract. |
| FR-003 | MUST | Gateway and application-auth records must be normalized to a shared event schema while retaining only minimized, source-specific evidence. | Core Event Model fields can be stored and retrieved; prohibited HTTP fields never persist; parse failures and missing fields remain traceable. |
| FR-004 | MUST | Normalized events and incidents must be persisted in PostgreSQL. | Incidents and linked evidence survive restart, and duplicate-handling behavior is tested. |

Optional legacy adapters retain their established IDs and meanings, but they are P2/post-v0.1 work and cannot delay the Gateway-first release gate.

### 7.2 Gateway-first ingress and authenticated application events

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-022 | MUST | The SentinelFlow Gateway must run as an inline Go reverse proxy before one private fixed upstream and act as the primary v0.1 HTTP sensor, not as a general origin server. | Protected app traffic reaches the Gateway directly; optional TLS terminates in the Gateway; allowed requests proxy end to end; arbitrary upstream selection, origin file serving, dynamic virtual hosting, and direct public access to the upstream are absent; the admin UI may use a separate endpoint. |
| FR-023 | MUST | The Gateway must derive canonical client identity from the TCP peer, sanitize forwarding and SentinelFlow identity headers, and accept only the frozen HTTP/1.1 host/origin contract. | Spoofed forwarding/request/trace headers cannot change identity; the Gateway supplies fresh request/trace IDs to the private application; Go `net/http` is the sole framing parser and raw-socket differential tests prove rejected or safely normalized input reaches the origin as at most one request; only normalized ASCII allowlisted Host and origin-form HTTP/1.1 are accepted; the fixed upstream uses private `http`, and every DNS/dial address remains inside non-broad RFC 1918 `origin_cidrs`. |
| FR-024 | MUST | The Gateway must asynchronously emit a versioned, sanitized request/response event containing only approved metadata. | `gateway-http-v1` contains IDs/times, canonical source IP, allowlisted host/service, method, fixed `HTTP/1.1`, `route_label`, `path_catalog_version`, allowlisted `suspicious_path_id` or `none`, response status, byte counts, and latency; exact/raw/decoded paths, query strings, bodies, cookies, `Authorization`, and raw secret-bearing headers never persist or enter AI context. |
| FR-025 | MUST | The Gateway data plane must be isolated from the database, AI, HIL, and enforcement control plane and must continue forwarding valid traffic during their outage or bounded-queue saturation. | The request path never waits for the control plane; `event-batch-v1` authenticates bounded header sender ID plus endpoint/body digest, requires header/body sender equality, and uses per-boot epoch, sequence, atomic acknowledgement, and per-producer checkpoint/source health without an event spool; saturation, gaps, restart loss, or record time beyond +60 s/-5 min creates explicit untrusted/incomplete coverage that cannot support enforcement; approved TTL rules still expire. |
| FR-026 | MUST | An authenticated application auth-event adapter must provide trustworthy account-aware success/failure evidence for configured authentication routes. | The demo application binds its HTTP listener only to the origin network and its producer reaches only the ingest-network API listener; it uses the Gateway-generated request/trace IDs, its own checkpoint/source-health stream, and HMAC replay protection; pending binding lasts at most 5 minutes and requires exact request ID, trace, source IP, `demo-app` service, and route; only verified failures support attack evidence, mismatch/expiry cannot enforce, and any unverified success blocks impact approval. |

### 7.3 Detection and correlation

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-005 | MUST | Before any AI call, the system must calculate measurable Gateway and verified-auth signals by canonical source IP. | Identical input yields identical signals; `path-catalog-v1` fixes `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, and `backup_archive`; exact fixtures cover all 8 IDs/60s, burst 120/10s, exact `/login` route 10 `401/403`/60s, and 20 verified failures across 8 account hashes/5m. |
| FR-006 | MUST | Suspicious activity must be detected with the frozen deterministic thresholds and event-time windows defined in FR-005. | Every scenario is detected exactly at its threshold, remains absent immediately below it, tolerates defined duplicates/order behavior, and reports normal-fixture outcomes separately. |
| FR-007 | MUST | Events must correlate on canonical source IP using a 5-minute overlap; incidents must close after 15 minutes idle and reopen for matching evidence received within 30 minutes after closure. | Related Gateway/auth fixtures join one incident with stored relation reasons; unrelated source IPs remain separate; close, late-event, and reopen boundary tests pass. |

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> — [`README.md`](../README.md)

### 7.4 AI analysis and explanation

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-008 | MUST | The asynchronous AI adapter must call `gpt-5.6-sol` through the Responses API with reasoning `medium`, `store: false`, no tools, and immutable checked-in input-schema, prompt, and strict `sentinelflow_analysis_v1` output artifacts. | Contract tests inspect every digest and outgoing request; all enforcement-eligible signal references for one immutable incident version are stable-ID sorted and included without truncation; duplicate/out-of-order/over-50/over-12-KiB input fails typed; the complete server-side event expansion is sorted-unique and limited to 1,000,000 IDs, with overflow failing as `input_too_large` rather than sampling; concurrency is two and USD 10/UTC-day uses versioned rates plus atomic reservation/settlement. A queued version that immutable history proves was overtaken completes as audited `analysis_superseded` before any provider claim or dead letter and does not mutate the current incident, while a truly missing aggregate remains unresolved fail-closed evidence. |
| FR-009 | MUST | AI analysis must include an incident summary, likely classification, evidence, confidence or uncertainty, possible false positives, a proportionate response recommendation, and the FR-021 command candidate. | Output evidence arrays are duplicate-free, strictly sorted, and byte-identical; one 30-second attempt and at most one classified transient retry are allowed; refusal, incomplete response, timeout, `input_too_large`, schema/evidence-reference failure, or budget exhaustion sets the sole non-enforcing `analysis_failed` state with a typed reason and creates no enforcement. |
| FR-010 | MUST | AI output must be visibly and structurally separated from observed deterministic signals and evidence. | API and UI consumers can distinguish observed facts, model interpretation, and unresolved claims. `latest_analysis` is exposed only when its incident and observed evidence-version binding matches the current incident projection, and the read is cross-statement consistent. |

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> — [`README.md`](../README.md)

The fixed adapter contract follows the official [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). Any model or schema-version change requires contract revalidation and documentation updates. The opt-in `cmd/openaismoke` proves disabled and missing-key fail-closed behavior locally, but no live billable model result has been recorded.

### 7.5 Policy safety, approval, and enforcement

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-011 | MUST | A response recommendation must contain a constrained policy and a schema-bounded nftables command candidate rather than an unrestricted shell command. | Unsupported actions, invalid IP/CIDR/duration values, additional statements, shell syntax, and command fields outside the allowed grammar are rejected. |
| FR-012 | MUST | A policy and command candidate must pass structured-output/schema validation, command parsing/canonicalization, policy/evidence/command consistency, protected-network checks, nftables syntax validation against the owned-set schema, and historical-impact analysis in order. | Policy, sorted-unique evidence, validation, normalized reason, and authorization use versioned JCS/lowercase SHA-256 contracts; the protected-IPv4 file, raw base-chain SHA, canonical live-schema digest, checks, and 24-hour impact are bound into one immutable 5-minute snapshot. Artifact-content digests are non-unique integrity/lookup values rather than row, lifecycle, or authorization identities, so repeated bytes require fresh evidence-bound workflow IDs and authority. In the asserted demo profile, historical completeness additionally requires a fresh run-scoped signed proof imported under a five-minute one-shot lease and an unexpired, exact one-hour consumer activation; any failed, stale, missing, timed-out, expired, ambiguous, or claim/result-mismatched result prevents HIL and enforcement. |
| FR-013 | MUST | The authenticated v0.1 administrator must review and decide the exact validated artifact through HIL. | The Argon2id/session/CSRF contracts apply; a five-minute one-use challenge is issued for the exact session/operation/artifact, and password step-up is required when independent `authenticated_at` exceeds 15 minutes; session rotation does not advance it; decision consumption requires challenge, idempotency, exact JCS digests, normalized nonempty reason, and optimistic concurrency. |
| FR-014 | MUST | The isolated executor must execute only a dispatcher-authorized exact canonical nftables add artifact using fixed shell-free arguments. | A minimal dispatcher reads a restricted authorized-operation view and sends a strict 16-KiB, 4-byte-big-endian-framed request over private UDS; executor alone bootstraps/verifies raw and live base-chain contracts; before one mutation it file/directory-fsyncs a checksummed record containing exact capability/signature/artifact bytes; corrupt/torn replay fails closed and a signed result is returned without host access. |
| FR-015 | MUST | Temporary rules must expire automatically and support safe read-only reconciliation plus separate manual revocation. | Native timeout removes the rule; separately signed `nft-inspect-v1` performs only fixed read-back and cannot mutate; premature disappearance is failed/alerted and never auto-readded; reapplication requires new validation/HIL; deterministic `nft-revoke-v1` can only delete from the owned set and is independently authorized, idempotently read back, and audited. |
| FR-016 | MUST | The evidence, AI analysis, command candidate, canonical command, validation, HIL approval/rejection, application, inspection, and expiry lifecycle must be auditable. | The complete timeline, canonical JCS bytes/digests, signatures, journal sequence, and read-back outcome can be queried by incident and policy ID without exposing secrets. |
| FR-021 | MUST | GPT-5.6 must generate an evidence-bound `nft-blacklist-v1` command candidate for one canonical IPv4 source address with a bounded timeout. | Every evidence ID belongs to the immutable incident/analysis-input snapshot and resolves to the same canonical source address; policy and command use the same evidence set and target; timeout is at least 1 minute, defaults to 30 minutes, and is at most 24 hours; the command targets only `inet sentinelflow blacklist_ipv4`, contains exactly one add-element statement, is canonicalized as UTF-8/LF bytes and SHA-256 digested, and cannot execute until FR-012 and FR-013 pass. |

### 7.6 Investigation UI and demo

| ID | Priority | Requirement | Acceptance criteria |
| --- | --- | --- | --- |
| FR-017 | MUST | A dashboard must expose Gateway health/degradation, incident list/detail, normalized minimized events, deterministic signals, AI explanation, evidence-bound blacklist policy, generated and canonical commands, command digest, successful validation snapshots, terminal fail-closed validation attempts, HIL approval, and lifecycle state. | The demo review can distinguish an immutable HIL-authorizing snapshot from a typed failed-attempt projection without exposing raw prepared/terminal JSON or direct validation-attempt table access, hiding the exact artifact that will execute, or conflating dropped telemetry with forwarded traffic. Backend/API projection and frontend/UI/UX presentation remain separately owned and verified tasks. Production uses the exact checked deployment CSP without `'unsafe-eval'`; API-error decoding is static, every emitted JavaScript chunk is scanned for dynamic code generation, and Chromium exercises the built bundle under that header. |
| FR-018 | MUST | Authenticated Server-Sent Events must deliver server-side state changes to the UI without becoming a command channel. | `GET /api/v1/events/stream` emits the ADR-008 event types with IDs and heartbeats; reconnect uses `Last-Event-ID`; a replay gap reloads an authorized REST snapshot; clients deduplicate by resource version; no SSE message can approve or enforce. |
| FR-019 | MUST | Credential-stuffing, brute-force, path-scanning, and request-burst simulators must send repeatable traffic through the Gateway and auth-event adapter. | Each documented command is rerunnable and reaches the exact threshold-boundary fixtures without direct upstream access. |
| FR-020 | MUST | Normal, attack, outage, saturation, malformed-protocol, spoofed-header, upstream-failure, expiry, and revocation simulations must define expected outcomes. | The asserted demo profile uses a disposable RFC 5737 client subnet/source, shared Gateway/executor namespace, application test clock, signed manifest bound to a canonical 24-hour dataset/import ID, raw/live base-chain digests, and host-ruleset before/after evidence; native nft expiry uses a bounded real-time Linux test rather than the injected clock. |

## 8. Non-functional requirements

| ID | Priority | Requirement | Verification |
| --- | --- | --- | --- |
| NFR-001 | MUST | **Fail safely:** validation error, AI error, or missing approval must never cause enforcement. | Fault-injection integration tests |
| NFR-002 | MUST | **Least privilege:** model, Gateway, API, and general worker have no executor signing key/capability; only a minimal dispatcher signs approved exact jobs and only the namespace-sharing executor has `NET_ADMIN`. Demo-history import and activation use separate short-lived PostgreSQL roles and distinct analysis/validation capabilities; long-running workers cannot import, activate, or read the other consumer's capability. | Credential, mount, DB-role, capability, session, and execution-path review |
| NFR-003 | MUST | **Isolation:** the executor sidecar shares only the Gateway network namespace, where a digest-owned protected-port input chain consumes the timeout set, and never alters host nftables. | Traffic-block proof plus host ruleset before/after comparison |
| NFR-004 | MUST | **Untrusted input:** Gateway metadata, application auth events, optional logs, and all evidence must be treated as data; embedded text must not become model instructions. | Prompt-injection and malicious-event fixtures |
| NFR-005 | MUST | **Secret handling:** API keys and credentials must not be committed or exposed through logs or model output. | Secret scan and configuration review |
| NFR-006 | MUST | **Explainability and traceability:** decisions and policies must link to evidence, signals, validation results, and actors. | Per-incident audit tests |
| NFR-007 | MUST | **Reversibility:** every block must expire and its removal must be audited. | Time-based lifecycle tests |
| NFR-008 | MUST | **Determinism:** normalization, signal computation, and rule detection must be reproducible for identical events and configuration. | Golden-fixture regression tests |
| NFR-009 | MUST | **Recovery:** restarts, duplicate messages, torn journal records, SSE reconnection, and demo-history bootstrap retries must not create duplicate incidents, mutation, TTL refresh, import, or activation refresh. Expired demo-history activation requires a full disposable profile/volume reset and a newly signed run. | Restart, replay, journal-corruption, signed-inspect, staged-role-fence, activation-expiry, and full-reset integration tests |
| NFR-010 | MUST | **Compatibility:** the demo must run on the selected minimum Linux, Docker 24+, Compose v2, 4 GB RAM, and a modern browser. | Supported-environment smoke test |
| NFR-011 | MUST | **Testability:** backend, frontend, and integration commands must match the implementation and run automatically. | CI execution of documented commands; the long Compose run parses its evidence SQL on migrated PostgreSQL before the 305-second wait |
| NFR-012 | MUST | **Gateway latency and forwarding availability:** at 500 requests/second on the 4 GB reference host, Gateway-added p95 latency must be at most 5 ms with zero event drops; control-plane failure or bounded-queue saturation must not block otherwise valid traffic. | Repeatable load test plus database/AI/worker/queue fault injection |
| NFR-013 | MUST | **Proxy correctness/security:** Go `net/http` is the sole framing authority; origin-form HTTP/1.1, ASCII Host normalization, target/path bounds, forwarding/identity/hop headers, 100-continue, no trailers/upgrades/auto-decompression, streaming/timeouts, and upstream single-request normalization have one pinned-toolchain contract. | Raw-socket differential proxy tests, malformed-message suites, origin request-count proof, and security review |
| NFR-014 | MUST | **Minimization/origin isolation:** observed exact paths and prohibited HTTP content never persist or enter AI; only reviewed synthetic parser fixtures may contain exact paths; the unpublished private-HTTP origin binds only its origin address, its auth producer reaches only ingest, and Gateway has no `NET_ADMIN` or DB reachability. | Schema/redaction, synthetic-fixture review, DNS/dial/listener/network reachability, and capability tests |

> "The default demo keeps the upstream private and runs nftables enforcement only inside an isolated container or network namespace."
>
> — [`README.md`](../README.md)

### 8.1 Frozen v0.1 operating bounds

| Area | v0.1 bound |
| --- | --- |
| Header parser setting | Go `http.Server.MaxHeaderBytes=32768`; observed accept/reject boundary is pinned by raw-socket tests for the selected Go toolchain, not claimed as a raw-wire exact 32-KiB limit |
| Request target / classification path | Maximum 4 KiB / 2 KiB; exact paths are not persisted |
| Request body | Maximum 10 MiB; content is proxied within bounds but never persisted or sent to AI |
| Header-read timeout | 5 seconds |
| Upstream/request timeout | 30 seconds |
| Idle timeout | 60 seconds |
| Reference load | 500 requests/second on a 4 GB single-node reference host |
| Gateway overhead | p95 at most 5 ms at reference load |
| Event delivery at reference load | Zero drops; bounded-queue saturation outside the target is observable and does not block valid traffic |
| AI request | 30-second timeout and one transient retry |
| AI worker and demo budget | Two concurrent analyses; USD 10 per UTC day with versioned operator token rates and atomic conservative reservation |
| Validation and HIL decision validity | At most 5 minutes; approval cannot outlive validation |
| Evidence lookback | 24 hours for impact analysis |

## 9. Primary journeys and acceptance scenarios

### 9.1 Investigate and approve an attack incident

1. An operator sends attack traffic through the SentinelFlow Gateway to the private demo upstream; the authenticated adapter emits account-aware auth outcomes when applicable.
2. The Gateway forwards valid traffic and asynchronously publishes minimized events without waiting for the control plane.
3. The deterministic engine computes signals and creates an incident.
4. Correlation links Gateway and authenticated application evidence by canonical source IP.
5. `gpt-5.6-sol` analyzes the bounded structured incident summary asynchronously.
6. The analyst reviews facts, AI interpretation, uncertainty, and false-positive possibilities.
7. GPT-5.6 returns a constrained policy and command candidate; the server parses and canonicalizes it, verifies evidence consistency, and runs every required ordered validation stage.
8. The administrator reviews evidence, generated/canonical diff, impact, digests, and validity, then HIL-approves or rejects the exact artifact.
9. The minimal dispatcher signs a short-lived, single-use capability for the exact approved digest, and only that capability plus the canonical bytes reaches the shell-free isolated executor over the private UDS for temporary application and read-back.
10. The rule expires automatically and the complete lifecycle remains auditable.

### 9.2 Reject an unsafe policy or command

- Prepare a policy/command pair containing a protected target, invalid IP, unbounded duration, unsupported action, additional nft statement, shell token, invalid syntax, unrelated evidence, policy/command mismatch, or post-validation digest mutation.
- The system fails the corresponding validation stage.
- The failed or stale artifact cannot be approved or enforced, and a swapped approval digest is rejected.
- Inputs, results, and reasons are audited without secrets.

### 9.3 Model failure or malicious log content

- Include model-manipulation text in an authenticated event or optional log, or make the OpenAI API unavailable.
- Deterministic detection and incident evidence remain available.
- Missing or schema-invalid model output is explicitly marked failed.
- The system does not bypass AI or validation failures to auto-enforce a policy.

### 9.4 Control-plane outage and queue saturation

- Make PostgreSQL, the AI worker, or the administrator UI unavailable, or saturate the bounded event queue.
- The Gateway continues proxying otherwise valid traffic to the fixed upstream and applies only deterministic protocol/size/timeout controls.
- No new adaptive block is generated; already approved nftables rules continue until their TTL expires.
- Queue depth, dropped-event count, and degraded state are observable and auditable; recovery does not invent missing evidence.

## 10. Product UX requirements

The dashboard must distinguish:

- Incident state, detection type, time window, sources, and targets
- Gateway health, forwarding status, queue depth, dropped-event count, and degradation reason
- Normalized events and retained minimized evidence
- Deterministic metrics and rule results
- GPT-5.6 explanation, confidence or uncertainty, and possible false positives
- Policy target, exclusions, action, duration, generated command candidate, canonical command, and digest
- Per-stage validation results and historical impact
- HIL approval/rejection actor, time, reason, policy and generated/canonical command digests, evidence/validation snapshot digest, and validity window
- Applied rule, state, expiry time, and actual cleanup result

**Design proposal:** do not rely on color alone for state; use textual labels. Show the generated and canonical commands with a visible difference indicator, and disable approval controls until every required validation has passed. Editing the command creates a new candidate and restarts validation rather than modifying an approval-ready artifact.

## 11. Data, security, and privacy

- Persist only approved normalized metadata and minimized evidence. Query strings, request/response bodies, cookies, `Authorization`, and raw secret-bearing headers must never persist or enter AI context.
- Retain normalized events/evidence for 7 days, incidents/AI analyses/policies for 30 days, and audit records for 90 days, then delete them through tested lifecycle jobs.
- Inject OpenAI and database credentials through environment configuration or a secret store; never commit them.
- Remove secrets and unnecessary raw text from model request/response logs.
- Treat the AI-generated command as untrusted data; retain its provenance and digest, but never pass it to a shell.
- Normal enforcement accepts only canonical global-unicast IPv4 and rejects unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, RFC 5737 documentation, configured management, Gateway/upstream/executor, current-administrator-path targets, and all IPv6. `PROTECTED_CIDRS` can only add protection. An isolated demo/test profile may allow only RFC 5737 targets after namespace and host-ruleset-diff assertions.
- v0.1 uses one administrator identity with an Argon2id password hash, Secure/HttpOnly/SameSite session cookie, and CSRF plus replay protection. Multi-role and separation-of-duties authorization remain post-v0.1.
- The private upstream must not be published outside the demo network, and the Gateway must strip untrusted forwarding headers before regenerating its own.

## 12. Success criteria and release gates

### 12.1 v0.1 implementation and release success

| Gate | Pass condition |
| --- | --- |
| End-to-end | Normal traffic and each of the four attack simulations traverse the Gateway to the private upstream and reproduce event generation through incident investigation; the approved path also reaches isolated application and expiry. |
| Gateway safety | Spoofed forwarding headers, unlisted hosts, malformed protocol, oversized input, upstream failure, control-plane outage, and queue saturation produce the specified proxy/rejection/degradation behavior without privilege expansion. |
| Data minimization | Prohibited HTTP fields do not appear in persistence, AI requests, logs, audit payloads, fixtures, or screenshots. |
| Explainability | Incident detail distinguishes signals, evidence, AI interpretation, uncertainty, and false-positive hypotheses. |
| Policy safety | Valid policy/command pairs pass; command injection, policy mismatch, protected targets, extra statements, and unsafe fixtures fail at the intended stage. |
| Human control | No rule is applied before HIL approval binds the exact policy, generated/canonical command, and evidence/validation snapshot digests; rejection, expiry, and post-approval mutation invalidation work. |
| Reversibility | An approved temporary rule expires on schedule and is audited. |
| Isolation | Host nftables state is unchanged before and after the demo. |
| Regression | Final backend, frontend, and integration commands succeed. |
| Documentation | Installation and demo commands and screenshots match the implementation; placeholders are removed or updated. |

Current evidence covers final root reruns of the 88-package backend build/test and PostgreSQL 17.10 verifier with 33 migrations and 72 tables, including fresh/restart-noop, `33→24→33`, ACL, sqlc, repeated-content-digest identity, the API-only validation-attempt projection, and queued stale-analysis supersession; contract vectors; export, observability, security, nft namespace, threshold, performance-smoke, and the previously completed reproducible-image/SBOM/vulnerability supply-chain gate; final root frontend evidence of 39 Vitest files/363 tests plus a 1/1 production-CSP Chromium gate; and root-reverified 39/39 demo-E2E helper plus 6/6 shell-contract tests. RUN25 fast Compose E2E (log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`) covered the mutation/outage/restart path, and a later macOS `--fast --browser-qa-hold-seconds 900 --run-browser-qa` execution passed active and revoked browser QA after a fixed 61-second pre-hash login-window wait for the revoked phase, without retrying login or changing a limit. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520` also passed `make check` in an external clean clone. Hosted CI run `29696139988` passed all ten shards for implementation checkpoint `5ef870155bc59e6ac3c30279a7cd8be8d0249887`, including frontend functional-browser and pinned Linux visual-baseline gates. This evidence does not satisfy the release table: the default native-expiry run, native host-nft and 4-GB/five-minute performance references, release-level screenshots, and a live OpenAI call remain pending. [Implementation Readiness](./IMPLEMENTATION_READINESS.md) records the detailed boundary.

### 12.2 Product metrics — design proposal

In addition to the frozen release targets, v0.1 must measure:

- Detection outcome and false positives by scenario
- Gateway request volume, p50/p95/p99 added latency, upstream errors, queue depth, event drops, and degraded duration
- Latency for event publication, incident creation, AI analysis, and validation
- AI schema-failure and retry rates
- Failure counts by validation stage
- Approval/rejection ratio and time to decision
- Temporary-rule application and expiry success rate

## 13. Dependencies, assumptions, and constraints

- OpenAI API connectivity and credentials are required for GPT-5.6 analysis.
- The primary data plane is a Go reverse proxy with one allowlisted host and one fixed private upstream.
- PostgreSQL is the selected event, incident, policy, and audit store.
- Linux and nftables are required for enforcement tests.
- Docker and Docker Compose are required for the default demo.
- The selected v0.1 deployment is single-node with a minimum of 4 GB RAM.
- The README stack—Go/chi/pgx/sqlc, React/TypeScript/Vite/MUI, and SSE—remains governed by architecture decisions.

## 14. Risks and mitigations

| Risk | Impact | Required mitigation |
| --- | --- | --- |
| Malicious or malformed logs | Parser failure or model manipulation | Input limits, safe parsing, untrusted-data handling |
| Forwarding-header spoofing or origin bypass | Incorrect attribution or evasion | TCP-peer canonical identity, strip/regenerate forwarding headers, allowlisted host, unpublished fixed upstream |
| Proxy parsing ambiguity or request smuggling | Cross-boundary request confusion | Strict Go HTTP parsing, hop-by-hop sanitation, differential malformed-message and desynchronization tests |
| Control-plane outage or queue saturation | Telemetry loss or delayed detection | Forward valid traffic, observable bounded queue/drop state, no new adaptive block, normal TTL expiry |
| Sensitive HTTP data collection | Credential or personal-data exposure | Never persist or send query, body, cookies, authorization, or raw secret-bearing headers to AI |
| Incorrect correlation | Misleading incident | Explicit relation reasons, minimized evidence, regression fixtures |
| AI hallucination or schema drift | Incorrect explanation, policy, or command candidate | Structured I/O, schema rejection, fact/interpretation separation |
| AI command injection, unrelated evidence, or policy/command mismatch | Unintended firewall change | Strict grammar, AST canonicalization, immutable evidence membership, single owned set, snapshot/digest binding, syntax/impact checks, HIL approval, shell-free execution |
| False-positive block | Legitimate-user impact | Historical-impact analysis, protected networks, human approval, temporary rules |
| Administrator lockout | Loss of management access | Management-network protection, isolation, expiry, rollback validation |
| Excess privilege or forged/replayed execution | Host damage or unauthorized/duplicate block | Restricted dispatcher view, separate Ed25519 key pairs, JCS-signed one-shot capability/result, private UDS, two-phase journal, namespace-only executor capability |
| Credential leak | Account, cost, and data exposure | External secret storage, redaction, secret scanning |
| API outage | Analysis unavailable | Preserve deterministic evidence, explicit `analysis_failed` state, no auto-enforcement |

## 15. Resolved decisions and post-v0.1 triggers

The former v0.1 blockers are frozen below. The last four rows are explicit post-v0.1 decision triggers and do not block the single-node reference implementation.

| ID | Resolution or open trigger | Status |
| --- | --- | --- |
| OQ-001 | Path scan `8 distinct configured paths/60s`; burst `120 requests/10s`; brute force `10 configured-auth-route 401/403 responses/60s`; credential stuffing `20 failures across 8 account hashes/5m`. | Resolved 2026-07-18 |
| OQ-002 | Correlate on canonical source IP with a 5-minute overlap, close after 15 minutes idle, and reopen within 30 minutes after closure. | Resolved 2026-07-18 |
| OQ-003 | Responses API with `gpt-5.6-sol`, reasoning `medium`, `store: false`, checked-in input schema/prompt/output schema, sorted complete signal references without silent truncation, no tools, 50 references/12 KiB input/2,048 output-token caps, 30-second timeout, one transient retry, concurrency two, and USD 10 per UTC day using a versioned rate card and atomic reservation. | Resolved 2026-07-18 |
| OQ-004 | One v0.1 administrator, Argon2id password hash, Secure/HttpOnly/SameSite cookie, CSRF, independently stored `authenticated_at`, password step-up after 15 minutes, and server-issued exact-artifact one-use challenge with at most 5-minute validity. | Resolved 2026-07-18 |
| OQ-005 | Accept only canonical global-unicast IPv4 under a versioned, JCS-digested protected-range contract. `PROTECTED_CIDRS` only adds protection; an isolated demo/test profile may remove only the three RFC 5737 ranges after isolation assertions. | Resolved 2026-07-18 |
| OQ-006 | Historical-impact lookback is 24 hours; successful authentication evidence for the target and insufficient or ambiguous evidence are blocking. | Resolved 2026-07-18 |
| OQ-007 | Executor-only bootstrap verifies raw/live protected-port chain contracts for `inet sentinelflow blacklist_ipv4`; a restricted dispatcher and framed-UDS executor apply add once, inspect through separately signed read-only `nft-inspect-v1`, never re-add/refresh TTL, and remove only through separately authorized `nft-revoke-v1`. | Resolved 2026-07-18 |
| OQ-008 | Events/evidence 7 days; incidents/AI/policies 30 days; audit 90 days. Prohibited raw HTTP fields are never retained. | Resolved 2026-07-18 |
| OQ-009 | 500 requests/second on a 4 GB reference host, p95 Gateway overhead at most 5 ms, and zero event drops at target; saturation is visible and must not block valid traffic. | Resolved 2026-07-18 |
| OQ-010 | README references the MIT `LICENSE`; dependency notices still require final release verification. | Resolved 2026-07-17; release check remains |
| OQ-011 | `nft-blacklist-v1`; `inet sentinelflow blacklist_ipv4`; integer `ttl_seconds` 60..86400 equal to the parsed timeout, canonicalized to the largest exact `h`/`m` unit or integer `s`; UTF-8/LF bytes; SHA-256; validation and approval validity at most 5 minutes. | Resolved 2026-07-18 |
| OQ-012 | Production TLS ownership, certificate rotation, horizontal scaling, and high availability require operational evidence and a follow-up ADR before production positioning. | Open post-v0.1 trigger |
| OQ-013 | Any adaptive Gateway `http-deny-v1` action requires a separate typed artifact, validator, digest/HIL contract, tests, and follow-up ADR; nftables approval cannot authorize it. | Open post-v0.1 trigger |
| OQ-014 | Any raw-packet/eBPF/XDP sensor must be a separate least-privilege component and requires privacy, capacity, trust-boundary, and failure-mode decisions in a follow-up ADR. | Open post-v0.1 trigger |
| OQ-015 | Any production or renewable history-attestation mechanism must replace the demo-only five-minute importer/activator leases and one-hour non-renewable activation with a separately reviewed authority, rotation, revocation, multi-database, recovery, and audit design. v0.1 permits only full disposable reset and reseal after expiry. | Open post-v0.1 trigger |

## 16. Requirements traceability

| Product area | Requirements | Design / decisions | Verification / work |
| --- | --- | --- | --- |
| Gateway ingress, identity, minimization, and isolation | FR-022~FR-025 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| Auth events and optional adapters | FR-001~FR-004, FR-026 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| Detection and correlation | FR-005~FR-007 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| AI explanation and command generation | FR-008~FR-010, FR-021 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| Policy, HIL approval, enforcement | FR-011~FR-016, FR-021 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| UI and demo | FR-017~FR-020 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |
| Quality and security | NFR-001~NFR-014 | [`ADR.md`](ADR.md), [`TDD.md`](TDD.md) | [`TASKLIST.md`](TASKLIST.md) |

## 17. Related documents

- Product source: [`README.md`](../README.md)
- Architecture decisions: [`ADR.md`](ADR.md)
- Technical design: [`TDD.md`](TDD.md)
- Implementation work: [`TASKLIST.md`](TASKLIST.md)
- Current evidence and blockers: [`IMPLEMENTATION_READINESS.md`](IMPLEMENTATION_READINESS.md)
