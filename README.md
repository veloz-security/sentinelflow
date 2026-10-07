# SentinelFlow

Explainable AI security gateway with evidence-bound, administrator-approved response actions.

SentinelFlow is an explainable AI security gateway that observes web traffic through an inline reverse proxy, correlates structured evidence, and applies temporary response actions only after strict validation and administrator HIL approval.

Developed and maintained by [Veloz (벨로즈)](https://sec.veloz.kr) Security Research as open-source defensive security research. Research note: [SentinelFlow: Evidence-Bound Defensive Security Gateway](https://sec.veloz.kr/research/sentinelflow/) · Security contact: [security@veloz.kr](mailto:security@veloz.kr)

> Status: **Still implementing.** The Gateway-first v0.1 implementation, contracts, database, control-plane services, administrator UI, isolated executor, and test harnesses exist and pass the verified local gates listed below.
> Current implementation evidence includes RUN25 fast Compose E2E (log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`), a later macOS execution of `./scripts/check-demo-e2e.sh --fast --browser-qa-hold-seconds 900 --run-browser-qa`, and successful [hosted CI run 29696139988](https://github.com/veloz-security/sentinelflow/actions/runs/29696139988) for implementation checkpoint `5ef870155bc59e6ac3c30279a7cd8be8d0249887`. They passed the exact active/revoked browser flows, signed inspect, digest-mismatch fail-closed revoke, control-plane outage forwarding, restart/reconciliation, cleanup, all hosted quality shards, frontend functional-browser tests, and the pinned Linux visual baseline. Release qualification is still open: the default native-expiry run, native host-nft invariance, a billable OpenAI smoke call, release screenshots, and the five-minute 4 GB performance gate have not passed.

---

## Overview

Log-only security tools depend on heterogeneous formats, delayed delivery, and incomplete context. A gateway sees HTTP requests and responses as structured protocol objects before they reach a protected application, which makes detection evidence more direct and a live demonstration easier to understand.

SentinelFlow therefore uses a Gateway-first architecture:

- a Go reverse proxy is the primary v0.1 web sensor;
- a private, fixed upstream application is reachable only through the Gateway;
- an authenticated application event adapter adds login outcome and account-hash semantics;
- optional Nginx, Syslog, and firewall-log adapters remain post-v0.1 extensions;
- deterministic detection runs before GPT-5.6 analysis;
- GPT-5.6 analysis, validation, administrator approval, and nftables execution stay outside the synchronous request path.

The request path never waits for GPT-5.6, PostgreSQL, or administrator approval.

The intended workflow is:

```text
HTTP request
    ↓
SentinelFlow Gateway → private fixed upstream → HTTP response
    ↓ asynchronous minimized event
Normalization and persistence
    ↓
Deterministic detection and incident correlation
    ↓
GPT-5.6 explanation, policy, and constrained nftables command candidate
    ↓
Command grammar/canonicalization, evidence consistency, protected-network,
nftables syntax, and historical-impact validation
    ↓
Administrator HIL approval of the exact artifact by digest
    ↓
Isolated shell-free nftables execution, read-back, expiry, and audit
```

---

## Product Boundary

SentinelFlow Gateway is a security reverse proxy, not a new general-purpose origin web server. It uses Go's maintained HTTP stack and `httputil.ReverseProxy`; it does not implement HTTP parsing, TLS, TCP, or packet reassembly from scratch.

Raw packet capture and analysis are not part of v0.1.

Future L3/L4 sensors may use read-only conntrack, nftables counters, or eBPF in a separate privilege and failure domain. The Gateway never receives `CAP_NET_ADMIN`, raw-socket access, OpenAI credentials, or executor authority.

---

## Core Features

The v0.1 single-node reference implementation provides:

- Inline HTTP reverse proxying to one configured private upstream
- Canonical client identity from the direct TCP peer
- Removal and regeneration of `Forwarded` and `X-Forwarded-*` headers
- Host allowlisting and origin-bypass prevention
- Minimized request/response security events without query strings, bodies, cookies, authorization headers, or secret-bearing raw headers
- An authenticated application-authentication event contract using account hashes rather than usernames
- Deterministic path-scan, request-burst, brute-force, and credential-stuffing detectors
- Incident correlation by canonical source IP, time, service, path, and account hash
- Asynchronous GPT-5.6 incident explanation and false-positive analysis
- An evidence-bound `block_ip` policy and one constrained `nft-blacklist-v1` command candidate
- Strict command parsing, typed AST canonicalization, digest binding, and ordered validation
- Exact-artifact administrator Human-in-the-Loop (HIL) approval
- Shell-free nftables application in an isolated namespace
- Automatic TTL expiry, read-back, reconciliation, and lifecycle audit
- REST/SSE investigation UI and repeatable normal/attack simulations

Optional Nginx access-log, TCP/UDP Syslog, and Linux firewall-log ingestion are explicitly not v0.1 release gates.

---

## Supported Detection Scenarios

### Credential stuffing

Creates a candidate incident when one canonical source produces at least 20 failed authentication events across at least 8 distinct account hashes within 5 minutes.

### Brute-force login attempts

Creates a candidate incident after at least 10 `401` or `403` responses on configured authentication routes from one source within 60 seconds.

### Automated path scanning

Creates a candidate incident after at least 8 distinct configured suspicious paths from one source within 60 seconds.

`path-catalog-v1` fixes the initial IDs as `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, and `backup_archive`. The Gateway emits only the matched ID and configured route label, never the exact path. Authentication-route mapping starts with the exact `/login` route labeled `login`; catalog changes are versioned and regression-tested.

### Abnormal request bursts

Creates a candidate incident after at least 120 requests from one source within 10 seconds.

These are versioned v0.1 defaults, not universal security truths. Configuration changes are audited and regression-tested against normal and attack fixtures.

---

## Design Principles

### Data plane and control plane are separate

The Gateway performs bounded protocol handling, deterministic server-safety checks, forwarding, response observation, and asynchronous event emission. PostgreSQL, GPT-5.6, policy validation, administrator review, and nftables execution form the control plane.

If the control plane or event sink is unavailable, the Gateway continues forwarding traffic, exposes degradation and drop metrics, and creates no new adaptive block. Existing approved rules retain only their remaining TTL and still expire.

### Deterministic signals first

SentinelFlow calculates measurable signals before AI analysis. The model receives a compact incident summary rather than a raw traffic stream.

Observed facts, deterministic results, AI interpretation, administrator decisions, and enforcement outcomes remain distinct and traceable.

### AI is asynchronous and untrusted

The adapter uses the OpenAI Responses API with explicit `gpt-5.6-sol`, `reasoning.effort: medium`, `store: false`, no tools, and strict Structured Outputs through `text.format`. The exact versioned [input schema](./contracts/ai/sentinelflow_analysis_input_v1.schema.json), checked-in [system prompt](./contracts/ai/sentinelflow_system_prompt_v1.txt), and [output schema](./contracts/ai/sentinelflow_analysis_v1.schema.json) are immutable request artifacts whose digests are audited. Schema conformance does not replace application-side evidence, policy, IP, TTL, or command validation. The adapter handles refusals, incomplete responses, timeouts, schema failures, and budget failures explicitly. The opt-in `cmd/openaismoke` uses the same fixed contracts for one synthetic, non-mutating request, but it has only been verified in disabled and missing-key fail-closed modes; no live billable request is claimed. See the official [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

The AI input contains every enforcement-eligible deterministic signal reference for one immutable incident version, sorted by stable reference ID. Signal references expand server-side to the complete retained event set, so the 50-reference bound does not truncate a 120-event burst. Duplicate, out-of-order, over-50, or over-12-KiB input fails as `input_too_large` or `evidence_invalid`; it is never silently reordered or truncated. Output evidence lists must be duplicate-free, strictly sorted, and byte-identical at the analysis, policy, and command levels. Output is limited to 2,048 tokens, the request timeout is 30 seconds, and only one retry is allowed for classified transient failures. The default worker concurrency is two analyses and the configurable demo budget is USD 10 per UTC day. A versioned operator rate card and atomic worst-case reservation are mandatory; a missing rate card or exhausted budget becomes `analysis_failed` with a typed reason and cannot create enforcement work. This is an operator budget, not an API price claim.

### Human approval before enforcement

The model does not receive unrestricted shell access and does not directly modify a firewall.

It may generate one constrained nftables blacklist command candidate, but the candidate remains untrusted data until the server has parsed and canonicalized it, every hard validation gate has passed, and an administrator has approved the exact immutable artifact by digest.

Protocol-invalid, oversized, or timed-out HTTP requests may be rejected by deterministic Gateway safety controls. That behavior does not authorize AI-driven blocking. A future Gateway-native `http-deny-v1` action would require its own grammar, validator, digest, HIL artifact, ADR, and tests; nftables approval cannot silently authorize it.

### Temporary and reversible actions

Every adaptive block has a bounded TTL, actual-state read-back, automatic expiry, and auditable recovery behavior.

---

## Architecture

```text
┌──────────────┐       ┌──────────────────────────┐       ┌──────────────────┐
│ HTTP Client  │──────▶│ SentinelFlow Gateway     │──────▶│ Private Upstream │
└──────────────┘       │ fixed reverse proxy      │◀──────│ Application      │
                       │ sanitized metadata       │       └──────────────────┘
                       │ bounded async EventSink  │
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ Normalization / Storage  │◀── Auth event adapter
                       │ PostgreSQL + outbox      │    (account hashes)
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ Detection / Correlation  │
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ GPT-5.6 Analyst          │
                       │ structured untrusted I/O │
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ Safety Validators        │
                       │ exact artifact + digest  │
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ Administrator HIL        │
                       └────────────┬─────────────┘
                                    │
                       ┌────────────▼─────────────┐
                       │ Minimal Dispatcher       │
                       │ signed exact capability │
                       └────────────┬─────────────┘
                                    │ private UDS
                       ┌────────────▼─────────────┐
                       │ Isolated nft Executor    │
                       │ TTL / read-back / audit  │
                       └──────────────────────────┘

Optional post-v0.1 sources:
Nginx logs / Syslog / firewall logs ──▶ normalized Event contract
```

---

## Gateway Contract

### Request identity and forwarding

- The canonical v0.1 source IP is the direct TCP peer after canonical IP parsing.
- Inbound `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-SentinelFlow-Request-ID`, and `X-SentinelFlow-Trace-ID` values are removed.
- The Gateway regenerates forwarding headers from trusted connection state and supplies new request and trace IDs to the private application for exact auth-event binding.
- v0.1 accepts origin-form HTTP/1.1 only. Optional TLS advertises only `http/1.1` through ALPN and disables Go HTTP/2 auto-configuration. The Gateway rejects `CONNECT`, absolute/authority/asterisk targets, HTTP/2 prefaces, protocol upgrades, WebSocket/h2c, request trailers, unsupported `Expect`, and ambiguous path encodings before proxying.
- Go `net/http` is the sole request-framing parser. The implementation does not reconstruct raw framing in middleware; raw-socket differential tests pin the selected Go toolchain's rejection or safe normalization of conflicting length/transfer forms, and `ReverseProxy` sends one normalized upstream request.
- Only normalized ASCII allowlisted host values are accepted; untrusted IDNA/Unicode, duplicate, malformed, or unexpected port forms fail deterministically.
- The upstream URL is fixed by startup configuration, uses private `http`, and cannot be supplied by a request. Every resolved/dialed IPv4 address must remain inside a non-broad RFC 1918 allowlist; public, loopback, link-local/metadata, IPv6, mixed, or rebinding answers fail closed.
- The default Compose upstream has no published host port and is reachable only on the private application network.

Multi-hop trusted-proxy identity is a post-v0.1 decision; it is not inferred from untrusted headers.

### Data minimization

The persisted Gateway event may contain:

- stable event, trace, request, and schema IDs;
- occurrence and ingestion timestamps;
- canonical source IP and service label;
- HTTP method, HTTP/1.1 protocol label, allowlisted host, versioned route label/path-catalog version, and an allowlisted suspicious-path ID or `none`;
- response status, request/response byte counts, and duration.

It must not contain an exact/raw/decoded path, query string, request or response body, cookie, bearer token, authorization header, session ID, password, raw account name, or unrestricted header map. Path matching occurs in memory against a versioned catalog; ambiguous escapes, encoded separators, dot segments, backslashes, controls, and over-limit targets are rejected rather than retained.

### Bounds and failure behavior

| Setting | v0.1 default |
| --- | --- |
| Go `http.Server.MaxHeaderBytes` | 32 KiB configured value; parser boundary is verified against the pinned Go toolchain |
| Maximum request target / decoded classification path | 4 KiB / 2 KiB |
| Maximum request body | 10 MiB |
| Header read timeout | 5 seconds |
| Upstream/request timeout | 30 seconds |
| Idle timeout | 60 seconds |
| Event delivery | Bounded asynchronous queue and authenticated batch sink |
| Queue or sink failure | Forward traffic, expose degradation/drop evidence, never create a block |
| Performance gate | p95 Gateway overhead ≤ 5 ms at 500 RPS on the 4 GB reference environment |

`POST /internal/v1/gateway-events` and `POST /internal/v1/auth-events` accept an `event-batch-v1` JSON envelope with stable `sender_id`, per-boot `sender_epoch`, `batch_id`, monotonic per-epoch `sequence`, `sent_at`, and 1–100 typed records, subject to a 256 KiB raw-body limit. Each request carries `X-Sentinel-Sender-ID`, a bounded Unix timestamp, a 128-bit random base64url nonce, and an HMAC-SHA256 signature. The signing input binds the endpoint path, header sender ID, timestamp, nonce, and lowercase raw-body SHA-256 digest. The bounded sender header selects a base64-encoded random key of at least 32 bytes before the body is read; after constant-time verification the body `sender_id` must match the header byte-for-byte. Only then may the receiver atomically insert the nonce into the five-minute replay cache, preventing unauthenticated cache exhaustion.

The receiver validates and persists a whole batch atomically and acknowledges only `accepted` or an exact `duplicate`; conflicting reuse is `409` and invalid input is `422`. Retries keep body, epoch, batch ID, and sequence stable but use fresh authentication values. Both the Gateway and auth producer own independent durable checkpoints that record epoch, clean-shutdown state, and the last acknowledgement without storing request events. Either sender may submit endpoint-scoped `source-health-v1`; an unclean restart or permanent gap emits an incomplete interval and can never support enforcement, while Gateway forwarding remains non-blocking. Record time may be at most 60 seconds in the future or 5 minutes in the past relative to receipt; outliers remain traceable but are untrusted and non-enforcing. The default in-memory queue is 10,000 events with batches of 100 or a 100 ms flush interval.

---

## Event Model

Example Gateway event:

```json
{
  "schema_version": "gateway-http-v1",
  "event_id": "019b0000-0000-7000-8000-000000000001",
  "request_id": "019b0000-0000-7000-8000-000000000002",
  "trace_id": "019b0000-0000-7000-8000-000000000003",
  "idempotency_key": "sha256:...",
  "started_at": "2026-07-18T02:00:00.000Z",
  "completed_at": "2026-07-18T02:00:00.007Z",
  "source_ip": "203.0.113.20",
  "method": "POST",
  "protocol": "HTTP/1.1",
  "host": "app.example.test",
  "service_label": "demo-app",
  "route_label": "login",
  "path_catalog_version": "path-catalog-v1",
  "suspicious_path_id": "none",
  "status_code": 401,
  "request_bytes": 128,
  "response_bytes": 431,
  "latency_ms": 7
}
```

Example authentication event:

```json
{
  "schema_version": "auth-event-v1",
  "event_id": "019b0000-0000-7000-8000-000000000010",
  "gateway_request_id": "019b0000-0000-7000-8000-000000000002",
  "trace_id": "019b0000-0000-7000-8000-000000000003",
  "idempotency_key": "sha256:...",
  "occurred_at": "2026-07-18T02:00:00.006Z",
  "source_ip": "203.0.113.20",
  "service_label": "demo-app",
  "route_label": "login",
  "account_hash": "hmac-sha256:...",
  "outcome": "failed"
}
```

The account hash uses a deployment secret outside the repository so that fixtures and model input never contain real account names. The demo application's authenticated auth producer reads only the Gateway-generated request/trace headers and canonical forwarding value. Its HTTP listener binds only the private origin-network address, while the producer also joins the separate ingest network to reach the API's ingest-only listener; neither listener has a host port. Because the producer can submit the auth outcome before the Gateway emits its response event, the control plane holds the event in `pending` for up to five minutes and verifies request ID, trace, source IP, `demo-app` service, and configured route. Only `verified` failures support attack evidence; mismatched or expired bindings remain non-enforcing, while any unverified successful-auth event conservatively blocks historical-impact approval.

---

## Structured Response Policy and Command Candidate

GPT-5.6 returns a strict structured object containing the incident explanation, uncertainty, false-positive hypotheses, evidence references, a `block_ip` policy, and one `nft-blacklist-v1` candidate.

The only v0.1 command form is:

```nftables
add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }
```

The server accepts no table, set, action, address cardinality, timeout form, include, variable, redirection, pipeline, command substitution, or additional statement outside the grammar. It parses a typed AST, requires integer `ttl_seconds` in `60..86400` to equal the parsed command timeout, and serializes the timeout as the largest exact `h` or `m` unit, otherwise integer `s`. The canonical command is UTF-8 with exactly one trailing LF and a SHA-256 digest.

Only canonical global-unicast IPv4 targets are eligible. The versioned [`protected_ipv4_v1.json`](./contracts/enforcement/protected_ipv4_v1.json) contract is the shared validator/dispatcher source for special-use, unspecified, loopback, private, link-local, CGNAT, benchmarking, documentation, multicast, reserved, configured management, current-administrator-path, and IPv6 exclusions. Configured protected CIDRs can add protection but cannot remove built-ins. An isolated demo profile may remove only the three RFC 5737 documentation ranges after namespace and host-ruleset assertions; the contract and effective set are JCS-digested into validation and authorization.

The v0.1 enforcement constants are:

| Setting | Value |
| --- | --- |
| Table/set | `inet sentinelflow blacklist_ipv4` |
| TTL | minimum `1m`, default `30m`, maximum `24h` |
| Validation validity | 5 minutes |
| Approval validity | 5 minutes, capped by validation expiry |
| Historical lookback | 24 hours |
| Blocking impact condition | Any successful authentication evidence for the target, protected target, missing evidence, or insufficient history |
| Digest | SHA-256 over the versioned canonical artifact |

The ordered hard-gate path is:

1. Structured-output and command-grammar parsing/canonicalization
2. Policy, evidence, and command consistency
3. Protected-network checks
4. `nft --check -f -` against the identical owned-set schema
5. Historical-impact analysis
6. Administrator HIL approval of the exact artifact by digest
7. Isolated shell-free `nft -f -` execution with digest recomputation
8. Actual-state read-back, TTL expiry, reconciliation, and audit

Missing, stale, failed, timed-out, or ambiguous evidence fails closed for enforcement.

The demo executor is a capability-bearing sidecar that shares only the Gateway network namespace; the Gateway process and container retain no capability. During bootstrap the executor is the sole privileged provisioner of the raw-SHA-pinned [`nft_base_chain_v1.nft`](./contracts/enforcement/nft_base_chain_v1.nft) input chain and then verifies its separate canonical live-structure digest. The protected-port drop rule references `blacklist_ipv4`, so adding an element actually blocks later Gateway traffic without touching host nftables. API, AI, and general workers cannot contact or authorize the executor. A minimal non-AI dispatcher reads only a restricted authorized-operation outbox and signs short-lived, single-use exact-artifact capabilities for a private Unix socket.

Dispatcher/executor traffic is one 4-byte unsigned big-endian length-prefixed UTF-8 JSON request and one response per connection, each at most 16 KiB with 2-second I/O deadlines. Envelopes use strict schemas and unpadded base64url for canonical bytes and Ed25519 signatures; malformed, duplicate-field, oversized, trailing, or non-canonical input closes without mutation. Policy, evidence, validation, normalized administrator reason, HIL authorization, execution capability, result, and demo-history payloads use RFC 8785/JCS plus lowercase `sha256:` digests and checked-in golden vectors. Artifact-content digests are integrity values and non-unique lookup keys, not database-row, lifecycle, or authorization identities: identical canonical command or inspect bytes in a later workflow still require fresh evidence-bound candidate, policy, validation, challenge, decision, authorization, schedule/action, and capability identifiers.

An add artifact is applied at most once. Before mutation, the executor appends the complete exact capability JCS bytes, detached signature, canonical artifact bytes, digests, operation/target/schema fields, receive/deadline times, and journal sequence to a checksummed `started` record, then fsyncs both file and directory. After one invocation and read-back it fsyncs the signed terminal result. A torn or corrupt record fails closed. A crash with only `started` is resolved by signature/digest re-verification and read-back, never by another add. Duplicate delivery returns the terminal result or triggers read-back resolution without refreshing the relative timeout, and a fresh add fails if the target already exists.

The worker schedules separately signed `nft-inspect-v1` operations through the restricted outbox to verify active or expired state. Inspect maps only to a fixed read-only nftables query and can never add, delete, or extend a rule. Reconciliation never re-adds a prematurely missing rule; reapplication requires a new candidate, validation, and HIL decision. Manual removal uses a separate deterministic `nft-revoke-v1` artifact bound to the active action, administrator, reason, and original digest. It cannot create a block or reuse the AI add approval. HIL decisions and revocations consume a five-minute, session-and-artifact-bound challenge issued by the API; password step-up is required when the independently stored `authenticated_at` is older than 15 minutes, and session rotation never advances that timestamp.

---

## Implemented Technology Stack

### Backend and data plane

- Go `1.25.12`
- `net/http` and `httputil.ReverseProxy`
- `github.com/go-chi/chi/v5` `v5.3.1`
- `github.com/jackc/pgx/v5` `v5.9.2`, SQL query sources, and a sqlc configuration
- PostgreSQL 17-compatible migrations
- OpenAI Responses API
- Server-Sent Events

### Frontend

- React `19.2.7`
- TypeScript `6.0.2`
- Vite `8.1.5`
- MUI `7.3.8`

### Infrastructure

- Docker and Docker Compose
- Linux network namespace or isolated container
- nftables
- Nginx is reserved for post-v0.1 deployments after a trusted-proxy identity contract; it is not in the v0.1 request path

---

## Repository Structure

The following top-level implementation areas exist. Optional `cmd/ingestor` adapters remain post-v0.1 and are intentionally absent.

```text
sentinelflow/
├── contracts/
│   ├── ai/                # versioned input, prompt, and strict model output
│   ├── events/            # Gateway, auth, source-health, and batch schemas
│   ├── enforcement/       # JCS/HIL/UDS/journal/nft/protected-range contracts
│   ├── fixtures/          # canonical synthetic demo-history dataset/manifest
│   └── vectors/           # public test-only byte-exact interoperability bundle
├── cmd/
│   ├── gateway/           # inline reverse proxy and minimized event producer
│   ├── api/               # REST/SSE, investigation, auth, HIL commands
│   ├── worker/            # detection, correlation, AI, validation, expiry
│   ├── dispatcher/        # signs approved exact executor capabilities
│   ├── executor/          # isolated nftables application boundary
│   ├── simulator/         # normal and attack traffic
│   ├── validator/         # isolated nft syntax validation
│   ├── lifecycleworker/   # signed inspect and expiry reconciliation
│   ├── retentionworker/   # retention lifecycle
│   ├── openaismoke/       # opt-in non-mutating live-contract probe
│   └── recoverytool/      # backup/restore and evidence validation
├── internal/
│   ├── gateway/
│   ├── events/
│   ├── ingestion/
│   ├── detection/
│   ├── correlation/
│   ├── ai/
│   ├── policy/
│   ├── validation/
│   ├── enforcement/
│   ├── api/
│   └── repository/
├── db/
├── web/
├── deployments/
├── samples/
├── scripts/
├── docs/
└── AGENTS.md
```

Additional focused command and internal packages implement demo configuration/history, observability, export, stub analysis, validation, detection, and lifecycle work. Directory existence is not release evidence; the verified and pending gates below define current status.

---

## Implementation Baseline

The implementation follows these frozen choices:

- single-node reference deployment and one fixed upstream;
- HTTP/1.1 release contract; optional TLS is terminated by the Gateway when certificate paths are configured, advertises ALPN `http/1.1` only, and does not auto-enable HTTP/2;
- HTTP/2, HTTP/3, multi-upstream routing, cache, compression transformation, and production HA are not v0.1 release claims;
- exact request paths are never persisted; `path-catalog-v1` supplies route labels plus eight fixed suspicious-path IDs for deterministic detection;
- the Gateway uses an in-memory event queue plus only a durable sender-health checkpoint, so detected restart/gap loss fails closed for enforcement rather than becoming hidden evidence;
- the authenticated application producer has its own checkpoint and source-health stream, and event timestamps outside the frozen +60-second/-5-minute receipt window remain traceable but non-enforcing;
- API/AI/general workers have no executor signing authority; only the narrow dispatcher can mint a short-lived exact capability, and only the executor can sign an execution result with its separate key;
- one administrator account with an Argon2id PHC hash (minimum 64 MiB memory, 3 iterations, parallelism 2, 16-byte salt, and 32-byte output), an opaque server-side session lasting at most 8 hours/30 minutes idle, rotation at login and privileged actions, HttpOnly `SameSite=Strict` cookies (`Secure` under TLS), synchronizer CSRF protection, single-use exact-artifact HIL challenges, password step-up after 15 minutes based on independent `authenticated_at`, and a five-decision-per-minute session limit;
- events/evidence retained 7 days, incidents/AI/policies 30 days, and audit records 90 days;
- same-source correlation uses a 5-minute overlap, closes after 15 minutes of inactivity, and may reopen within 30 minutes;
- the asserted demo profile accepts signed history only through a one-shot staged bootstrap: distinct analysis/validation 32-byte activation capabilities are represented in PostgreSQL only by SHA-256 digests; a five-minute importer lease and then a five-minute activator lease are fenced to `NOLOGIN`, null password, expired `VALID UNTIL`, and zero surviving peer sessions; one atomic activation pair is valid for one hour and cannot be refreshed;
- after the one-hour demo-history activation expires, analysis and validation fail closed and the operator must reset the entire disposable demo environment and volumes and generate a newly signed run; partial reseeding or in-place reactivation is unsupported;
- a queued analysis for an immutable incident version that history proves existed but that a newer current incident version has overtaken is completed as `analysis_superseded` before any provider claim or dead letter; the current incident remains unchanged. A genuinely missing aggregate still fails closed as unresolved `analysis_incident_missing` dead-letter evidence;
- the management API exposes terminal fail-closed validation evidence as a typed `latest_validation_attempt` projection for the selected policy. Only the API role may execute the bounded projection; direct reads of raw attempt tables and raw prepared/terminal JSON remain denied, and a claim/result binding mismatch fails closed as a generic service-unavailable response;
- incident detail captures the observed evidence version with its base incident read and exposes `latest_analysis` only for that exact version; later statements reuse the captured version, so concurrent incident advance cannot substitute a newer analysis into the older projection;
- the administrator frontend decodes API errors with a CSP-safe static contract. The production bundle is scanned across every emitted JavaScript chunk for dynamic-code-generation markers and is exercised in Chromium under the exact deployment CSP: `default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
- every implementation, frontend, security, recovery, documentation, and release task must produce reproducible evidence before its Tasklist checkbox changes.

See [Implementation Readiness](./docs/IMPLEMENTATION_READINESS.md) for current local verification evidence and the release inputs that remain intentionally unverified.

---

## Requirements

Development and release requirements:

- Go `1.25.12`, as pinned by `go.mod`
- Node.js and npm versions compatible with the checked frontend lockfile
- Docker 24+ and Docker Compose v2
- PostgreSQL-compatible local container
- Linux runner or VM with network namespaces and nftables for enforcement tests
- OpenAI API key supplied outside the repository for the live AI smoke test
- Minimum 4 GB RAM reference environment

macOS development can run the Gateway, API, worker, dispatcher, database, frontend, deterministic tests, Docker-isolated nftables probes, and performance smoke mode. Native Linux host-nft invariance, real kernel-expiry release evidence, and the five-minute 4 GB performance gate still require a qualifying Linux target.

---

## Installation

From a fresh clone, generate the local secret/demo bundle and start the deterministic stub-analysis profile:

```bash
git clone https://github.com/veloz-security/sentinelflow.git
cd sentinelflow
./scripts/prepare-demo.sh
COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --env-file .env.demo \
  --file deployments/compose.yaml \
  --profile stub-ai up --build
```

`prepare-demo.sh` refuses to overwrite an existing `.env.demo`, `secrets/demo`, or `data/demo-history`. `.env.example` contains names and safe defaults only. Real secrets, password hashes, HMAC keys, OpenAI credentials, and certificates must remain outside Git. These commands reflect the implemented entry points; a clean-checkout release rehearsal is still pending.

---

## Demo Scenarios

1. Start the Gateway, private demo application, PostgreSQL, API, worker, dispatcher, frontend, and namespace-sharing executor sidecar.
2. Assert the disposable RFC 5737 client network, executor raw/live base-chain digests, host-ruleset invariance, application test clock, and run-scoped signed manifest bound to the canonical 24-hour dataset/import ID. The one-shot history importer must close its five-minute DB lease, the one-shot activator must atomically create distinct one-hour analysis/validation activations and close both bootstrap roles, and long-running consumers may only attach their own exact activation.
3. Send normal traffic through the Gateway and confirm no incident or block.
4. Run one fixed-seed attack simulator from `203.0.113.20` through the same Gateway endpoint.
5. Inspect Gateway events, verified authentication events where applicable, deterministic signals, and the correlated incident.
6. Request GPT-5.6 analysis and inspect the evidence-bound policy and generated/canonical command comparison.
7. Confirm every validation gate and historical-impact result.
8. Approve the exact artifact as the administrator.
9. Verify the shared Gateway namespace blocks subsequent simulator traffic, the host ruleset is unchanged, and the applied target/TTL match the approved digest.
10. Use a bounded real-time Linux run to verify native nftables expiry and signed read-only inspection, then verify traffic recovery, non-reapplication reconciliation, and audit history; separately test deterministic administrator revocation. Injected application time never stands in for the kernel timeout clock.

The simulator modes are `normal`, `credential-stuffing`, `brute-force`, `path-scan`, and `request-burst`.

---

## Testing

The primary repository gates are:

```bash
make check-backend
make check-contracts
make check-database
make check-frontend
make check-security
make check-observability
make check-export
make check-recovery
make check-nft-namespace
SENTINELFLOW_GATEWAY_PERF_MODE=smoke make check-gateway-performance
./scripts/check-clean-input.sh
make check-docs
```

Verified on the current development workspace:

- the backend gate formats, vets, statically checks, tests, and builds 88 `cmd`/`internal` packages;
- the final root PostgreSQL 17.10 verifier passes 33 migrations and 72 tables, including fresh/restart-noop, `33→24→33`, ACL, sqlc, repeated-content-digest identity, the API-only validation-attempt projection, and queued stale-analysis supersession. Migration 31 makes content digests non-unique integrity indexes, migration 32 exposes only the bounded attempt projection, and migration 33 completes a provably overtaken queued analysis without a provider claim or dead letter while a genuinely missing aggregate remains fail-closed;
- final root frontend verification reports 39 Vitest files/363 tests and a production-CSP Chromium gate passing 1/1. The CSP-safe error decoder, exact deployment-header parser, and all-production-JavaScript dynamic-code-generation scan are implemented; release-level browser certification remains pending;
- the demo E2E helper suite passes 39/39 tests and its shell-contract suite passes 6/6 tests (46 combined tests). The shell contract requires the evidence-chain SQL to parse and return zero rows on the migrated PostgreSQL before entering the 305-second coverage wait. The helper now keeps generated and canonical artifact digests distinct, expects queue audit only for add, and restarts only long-running services during outage recovery;
- the third full `make check-supply-chain` run passes static 18/18, reproducible source SBOM, reproducible backend/PostgreSQL/Web images, fail-fast runtime probes, frozen Trivy database scans and SPDX output for all four shipped images with zero CRITICAL findings, PostgreSQL fresh/migrate/restart/wrong-owner-fail-closed lifecycle checks, evidence binding, and scoped cleanup; the legacy Sentinel container and demo images were preserved;
- `./scripts/check-clean-input.sh` materialized 905 tracked or unignored candidate source files into an external temporary Git-initialized snapshot, recorded manifest SHA-256 `2c395c3c5e3d28e908513e3304f5896ac7ae1eebe9a88dc80c543fe8baa73150`, and passed `make check`; this is source-only pre-commit evidence, not a committed checkout, CI, Linux, or release qualification;
- disabled and missing-key `cmd/openaismoke` paths fail closed without a network request.

Still pending or not qualified:

- serialized RUN25 of `./scripts/check-demo-e2e.sh --fast --browser-qa-hold-seconds 900` (log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`) passed pinned-image startup, authority/private-origin isolation, exact 305-second Gateway/auth coverage, all five scenarios, stable incident/policy bindings, exact HIL add, signed inspect, digest-mismatched revoke rejection, exact revoke, control-plane outage forwarding without a new block, long-running service recovery, dispatcher/executor/Gateway restart reconciliation, and exact-project cleanup. A later macOS run with `--run-browser-qa` also passed active and revoked browser QA. The revoked phase waits 61 seconds before the pre-hash login-window check; it does not retry a login or change any login-limit setting. This is non-release evidence because `--fast` revokes the action and macOS cannot certify native host nftables;
- these fast runs do not complete the separate frontend/UI/UX release task, default native-expiry run, native host-nft invariance, billable live OpenAI smoke, release screenshots, or the five-minute 4 GB performance gate;
- default `./scripts/check-demo-e2e.sh`, including its separate native kernel-expiry wait;
- a billable opt-in live OpenAI call;
- the five-minute `500 RPS` performance release gate on a documented 4 GB Linux reference host and native host-nft invariance evidence.

The smoke modes and macOS/Docker evidence do not substitute for those release qualifications.

---

## Safety Model

- The Gateway uses maintained HTTP protocol implementations and a fixed upstream.
- The origin is private and cannot be reached through a request-supplied URL.
- Sensitive request content is not persisted or sent to GPT-5.6.
- Logs, HTTP metadata, authentication events, and model output are untrusted data.
- Deterministic signals precede AI interpretation.
- Structured Outputs reduce format drift but do not replace semantic, evidence, policy, or command validation.
- Every structured security digest is taken over a versioned JCS contract; administrator reasons are NFC-normalized before hashing, and evidence references must be sorted, unique, and identical across the analysis, policy, and command.
- The AI has no direct Gateway policy, shell, approval, executor, or firewall authority.
- Only the isolated executor receives canonical bytes plus a dispatcher-signed, short-lived capability for a persisted exact HIL decision; API, AI, and general workers have no signing key, and the executor signs the digest-bound result with a distinct key.
- Lifecycle inspection is separately signed and read-only; it cannot inherit or manufacture mutation authority.
- Signed demo history is demo-only, run-scoped, and one-shot. Importer and activator credentials are separate five-minute PostgreSQL leases; both are removed with committed `NOLOGIN`/password-null/expired-credential fencing plus peer-session termination. Analysis and validation receive different activation capabilities, PostgreSQL retains only their digests, and neither consumer can create, refresh, or substitute the other activation.
- Adaptive enforcement fails closed; a control-plane outage does not take the protected application offline.
- Every applied block expires and is audited.

The default demo keeps the upstream private and runs nftables enforcement only inside an isolated container or network namespace.

---

## Threat Model

SentinelFlow explicitly considers:

- forged forwarding headers and client identity;
- request smuggling and frontend/backend parser disagreement;
- slow clients, oversized headers/bodies, streaming, and upstream exhaustion;
- origin bypass and request-controlled upstream SSRF;
- secret, cookie, query, body, or account leakage into persistence, prompts, logs, screenshots, and audit records;
- malicious authentication events, weak-key configuration, replay, and unauthenticated nonce-cache exhaustion;
- forged internal sender identity, auth-producer restart loss, trace-binding substitution, and out-of-window event time;
- prompt injection inside retained evidence;
- invented evidence, policy/command mismatch, extra nftables statements, digest substitution, and stale approval;
- administrator lockout and protected-network blocking;
- Gateway, database, OpenAI, worker, executor, or SSE outage;
- event loss, restart epochs, permanent sequence gaps, or delayed evidence during control-plane degradation;
- residual or unexpired rules after a crash, duplicate TTL refresh, and unsafe recovery reapplication;
- torn executor journal records, UDS frame confusion, forged results, and unauthorized mutating reconciliation.

---

## Known Limitations

Expected v0.1 limitations include:

- one fixed upstream and single-node deployment;
- HTTP/1.1 as the release protocol contract;
- no production HA, automated certificate lifecycle, or multi-region policy distribution;
- no raw packet capture, TCP reassembly, eBPF/XDP sensor, or payload inspection;
- no Gateway-native AI-adaptive `http-deny-v1` enforcement;
- Nginx/Syslog/firewall-log adapters are post-v0.1;
- credential-stuffing semantics require the authenticated application event adapter;
- fixed deterministic thresholds rather than learned organization baselines;
- nftables-only adaptive enforcement and Linux-only enforcement tests;
- observable event loss is possible after bounded queues saturate during a prolonged control-plane outage;
- possible false positives and dependence on deployment-specific route configuration;
- GPT-5.6 analysis requires network access, an API key, and adequate account access.
- signed demo-history activation lasts one hour and has no in-place renewal; expiry requires a complete disposable profile/volume reset and a newly sealed run;
- the demo importer and activator roles are PostgreSQL cluster-global, so the reference lifecycle assumes one isolated SentinelFlow demo profile per PostgreSQL cluster and rejects unsafe cross-database role state.

The current release candidate is additionally limited by the unqualified default native-expiry run, native host-nft invariance, absence of a live OpenAI result, and lack of a qualifying 4 GB Linux release host.

SentinelFlow is an implementation-oriented reference security gateway, not a production replacement for a mature WAF, SIEM, IDS, IPS, reverse proxy, or professional security review.

---

## Roadmap

Potential follow-up work:

- independently validated `http-deny-v1` Gateway enforcement adapter
- multi-upstream routing and signed policy distribution
- production TLS lifecycle, HTTP/2 and HTTP/3 validation, and HA data planes
- trusted proxy-chain and PROXY protocol support
- Nginx, Apache, Traefik, Syslog, firewall-log, SSH, and cloud WAF adapters
- read-only conntrack, nftables-counter, or eBPF sensor in a separate privilege domain
- OWASP CRS/Coraza interoperability research
- OpenSearch and SIEM integrations
- organization-specific baselines and policy tuning
- multi-host enforcement agents and role-based approval
- reports, threat-intelligence enrichment, MCP integrations, and multi-tenancy

---

## How Codex Was Used

Codex is used to maintain architecture and product contracts, decompose implementation into bounded agent-owned packages, implement and test code, review security and recovery paths independently, verify browser behavior, and keep English/Korean project documents synchronized with integrated evidence.

Agent status alone is not completion evidence. The root integrator must inspect every handoff and rerun the relevant build, test, security, recovery, browser, traceability, and documentation gates.

---

## How GPT-5.6 Is Used

GPT-5.6 is an incident analyst and constrained command-candidate generator, not the inline WAF engine or executor. It receives compact structured facts after deterministic detection and returns schema-bound analysis that remains untrusted until application-side validation succeeds.

No model call occurs for each incoming request.

---

## License

SentinelFlow is available under the [MIT License](./LICENSE).

---

## Disclaimer

SentinelFlow is experimental security software. Use it only in environments you own or are explicitly authorized to test. Keep enforcement isolated until the implementation, tests, and deployment controls have been independently reviewed.
