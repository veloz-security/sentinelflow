# SentinelFlow Technical Design Document (TDD)

**English** | [한국어](TDD.ko.md)

- Status: Draft
- Source of record: [README.md](../README.md)
- Related documents: [PRD.md](PRD.md) · [ADR.md](ADR.md) · [TASKLIST.md](TASKLIST.md) · [WBS.md](WBS.md)
- Decision baseline: `ADR-010`, `ADR-011`, `ADR-012`, `ADR-013`, `ADR-014`
- Target: implementation-complete single-node SentinelFlow v0.1 / OpenAI Build Week submission
- Terminology: TDD means *Technical Design Document* in this repository.

This document is the implementation contract for code that now exists. It is not, by itself, release evidence: current code, tests, rerun outputs, and runtime observations remain the source of truth for implementation and qualification status.

## Public research distribution checkpoint (2026-10-07)

SentinelFlow is owned by Veloz (벨로즈), whose official site is [sec.veloz.kr](https://sec.veloz.kr); the owner supplied [security@veloz.kr](mailto:security@veloz.kr) as the security contact. The owner requested public restructuring and release publication. `v0.1.0-rc.1` is an experimental research distribution, separate from the implementation-qualified v0.1 release and historical Build Week submission. No production, customer, certification, or CVP approval claim is made. Runtime and enforcement contracts are unchanged.

Implementation checkpoint `b125adec66864c87f5d37f15049514381dd9e4f3` already committed migration 34 and the v2 expiry repair; [CI run 29709922172](https://github.com/devwooops/sentinelflow/actions/runs/29709922172) passed all ten shards for that commit. Earlier references below to “current-tree” results describe the July 2026 snapshot, not a fresh October rerun. The release record must identify its own exact commit and verification. Existing P0 prerequisites and full v0.1 acceptance gates remain open until independently satisfied. See [release guide](./RELEASE.md), [research evidence](./RESEARCH.md), ADR-015, and M9-010.

Patch maintenance for public distribution follows ADR-016: Go `1.25.13`, `golang.org/x/text` `v0.39.0`, and same-major frontend dependency fixes require fresh backend (M9-011) and independent frontend (M9-012) verification. Existing safety contracts and the full release gates remain unchanged.

## 1. Objective

SentinelFlow v0.1 is a Gateway-first, explainable security system. A Go reverse proxy observes HTTP request and response metadata while forwarding traffic to one fixed private upstream. Deterministic rules correlate minimized evidence before GPT analysis. GPT may propose one evidence-bound `nft-blacklist-v1` command, but only strict validation and administrator HIL approval of the exact artifact can authorize temporary execution by a separate privileged executor.

Success means satisfying `FR-001`~`FR-026` and `NFR-001`~`NFR-014`, preserving request-path availability during control-plane failure, meeting the gateway performance budget, and ensuring that no AI, validation, approval, recovery, or audit ambiguity can create an unintended firewall change.

## 2. Scope and non-scope

v0.1 scope:

- `cmd/gateway`, implemented with Go `net/http` and `net/http/httputil.ReverseProxy`, is the primary inline sensor in front of one fixed private upstream. It is not an origin web server.
- The Gateway derives client identity from the direct network peer, sanitizes forwarding headers, enforces static protocol/size/time bounds, forwards the request, and emits only minimized metadata through a non-blocking `EventSink`.
- An authenticated internal application contract emits minimized authentication outcomes for credential-stuffing detection.
- Deterministic path-scan, request-burst, brute-force, and credential-stuffing rules produce evidence-bound signals and incidents.
- GPT-5.6 supplies explanation, uncertainty, a constrained `block_ip` policy, and one evidence-bound `nft-blacklist-v1` candidate outside the request path.
- Strict parsing, canonicalization, ordered validation, exact-artifact HIL, isolated shell-free nftables execution, expiry, reconciliation, audit, REST/SSE, and the administrator UI remain in scope.
- `cmd/ingestor` is reserved for optional post-v0.1 log and Syslog adapters that emit the same normalized evidence contracts. It is not on the v0.1 critical path.

Out of scope:

- Building a general-purpose origin web server or accepting a client-selected upstream
- Raw packet capture, eBPF/XDP/AF_XDP sensing, deep packet inspection, or a combined packet sensor/executor
- An adaptive AI-generated L7 deny rule in the Gateway; any future `http-deny-v1` artifact requires its own schema, validator, HIL binding, executor, tests, and ADR
- Replacing a production WAF, CDN, DDoS service, SIEM, or identity provider
- Multi-node, multi-tenant, multi-admin RBAC, unattended production blocking, and IPv6 nftables command generation

Static and versioned protocol safeguards may reject malformed, oversized, timed-out, or disallowed-host requests without HIL. They are part of the Gateway server configuration, not adaptive incident-response policy. AI output never directly changes request forwarding behavior.

## 3. Design principles and invariants

1. **One fixed private origin:** the Gateway proxies only to the configured upstream and never derives an upstream address from request data (`FR-022`, `FR-023`).
2. **Canonical direct-peer identity:** v0.1 trusts only the TCP peer address. It strips inbound `Forwarded` and `X-Forwarded-*` identity headers and regenerates them from canonical state (`FR-023`).
3. **Minimized evidence:** request bodies, response bodies, query strings, cookies, `Authorization`, raw secret-bearing headers, and raw request targets are never persisted, audited, sent to GPT, or placed in telemetry (`FR-024`, `NFR-014`).
4. **Non-blocking observation:** the request path never waits for PostgreSQL, GPT, administrator approval, or the EventSink network flush. Sink saturation or control-plane outage forwards traffic, reports degradation, and cannot produce a new block (`FR-025`).
5. **Deterministic first:** versioned quantitative rules run before AI analysis (`NFR-008`).
6. **Facts remain separate from inference:** observed Gateway/auth events, deterministic signals, AI interpretation, human decisions, and enforcement outcomes are stored as distinct records (`FR-010`).
7. **AI is untrusted and asynchronous:** GPT has no Gateway, administrator, database-write, shell, or firewall authority. Refusal, incomplete output, schema failure, timeout, and ambiguous evidence become `analysis_failed` (`FR-008`~`FR-010`, `FR-021`).
8. **Fail closed for enforcement:** missing, degraded, stale, failed, timed-out, or ambiguous evidence/validation/approval prevents a new block, while the Gateway continues forwarding otherwise valid traffic (`NFR-001`).
9. **Exact-artifact HIL:** approval binds immutable policy, generated and canonical command, evidence, validation, actor, reason, and validity digests. Any dependent mutation requires revalidation and reapproval (`FR-013`, `FR-021`).
10. **Shell-free least privilege:** only the isolated executor has the minimum nftables capability. A least-privilege dispatcher signs one short-lived, single-use exact-artifact capability; the executor verifies it, recomputes SHA-256, and invokes a fixed `nft -f -` without a shell (`FR-014`, `NFR-002`). API, AI, and general workers have neither a signing key nor executor reachability.
11. **Reversible, once-only enforcement:** every add has a finite TTL, kernel expiry, read-back, lifecycle audit, and conservative reconciliation. The same relative-timeout artifact is applied at most once and is never replayed to refresh its timeout; early disappearance fails and alerts rather than auto-restoring (`FR-015`, `NFR-007`).
12. **Private origin:** the upstream has no published host port and is reachable only from the Gateway network. Direct-origin reachability is a release-blocking failure (`FR-023`, `NFR-014`).
13. **Protocol correctness:** HTTP ambiguity, request smuggling, hop-by-hop header handling, host validation, and limits are security boundaries tested independently from detection (`NFR-013`).
14. **Traceability:** stable IDs and digests link Gateway/auth event → signal → incident → analysis → policy → validation → approval → action (`NFR-006`).

Artifact digests attest immutable bytes; they are not candidate, action, schedule, or authorization identity. Byte-identical generated, canonical, or inspection artifacts may recur under different evidence and lifecycle bindings. Every new add therefore requires a fresh candidate, policy, validation, challenge, decision, authorization, action, and capability chain, while every inspect requires a fresh typed read-only authorization and capability. A prior digest, HIL decision, or capability never authorizes the new chain.

## 4. Logical architecture and trust boundaries

```text
                         request/response data plane
Client ──> cmd/gateway ───────────────────────────────> Private origin
              │  Go ReverseProxy; fixed upstream             no published port
              │
              └─ non-blocking bounded EventSink
                              │ minimized Gateway events
                              v
                    authenticated batch endpoint <── Auth-event adapter
                              │
                              v
                    PostgreSQL + transactional outbox
                              │
             Detector/Correlator ──> GPT-5.6 analysis
                              │             │ untrusted candidate
                              v             v
Admin UI <── REST/SSE ── API/HIL <── Validator/Canonicalizer
                              │ exact artifact + approved digest
                              v
                    approved-job DB view
                              │
                     cmd/dispatcher (Ed25519 signer)
                              │ private UDS + single-use capability
                              v
                    Isolated nftables executor
                              │ shared Gateway netns only
                     read-back / expiry / audit
```

The request/response data plane contains only the Gateway and private origin. Detection, GPT, PostgreSQL, HIL, and nftables execution are control-plane work. Control-plane latency or unavailability cannot be converted into request latency or an automatic deny decision.

Trust boundaries:

- **A — Client to Gateway:** untrusted HTTP syntax, method, host, headers, path, query, body, rate, and direct peer address
- **B — Gateway to origin:** fixed scheme/address/host, sanitized hop and forwarding headers, bounded streaming, private network
- **C — Gateway/application to control plane:** authenticated minimized event contracts, non-blocking queue, batch limits, replay protection, degradation markers
- **D — Control plane and PostgreSQL:** typed repositories, transactions, retention, least-privilege roles, outbox idempotency
- **E — OpenAI API:** compact structured facts, no raw secrets, fixed model/options, no tools, strict output schema
- **F — Administrator browser:** single-admin authentication, secure session cookie, CSRF/origin/replay checks, exact-artifact decision
- **G — Dispatcher to isolated executor:** approved canonical bytes/digests plus a short-lived Ed25519 capability over a private UDS; fixed binary/arguments, no shell or general network API
- **H — Shared demo network namespace:** only the Gateway traffic namespace is shared with the executor sidecar; the Gateway retains zero capabilities and the host ruleset must remain invariant

## 5. Deployment units and component contracts

| Unit | Responsibility | Prohibited / boundary |
| --- | --- | --- |
| `cmd/gateway` | Configure HTTP server and one ReverseProxy, lifecycle, health, metrics, bounded EventSink | No AI, HIL, PostgreSQL request-path call, arbitrary upstream, shell, or nft capability |
| `internal/gateway` | Peer identity, host/header sanitation, fixed rewrite, bounds, metadata capture, event construction | No body/query/header persistence or adaptive AI deny logic |
| `cmd/api` | Admin REST/SSE/session/CSRF and authenticated internal event endpoints | No nft mutation; no raw request or auth secret exposure |
| `cmd/worker` | Event persistence jobs, detection, correlation, GPT, validation, expiry, and audit/outbox work | No arbitrary shell or direct nft mutation |
| `cmd/historyimporter` | One-shot verification and import or exact completed-state attachment for the fixed signed demo-history run under a five-minute importer lease | No AI, HIL, general worker role, activation capability, listener, signing key, or renewable import authority |
| `cmd/demoactivator` | One-shot public-proof verification and atomic creation/exact reattachment of the distinct analysis/validation activation pair | No import, prepare, AI, HIL, dispatcher, executor, listener, activation renewal, or long-running service authority |
| `cmd/dispatcher` | Read only approved, still-valid jobs; mint Ed25519 exact-artifact capabilities; submit over private UDS; persist signed result attestations | No general worker/API role, OpenAI secret, nft capability, arbitrary job, or network executor endpoint |
| `cmd/executor` | Verify single-use capability, execute exact add/revoke artifact, read back, journal replay state, and reconcile only removable residue | No GPT/API secret, DB access, private dispatch key, alternate command, network listener, or shell |
| `cmd/simulator` | Reproducible origin, normal traffic, and attack traffic | No host-firewall access or real credentials |
| `cmd/ingestor` | Post-v0.1 optional log/Syslog adapters | Not a v0.1 dependency; no AI or enforcement calls |
| `internal/events` | Typed Gateway/auth/source-health contracts, validation, IDs, schema versions | No generic raw payload persistence |
| `internal/detection` | Versioned deterministic windows and evidence-bound signals | No AI result as input fact |
| `internal/correlation` | Same-source time relations and incident lifecycle | No identity claim based only on an IP address |
| `internal/ai` | Bounded Responses API request, strict Structured Outputs, result classification | No tools, persistence authority, approval, shell, or executor access |
| `internal/policy` | `nft-blacklist-v1` grammar, AST, canonical bytes, SHA-256, artifact state | No general nft or shell grammar |
| `internal/validation` | Evidence consistency, protected ranges, nft check, historical impact, snapshot | No bypass or approval mutation |
| `internal/enforcement` | Capability/result schemas, dispatcher/executor UDS, exact digest recheck, fixed invocation, read-back, revocation, recovery | No model text, generated candidate, stale approval, generic HMAC, or general firewall request |
| `internal/repository` | pgx/sqlc persistence, transactions, retention, outbox leases | No domain decisions |
| `web/` | Administrator investigation and HIL experience | No backend/domain/enforcement implementation |

Component-facing Go APIs use typed domain objects and explicit `context.Context`. External HTTP, PostgreSQL, OpenAI, and nftables implementations are adapters. Shared contracts have one owner and circular imports are prohibited.

### 5.1 Gateway configuration contract

The immutable startup configuration includes:

- `listen_addr`, optional paired `tls_cert_file`/`tls_key_file`, `public_hosts`, `service_label`, `upstream_url`, `upstream_host`, and nonempty `origin_cidrs`
- `max_header_bytes=32768`, `max_body_bytes=10485760`, `read_header_timeout=5s`, `request_timeout=30s`, `upstream_timeout=30s`, and `idle_timeout=60s`
- `max_request_target_bytes=4096`, `max_path_bytes=2048`, `path_catalog_version=path-catalog-v1`, and an explicit configured login-route map
- EventSink endpoint/auth secret ID, `queue_capacity=10000`, `batch_size=100`, `max_batch_bytes=262144`, and `flush_interval=100ms`

The asserted demo profile fixes the shared service label as `SENTINELFLOW_SERVICE_LABEL=demo-app`, the application listener as `DEMO_ORIGIN_HTTP_LISTEN_ADDR=172.30.0.10:8081`, the API internal ingestion listener as `INTERNAL_API_INGEST_LISTEN_ADDR=172.31.0.10:8082`, and the separate container management listener as `API_MANAGEMENT_LISTEN_ADDR=:8083`. Compose publishes only that management port to the host address selected by `API_MANAGEMENT_PUBLISHED_HOST=127.0.0.1`; the container listener itself is not described as loopback-bound.

`net/http.Server` is the sole wire HTTP parser. `MaxHeaderBytes=32768` is the configured Go parser limit, not a promise that exactly 32,768 raw wire bytes are accepted: Go may read implementation-defined protocol overhead and buffering slop. SentinelFlow never adds a second raw-header parser or rewinds/reinterprets the request. Parser-version behavior is frozen by differential raw-socket tests against a minimal `net/http` oracle.

The sole v0.1 upstream scheme is `http`. Each `origin_cidrs` entry must be an IPv4 RFC 1918 subnet with prefix length at least `/16`; the list cannot be empty and cannot contain `0.0.0.0/0`, loopback, link-local/metadata, public, multicast/reserved, or IPv6 space. At startup and before every new connection, a custom resolver must return only A records and every answer must be inside `origin_cidrs`; any disallowed A, any AAAA, or a mixed allowed/disallowed answer set rejects the configuration or connection. The custom dialer rechecks and dials the selected allowed IP directly. The dedicated `http.Transport` sets `Proxy=nil`, so environment proxy variables cannot redirect origin traffic.

Startup also fails if there is not exactly one upstream URL, it contains user info/query/fragment, its host is missing, or the fixed upstream Host is not configured. Client input never changes upstream scheme, authority, address, or Host. Public Host entries are lowercase ASCII DNS names with optional explicit ports; matching rejects non-ASCII, IP literals, user info, ambiguous/multiple values, and normalizes case, one trailing dot, and default port (`80` for HTTP, `443` for TLS) before exact allowlist comparison. A nondefault port must appear explicitly in the allowlist. When TLS is configured, ALPN advertises only `http/1.1`; Go HTTP/2 automatic server configuration is explicitly disabled with an empty non-nil `TLSNextProto` map, and the origin transport has `ForceAttemptHTTP2=false`.

### 5.2 EventSink contract

```go
type EventSink interface {
    TryEnqueue(events.GatewayEvent) events.EnqueueResult
}
```

`TryEnqueue` is non-blocking and returns `accepted`, `degraded`, or `dropped`; it never returns a database or GPT result. The default adapter owns a bounded in-memory queue and asynchronously sends authenticated batches to the internal control-plane endpoint. A background sender uses batches of at most 100 records and 256 KiB, a 100 ms healthy flush interval, and bounded backoff from 100 ms to 5 s. It has no durable event spool in v0.1.

Each configured Gateway or authenticated-application `sender_id` is stable, while `sender_epoch` is a random 128-bit value created on every process boot and `sequence` starts at one and increases monotonically within that epoch. Each producer owns the same checkpoint/epoch lifecycle and may emit its own `source-health-v1`. A small durable checkpoint stores only sender ID, endpoint, epoch, last acknowledged sequence/body digest, and a clean-shutdown flag; it never stores event records. Startup atomically marks the checkpoint unclean before accepting requests. Clean shutdown stops accepting, attempts a bounded five-second flush, records any known unsent range through `source-health-v1`, and marks clean only after the last batch or loss marker is acknowledged. After an unclean restart, the new epoch permanently records an `unclean_restart` event in `lost` state for the previous epoch with an unknown range. It does not invent sequence, time-range, or drop-count evidence that the checkpoint does not contain.

Every outage, rejected batch, sequence gap, or dropped event opens a source-health degraded interval. The receiver validates and persists a whole batch atomically or not at all. It may accept later sequences without request-path backpressure, but a gap closes only when every missing batch arrives byte-identically or an authenticated `source-health-v1` permanently marks its exact sequence/time range lost. Permanent closure allows later complete windows to proceed; it never makes an overlapping window complete. The first acknowledged health event closes the live interval and commits its drop/loss count. Any signal, analysis, or validation window overlapping unresolved, permanently lost, `unclean_restart`, or `unknown_loss` degradation is insufficient evidence for a new block.

### 5.3 Dispatcher and executor capability contract

Only `cmd/dispatcher` can read the least-privilege approved-job database view and the Ed25519 private dispatch key. API, AI, validator, and general worker processes have neither that view, that key, nor the dispatcher/executor shared runtime directory. `cmd/executor` has the corresponding dispatch public verification key plus a separate Ed25519 private result-signing key, and listens on a filesystem-permissioned Unix domain socket in a tmpfs volume mounted only into dispatcher and executor; it exposes no TCP/UDP listener. Dispatcher has the executor result public verification key but never its private key.

[`execution-capability-v1`](../contracts/enforcement/execution_capability_v1.schema.json) uses RFC 8785 JSON Canonicalization Scheme (JCS) and has these exact fields, all present with non-applicable values set to JSON `null`: `schema_version`, `capability_id`, `operation`, `job_id`, `action_id`, `policy_id`, `policy_version`, `target_ipv4`, `artifact_digest`, `original_add_digest`, `evidence_snapshot_digest`, `validation_snapshot_digest`, `authorization_digest`, `actor_id`, `reason_digest`, `owned_schema_digest`, `issued_at`, `not_before`, `expires_at`, and `nonce`. `operation` is exactly `add`, `revoke`, or `inspect`; inspect carries the immutable read-only [`nft-inspect-v1`](../contracts/enforcement/nft_inspect_v1.schema.json) artifact rather than mutation bytes. It is signed as `Ed25519("sentinelflow execution-capability-v1\n" || SHA256(JCS(payload)))`. Expiry is at most 60 seconds after issue and never outlives validation/approval. The checked [`contract_vectors_v1.json`](../contracts/vectors/contract_vectors_v1.json) freezes JCS bytes, digests, and signatures for add, revoke, and inspect.

For `add` and `revoke`, `authorization_digest`, `actor_id`, and `reason_digest` bind the administrator's exact HIL authorization. For `inspect`, `authorization_digest` instead binds the strict non-HIL [`inspection-authorization-v1`](../contracts/enforcement/inspection_authorization_v1.schema.json), `actor_id` is the system scheduler identity, and `reason_digest` is the deterministic digest of its typed machine purpose. The capability `nonce` remains dispatcher anti-replay material, not an administrator decision nonce. An inspect lifecycle has no password step-up, administrator HIL decision/nonce, or administrator-authored reason and can never authorize mutation or TTL refresh.

Capability expiry never outlives its source authority: validation/HIL for add or revoke, and `inspection-authorization-v1.valid_until` for inspect.

The UDS protocol is strict and versioned. Each connection carries one request frame and one response frame, then closes. A frame is a four-byte unsigned big-endian length followed by at most 16 KiB of strict JSON; short, zero, oversized, second, or trailing frames fail closed. Read, write, and total exchange deadlines are each 2 seconds. The exact [`executor-request-envelope-v1`](../contracts/enforcement/executor_request_envelope_v1.schema.json) fields are `schema_version`, `capability_jcs_b64url`, `capability_signature_b64url`, and `artifact_b64url`; the exact [`executor-response-envelope-v1`](../contracts/enforcement/executor_response_envelope_v1.schema.json) fields are `schema_version`, `result_jcs_b64url`, and `result_signature_b64url`. Binary fields are unpadded base64url, and an Ed25519 signature encodes to 86 characters. The capability, result, inspect, request, and response schemas under `contracts/enforcement/` are authoritative for add/revoke/inspect exchanges. `inspect` is signed, read-only, and bound to target/action/original-add/live-schema digests; it may execute only the fixed read-back operation for `inet sentinelflow blacklist_ipv4`, cannot use `nft -f`, and cannot change state. Every pre/post add or revoke read-back, recovery classification, expiry check, and lifecycle reconciliation uses a signed inspect request and signed result.

The durable replay journal is two-phase and each payload conforms to [`executor-journal-record-v1`](../contracts/enforcement/executor_journal_record_v1.schema.json). After capability syntax/signature/digest validation, journal lookup occurs before temporal freshness checks: an exact matching `terminal` duplicate returns its byte-identical stored signed result, and an exact matching `started` duplicate performs signed inspect-only resolution. Only an unseen capability must pass not-before/expiry/authorization freshness and target-state checks. Before any mutation, a length/version-delimited record stores the exact capability JCS bytes—which bind issued, not-before, and expiry times—the exact Ed25519 signature bytes, exact artifact bytes including the read-only inspect artifact, their digests, received/deadline times, and journal sequence. Each JCS record contains its own checksum and the digest of the complete preceding record, while the binary frame adds a separate checksum; together with sequence continuity these form the verified chain. The executor appends `started`, fsyncs the journal file, and fsyncs its parent directory before invoking nft. It then performs the fixed operation and signed inspect, appends the exact signed terminal result, and fsyncs the file. A torn or corrupt tail, checksum/previous-digest/sequence/version failure, or directory-sync uncertainty makes executor readiness fail closed and requires explicit recovery; it is never truncated-and-continued and no mutation is allowed. A crash leaving `started` without `terminal` uses signed inspect to terminally classify add state as `active`, `failed`, or `indeterminate` (and revoke state as `revoked`, `failed`, or `indeterminate`) without ever invoking an add again. A duplicate never refreshes timeout. A fresh, non-replay add fails if the target already exists.

[`execution-result-v1`](../contracts/enforcement/execution_result_v1.schema.json) uses RFC 8785 JCS and has these exact fields, all present with non-applicable values set to JSON `null`: `schema_version`, `result_id`, `capability_id`, `capability_digest`, `operation`, `action_id`, `artifact_digest`, `target_ipv4`, `classification`, `nft_exit_class`, `readback_state`, `element_handle`, `remaining_ttl_seconds`, `owned_schema_digest`, `started_at`, `completed_at`, `journal_sequence`, and `error_code`. The exact pinned `nft --json list set inet sentinelflow blacklist_ipv4` read-back exposes a set handle but no per-element handle, so `element_handle` is a reserved field that MUST be `null`; the set handle MUST NOT be substituted. Active membership is attested by the exact canonical IPv4 element and a positive bounded `remaining_ttl_seconds`. `started_at` and `completed_at` are the actual result-assessment interval. They may be later than capability expiry for a started-only read-back recovery because journal receive/deadline plus the one-use permit—not result-signing time—prove mutation freshness; a later result can attest state but cannot recreate execution authority. The executor signs `Ed25519("sentinelflow execution-result-v1\n" || SHA256(JCS(payload)))` with its separate result key. Dispatcher matches it to the UDS exchange and capability, verifies it with the executor result public key, and commits the signed result with action/audit state. Checked vectors cover applied, recovered-active, revoked, and inspect-absent results. A missing, mismatched, invalidly signed, or uncommittable result is `indeterminate`, never success. No generic worker HMAC or shared service secret grants executor authority.

Under `ADR-014`, v1 is historical-only for fixtures and already-recorded results; it MUST NOT establish a new lifecycle expiry boundary. New executor output MUST use [`execution-result-v2`](../contracts/enforcement/execution_result_v2.schema.json), which retains every v1 field and adds required millisecond UTC `readback_started_at` and `readback_completed_at`. They bracket the fixed nft JSON read-back and MUST satisfy `started_at <= readback_started_at <= readback_completed_at <= completed_at`; v2 is signed as `Ed25519("sentinelflow execution-result-v2\n" || SHA256(JCS(payload)))`, a distinct signing domain from v1. For a signed active v2 read-back, lifecycle derives `expiry_lower = readback_started_at + remaining_ttl_seconds` and `expiry_upper = readback_completed_at + remaining_ttl_seconds + 1 second`. The upper guard accounts only for nftables' integer-second remaining-time projection. Storage and scheduler retain both bounds or an equivalent lossless representation; they MUST NOT manufacture one exact expiry instant from the outer execution interval.

Recovery-bundle export and verification preserve the exact signed `execution-result-v2` bytes and compare its read-back bracket to the persisted `execution_result_readback_bounds_000034` row. Dispatcher crash recovery also accepts a v2 terminal result only when its exact persisted JCS, digest, signature, and bounds match; an exact replay returns without another lifecycle mutation. A missing, malformed, or mismatched bound fails closed; it cannot be inferred from outer result timestamps. Historical v1 records remain exportable only without a bound row and cannot be reinterpreted as v2 lifecycle evidence.

## 6. Gateway request and response flow

1. `net/http.Server` is the sole request parser under configured `MaxHeaderBytes=32768` and a 5 s header-read limit; the configured value is not an exact raw-wire-byte guarantee and no SentinelFlow raw parser second-guesses accepted bytes. v0.1 accepts origin-form HTTP/1.1 only. Optional TLS advertises ALPN `http/1.1` only and Go HTTP/2 auto-configuration is disabled. The server rejects HTTP/1.0, HTTP/2 cleartext prefaces, `CONNECT` authority-form, absolute-form, asterisk-form, `Upgrade`/WebSocket/h2c, request trailers, and malformed framing before proxying.
2. Middleware removes inbound `X-SentinelFlow-Request-ID`, `X-SentinelFlow-Trace-ID`, `X-Request-ID`, `X-Trace-ID`, `traceparent`, and `tracestate`, then generates new `request_id` and `trace_id`; no client-supplied request/trace identity is canonical.
3. Parse `RemoteAddr` with `net/netip`, remove the port, unmap IPv4-mapped IPv6, and serialize the canonical address. v0.1 does not accept a trusted-proxy chain.
4. Normalize Host using the exact ASCII/case/trailing-dot/port rules in Section 5.1 and match `public_hosts`. Unknown hosts receive `421 Misdirected Request`; invalid or ambiguous Host receives `400`; neither is forwarded.
5. Rely on Go parser rejection for malformed/conflicting framing, `Transfer-Encoding` plus `Content-Length`, unsupported transfer coding, obs-fold, and invalid header octets. SentinelFlow evaluates only the parsed canonical `http.Request`; equal duplicate `Content-Length` values proceed as one canonical value only when the pinned Go parser accepts/canonicalizes them, and raw bytes are never reinterpreted. Reject a `Connection` token that nominates a security-sensitive forwarding/identity/framing header. Remove inbound `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, all standard hop-by-hop headers, and every remaining header named by `Connection`. Request trailers are rejected. The only supported expectation is case-insensitive exact `100-continue`; all others receive `417`. The transport uses a one-second `ExpectContinueTimeout`, relays an upstream `100`, and otherwise begins streaming the body after that bound.
6. Regenerate `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` from the canonical peer, allowlisted public host, and actual listener scheme. Pass both newly generated IDs to the origin as `X-SentinelFlow-Request-ID` and `X-SentinelFlow-Trace-ID`.
7. Enforce a 4 KiB request-target and 2 KiB classification-path bound. Reject malformed percent escapes, raw or percent-encoded backslashes, percent-encoded slash, NUL/C0/DEL bytes, and literal or once-decoded `.`/`..` path segments. The classifier decodes unreserved percent escapes once, uppercases retained escapes, and collapses repeated slashes; it never decodes twice. Rewrite only scheme, authority, and upstream Host to the fixed configured origin. Preserve the validated path/query for origin behavior, but never retain the raw path, target, or query.
8. Reject a declared `Content-Length` above 10 MiB with `413 Content Too Large` before contacting the origin. For an unknown-length/chunked body, wrap the stream with the same hard limit; exceeding it cancels the upstream request and returns `413` if no response was committed, otherwise terminates the stream. Body bytes are never inspected or stored.
9. Apply a 30 s total request context and 30 s upstream timeout. The dedicated transport sets `DisableCompression=true`, never injects `Accept-Encoding`, and passes content encodings through without automatic decompression. Strip response hop-by-hop headers and headers named by the response `Connection`; only relay a request-correlated `100 Continue`, reject every other upstream 1xx including `101 Switching Protocols`, discard response trailers and `Trailer`, stream the opaque body, and never retain content.
10. Classify the bounded canonical comparison path using `path-catalog-v1`. Persist only configured enum `route_label`, `path_catalog_version`, and `suspicious_path_id`; never persist an exact path. The built-in suspicious IDs are `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, and `backup_archive`, otherwise `none`. The fixed patterns are respectively `/admin` or `/administrator` prefixes, `/.env`, `/.git/config`, `/wp-admin` or `/wp-login.php`, `/phpmyadmin` prefix, `/server-status`, `/actuator/env`, and filename suffixes `.bak`, `.backup`, `.old`, or `.zip`, compared case-insensitively on ASCII. The configured login-route map produces only allowlisted labels such as `login` or `other` and is versioned with the catalog.
11. Call `EventSink.TryEnqueue` after the response metadata is known. `degraded` or `dropped` increments metrics but never changes an otherwise valid origin response.

Static outcomes do not require HIL: `400`/`414` for malformed or out-of-contract syntax/targets, `417` for unsupported expectations, `421` for a non-allowlisted Host, `413` for an oversized body, `505` for an unsupported HTTP version, and `504` for upstream timeout. An origin resolution/address/connection failure or unsupported upstream protocol response returns `502`. Adaptive AI policy never creates these responses.

## 7. Asynchrony, state, and consistency

The Gateway remains able to forward valid traffic when the EventSink, API, PostgreSQL, worker, or OpenAI service is unavailable. The healthy-load target is zero event drops at 500 requests/second on the 4 GB reference environment. On sustained outage the bounded queue may drop observations; it must not apply backpressure to origin traffic or silently treat the remaining sample as complete evidence.

- Event idempotency key: SHA-256 of schema version, Gateway instance ID, and generated event ID
- Internal batch idempotency key: sender ID + sender epoch + batch ID; the receiver also tracks a monotonic per-epoch sequence and exact raw-body digest
- Job idempotency key: job type + aggregate ID + aggregate version
- Enforcement idempotency key: policy ID + policy version + generated/canonical command digests + evidence/validation snapshot digest
- Event and outbox insertion: one PostgreSQL transaction; duplicate event/batch keys are acknowledged without duplicate effects
- Job delivery: at least once through `FOR UPDATE SKIP LOCKED`; unique constraints and state transitions bound effects
- Worker outbox fencing: a lease is at most 60 seconds and every completion binds the exact lease token before its strict expiry. Expired work is reclaimable without waiting, a crashed final attempt moves to `dead` with its dead-letter evidence in the same transaction, and a unique business-effect key prevents a second domain effect even when an idempotency key differs.

Incident state is `open → analyzing → review_ready → closed`, with `analysis_failed` as the only non-enforcing AI failure state. Its required reason is one of `budget_exhausted`, `input_too_large`, `network_error`, `http_408`, `http_409`, `rate_limited`, `server_error`, `timeout`, `refused`, `incomplete`, `schema_invalid`, `evidence_invalid`, `unsupported_action`, `cancelled`, or `configuration_error`; the reason also determines whether and when a new idempotent attempt may return to `analyzing`. Candidate state is `generated → parsing → canonical|invalid → validating → valid|stale`. Policy/action state is `draft → validating → valid|invalid|stale → approved|rejected → queued → active → expired|failed|revoked|indeterminate`. The server enforces allowed transitions and optimistic versions.

Correlation compares every Gateway, auth, and source-health record timestamp with server `received_at`. More than 60 seconds in the future or more than 5 minutes in the past is persisted as `trust_state=untrusted` with `trust_reason=timestamp_skew`; the record is retained for audit but cannot contribute to detection, analysis evidence, validation, or enforcement. It is never silently dropped or shifted. Source-health degradation, missing referenced rows, duplicate conflicts, pending/failed auth binding, and incomplete rule windows fail evidence sufficiency.

## 8. Minimized event contracts

Persistence uses typed allowlisted columns, not arbitrary request JSON. Unknown contract fields are rejected at the internal API boundary so a new field cannot accidentally become retained evidence.

### 8.1 Gateway event `gateway-http-v1`

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
  "route_label": "login",
  "path_catalog_version": "path-catalog-v1",
  "suspicious_path_id": "none",
  "host": "app.example.test",
  "service_label": "demo-app",
  "status_code": 401,
  "request_bytes": 128,
  "response_bytes": 431,
  "latency_ms": 7
}
```

The persisted Gateway allowlist is exactly: schema/trace/idempotency IDs, start/end timestamps, canonical source IP, bounded method, fixed `HTTP/1.1` protocol label, configured route label, path-catalog version, suspicious-path enum, configured host/service label, status, request/response byte counts, and latency. The event never contains an exact normalized/decoded/raw path, request target, query, request or response body, cookie, `Authorization`, username, user agent, referrer, forwarding-header input, or arbitrary headers.

`host` is the normalized matched allowlist value, not untrusted raw Host text. Route and suspicious-path values must be members of the startup-frozen catalog, not strings copied from request data. Counts are non-negative integers and latency is derived from a monotonic clock while timestamps are UTC.

### 8.2 Authentication event `auth-event-v1`

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

Only an authenticated allowlisted internal application may submit this contract. `outcome` is `failed` or `succeeded`. `account_hash` is a stable HMAC-SHA-256 value computed by the application with a secret outside the repository; raw username, email, credential, token, and password fields are forbidden. `source_ip` must be canonical and must originate from the sanitized Gateway forwarding value.

An auth event enters `binding_state=pending` for at most five minutes when its Gateway event is not yet present. Reconciliation requires exact `gateway_request_id`, `trace_id`, canonical `source_ip`, `service_label`, and configured login `route_label` agreement. Only `verified` bindings may support attack evidence. Any mismatch becomes permanently `untrusted`; an unresolved pending binding expires to `untrusted`. A failed or unverified event never contributes to an attack threshold, while any pending or untrusted `succeeded` event for the target conservatively blocks historical-impact validation.

Both internal event endpoints accept JSON batches of at most 100 records and 256 KiB. They require `X-Sentinel-Sender-ID` to match `^[a-z0-9][a-z0-9._-]{0,63}$` (1–64 lowercase ASCII characters), `X-Sentinel-Timestamp` as 1–12 ASCII decimal Unix-second digits, `X-Sentinel-Nonce` as exactly 22 unpadded base64url characters decoding to 128 random bits, and `X-Sentinel-Signature` as exactly 64 lowercase hexadecimal characters. Each sender HMAC key is a CSPRNG-generated value of at least 32 bytes configured as base64. The lowercase-hex signature is `HMAC-SHA256(secret, endpoint_path + "\n" + sender_id + "\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(raw_body)))`; `endpoint_path` is the literal internal path and is the first signing-input field, while `sender_id` is the exact header value. The checked event schemas and vector are [`contracts/events/`](../contracts/events/) and [`contract_vectors_v1.json`](../contracts/vectors/contract_vectors_v1.json).

Authentication order is fixed: validate bounded header/base64 syntax; use the sender header plus literal endpoint to look up the bound key; check ±60 s authentication timestamp; enforce raw-body size and calculate SHA-256; compare the signature in constant time; parse the strict body; and require byte-identical header/body `sender_id`. Only then does one transaction atomically insert the nonce into the five-minute unique replay store and validate/persist the whole batch; any later validation failure rolls the nonce back with the batch. Invalid authentication therefore cannot exhaust the nonce cache. Gateway and application senders use separate configured secret IDs; secret values, authentication metadata, and signatures are never persisted as evidence. Golden vector `event-batch-hmac-v1` under `contracts/vectors/` freezes endpoint, sender header, raw body bytes, body digest, signing input, and signature.

### 8.3 Internal batch envelope `event-batch-v1`

Both `/internal/v1/gateway-events` and `/internal/v1/auth-events` use the same typed envelope:

```json
{
  "schema_version": "event-batch-v1",
  "sender_id": "gateway-demo-1",
  "sender_epoch": "X5YwQfP7gH2mN9sT4uV6aA",
  "batch_id": "019b0000-0000-7000-8000-000000000020",
  "sequence": 42,
  "sent_at": "2026-07-18T02:00:00.100Z",
  "records": []
}
```

`records` contains 1 through 100 items and the exact raw request body is at most 256 KiB. The configured stable `sender_id` is bound to one endpoint, an allowlisted record schema set, and its HMAC key ID. `sender_epoch` is random per boot and `sequence` is an unsigned counter monotonic within that epoch. A Gateway sender may submit `gateway-http-v1` and its own `source-health-v1`; an application sender may submit `auth-event-v1` and its own `source-health-v1`. Each has independent checkpoint, epoch, sequence-gap, and degradation state. Unknown senders, header/body sender mismatch, a sender on the wrong endpoint, mixed/disallowed record types, unknown fields, or an invalid epoch/sequence are rejected before persistence.

A retry preserves `sender_epoch`, `batch_id`, `sequence`, and exact body bytes, but uses a fresh `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, and signature. Receiver validation plus receipt, all records, outbox effects, gap state, and acknowledgement state commit in one transaction. A newly accepted batch or an exact duplicate returns only `202`; its minimal acknowledgement is `accepted` or `duplicate` plus sender/epoch/batch/sequence/body digest, and an exact duplicate returns the same acknowledgement. Reuse of a batch ID or sender/epoch/sequence with a different digest returns `409`, is security-audited, and has no partial effect. Any schema, sender, record, HMAC, replay, bound, or unknown-field failure returns `422` with no partial effect. Later batches may be accepted while a gap is recorded; the Gateway never waits for closure.

### 8.4 Source-health event `source-health-v1`

This typed event records source ID, sender epoch, occurrence and degraded interval times, state (`degraded`, `lost`, or `recovered`), cause enum (`queue_overflow`, `delivery_outage`, `rejected_batch`, `sequence_gap`, `permanent_loss`, `unclean_restart`, `unknown_loss`, or `recovered`), dropped/unknown count, exact batch sequence range when known, and a bounded detail code. It carries no request data. An open interval, permanent loss, unknown loss, or non-zero drop count marks every overlapping detection and historical-impact window incomplete.

## 9. Deterministic detection and correlation

All thresholds are inclusive, configuration-versioned, evaluated in event time, and grouped by canonical `source_ip` plus `service_label` unless stated otherwise.

| Rule | Evidence and threshold | Signal |
| --- | --- | --- |
| `path_scan.v1` | All 8 distinct non-`none` `suspicious_path_id` values from the same `path-catalog-v1` within 60 s | `path_scan` |
| `request_burst.v1` | At least 120 Gateway events within 10 s | `request_burst` |
| `login_bruteforce.v1` | At least 10 Gateway responses with status `401` or `403` and a configured login `route_label` within 60 s | `brute_force` |
| `credential_stuffing.v1` | At least 20 binding-`verified` `failed` auth events spanning at least 8 distinct `account_hash` values within 5 min | `credential_stuffing` |

Each signal stores rule ID/version, exact window, metrics, source/service keys, evidence event IDs, and source-health status. A rule cannot fire for enforcement purposes if the evidence set overlaps degradation, contains an untrusted timestamp/binding, or cannot reproduce the threshold from retained events.

Signals for the same canonical source are merged when their windows overlap or are separated by no more than 5 minutes. Account hash, path, and service are supporting relations, never proof of a common person. An incident closes after 15 minutes without a new related signal. A related signal arriving within 30 minutes after closure reopens the same incident version; a later signal creates a new incident.

## 10. Persistent data and retention

| Entity | Core fields | Invariant |
| --- | --- | --- |
| `gateway_events` | `gateway-http-v1` allowlisted fields, catalog enums, received time, trust state/reason | No exact path, body, query, cookie, authorization, raw target, or arbitrary header column; skewed records retained but never used as evidence |
| `auth_events` | `auth-event-v1` fields, received time, trust state/reason, binding state/deadline/reason | Only opaque account hash; authenticated source, replay check, trusted time, and verified relation required for attack evidence |
| `ingest_batches` | sender, epoch, batch ID, sequence, raw-body digest, sent/received time, acknowledgement | Batch and sequence unique per sender/epoch; whole-batch atomicity; conflicting digest rejected and audited |
| `source_health_intervals` | instance, cause, start/end, drops, batch range | Overlap makes evidence incomplete for enforcement |
| `signals` | rule/version, window, metrics, source/service, evidence IDs | Threshold reproducible from complete evidence |
| `incidents` | kind, state, first/last seen, source/service, deterministic score, version | AI fields are not observed facts |
| `incident_events` | incident ID, event type/ID, relation | Composite unique; immutable relation reason |
| `ai_analyses` | incident/version, model/options, input/schema/output digests, result/error | Only strict complete output is usable |
| `command_candidates` | evidence snapshot/refs, generated bytes/digest, AST, canonical bytes/digest, grammar | Immutable one-statement artifact; content digests are non-unique forensic indexes, while candidate and evidence/analysis bindings provide identity |
| `policy_proposals` | policy/version/digest, incident, command/evidence digests, TTL, state | Exact `block_ip` artifact only |
| `policy_validations` | artifact/input/config/tool digests, checks, impact, snapshot digest, `valid_until` | Every required check for one exact artifact committed |
| `validation_attempt_claims/results/gates` | policy/analysis/incident/version, terminal state/failure, prepared and terminal digests, ordered gate results | Immutable valid/invalid/interrupted attempt evidence; raw prepared/terminal JSON is never an API payload |
| `decision_challenges` | nonce digest, session/actor, decision, exact artifact digests/version, issued/expiry/consumed time | Five-minute, single-use exact-artifact challenge; raw nonce returned once and never stored |
| `approval_decisions` | exact digests, challenge, actor, decision, reason/digest, time, `decision_valid_until` | One final decision per exact version; challenge consumed atomically; cannot outlive validation |
| `enforcement_actions` | canonical bytes/digest, approval/snapshot refs, target, state/times | Exact-IP read-back and exact HIL reference required; repeated content digest never reuses action or authority identity |
| `revocation_operations` | action/target/original digest, actor/reason, artifact/capability/result digests, state | Deterministic `nft-revoke-v1`; never AI-generated or authorized by add approval |
| `inspection_authorizations` | system purpose, action/policy/original authorization, evidence/validation/artifact/live-schema/idempotency digests, scheduler, validity | Non-HIL and read-only; no administrator nonce/reason; cannot mutate or refresh TTL |
| `execution_capabilities` | canonical capability/signature/artifact bytes and digests, expiry, nonce, add/revoke/inspect operation, result attestation | Dispatcher-only creation; durable single-use/replay evidence; inspect is read-only |
| `audit_events` | sequence, actor, action, object/digests, time, trace ID | Append-only through application APIs |
| `ai_budget_ledger` | UTC date, model/rate-card version, limit, reserved/settled/consumed USD | Atomic worst-case reservation; no over-budget attempt |
| `outbox_jobs` | kind, aggregate/version/operation, attempts, lease token/owner/expiry, state, error evidence | Idempotency and business-effect keys unique; lease completion is token/expiry-fenced; terminal crash/dead-letter transition is atomic |
| `admin_sessions` | opaque token digest, CSRF digest, `authenticated_at`, created/last/expiry, revoked | No plaintext session token or password; rotation does not advance password-authentication time |

Recommended indexes include `gateway_events(source_ip, started_at)`, `gateway_events(service_label, started_at)`, `auth_events(source_ip, occurred_at, outcome, binding_state)`, `auth_events(source_ip, account_hash, occurred_at)`, `ingest_batches(sender_id, sender_epoch, sequence)`, `incidents(state, last_seen)`, `execution_capabilities(capability_id)`, and `outbox_jobs(state, available_at)`.

Retention is fixed for v0.1:

- Gateway/auth events, ingest-batch receipts, source-health intervals, signal evidence, and evidence snapshots: 7 days
- Incidents, AI analyses/budget ledgers, command candidates, policy proposals/validations/decisions, enforcement/revocation actions, capabilities, and signed result attestations: 30 days
- Audit events: 90 days
- Expired sessions, nonces, and transient queue data: delete as soon as their security/recovery window ends

Retention jobs preserve referentially necessary digests in audit rows but never copy deleted sensitive data into audit payloads. Deletion is idempotent, audited, and covered by backup/restore tests.

Migration 31 replaces the former global uniqueness constraints on generated/canonical candidate content, enforcement-action canonical content, and inspection-artifact content with non-unique lookup indexes. Its downgrade fails closed with SQLSTATE `55000` if recurring content prevents restoration of the obsolete uniqueness model. Migration 32 adds the API-only `read_policy_validation_attempt_000032(policy_id)` security-definer projection. `sentinelflow_api` can execute that function but cannot select the three raw attempt tables, and the function returns digests rather than `prepared_snapshot` or `terminal_mutation` JSON. A claim/result mismatch in terminal state, failure code, prepared digest, or completion time raises SQLSTATE `55000`; the management API exposes only its generic `503 service_unavailable` boundary.

## 11. GPT-5.6 analysis contract

The AI worker uses the Responses API with this fixed v0.1 request-policy excerpt:

```json
{
  "model": "gpt-5.6-sol",
  "reasoning": {"effort": "medium"},
  "store": false,
  "tools": [],
  "max_output_tokens": 2048,
  "text": {
    "format": {
      "type": "json_schema",
      "name": "sentinelflow_analysis_v1",
      "strict": true
    }
  }
}
```

The request builder must insert the parsed, immutable contents of [`contracts/ai/sentinelflow_analysis_v1.schema.json`](../contracts/ai/sentinelflow_analysis_v1.schema.json) as `text.format.schema`; an empty, generated-at-runtime, remotely fetched, or caller-supplied schema is forbidden. That file is the single source for generated Go/TypeScript output types and its digest is recorded with each analysis. It requires every property, rejects additional properties at every object level, fixes the classification/policy/command enums, constrains both `target_ip` fields with `format: ipv4`, constrains candidate `timeout` with `^[1-9][0-9]{0,4}[smh]$`, and bounds text, evidence arrays, `ttl_seconds`, and command fields. Application validation still canonicalizes IPv4 and TTL, verifies evidence-set equality at all three levels, parses the command grammar, and rejects semantic mismatch; schema conformance alone never authorizes a policy.

The exact input contract is the checked-in strict [`sentinelflow_analysis_input_v1.schema.json`](../contracts/ai/sentinelflow_analysis_input_v1.schema.json), and the only system instruction is the checked-in byte-exact [`sentinelflow_system_prompt_v1.txt`](../contracts/ai/sentinelflow_system_prompt_v1.txt). Startup verifies both pinned SHA-256 digests; runtime, caller, evidence, or remote text cannot replace or append instructions. The input schema requires schema/incident/attempt/version/time, prompt/output-schema version, source/service/window, detector configuration, `source_health_status=complete`, sorted `signals`, sorted `evidence_refs`, historical impact, and allowed-policy fields, and rejects unknown fields.

The compact input contains every relevant deterministic signal object and exactly one output-addressable `evidence_refs` item per signal. These are deterministic-signal references, not raw event references: each `evidence_id` is byte-equal to its `signal_id` and carries the same rule, signal/evidence digest, and complete expanded-event count. For validation and audit, the server resolves each reference one-to-one to that signal's complete retained event-ID set; the model receives the bounded reference, never a sampled raw-event subset. `signals` is unique and sorted by `signal_id`; `evidence_refs` is unique and sorted by `evidence_id`, both lexicographically by UTF-8 bytes. No signal, reference, or server-side expansion may be sampled, truncated, or silently reordered. The complete strict model input is limited to 50 references and 12 KiB after UTF-8 JSON serialization. The separate sorted-unique server-side event expansion in `evidence-snapshot-v1` is limited to 1,000,000 IDs so the 120-event burst remains representable without an unbounded snapshot. If any reference, byte, or expansion limit would be exceeded, no OpenAI call starts and the incident records typed `analysis_failed/input_too_large`; the worker never truncates to fit. Input never includes request/response bodies, queries, cookies, authorization, raw headers, raw usernames, account hashes, arbitrary log text, or raw event rows.

Output permits explanation, classification, confidence, uncertainty, false-positive factors, evidence IDs, one structured `block_ip` policy, and one `nft-blacklist-v1` candidate. Beyond JSON Schema validation, the application requires the top-level, policy, and candidate evidence arrays to be sorted, unique, and byte-identical to the complete input `evidence_refs`; an unsorted, duplicate, missing, extra, or differently encoded reference is `evidence_invalid`, never silently normalized. The policy and command must also reference the identical canonical IPv4 target.

Live AI also requires an operator-supplied, versioned rate card for input, cached-input, and output USD per one million tokens. Missing, zero/negative, unparseable, or unversioned rates disable live AI and store `analysis_failed` with `configuration_error`; they are never inferred from documentation or hard-coded as provider prices. The configurable demo ledger limit defaults to USD 10 per UTC day.

Before each attempt, one PostgreSQL transaction locks the UTC-day/model/rate-card ledger and reserves the worst case: 12,288 input token units priced at the greater of input and cached-input rates plus 2,048 output token units, rounded upward at the ledger's fixed micro-USD precision. A retry is a separate attempt and requires a separate reservation. A completed response settles only from provider usage: noncached input is `input_tokens - input_tokens_details.cached_tokens`, cached input is `input_tokens_details.cached_tokens`, and output is `output_tokens`; malformed or missing usage consumes the full reservation. Settlement releases any unused reservation. A timeout or transport outcome without trusted usage also consumes the full reservation conservatively. If the reservation would exceed the daily limit, no call starts and the incident stores `analysis_failed` with `budget_exhausted`. Concurrency two cannot overspend because reservation is atomic.

Each attempt has a 30 s timeout. An incident version permits at most two attempts total: its initial call and exactly one retry only for a network error or an OpenAI response status of `408`, `409`, `429`, or `5xx`, with bounded jitter. Validation errors, refusals, and manual API repetition cannot bypass this cap. Oversized complete input, refusal, incomplete response, timeout exhaustion, unknown field, schema error, missing reference, evidence mismatch, unsupported action, configuration error, or exhausted budget always uses the unified non-enforcing `analysis_failed` state with its enumerated reason and creates no valid policy. Model, reasoning effort, prompt/input-schema/output-schema/rate-card versions, token usage, reservation/settlement, and input/output digests are audited without content secrets. GPT is never called synchronously from Gateway code.

Migration 33 resolves a distinct pre-provider race. When a leased queued `analyze` job has no attempt claim, immutable `incident_version_history` proves its aggregate version existed, and the current incident has advanced, the security-definer prepare boundary completes the job, emits one digest-bound `analysis_superseded` audit event, creates no provider claim, and creates no dead letter. It never changes the current incident version, evidence version, or state. A job whose aggregate never existed still returns `no_call`, becomes unresolved `analysis_incident_missing` dead-letter evidence, and emits no supersession audit. Existing in-flight claims and intentional `analysis_superseded` dead letters are not rewritten. The activated-demo wrapper verifies and records its own exact analysis capability use even on the provider-free supersession path.

`cmd/openaismoke` is an explicit opt-in, one-attempt, non-mutating contract probe using the same checked artifacts and a fixed synthetic RFC 5737 path-scan input. It requires `SENTINELFLOW_OPENAI_LIVE_SMOKE=1` and `OPENAI_API_KEY`, has no database, HIL, dispatcher, or executor path, and emits only safe status/provenance digests. Disabled and missing-key behavior has local fail-closed evidence. One billable live attempt has returned `status=ok` from `openai_responses` using `gpt-5.6-sol`, with one evidence reference and schema-valid generated/canonical command digests; it did not mutate the control plane.

## 12. Policy validation, HIL, and nftables

### 12.1 Artifact and canonical form

Under `ADR-010` as hardened by `ADR-012`, v0.1 permits exactly one IPv4 add-element operation in the owned set. The RFC 5737 address below is a syntax illustration and is executable only in the isolated demo/test exception described in Section 12.2:

```text
add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }
```

Canonical bytes are UTF-8 without BOM, contain no leading/trailing spaces, comments, tabs, or extra statements, and end in exactly one LF byte. SHA-256 over the exact canonical byte sequence is encoded as lowercase hexadecimal with the `sha256:` prefix. Structured policy uses required integer `ttl_seconds` in `60..86400`, with default `1800`. Candidate grammar accepts exactly one lowercase TTL token matching `[1-9][0-9]{0,4}[smh]`; checked arithmetic must remain in range and parsed seconds must equal policy `ttl_seconds`. Canonical serialization uses the largest exact unit: hours when divisible by 3600, otherwise minutes when divisible by 60, otherwise integer seconds. Thus the minimum/default/maximum canonical values are `1m`, `30m`, and `24h`. Golden vector `ttl-canonical-v1` freezes accepted/rejected tokens and canonical output. IPv6 and every other family/table/set/action are rejected.

The checked policy, [`evidence-snapshot-v1`](../contracts/enforcement/evidence_snapshot_v1.schema.json), [`validation-snapshot-v1`](../contracts/enforcement/validation_snapshot_v1.schema.json), [`enforcement-authorization-v1`](../contracts/enforcement/enforcement_authorization_v1.schema.json), capability, and [`hil-reason-v1`](../contracts/enforcement/hil_reason_v1.schema.json) objects use RFC 8785 JCS after every human-authored string has been normalized to Unicode NFC. Their digest form is exactly `sha256:` plus 64 lowercase hexadecimal characters over those canonical bytes; `reason_digest` covers the exact NFC UTF-8 reason. Producers canonicalize before signing, and validators reserialize and require byte equality rather than silently changing a signed object. Evidence-reference arrays in the AI input, all three AI output levels, policy, candidate, and evidence snapshot are unique, lexicographically sorted by UTF-8 bytes, and byte-identical where the contract repeats them. Validation, challenge, decision, authorization, and capability objects carry the exact `evidence_snapshot_digest` rather than copying the array; each stage must preserve that digest byte-for-byte. Duplicate, unsorted, re-encoded, missing, extra, or digest-substituted evidence fails closed without silent repair. The checked contract-vector bundle freezes NFC/JCS/digest behavior.

### 12.2 Ordered hard-gate validation

1. Validate strict Structured Output, required policy/command fields, canonical IPv4, TTL bounds, and immutable evidence-snapshot membership.
2. Parse with `nft-blacklist-v1`; reject unsupported tokens, extra statements, alternate table/set, multiple addresses, missing timeout, shell syntax, includes, variables, redirection, pipelines, substitution, comments, NUL, or hidden trailing input.
3. Build a typed AST, require exactly one allowlisted operation, require policy/command target and evidence-set equality, serialize canonical bytes, and calculate generated/canonical digests.
4. Prove that every evidence ID exists in the immutable analysis input, resolves to the same source, reproduces at least one deterministic rule threshold, and does not overlap a degraded source-health interval. Missing or insufficient evidence fails closed.
5. Require canonical global-unicast IPv4. The authoritative strict [`protected_ipv4_v1.json`](../contracts/enforcement/protected_ipv4_v1.json), validated by its adjacent schema, contains immutable built-in CIDRs/ranges, reasons, and demo-exception flags; its pinned static JCS digest is `sha256:d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104`. A separate effective object validated by [`protected_ipv4_effective_config_v1.schema.json`](../contracts/enforcement/protected_ipv4_effective_config_v1.schema.json) binds that static digest, unique sorted operator additions, the selected demo exception, and current management/origin/Gateway/executor/administrator-path addresses before its JCS digest is calculated. Validation, challenge/decision, authorization, and the capability's validation digest bind both static and effective digests. Reject unspecified, loopback, private, link-local, CGNAT, benchmarking, documentation, multicast/reserved, and every effective protected address; do not rely on `IsGlobalUnicast` alone. Configuration can add protection but cannot remove a built-in entry. An isolated demo/test profile may select only entries flagged for the RFC 5737 exception after namespace and host-difference proof; production never enables it.
6. The executor is the sole privileged bootstrap provisioner. Before Gateway readiness, explicit bootstrap mode inventories the full stateless namespace ruleset, verifies byte-exact [`nft_base_chain_v1.nft`](../contracts/enforcement/nft_base_chain_v1.nft) with raw-file digest `sha256:2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488`, then creates the owned table/set/chain/rule only when the owned table is absent. The raw digest is never used as the live-schema digest. Signed read-back is projected from only `inet sentinelflow` into checked [`nft_base_chain_v1.live.json`](../contracts/enforcement/nft_base_chain_v1.live.json) under [`nft_base_chain_live_v1.schema.json`](../contracts/enforcement/nft_base_chain_live_v1.schema.json), excluding handles/counters; its pinned JCS digest is `sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997`. Both digests are required. The full before/after inventory must show every foreign table unchanged. On restart, an exact existing owned schema is verified without loading the base file or refreshing any element TTL; partial, extra, duplicated, or drifted owned state fails closed and is not repaired. Normal add/revoke/inspect requests cannot create or alter tables, sets, chains, or base rules. Before check/application, use signed inspect to verify the live digest, then run fixed-binary `nft --check -f -` with canonical artifact bytes on stdin. The host namespace ruleset digest captured before profile startup must remain byte-for-byte invariant at validation and teardown.
7. Evaluate the preceding 24 hours of retained Gateway and auth evidence for the target. Any `verified`, pending, or untrusted `succeeded` auth event for the target blocks validation; only a verified failed event may support attack evidence. Missing history, pending binding, retention gaps, source degradation, or unavailable impact input also fails closed. In the asserted demo/test profile only, the signed strict [`demo-history-v1` manifest](../contracts/enforcement/demo_history_manifest_v1.schema.json) may bind synthetic complete coverage to the concrete [`demo_history_dataset_v1.json`](../contracts/fixtures/demo_history_dataset_v1.json) locator and schema. Its exact fields are `schema_version`, `manifest_id`, `profile`, `clock_at`, `dataset_id`, `dataset_schema_version`, `dataset_digest`, `dataset_record_count`, `import_id`, `coverage_start`, `coverage_end`, `path_catalog_version`, `source_health_digest`, and `issued_at`; the pinned dataset JCS digest is `sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00`. Import commits persist a digest of the exact canonical imported rows and bind it transactionally to `import_id`, dataset ID/digest, and the fixed locator, so an arbitrary database seed never counts as complete history. Application fake time defines fixture event/coverage time only; security freshness and kernel expiry use bounded real time. The checked [`demo_history_manifest_v1.json`](../contracts/fixtures/demo_history_manifest_v1.json) is fixture-only; actual demo runs create a run-scoped signing key and manifest. Production rejects this fixture contract.

   Under `ADR-013`, that proof becomes usable only through a staged authority lifecycle. Demo preparation creates distinct nonzero 32-byte analysis and validation capabilities. Migration receives only their `sha256:` digests, pins them once, and opens `sentinelflow_demo_importer` with an exact SCRAM credential and server-side `VALID UNTIL` no later than five minutes. The importer verifies the fixed public bundle, imports once or attaches only its exact completed state, then executes two committed fence statements: first `NOLOGIN`/password-null/epoch-expired, then termination and zero-peer-session verification. A narrow handoff checks the inert importer and briefly opens only `sentinelflow_demo_activator`, which re-verifies the proof and atomically creates exactly one analysis and one validation activation with identical claims and an expiry exactly one hour after `clock_timestamp()` activation. It then fences both roles with the same two-phase ordering.

   Analysis and validation services each mount only their own capability. Their prepare path may attach only the exact, existing, unexpired consumer activation and records append-only use for the job and aggregate version; it cannot import, create, refresh, swap, or repair an activation. Missing, wrong, stale, expired, partially created, or drifted state returns a typed non-enforcing result. No in-place renewal exists. Once activation expires, recovery requires stopping the profile, deleting the complete disposable demo environment and volumes, generating a new signed run and distinct capabilities, and replaying migration/import/activation from a fresh isolated PostgreSQL cluster.
8. Create the checked immutable validation snapshot over policy, incident/evidence snapshot, analysis input/version, generated candidate, canonical bytes, grammar/parser/validator versions, protected-IPv4 static and effective digests, raw base-file and deterministic live-schema digests, nft binary/version, impact dataset/import locator/IDs/digests/results, and `valid_until`.
9. Set validation `valid_until` to 5 minutes after snapshot creation. Show evidence, generated/canonical diff, target, TTL, impact, checks, digests, and remaining validity to the administrator.
10. Accept HIL approval/rejection only for the exact artifact. Approval validity is at most 5 minutes and `decision_valid_until` is the earlier of approval time + 5 minutes and validation `valid_until`.
11. Immediately before the only permitted initial execution, the dispatcher rechecks all versions/digests, HIL actor/reason, both validity timestamps, protected configuration, owned-set schema, nft version policy, evidence-health status, and full requested relative TTL, then mints the capability in Section 5.3. An artifact with a relative timeout is never reapplied, including after crash or recovery.
12. The executor verifies capability syntax/signature/digests, performs journal lookup before freshness, and recomputes SHA-256. A known exact capability returns terminal/signed-inspect resolution. Only an unseen capability checks expiry/single use and target absence, durably commits the exact `started` record, invokes fixed `nft -f -` once without a shell with canonical bytes on stdin, obtains a signed inspect result for exact target membership and remaining kernel timeout, and durably commits `terminal`. Under `ADR-014`, new terminal output is `execution-result-v2` and includes the signed read-back interval; v1 remains historical-only. A byte-identical duplicate never invokes nft or refreshes the kernel timeout; conflicting replay fails.

The executor rejects GPT prose, the generated raw candidate, a shell command line, arbitrary nft input, stale approval, a different byte sequence, or any non-capability request. Digest/schema/read-back mismatch is failure, never success. Under `ADR-014`, reconciliation interprets a v2 active read-back against its signed `expiry_lower`/`expiry_upper` interval: absence completed strictly before lower is `missing_early`; absence beginning at or after upper is `expired`; active beginning at or after upper is `late_active`; and a boundary-overlapping, missing, invalid, unavailable, or mismatched observation is `indeterminate`. Only valid active observation before upper preserves active state. `missing_early`, `late_active`, and indeterminate paths fail closed, alert/audit, and never re-add. Reapplication requires a newly generated candidate, new validation snapshot, new HIL decision, and new capability. Reconciliation may only observe valid active state or remove expired/unapproved residue; it cannot extend TTL, synthesize approval, or restore missing state.

Read-only inspection is not a HIL decision. The system scheduler may create [`inspection-authorization-v1`](../contracts/enforcement/inspection_authorization_v1.schema.json) only for `reconciliation`, `expiry_confirmation`, or `operator_status`, bound to the original add authorization/artifact, action/policy/version, evidence/validation/live-schema digests, fixed inspect artifact, idempotency key, and short validity. Dispatcher then mints a signed inspect capability. This authority carries no administrator decision nonce or administrator reason and cannot add, revoke, refresh TTL, alter schema, or substitute a mutation artifact.

### 12.3 Deterministic revocation

Revocation uses a separate typed `nft-revoke-v1` operation, never model output and never the original add approval. An authenticated administrator submits the active enforcement action ID, target, original canonical add digest, actor, and non-empty reason through the revocation endpoint. In one transaction the API validates active state, CSRF/session/re-auth/nonce/idempotency, records authorization/audit, and creates a deterministic canonical delete artifact:

```text
delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }
```

The dispatcher reads only this authorized revoke job and signs a distinct operation capability bound to action/target/original add digest/revocation artifact digest/actor/reason. The executor permits only the fixed delete grammar, invokes fixed `nft -f -` shell-free, and verifies absence through a separate signed inspect capability/result lifecycle. Already absent returns the original idempotent revoked result and never authorizes an add. Conflicting target/digest reuse fails and audits. Successful, failed, and indeterminate revocations use the same durable replay journal and signed result-attestation rules as add execution.

### 12.4 Administrator authentication and decision integrity

v0.1 supports one administrator. `ADMIN_PASSWORD_ARGON2ID_HASH` supplies only an Argon2id PHC hash and is never stored in source or logged. Startup rejects parameters below 64 MiB memory, time cost 3, parallelism 2, 16-byte salt, or 32-byte derived key. Before Argon2 work, an in-memory limiter allows at most 5 login attempts per minute per canonical direct source and 20 per minute process-wide. Rate-limited responses include `Retry-After`; all invalid user/password cases use the same generic failure and no persistent account lockout exists. The server uses a random opaque server-side session with an 8-hour absolute and 30-minute idle limit. Persisted session timestamps are canonical UTC at PostgreSQL microsecond precision before issuance so insert/read-back and optimistic CAS compare the same record. It rotates the session at login and after a privileged action. The cookie is `HttpOnly`, `SameSite=Strict`, `Path=/`, has no `Domain`, and is `Secure` whenever TLS is active.

Every state-changing browser request requires an origin-checked synchronizer CSRF token in `X-CSRF-Token`. Approval, rejection, and revocation share a limit of 5 attempts per minute per session, separate from login limits. Before a decision, the authenticated client requests an exact-artifact challenge containing the intended decision, expected policy/action version, and policy/evidence/generated/canonical/validation digests. The validation digest transitively binds protected-IPv4 static/effective configuration and raw/live owned-schema digests; the submitted NFC reason is separately digested into the consumed decision. The stored challenge conforms to [`hil_challenge_v1.schema.json`](../contracts/enforcement/hil_challenge_v1.schema.json), the consumed decision to [`hil_decision_v1.schema.json`](../contracts/enforcement/hil_decision_v1.schema.json), and its structured reason to [`hil_reason_v1.schema.json`](../contracts/enforcement/hil_reason_v1.schema.json). If `admin_sessions.authenticated_at` is older than 15 minutes, challenge issuance returns typed `step_up_required`; only then does a password step-up verify Argon2id, update `authenticated_at`, rotate the session, and issue the challenge. A fresh session never re-sends the password merely to obtain a challenge, and rotation alone does not advance `authenticated_at`.

The challenge stores a CSPRNG opaque nonce digest bound to session, actor, object/version, intended decision, every exact artifact digest, issuance time, five-minute expiry, and consumed state; the raw nonce is returned exactly once. The decision or revocation request supplies that nonce, `Idempotency-Key`, the same exact fields, and non-empty reason. One transaction verifies freshness and byte identity, consumes the nonce, records authorization/audit, and creates the approved job; stale, mutated, expired, missing, or replayed challenges fail without approval. Used idempotency keys return the original result only for an identical request and reject a conflicting replay. Optimistic concurrency allows one final HIL decision per artifact version and one revocation authorization per active action version.

### 12.5 Audit failure semantics

A required pre-application or pre-revocation audit/outbox write and approved-job creation are one transaction. Failure means no capability and no execution. If nft mutation succeeds but result-attestation persistence fails, state becomes `indeterminate`, later transitions stop, an alert fires, and the durable executor replay journal plus a newly authorized signed inspect lifecycle resolves it without reapplying an add. The system never records success merely because process output looked successful.

## 13. REST, internal API, and SSE contracts

External base path is `/api/v1`; internal service path is `/internal/v1`. JSON uses UTC RFC 3339 timestamps, opaque IDs, cursor pagination, and `{code,message,trace_id,details}` errors without raw evidence or internals.

| Method / path | Purpose | Core contract |
| --- | --- | --- |
| `POST /api/v1/session/login` | Single-admin login | Password over TLS/local demo boundary; session + CSRF token; rate-limited |
| `POST /api/v1/session/logout` | Revoke session | Session, Origin, and CSRF required |
| `GET /api/v1/incidents` | Filtered paginated list | state, kind, source, service, time filters |
| `GET /api/v1/incidents/{id}` | Facts, signals, analysis, policy summary | Observed/deterministic/AI/human/action sections remain separate |
| `GET /api/v1/incidents/{id}/events` | Minimized evidence | Typed allowlisted fields only; no raw request data |
| `POST /api/v1/incidents/{id}/analyses` | Request/retry analysis | Idempotency key and expected incident version |
| `GET /api/v1/policies/{id}` | Exact policy/command/validation view | Evidence and all generated/canonical/config/validation digests and validity, plus a minimized `latest_validation_attempt` for valid, invalid, or interrupted terminal evidence |
| `POST /api/v1/policies/{id}/validations` | Validate exact artifact | Expected policy/evidence/generated/canonical digests |
| `POST /api/v1/policies/{id}/decision-challenges` | Issue exact-artifact HIL challenge | Session + Origin + CSRF; password step-up only on typed stale-`authenticated_at` response; exact version/digests/decision; no reason or `reason_digest` yet |
| `POST /api/v1/policies/{id}/decisions` | HIL approve or reject | Session + Origin + CSRF + idempotency + single-use challenge nonce + byte-identical exact digests/decision/reason |
| `GET /api/v1/enforcement-actions/{id}` | Apply/expiry/read-back status | Target, state, times, safe error code |
| `POST /api/v1/enforcement-actions/{id}/revocation-challenges` | Issue exact-action revocation challenge | Session + Origin + CSRF; conditional password step-up; exact action/version/target/original digest; no reason or `reason_digest` yet |
| `POST /api/v1/enforcement-actions/{id}/revocations` | Deterministic active-rule removal | Session + Origin + CSRF + single-use challenge nonce + idempotency + byte-identical action/target/original digest + reason |
| `GET /api/v1/audit-events` | Audit query | Actor/object/trace/time filters; minimized payload |
| `POST /internal/v1/gateway-events` | Persist Gateway/source-health batch | Exact HMAC `event-batch-v1`, sender/epoch/sequence/idempotency, atomic 1–100 records/256 KiB |
| `POST /internal/v1/auth-events` | Persist application auth outcomes | Exact HMAC `event-batch-v1`, sender/epoch/replay guard, atomic 1–100 `auth-event-v1` records/256 KiB |
| `GET /health/live`, `/health/ready` | Per-unit health | Gateway readiness covers configuration/origin; control readiness covers DB/workers |

Use `409` for stale version, digest/challenge mismatch, conflicting idempotency key/batch digest, mutation, consumed challenge, or duplicate final decision; `422` for typed contract/schema/grammar/safety/internal-batch failure and expired/malformed challenge; `401/403` for authentication/authorization/CSRF failure; and `429` plus `Retry-After` for rate limiting. `step_up_required` is a typed authentication response only when `authenticated_at` is stale. Internal batches return `202` only for atomic accepted or exact-duplicate results; they never return partial accepted/duplicate/rejected counts.

`latest_validation_attempt` contains only `validation_attempt_id`, the exact policy/analysis/incident/version binding, terminal `state`, optional `failure_code` and `failed_gate`, prepared/terminal mutation digests, `completed_at`, and the ordered gate name/state/result/digest list. Go validates those bindings against the requested policy, the legal terminal policy/decision/lifecycle combination, and the canonical gate prefix; a failed terminal gate must be last and must match the attempt failure. The TypeScript decoder repeats the exact binding and gate checks. A valid HIL path still requires the separate immutable `latest_validation` snapshot. Invalid or interrupted attempt evidence is read-only UI evidence and must disable HIL; it cannot synthesize or repair a validation snapshot.

Incident detail captures `evidence_version` with the base incident row and queries `latest_analysis` by that exact observed version, ordering only attempts within that version. It never substitutes the numerically latest analysis from another version. Subsequent reads use the captured evidence-version argument, so a concurrent incident advance between statements cannot mix a newer analysis into the older observed projection; no analysis row for the captured version means `latest_analysis` is omitted. Provider provenance is exact: live rows use `openai_responses`, while deterministic stub rows cannot claim a model, reasoning effort, or rate-card version.

Frontend API errors are decoded by a handwritten exact-field decoder and never by runtime schema compilation or `eval`-family code. The administrator Web deployment emits exactly one CSP header: `default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. The checked deployment parser rejects duplicate, multiline, missing, weakened, or unpinned directives. Production verification scans every emitted JavaScript chunk for `eval`, `Function`-constructor, string-form timer, and WebAssembly dynamic-code-generation markers, then loads the built application in Chromium under that exact header. `'unsafe-eval'` is forbidden.

`GET /api/v1/events/stream` returns `text/event-stream` with `id`, `event`, `data`, and heartbeat comments. Clients reconnect with `Last-Event-ID` and reload a REST snapshot after a replay gap. Event types are `incident.created|updated`, `analysis.completed|failed`, `policy.validation_updated`, `approval.recorded`, `enforcement.updated`, and `source.degraded|recovered`. Payloads contain only event/resource IDs, time, version, trace ID, and a minimal summary. SSE is never a command channel.

## 14. Failure model, security, and observability

| Condition | Required behavior |
| --- | --- |
| Malformed HTTP, ambiguous framing, unknown Host, or configured limit | Reject with static server policy; do not create adaptive policy |
| Origin connection failure/timeout | Return `502`/`504`; emit minimized event if queue accepts it |
| Event queue saturation or control-plane outage | Continue forwarding, open degraded interval, increment drop/degradation metrics, create no block from affected windows |
| Gateway process crash | Origin remains private; orchestrator restarts Gateway; health fails until ready; no direct-origin fallback |
| Database outage | Internal ingestion fails/buffers only within bound; Gateway forwarding continues; no new enforcement |
| Unclean Gateway restart or permanent batch gap | Record an `unclean_restart` unknown-range loss or an exact lost range permanently; later traffic proceeds without backpressure; overlapping evidence can never authorize a block |
| Event timestamp beyond future 60 s/past 5 min | Persist as untrusted `timestamp_skew`; exclude from detection/analysis/validation/enforcement; do not drop or shift |
| Worker restart or duplicate job | Recover lease and rerun idempotently |
| AI input exceeds 50 evidence refs/12 KiB or prompt/input schema digest differs | Make no call; typed `analysis_failed/input_too_large` or `configuration_error`; never truncate or accept runtime instructions |
| OpenAI missing rates/budget/timeout/rate limit/refusal/incomplete/output-schema error | Reserve atomically; one separately charged retry where allowed; then unified `analysis_failed`; no policy reaches validation |
| Auth binding pending/mismatched/expired or successful-auth history | Attack evidence excludes it; any unverified success conservatively invalidates impact; approval/execution disabled |
| Command grammar, consistency, protected range, nft check, impact, digest, or mutation failure | Candidate invalid/stale; exact reason audited; no approval/execution |
| Validation attempt invalid or interrupted | Return only the bound minimized `latest_validation_attempt`; render terminal gate evidence; keep HIL disabled and create no validation snapshot or authority |
| Validation-attempt claim/result projection mismatch | Fail closed with SQLSTATE `55000`; return generic management API `503` without raw table or JSON detail |
| HIL challenge stale, mutated, expired, consumed, or replayed | Reject and audit; do not create a decision, approved job, capability, or execution |
| Validator or executor unavailable | Approval disabled or queued work remains non-executed until still-valid recheck |
| UDS framing/schema/signature/deadline violation or unsigned inspect result | Close exchange, classify failure/indeterminate as applicable, and perform no mutation or success transition |
| Journal checksum/sequence/version/torn-tail or fsync uncertainty | Executor readiness fails closed; require explicit recovery; never truncate-and-continue or mutate |
| Bootstrap raw-file or live-schema digest mismatch | Gateway profile remains unready; normal capability cannot repair schema; host namespace remains unchanged |
| Pre-application audit/outbox failure | Do not enqueue or execute |
| Post-application persistence failure | `indeterminate`; stop transitions, alert, read back, recover durably |
| Duplicate add capability/artifact | Return the original journaled result without invoking nft or refreshing timeout |
| Active rule missing before expected expiry | Mark `failed`, alert, and never auto-readd; a new candidate/validation/HIL is required |
| Crash after nft application | Replay journal and signed inspect resolve state without reapplying the relative-timeout add |
| Revocation request or replay | Separate `nft-revoke-v1` authorization/capability; exact duplicate returns original removal result; add approval is never reused |
| SSE disconnect | Reconnect with `Last-Event-ID`, then reload REST snapshot |

Security controls include origin-form HTTP/1.1 parsing, explicit framing/hop/target tests, strict private-origin resolution, direct-peer-only identity, regenerated forwarding headers, request/path bounds, typed path classification, service HMAC/replay protection, atomic batches and loss intervals, minimized storage, prompt-injection isolation, strict Structured Outputs, atomic AI budget reservation, nft grammar fuzzing, exact-digest HIL, CSRF/origin/session/login limits, Ed25519 single-use capabilities, private UDS, durable replay journal, fixed-binary shell-free execution, read-only filesystems, least-privilege DB roles, and minimal executor capability. Gateway and control-plane containers have no `NET_ADMIN`; only the executor sidecar has it, and only inside the shared Gateway demo namespace.

Required Gateway metrics include request count/status/latency, proxy errors, active connections, target/protocol/body/host/timeout rejections, queue depth, enqueue outcomes, dropped events, batch latency/errors/retries, epoch/sequence gaps, and source degraded duration. Control-plane metrics include auth binding state, event lag, signal/incident counts, AI reservation/settlement/budget/latency/error/tokens, validation failure reason, approval latency, dispatcher/capability/replay outcomes, active/expired/revoked/early-missing rules, outbox lag, audit recovery, and SSE clients.

JSON logs contain time, component, outcome, duration, safe resource IDs, and trace ID. They must not include an exact/raw/decoded path, raw URL, query, body, cookie, authorization, arbitrary headers, account hash, service HMAC, generated session/CSRF token, AI secret, or canonical command bytes. OpenTelemetry may connect request ID to an incident through safe IDs; it follows the same attribute denylist.

## 15. Deployment, isolation, and performance

The implemented Docker Compose topology contains PostgreSQL; migration plus capability-digest pinning; a one-shot history importer, authority handoff, and demo activator; API; private demo origin; Gateway plus its namespace-sharing executor; networkless validator plus validation worker; detector; retention, lifecycle, and control-metrics workers; Prometheus; dispatcher; frontend; and profile-selected simulator and exactly one stub or live analysis worker. The executor's sole normalized Compose dependency object targets `gateway` with `condition: service_started`, `required: true`, and `restart: true`. This fixes startup/restart ordering only; it is neither a health assertion nor a privilege grant. `cmd/ingestor` is absent from the default v0.1 profile and may be added later as an optional adapter profile.

```text
edge network:          RFC5737 client (203.0.113.20) ──> gateway protected port
shared Gateway netns:  gateway (zero caps) + executor sidecar (NET_ADMIN only here)
origin network:        gateway ──HTTP──> demo-app 172.30.0.10:8081 (no published port)
ingest network:        gateway + demo-app auth producer ──> API 172.31.0.10:8082
control network:       PostgreSQL/API/workers/dispatcher (distinct DB roles; no Gateway)
management network:    browser ──> host 127.0.0.1 publishes web :4173 and API :8083
AI-egress network:     live worker only; the stub worker remains control-only
observability network: Gateway metrics + control exporter ──> private Prometheus
private runtime volume: dispatcher ──UDS──> executor (only these two mounts)
```

Only the Gateway publishes protected TCP port `8080`, and protected application clients connect to it directly. The isolated demo client has source `203.0.113.20` on the edge network and can reach the shared Gateway namespace's protected port directly, so a set membership drop affects the demonstrated request path. Gateway and executor share only that network namespace: Gateway has zero Linux capabilities; executor alone has `NET_ADMIN` in it. The executor's explicit bootstrap mode is the sole privileged provisioner of the pinned table/set/`gateway_input` rule before Gateway readiness; normal capability handling only verifies and uses the owned schema. Profile start and teardown compare canonical host-namespace nft JSON digests and fail the run if the host ruleset changes.

The Gateway may terminate TLS itself when a configured certificate/key pair is present. No Nginx, load balancer, CDN, or other trusted identity hop sits in front of this v0.1 protected path. The separate `web` service serves the administrator frontend and proxies management API/SSE traffic on the management network, but is never a source of protected-traffic identity. The service labeled `demo-app` joins exactly the origin and ingest networks: its HTTP application listener binds only `172.30.0.10:8081`, and its auth-event producer connects only to API `172.31.0.10:8082`. It declares no host port. The API internal ingestion listener binds only `172.31.0.10:8082`; the separate management listener binds `172.34.0.10:8083`, while Compose publishes it only on host `127.0.0.1`. Gateway joins edge, origin, ingest, and the private observability network; it cannot reach PostgreSQL, worker, management, AI egress, or dispatcher UDS. Prometheus is unpublished on observability, and the validator has `network_mode: none` with only its validator UDS shared to the validation worker.

Database access uses distinct migration-owner, API read/write, worker job, read/report, dispatcher, demo-importer, and demo-activator roles with service-scoped credentials and grants. The two demo roles are PostgreSQL cluster-global, normally inert, and may authenticate only during their separate server-bounded five-minute bootstrap stages; exact `NOLOGIN`/password-null/epoch-expired state and zero other sessions are required afterward. One isolated demo profile per PostgreSQL cluster is the supported boundary. The dispatcher role can select only a restricted approved-outbox view and update its dispatch/result state through narrow stored operations; it cannot read general incidents, evidence, sessions, or arbitrary jobs. Gateway and executor have no database credential. Gateway receives only its internal event credential. Worker receives the OpenAI key and AI rate card but no dispatch signing key or `NET_ADMIN`; analysis and validation workers receive different demo-history activation volumes, and neither receives importer/activator credentials. Dispatcher receives only its restricted DB role, Ed25519 private dispatch key, executor-result public key, and UDS mount. Executor receives only the dispatch public verify key, separate executor-result private signing key, replay-journal volume, UDS mount, and namespace-local nft capability; neither dispatcher nor executor receives OpenAI/admin/general DB secrets. Ed25519 private files are single-link, owner-only `0400`/`0600`, single PKCS#8 PEM blocks with no auxiliary headers; public files are single-link, non-group/world-writable, single PKIX PEM blocks with no auxiliary headers. Both reject non-owner files, symlinks, extra blocks/data, wrong algorithms, and public/private role confusion.

The minimum reference environment is Linux, Docker 24+, Compose v2, nftables, and 4 GB RAM. Development uses a stub AI and dry-run executor. The asserted demo/test profile may inject an application fake clock only for fixture event generation, deterministic detector windows, and history coverage. HIL/step-up/validation/capability freshness, UDS deadlines, executor journal time, and nftables kernel expiry use real UTC plus monotonic time with bounded test tolerance; the fake clock can never extend or rewind them. The profile alone enables the signed concrete 24-hour dataset/import fixture and RFC 5737 exception after namespace/schema/host-invariance checks. Production rejects fake-clock, fixture, documentation-range, and host-enforcement switches. No host-enforcement profile is provided in v0.1. Secret files contain names/placeholders only and real values remain outside Git.

`NFR-012` acceptance is p95 added Gateway latency of at most 5 ms at 500 requests/second in the 4 GB reference environment, measured against the same direct origin after warm-up. The run must sustain five minutes with valid response parity, zero Gateway-induced 5xx, and zero event drops while the EventSink/control plane is healthy. A separate outage run proves forwarding continues when EventSink delivery fails; drops and degradation must be visible and no new block may be created.

## 16. Test strategy and identifiers

- `UT-001` optional source parser; `UT-002` event normalization; `UT-003` threshold boundaries; `UT-004` correlation windows
- `UT-005` exact checked input schema/prompt, complete sorted signal/evidence refs, no truncation, typed `input_too_large`; `UT-006` strict AI output plus sorted/unique/byte-identical evidence arrays; `UT-007` policy/command parser; `UT-008` protected network/historical impact plus signed-proof claims, distinct consumer capabilities, exact activation attach/use, expiry, and no refresh
- `UT-009` state transitions/idempotency; `UT-010` expiry calculation; `UT-011` outbox/lease/retry
- `UT-012` administrator session/CSRF/replay, `authenticated_at`, conditional password step-up, exact challenge, pre-Argon2 login/HIL limiters, generic failure/`Retry-After`; `UT-013` strict UDS frames/envelopes, add/revoke/inspect capabilities, exact two-phase journal/fsync, torn-tail failure, once-only mutation, and v2 read-back-interval/signing-domain validation; `UT-014` retention/masking/audit and signed-result integrity
- `UT-015` resource/performance limits; `UT-016` nft grammar/AST/canonicalization, NFC/JCS/lower-hex digests, protected-IPv4 contract, raw-file/live-schema digest separation
- `UT-017` direct-peer identity, IPv4 mapping, inbound request/trace-ID removal, origin ID/header sanitation and regeneration
- `UT-018` route/path-catalog classification and persistence/telemetry exact-path minimization denylist
- `UT-019` Host/private-origin resolution and 32 KiB/10 MiB/4 KiB/2 KiB/5 s/30 s/60 s Gateway bounds
- `CT-001` normalized event schema; `CT-002` AI I/O; `CT-003` REST/error including the CSP-safe exact error decoder, minimized `latest_validation_attempt`, exact policy/analysis/incident/version binding, current-observed-evidence `latest_analysis`, and generic projection-failure `503`; `CT-004` SSE reconnection
- `CT-005` generated client/mock parity; `CT-006` authorization/error mapping; `CT-007` strict 4-byte-BE/16-KiB/2-s UDS, add/revoke HIL versus non-HIL inspection authority, unpadded-base64url capability/artifact/result schemas and Ed25519 signatures; `CT-008` AI policy/command/canonical/HIL artifact, JCS evidence equality, and budget ledger
- `CT-009` `event-batch-v1`, `gateway-http-v1`, path enums, both-producer source-health, 1..100-record/256-KiB bounds, lowercase sender header/body/endpoint binding, exact HMAC, atomic `202` ACK, retry/dedup/`409` conflict/`422` invalid, sequence gap, checkpoint, timestamp skew, and unknown-field rejection
- `CT-010` authenticated `auth-event-v1` plus application source-health/checkpoint, endpoint/header/body sender/epoch binding, exact HMAC/replay, pending/verified/untrusted binding, account-hash, outcome, retry/dedup/conflict, and sequence contract
- `IT-001` optional TCP log ingestion; `IT-002` optional UDP log ingestion; `IT-003` event→DB; `IT-004` detect→correlate; `IT-005` AI stub
- `IT-006` validation chain including protected contract, raw/live schema digests, auth race, concrete signed 24h dataset/import fixture, five-minute importer/activator leases, two-phase role/session fencing, atomic one-hour consumer pair, API-only terminal-attempt projection, raw-table/JSON denial, claim/result mismatch fail-closed behavior, exact ACLs, and PostgreSQL cluster/multi-database guards; `IT-007` approval→dispatcher→isolated nft plus signed inspect lifecycle, deterministic revocation, fresh authority identities when command content digests recur, and persistence of exact v2 signed result bytes/digest; `IT-008` real-kernel expiry/audit/once-only reconciliation independent of application fake time, including signed lower/upper-bound classification of legitimate active, true early-missing, true expiry, late-active, and boundary-overlapping indeterminate observations
- `IT-009` outbox crash/restart plus queued stale-analysis provider-free supersession, true-missing dead letter, and unchanged current incident; `IT-010` authentication/exact-challenge issue/consume/step-up concurrency; `IT-011` executor journal crash/torn-tail/fsync recovery and signed inspect reconciliation; `IT-012` retention/backup/restore
- `IT-013` AI candidate→validation→HIL→Ed25519 dispatcher→shell-free executor, result attestation, and budget reservation
- `IT-014` origin-form HTTP/1.1 Gateway→fixed RFC1918 origin response parity plus asynchronous classified minimized event persistence
- `IT-015` EventSink/API/PostgreSQL outage/restart forwards traffic, records permanent/unknown loss and atomic ACK state, and suppresses new enforcement
- `E2E-001` credential stuffing; `E2E-002` path scanning; `E2E-003` request burst; `E2E-004` normal traffic/false positives
- `E2E-005` investigation; `E2E-006` approval/rejection; `E2E-007` lifecycle/SSE; `E2E-008` UI state matrix including bound invalid/interrupted validation evidence and disabled HIL; `E2E-009` accessibility/cross-browser plus exact deployment-CSP Chromium execution and all-chunk dynamic-code-generation scan
- `E2E-010` evidence-bound command and exact-artifact HIL/revocation; `E2E-011` fresh disposable profile→signed history import→atomic one-hour analysis/validation activation→isolated RFC5737 client→Gateway attack→incident→HIL→dispatcher→temporary namespace nft→TTL expiry without host change, with expired activation requiring full reset
- `E2E-012` public origin bypass attempt fails while Gateway path remains functional
- `SEC-001` malicious evidence; `SEC-002` prompt injection; `SEC-003` approval replay/concurrency; `SEC-004` secret/redaction
- `SEC-005` protected CIDR; `SEC-006` least privilege/no arbitrary command plus API denial of raw validation-attempt tables/JSON; `SEC-007` unsafe evidence/XSS; `SEC-008` unauthorized decision UI/API, disabled HIL on invalid/interrupted attempts, and generic projection-integrity failure
- `SEC-009` CSRF/replay/login and HIL rate limits/conditional step-up/exact single-use challenge; `SEC-010` Ed25519 add/revoke HIL and non-HIL read-only inspect capability/private UDS/journal/result/bootstrap least privilege; `SEC-011` command injection/mismatch/additional statement/post-approval mutation/JCS-NFC-digest/evidence-order/content-digest-as-authority/duplicate TTL-refresh attempts
- `SEC-012` differential raw-socket Go-parser oracle for origin-form/version/upgrade/trailer/expect/smuggling/framing/equal-or-conflicting Content-Length/encoding/hop/compression/Host confusion, direct-peer/forged identity, DNS rebinding and mixed A/AAAA rejection
- `SEC-013` exact-path/body/query/cookie/authorization/header leakage scans plus origin/network/DB/UDS/host-ruleset bypass
- `SEC-014` demo-history bootstrap role/ACL/session/mount/capability isolation, wrong/stale/expired secret rejection, committed two-phase fence race resistance, no raw-capability persistence, no activation refresh, and cluster-global multi-database fail-closed behavior
- `REC-001` optional ingestion restart; `REC-002` duplicate jobs; `REC-003` executor crash; `REC-004` database/SSE reconnect
- `REC-005` SSE replay-gap/snapshot; `REC-006` expiry downtime/early-missing/orphan/revocation without re-add, including v2 missing/invalid/reversed read-back brackets and boundary-overlap indeterminate handling; `REC-007` database plus capability-journal backup/restore, including v2 signed read-back-bracket versus persisted-bound equality and fail-closed mismatch; `REC-008` canonical approval/capability replay/restart without timeout refresh, while recurring content requires a fresh authority chain
- `REC-009` Gateway/EventSink/control-plane clean/unclean restart, sender epochs/checkpoint, out-of-order atomic batch ACK and permanent loss closure resume without request backpressure and never reconstruct a block from incomplete evidence
- `REC-010` exact completed demo-history import and activation-pair reattachment without renewal; failed/importing/drifted/partial/expired state remains non-enforcing and post-expiry recovery requires full disposable profile/volume reset plus reseal

The release E2E distinguishes two namespace cases. It restarts dispatcher and executor while the Gateway-owned namespace remains live, then requires the active element to remain present with a non-increasing TTL and no new add. A Gateway container restart is a separate recovery case: it discards that namespace, so the element must remain absent, must never be auto-re-added, and must converge through signed `inspect_absent` to the early-missing failure/audit path before the recorded expiry.

Use table/fuzz tests for HTTP target/path/Host/nft parsers, differential raw-socket tests against the pinned Go `net/http` oracle, an application fake clock only for detectors/fixture history, signed concrete demo datasets/imports, stubs for AI, real PostgreSQL roles/migrations, disposable shared Gateway namespaces for nft, and a real RFC1918 private origin for proxy integration. Kernel TTL and security freshness tests use bounded real time. Default CI stubs external OpenAI; a secret-gated opt-in smoke test may verify the pinned Responses API request and operator rate card without becoming a merge prerequisite.

Security tests must exercise Go-accepted/rejected equal and conflicting `Content-Length`/`Transfer-Encoding`, duplicate/invalid Host, every non-origin target form, HTTP version/upgrade/trailer/expect cases, hop and forged request/trace/forwarding headers, ambiguous encoded paths, oversized/slow bodies and headers, compressed/streamed responses, DNS-rebinding/mixed address answers, event/challenge/capability replay, malformed/oversized/trailing UDS frames, unsigned inspect, torn/corrupt journal tails, bootstrap/live-schema mismatch, UDS/network isolation, host-ruleset invariance, and storage/log/trace leakage. Browser tests remain separate frontend/UI tasks and cover loading, empty, error, disabled, success, stale, step-up, permission-denied, revocation, and expiry states.

Current local evidence includes final root backend/data/contract/security/recovery/frontend gates, RUN25 fast Compose evidence, fast browser QA for active/revoked action states, and a one-attempt billable `openai_responses`/`gpt-5.6-sol` synthetic `path_scan` result with `status=ok` and no control-plane mutation. The previously recorded v2 repair now also has a Linux native v6 E2E exit `0`: real kernel TTL expiry, signed absent inspection, audit/recovery/forwarding convergence, and unchanged semantic host nftables after cleanup were observed without TTL reapplication. A current-tree five-minute 4 GB Linux performance gate exited `0` with `GATE_VERDICT=pass`, p95 `533us`, and outage overhead `436us`. Fast browser QA exited `0` and produced sanitized active/revoked screenshots, but it remains non-release UI evidence. Current-SHA committed clean-checkout/CI, final release captures, and a release decision remain unresolved.

RUN25 of `./scripts/check-demo-e2e.sh --fast --browser-qa-hold-seconds 900` (log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`) remains fast-path evidence. The repaired current tree subsequently ran Linux native v6 E2E to exit `0`: it verified the unprivileged-Gateway/executor-`NET_ADMIN` boundary, private-origin isolation, coverage/scenarios/HIL/recovery/outage forwarding, real kernel TTL expiry, signed read-only absent inspection, audit convergence, no TTL reapplication, and unchanged semantic host nftables after cleanup. The same current tree ran the five-minute 4 GB Linux performance gate to `GATE_VERDICT=pass` with p95 `533us` and outage overhead `436us`. A one-attempt billable live `openai_responses`/`gpt-5.6-sol` probe returned `status=ok` without persistence or a HIL/dispatcher/executor path. Fast browser QA also exited `0` with sanitized active/revoked screenshots; it does not replace final release captures or the separate frontend/UI completion. Current-SHA clean-checkout/CI, release captures/submission evidence, and release decision remain unqualified.

## 17. PRD and ADR traceability

| Requirement / decision | Design sections | Verification |
| --- | --- | --- |
| `FR-001`~`FR-004` event contracts, normalization, persistence | 5, 7, 8, 10, 13 | UT-002/011/014/018, CT-001/009/010, IT-003/014/015, REC-007/009 |
| `FR-005`~`FR-007` deterministic rules and correlation | 7, 9 | UT-003/004, IT-004, E2E-001~004, REC-009 |
| `FR-008`~`FR-010` compact GPT and fact separation | 3, 10, 11 | UT-005/006, CT-002/008, IT-005, SEC-002/011/013 |
| `FR-011`~`FR-012` policy and ordered validation | 10~12 | UT-007/008/016, CT-007/008, IT-006/013, SEC-005/006/010/011/014, REC-010 |
| `FR-013`~`FR-016` HIL, nft, expiry, audit | 5, 7, 10, 12~16 | UT-009/010/012~014/016, CT-007/008, IT-007/008/010~013, E2E-006/007/010/011, SEC-009~011, REC-003/006/008 |
| `FR-017`~`FR-018` dashboard and SSE | 5, 13, 16 | CT-003~006, E2E-005~009, REC-004/005 |
| `FR-019`~`FR-020` attack and normal simulation | 9, 15, 16 | E2E-001~004/011/012 |
| `FR-021` evidence-bound command generation | 3, 10~12 | UT-006/016, CT-002/008, IT-005/013, E2E-010/011, SEC-002/011 |
| `FR-022` primary inline fixed-upstream Gateway | 2~6, 15 | UT-019, CT-009, IT-014/015, E2E-011, NFR-012 load gate |
| `FR-023` peer identity, header sanitation, private origin | 3~6, 15 | UT-017/019, IT-014, E2E-012, SEC-012/013 |
| `FR-024` minimized request/response event | 3, 6, 8, 10, 14 | UT-018, CT-009, IT-014, SEC-013 |
| `FR-025` asynchronous isolation and degradation | 3~7, 14, 15 | CT-009, IT-015, E2E-011, REC-009 |
| `FR-026` authenticated application auth-event adapter | 4, 5, 8, 9, 13~15 | CT-009/010, IT-015, E2E-001, SEC-004/013, REC-009 |
| `NFR-001`~`NFR-011` safety, privilege, traceability, recovery, testability | 3~16 | SEC-001~014, REC-001~010 |
| `NFR-012` Gateway latency/load/forwarding availability | 5~7, 14~16 | UT-015/019, IT-014/015, performance and outage gates |
| `NFR-013` proxy protocol correctness and security | 3, 5, 6, 14, 16 | UT-017/019, IT-014, SEC-012 |
| `NFR-014` data minimization and origin isolation | 3~6, 8, 10, 14~16 | UT-018, CT-009/010, E2E-012, SEC-013 |
| `ADR-010` exact evidence-bound nft artifact | 3, 10~12 | UT-007/008/016, CT-008, IT-006/007/013, SEC-005/006/010/011 |
| `ADR-011` Gateway-first hybrid architecture | 2~9, 13~16 | UT-017~019, CT-009/010, IT-014/015, E2E-011/012, SEC-012/013, REC-009 |
| `ADR-012` frozen v0.1 security and execution contracts | 3~16 | UT-005/006/012~019, CT-002/007~010, IT-006~015, E2E-010~012, SEC-005/006/009~013, REC-003/006~009 |
| `ADR-013` staged non-renewable demo-history authority | 5, 10, 12, 15~16 | UT-008, IT-006, E2E-011, SEC-014, REC-010 |

## 18. Resolved defaults and open decisions

### 18.1 Resolved for v0.1

`ADR-011` fixes the Gateway-first hybrid boundary: Go ReverseProxy, one fixed private upstream, direct-peer identity, regenerated forwarding headers, minimized typed events, non-blocking bounded EventSink, four deterministic rule thresholds, authenticated auth events, asynchronous GPT configuration, and no raw packet sensor or adaptive Gateway deny artifact. `ADR-010` fixes the exact-artifact nftables path. Accepted `ADR-012` supersedes affected `ADR-006`, `ADR-010`, and `ADR-011` clauses by freezing the proxy protocol, event completeness, dispatcher/executor authority, once-only TTL/recovery, revocation, demo isolation, AI budget, and administrator limits described here. `ADR-013` further freezes the demo-only five-minute importer/activator leases, committed two-phase session fencing, distinct digest-bound consumer capabilities, one-hour non-renewable activation pair, and full-reset expiry behavior. The limits, time windows, model/options, TTLs, retention periods, single-admin mode, and performance acceptance values in this TDD are implementation defaults, not open placeholders.

Changing one of these defaults requires synchronized PRD/TDD/Tasklist updates and, when it changes a trust boundary or enforcement semantics, a superseding or amended ADR plus negative tests.

### 18.2 Open, post-v0.1, or evidence-dependent

1. Production TLS certificate lifecycle, external load balancer compatibility, and an explicit trusted-proxy mode; v0.1 has none.
2. Any future HTTP/2 or HTTP/3 exposure; v0.1 explicitly advertises and accepts HTTP/1.1 only.
3. Queue/batch capacity tuning after load evidence; tuning may not add request-path blocking or permit incomplete-evidence enforcement.
4. The optional log/Syslog adapter set, raw-evidence policy, and source-specific normalization after v0.1.
5. A separate raw-packet sensor architecture and privilege boundary.
6. A separate `http-deny-v1` L7 artifact, validator, approval, distribution, rollback, and Gateway cache design.
7. IPv6 nftables grammar/set, multi-origin routing, multi-node ordering, multi-tenant isolation, and multi-admin RBAC/step-up authentication.
8. Production backup/export integrity level, long-term audit anchoring, and deployment-specific protected CIDRs.
9. Any production, renewable, multi-database, or cross-run history-attestation authority; the v0.1 demo roles and activation pair cannot be reused or promoted.

Do not settle these implicitly while implementing v0.1. Record options, evidence, safety impact, compatibility, and rollback in the appropriate ADR before expanding scope.
