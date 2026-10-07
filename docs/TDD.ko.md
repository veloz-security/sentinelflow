# SentinelFlow 기술 설계 문서 (TDD)

[English](TDD.md) | **한국어**

- 상태: Draft
- 기준 문서: [README.md](../README.md)
- 관련 문서: [PRD.ko.md](PRD.ko.md) · [ADR.ko.md](ADR.ko.md) · [TASKLIST.ko.md](TASKLIST.ko.md) · [WBS.ko.md](WBS.ko.md)
- 결정 기준선: `ADR-010`, `ADR-011`, `ADR-012`, `ADR-013`, `ADR-014`
- 목표: 구현이 완료된 single-node SentinelFlow v0.1 / 실험적 연구 릴리스
- 용어: 이 저장소에서 TDD는 *Technical Design Document*를 의미한다.

이 문서는 현재 존재하는 코드의 구현 계약이다. 그 자체로 release evidence는 아니며 현재 코드, 테스트, rerun output 및 runtime observation이 구현과 qualification status의 근거다.

## 공개 연구 배포 checkpoint (2026-10-07)

SentinelFlow는 벨로즈(Veloz) 소유이며 공식 사이트는 [sec.veloz.kr](https://sec.veloz.kr)이다. 소유자는 [security@veloz.kr](mailto:security@veloz.kr)을 보안 문의 주소로 제공했다. 소유자가 공개 구조 정리와 릴리스 게시를 요청했다. `v0.1.0-rc.1`은 구현 검증 완료 v0.1 릴리스와 별개인 실험적 연구 배포다. Production, 고객 실적, 인증 또는 CVP 승인 주장은 하지 않는다. Runtime과 enforcement contract는 변경하지 않는다.

Implementation checkpoint `b125adec66864c87f5d37f15049514381dd9e4f3`에는 migration 34와 v2 expiry repair가 이미 commit되어 있으며 [CI run 29709922172](https://github.com/devwooops/sentinelflow/actions/runs/29709922172)이 해당 commit의 10개 shard를 모두 통과했다. 아래의 이전 “current-tree” 결과는 2026년 7월 snapshot이며 새로운 10월 rerun이 아니다. Release record는 자신의 exact commit과 verification을 명시해야 한다. 기존 P0 prerequisite와 full v0.1 acceptance gate는 독립적으로 충족될 때까지 open으로 유지한다. [Release guide](./RELEASE.ko.md), [research evidence](./RESEARCH.ko.md), ADR-015 및 M9-010을 참조한다.

공개 배포용 patch maintenance는 ADR-016을 따른다. Go `1.25.13`, `golang.org/x/text` `v0.39.0` 및 동일 major 내 frontend dependency 수정은 새로운 backend(M9-011) 및 독립 frontend(M9-012) 검증이 필요하다. 기존 safety contract와 full release gate는 유지한다.

## 1. 목표

SentinelFlow v0.1은 Gateway-first 설명 가능한 보안 시스템이다. Go reverse proxy가 하나의 고정 private upstream으로 트래픽을 전달하면서 HTTP 요청·응답 metadata를 관측한다. 최소화된 근거를 결정론적 규칙이 먼저 상관한 뒤 GPT가 분석한다. GPT는 근거에 바인딩된 `nft-blacklist-v1` command 하나를 제안할 수 있지만, strict validation과 exact artifact에 대한 관리자 HIL 승인만 별도 privileged executor의 임시 실행을 허가할 수 있다.

성공은 `FR-001`~`FR-026`과 `NFR-001`~`NFR-014`를 충족하고, control-plane 장애 중에도 request-path 가용성을 보존하며, Gateway 성능 예산을 만족하고, AI·validation·approval·recovery·audit의 어떤 모호성도 의도하지 않은 firewall 변경을 만들지 않는 것이다.

## 2. 범위와 비범위

v0.1 범위:

- Go `net/http`와 `net/http/httputil.ReverseProxy`로 구현한 `cmd/gateway`가 하나의 고정 private upstream 앞에서 primary inline sensor가 된다. 이는 origin web server가 아니다.
- Gateway는 direct network peer에서 client identity를 산출하고 forwarding header를 정제하며, static protocol/size/time bound를 강제하고 요청을 전달한 뒤 non-blocking `EventSink`를 통해 최소화된 metadata만 내보낸다.
- 인증된 internal application contract가 credential-stuffing 탐지를 위해 최소화된 authentication outcome을 내보낸다.
- 결정론적 path-scan, request-burst, brute-force, credential-stuffing rule이 근거에 바인딩된 signal과 incident를 만든다.
- GPT-5.6은 request path 밖에서 설명, 불확실성, 제한된 `block_ip` policy, 근거에 바인딩된 `nft-blacklist-v1` candidate 하나를 제공한다.
- Strict parsing, canonicalization, ordered validation, exact-artifact HIL, 격리된 shell-free nftables 실행, expiry, reconciliation, audit, REST/SSE, 관리자 UI는 계속 범위에 포함된다.
- `cmd/ingestor`는 동일한 normalized evidence contract를 내보내는 선택형 post-v0.1 log·Syslog adapter를 위해 예약한다. v0.1 critical path에는 포함하지 않는다.

비범위:

- General-purpose origin web server 구축 또는 client가 선택한 upstream 수용
- Raw packet capture, eBPF/XDP/AF_XDP sensing, deep packet inspection, 결합된 packet sensor/executor
- Gateway의 adaptive AI-generated L7 deny rule. 미래의 `http-deny-v1` artifact는 자체 schema, validator, HIL binding, executor, test, ADR이 필요하다.
- Production WAF, CDN, DDoS service, SIEM, identity provider 대체
- Multi-node, multi-tenant, multi-admin RBAC, unattended production blocking, IPv6 nftables command generation

Static하고 versioning된 protocol safeguard는 malformed, oversized, timed-out, disallowed-host request를 HIL 없이 거부할 수 있다. 이는 adaptive incident-response policy가 아니라 Gateway server configuration의 일부다. AI output은 request forwarding behavior를 직접 변경하지 않는다.

## 3. 설계 원칙과 불변 조건

1. **하나의 고정 private origin:** Gateway는 구성된 upstream으로만 proxy하며 request data에서 upstream address를 만들지 않는다(`FR-022`, `FR-023`).
2. **Canonical direct-peer identity:** v0.1은 TCP peer address만 신뢰한다. Inbound `Forwarded`와 `X-Forwarded-*` identity header를 제거하고 canonical state에서 다시 생성한다(`FR-023`).
3. **최소화된 근거:** Request body, response body, query string, cookie, `Authorization`, raw secret-bearing header, raw request target을 저장·감사·GPT 전송·telemetry 기록하지 않는다(`FR-024`, `NFR-014`).
4. **Non-blocking 관측:** Request path는 PostgreSQL, GPT, 관리자 승인, EventSink network flush를 기다리지 않는다. Sink saturation이나 control-plane outage에서는 트래픽을 전달하고 degradation을 보고하며 신규 block을 생성할 수 없다(`FR-025`).
5. **결정론적 처리 우선:** Versioning된 quantitative rule을 AI 분석보다 먼저 실행한다(`NFR-008`).
6. **사실과 추론 분리:** 관측된 Gateway/auth event, deterministic signal, AI interpretation, human decision, enforcement outcome을 별도 record로 저장한다(`FR-010`).
7. **AI는 비신뢰·비동기:** GPT에는 Gateway, administrator, database-write, shell, firewall 권한이 없다. Refusal, incomplete output, schema failure, timeout, ambiguous evidence는 `analysis_failed`가 된다(`FR-008`~`FR-010`, `FR-021`).
8. **Enforcement fail closed:** 누락·degraded·stale·failed·timed-out·ambiguous evidence/validation/approval은 신규 block을 막지만, Gateway는 그 외 유효한 트래픽을 계속 전달한다(`NFR-001`).
9. **Exact-artifact HIL:** 승인은 immutable policy, generated/canonical command, evidence, validation, actor, reason, validity digest에 바인딩된다. 종속 항목 변경 시 재검증과 재승인이 필요하다(`FR-013`, `FR-021`).
10. **Shell-free 최소 권한:** 격리된 executor만 최소 nftables capability를 가진다. Least-privilege dispatcher가 수명이 짧은 single-use exact-artifact capability 하나에 서명하고, executor가 이를 검증해 SHA-256을 재계산한 뒤 shell 없이 고정 `nft -f -`를 호출한다(`FR-014`, `NFR-002`). API, AI, general worker에는 signing key도 executor reachability도 없다.
11. **가역적 once-only 집행:** 모든 add는 finite TTL, kernel expiry, read-back, lifecycle audit, 보수적 reconciliation을 가진다. 동일한 relative-timeout artifact는 최대 한 번만 적용하며 timeout 갱신을 위한 replay를 허용하지 않는다. 조기 소실은 자동 복구가 아니라 failure와 alert가 된다(`FR-015`, `NFR-007`).
12. **Private origin:** Upstream에는 published host port가 없고 Gateway network에서만 접근할 수 있다. Direct-origin reachability는 release-blocking failure다(`FR-023`, `NFR-014`).
13. **Protocol 정확성:** HTTP ambiguity, request smuggling, hop-by-hop header 처리, host validation, limit은 detection과 독립적으로 테스트하는 security boundary다(`NFR-013`).
14. **추적성:** Stable ID와 digest가 Gateway/auth event → signal → incident → analysis → policy → validation → approval → action을 연결한다(`NFR-006`).

Artifact digest는 immutable byte를 증명하지만 candidate, action, schedule 또는 authorization identity가 아니다. Byte-identical generated, canonical 또는 inspection artifact가 서로 다른 evidence와 lifecycle binding 아래 반복될 수 있다. 따라서 모든 새 add에는 fresh candidate, policy, validation, challenge, decision, authorization, action, capability chain이 필요하고 모든 inspect에는 fresh typed read-only authorization과 capability가 필요하다. 이전 digest, HIL decision 또는 capability는 새 chain을 authorize하지 않는다.

## 4. 논리 아키텍처와 신뢰 경계

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

Request/response data plane에는 Gateway와 private origin만 존재한다. Detection, GPT, PostgreSQL, HIL, nftables execution은 control-plane 작업이다. Control-plane latency나 unavailability가 request latency 또는 automatic deny decision으로 변환되어서는 안 된다.

신뢰 경계:

- **A — Client에서 Gateway:** 비신뢰 HTTP syntax, method, host, header, path, query, body, rate, direct peer address
- **B — Gateway에서 origin:** 고정 scheme/address/host, 정제된 hop·forwarding header, bounded streaming, private network
- **C — Gateway/application에서 control plane:** 인증된 minimized event contract, non-blocking queue, batch limit, replay protection, degradation marker
- **D — Control plane과 PostgreSQL:** Typed repository, transaction, retention, least-privilege role, outbox idempotency
- **E — OpenAI API:** Compact structured fact, raw secret 없음, fixed model/option, tool 없음, strict output schema
- **F — Administrator browser:** Single-admin authentication, secure session cookie, CSRF/origin/replay check, exact-artifact decision
- **G — Dispatcher에서 격리된 executor:** Private UDS를 통해 approved canonical byte/digest와 short-lived Ed25519 capability만 수용, fixed binary/argument, shell이나 general network API 없음
- **H — 공유 demo network namespace:** Executor sidecar와 Gateway traffic namespace만 공유한다. Gateway는 zero capability를 유지하고 host ruleset은 불변이어야 한다.

## 5. 배포 단위와 컴포넌트 계약

| Unit | 책임 | 금지 사항 / 경계 |
| --- | --- | --- |
| `cmd/gateway` | HTTP server와 하나의 ReverseProxy 구성, lifecycle, health, metric, bounded EventSink | AI, HIL, PostgreSQL request-path call, arbitrary upstream, shell, nft capability 금지 |
| `internal/gateway` | Peer identity, host/header sanitation, fixed rewrite, bound, metadata capture, event construction | Body/query/header persistence 또는 adaptive AI deny logic 금지 |
| `cmd/api` | Admin REST/SSE/session/CSRF 및 인증된 internal event endpoint | nft mutation 금지, raw request나 auth secret 노출 금지 |
| `cmd/worker` | Event persistence job, detection, correlation, GPT, validation, expiry, audit/outbox 작업 | Arbitrary shell 또는 direct nft mutation 금지 |
| `cmd/historyimporter` | Five-minute importer lease로 fixed signed demo-history run을 one-shot 검증/import하거나 exact completed state에 attach | AI, HIL, general worker role, activation capability, listener, signing key 또는 renewable import authority 금지 |
| `cmd/demoactivator` | Public proof를 one-shot 검증하고 distinct analysis/validation activation pair를 atomically create/exact reattach | Import, prepare, AI, HIL, dispatcher, executor, listener, activation renewal 또는 long-running service authority 금지 |
| `cmd/dispatcher` | Approved이고 still-valid인 job만 읽고 Ed25519 exact-artifact capability를 발급해 private UDS로 제출하며 signed result attestation을 저장 | General worker/API role, OpenAI secret, nft capability, arbitrary job, network executor endpoint 금지 |
| `cmd/executor` | Single-use capability 검증, exact add/revoke artifact 실행, read-back, replay state journal, removable residue만 reconciliation | GPT/API secret, DB access, private dispatch key, alternate command, network listener, shell 금지 |
| `cmd/simulator` | 재현 가능한 origin, normal traffic, attack traffic | Host-firewall access 또는 real credential 금지 |
| `cmd/ingestor` | Post-v0.1 선택형 log/Syslog adapter | v0.1 dependency가 아님, AI·enforcement call 금지 |
| `internal/events` | Typed Gateway/auth/source-health contract, validation, ID, schema version | Generic raw payload persistence 금지 |
| `internal/detection` | Versioning된 deterministic window와 evidence-bound signal | AI result를 input fact로 사용 금지 |
| `internal/correlation` | Same-source time relation과 incident lifecycle | IP address만으로 identity claim 금지 |
| `internal/ai` | Bounded Responses API request, strict Structured Outputs, result classification | Tool, persistence authority, approval, shell, executor access 금지 |
| `internal/policy` | `nft-blacklist-v1` grammar, AST, canonical byte, SHA-256, artifact state | General nft 또는 shell grammar 금지 |
| `internal/validation` | Evidence consistency, protected range, nft check, historical impact, snapshot | Bypass 또는 approval mutation 금지 |
| `internal/enforcement` | Capability/result schema, dispatcher/executor UDS, exact digest recheck, fixed invocation, read-back, revocation, recovery | Model text, generated candidate, stale approval, generic HMAC, general firewall request 금지 |
| `internal/repository` | pgx/sqlc persistence, transaction, retention, outbox lease | Domain decision 금지 |
| `web/` | Administrator investigation 및 HIL experience | Backend/domain/enforcement 구현 금지 |

Component-facing Go API는 typed domain object와 명시적 `context.Context`를 사용한다. External HTTP, PostgreSQL, OpenAI, nftables 구현은 adapter다. Shared contract는 owner가 한 명이며 circular import를 금지한다.

### 5.1 Gateway 구성 계약

Immutable startup configuration은 다음을 포함한다.

- `listen_addr`, optional paired `tls_cert_file`/`tls_key_file`, `public_hosts`, `service_label`, `upstream_url`, `upstream_host`, 비어 있지 않은 `origin_cidrs`
- `max_header_bytes=32768`, `max_body_bytes=10485760`, `read_header_timeout=5s`, `request_timeout=30s`, `upstream_timeout=30s`, `idle_timeout=60s`
- `max_request_target_bytes=4096`, `max_path_bytes=2048`, `path_catalog_version=path-catalog-v1`, 명시적으로 구성된 login-route map
- EventSink endpoint/auth secret ID, `queue_capacity=10000`, `batch_size=100`, `max_batch_bytes=262144`, `flush_interval=100ms`

Asserted demo profile은 shared service label을 `SENTINELFLOW_SERVICE_LABEL=demo-app`, application listener를 `DEMO_ORIGIN_HTTP_LISTEN_ADDR=172.30.0.10:8081`, API internal ingestion listener를 `INTERNAL_API_INGEST_LISTEN_ADDR=172.31.0.10:8082`, 별도 container management listener를 `API_MANAGEMENT_LISTEN_ADDR=:8083`으로 고정한다. Compose는 해당 management port만 `API_MANAGEMENT_PUBLISHED_HOST=127.0.0.1`이 선택한 host address에 publish하며 container listener 자체를 loopback-bound라고 표현하지 않는다.

`net/http.Server`가 유일한 wire HTTP parser다. `MaxHeaderBytes=32768`은 구성된 Go parser limit이지 정확히 32,768 raw wire byte를 수용한다는 보장이 아니다. Go는 implementation-defined protocol overhead와 buffering slop을 더 읽을 수 있다. SentinelFlow는 두 번째 raw-header parser를 추가하거나 request를 rewind/reinterpret하지 않는다. Parser-version behavior는 최소 `net/http` oracle과 비교하는 differential raw-socket test로 고정한다.

v0.1의 유일한 upstream scheme은 `http`다. 각 `origin_cidrs` 항목은 prefix length가 최소 `/16`인 IPv4 RFC 1918 subnet이어야 한다. 목록은 비어 있을 수 없으며 `0.0.0.0/0`, loopback, link-local/metadata, public, multicast/reserved, IPv6 공간을 포함할 수 없다. Startup과 새 connection 직전에 custom resolver는 A record만 반환해야 하며 모든 answer가 `origin_cidrs` 안에 있어야 한다. 허용되지 않은 A, AAAA, 허용/불허가 혼합 answer set이 하나라도 있으면 configuration 또는 connection을 거부한다. Custom dialer는 다시 검사한 뒤 선택한 허용 IP에 직접 dial한다. 전용 `http.Transport`는 `Proxy=nil`로 설정해 environment proxy variable이 origin traffic을 우회시키지 못하게 한다.

Upstream URL이 정확히 하나가 아니거나 user info/query/fragment가 있거나 host가 없거나 fixed upstream Host가 구성되지 않은 경우에도 startup이 실패한다. Client input은 upstream scheme, authority, address, Host를 바꾸지 못한다. Public Host 항목은 optional explicit port를 가진 lowercase ASCII DNS name이다. Matching은 non-ASCII, IP literal, user info, ambiguous/multiple value를 거부하며 case, trailing dot 하나, default port(HTTP는 `80`, TLS는 `443`)를 normalize한 뒤 exact allowlist와 비교한다. Nondefault port는 allowlist에 명시되어야 한다. TLS를 구성하면 ALPN은 `http/1.1`만 advertise한다. Empty non-nil `TLSNextProto` map으로 Go HTTP/2 automatic server configuration을 명시적으로 disable하고 origin transport는 `ForceAttemptHTTP2=false`로 설정한다.

### 5.2 EventSink 계약

```go
type EventSink interface {
    TryEnqueue(events.GatewayEvent) events.EnqueueResult
}
```

`TryEnqueue`는 non-blocking이며 `accepted`, `degraded`, `dropped` 중 하나를 반환한다. Database나 GPT 결과를 반환하지 않는다. Default adapter는 bounded in-memory queue를 소유하고 인증된 batch를 internal control-plane endpoint로 비동기 전송한다. Background sender는 최대 100 record·256 KiB batch, healthy 상태의 100 ms flush interval, 100 ms부터 5 s까지의 bounded backoff를 사용한다. v0.1에는 durable event spool이 없다.

구성된 각 Gateway 또는 authenticated-application `sender_id`는 stable하고 `sender_epoch`는 process boot마다 생성하는 random 128-bit value이며 `sequence`는 해당 epoch 안에서 1부터 monotonically 증가한다. 각 producer는 동일한 checkpoint/epoch lifecycle을 소유하고 자체 `source-health-v1`을 emit할 수 있다. 작은 durable checkpoint에는 sender ID, endpoint, epoch, 마지막 acknowledged sequence/body digest, clean-shutdown flag만 저장하고 event record는 저장하지 않는다. Startup은 request를 받기 전에 checkpoint를 atomically unclean으로 표시한다. Clean shutdown은 accept를 중단하고 최대 5초 동안 flush를 시도하며 알려진 unsent range를 `source-health-v1`으로 기록하고 마지막 batch 또는 loss marker가 acknowledged된 뒤에만 clean을 표시한다. Unclean restart 뒤 새 epoch는 이전 epoch에 대해 unknown range를 가진 `lost` state의 `unclean_restart` event를 영구 기록한다. Checkpoint에 없는 sequence, time range, drop count 근거를 만들어 내지 않는다.

Outage, rejected batch, sequence gap, dropped event가 발생할 때마다 source-health degraded interval을 연다. Receiver는 전체 batch를 atomically validate/persist하거나 아무것도 저장하지 않는다. Request-path backpressure 없이 후속 sequence를 수용할 수 있지만, 누락 batch가 모두 byte-identical하게 도착하거나 authenticated `source-health-v1`이 exact sequence/time range를 영구 loss로 표시할 때만 gap이 닫힌다. Permanent closure는 이후 complete window의 진행만 허용하며 겹치는 window를 complete로 만들지 않는다. 첫 acknowledged health event가 live interval을 닫고 drop/loss count를 commit한다. Unresolved, permanently lost, `unclean_restart`, `unknown_loss` degradation과 겹치는 signal, analysis, validation window는 신규 block에 불충분한 근거다.

### 5.3 Dispatcher와 executor capability 계약

`cmd/dispatcher`만 least-privilege approved-job database view와 Ed25519 private dispatch key를 읽을 수 있다. API, AI, validator, general worker process에는 그 view, key, dispatcher/executor shared runtime directory가 모두 없다. `cmd/executor`에는 대응하는 dispatch public verification key와 별도 Ed25519 private result-signing key가 있고, dispatcher와 executor에만 mount된 tmpfs volume의 filesystem-permissioned Unix domain socket에서 listen하며 TCP/UDP listener를 노출하지 않는다. Dispatcher에는 executor result public verification key가 있지만 그 private key는 없다.

[`execution-capability-v1`](../contracts/enforcement/execution_capability_v1.schema.json)은 RFC 8785 JSON Canonicalization Scheme(JCS)을 사용하며 다음 exact field를 모두 포함하고 non-applicable value는 JSON `null`로 둔다. `schema_version`, `capability_id`, `operation`, `job_id`, `action_id`, `policy_id`, `policy_version`, `target_ipv4`, `artifact_digest`, `original_add_digest`, `evidence_snapshot_digest`, `validation_snapshot_digest`, `authorization_digest`, `actor_id`, `reason_digest`, `owned_schema_digest`, `issued_at`, `not_before`, `expires_at`, `nonce`다. `operation`은 정확히 `add`, `revoke`, `inspect` 중 하나이고 inspect는 mutation byte가 아니라 immutable read-only [`nft-inspect-v1`](../contracts/enforcement/nft_inspect_v1.schema.json) artifact를 전달한다. `Ed25519("sentinelflow execution-capability-v1\n" || SHA256(JCS(payload)))`로 서명한다. Expiry는 issue 후 최대 60초이며 validation/approval보다 오래갈 수 없다. Checked [`contract_vectors_v1.json`](../contracts/vectors/contract_vectors_v1.json)이 add, revoke, inspect의 JCS byte, digest, signature를 고정한다.

`add`와 `revoke`에서 `authorization_digest`, `actor_id`, `reason_digest`는 관리자의 exact HIL authorization을 바인딩한다. `inspect`에서 `authorization_digest`는 대신 strict non-HIL [`inspection-authorization-v1`](../contracts/enforcement/inspection_authorization_v1.schema.json)을 바인딩하고 `actor_id`는 system scheduler identity이며 `reason_digest`는 typed machine purpose의 deterministic digest다. Capability `nonce`는 administrator decision nonce가 아니라 dispatcher anti-replay material이다. Inspect lifecycle에는 password step-up, administrator HIL decision/nonce, administrator-authored reason이 없으며 mutation 또는 TTL refresh를 authorize할 수 없다.

Capability expiry는 source authority보다 오래갈 수 없다. Add/revoke는 validation/HIL, inspect는 `inspection-authorization-v1.valid_until`이 bound다.

UDS protocol은 strict하고 versioned다. 각 connection은 request frame 하나와 response frame 하나를 전달한 뒤 닫힌다. Frame은 4-byte unsigned big-endian length와 최대 16 KiB strict JSON으로 이루어지며 short, zero, oversized, second, trailing frame은 fail closed한다. Read, write, total exchange deadline은 각각 2초다. Exact [`executor-request-envelope-v1`](../contracts/enforcement/executor_request_envelope_v1.schema.json) field는 `schema_version`, `capability_jcs_b64url`, `capability_signature_b64url`, `artifact_b64url`이고 exact [`executor-response-envelope-v1`](../contracts/enforcement/executor_response_envelope_v1.schema.json) field는 `schema_version`, `result_jcs_b64url`, `result_signature_b64url`이다. Binary field는 unpadded base64url이고 Ed25519 signature는 86자로 encode된다. `contracts/enforcement/` 아래 capability, result, inspect, request, response schema가 add/revoke/inspect exchange의 authoritative contract다. `inspect`는 target/action/original-add/live-schema digest에 바인딩된 signed read-only capability이고 `inet sentinelflow blacklist_ipv4`에 대한 고정 read-back operation만 실행할 수 있다. `nft -f`를 사용하거나 state를 변경할 수 없다. Add/revoke 전후 read-back, recovery classification, expiry check, lifecycle reconciliation은 모두 signed inspect request와 signed result를 사용한다.

Durable replay journal은 two-phase이고 각 payload는 [`executor-journal-record-v1`](../contracts/enforcement/executor_journal_record_v1.schema.json)을 따른다. Capability syntax/signature/digest validation 뒤 temporal freshness check 전에 journal을 lookup한다. Exact matching `terminal` duplicate는 byte-identical stored signed result를 반환하고 exact matching `started` duplicate는 signed inspect-only resolution을 수행한다. Unseen capability만 not-before/expiry/authorization freshness와 target-state check를 통과해야 한다. Mutation 전에 length/version-delimited record가 issued, not-before, expiry time을 바인딩하는 exact capability JCS byte, exact Ed25519 signature byte, read-only inspect artifact를 포함한 exact artifact byte, 각각의 digest, received/deadline time, journal sequence를 저장한다. 각 JCS record는 자체 checksum과 complete preceding record의 digest를 포함하고 binary frame은 별도 checksum을 추가하며, sequence continuity와 함께 verified chain을 이룬다. Executor는 `started`를 append하고 journal file을 fsync한 뒤 parent directory를 fsync하고 나서야 nft를 호출한다. 이후 고정 operation과 signed inspect를 수행하고 exact signed terminal result를 append해 file을 fsync한다. Torn/corrupt tail, checksum/previous-digest/sequence/version failure, directory-sync uncertainty는 executor readiness를 fail closed하고 explicit recovery를 요구한다. 절대 truncate-and-continue하지 않으며 mutation을 허용하지 않는다. `started`만 남긴 crash는 signed inspect로 add state를 `active`, `failed`, `indeterminate`로(revoke state는 `revoked`, `failed`, `indeterminate`) terminally 분류하고 add를 다시 호출하지 않는다. Duplicate는 timeout을 갱신하지 않는다. Fresh non-replay add는 target이 이미 존재하면 실패한다.

[`execution-result-v1`](../contracts/enforcement/execution_result_v1.schema.json)도 RFC 8785 JCS를 사용하며 다음 exact field를 모두 포함하고 non-applicable value는 JSON `null`로 둔다. `schema_version`, `result_id`, `capability_id`, `capability_digest`, `operation`, `action_id`, `artifact_digest`, `target_ipv4`, `classification`, `nft_exit_class`, `readback_state`, `element_handle`, `remaining_ttl_seconds`, `owned_schema_digest`, `started_at`, `completed_at`, `journal_sequence`, `error_code`다. Exact pinned `nft --json list set inet sentinelflow blacklist_ipv4` read-back은 set handle은 노출하지만 per-element handle은 노출하지 않으므로 `element_handle`은 반드시 `null`이어야 하는 reserved field이고 set handle로 대체해서는 안 된다. Active membership은 exact canonical IPv4 element와 positive bounded `remaining_ttl_seconds`로 attest한다. `started_at`과 `completed_at`은 actual result-assessment interval이다. Journal receive/deadline과 one-use permit이 result-signing time이 아니라 mutation freshness를 증명하므로 started-only read-back recovery에서는 capability expiry 뒤일 수 있다. Later result는 state를 attest할 수 있지만 execution authority를 다시 만들 수 없다. Executor는 별도 result key로 `Ed25519("sentinelflow execution-result-v1\n" || SHA256(JCS(payload)))`에 서명한다. Dispatcher는 이를 UDS exchange 및 capability와 대조하고 executor result public key로 검증한 뒤 signed result를 action/audit state와 함께 commit한다. Checked vector는 applied, recovered-active, revoked, inspect-absent result를 포함한다. Missing, mismatched, invalidly signed, uncommittable result는 success가 아니라 `indeterminate`다. Generic worker HMAC 또는 shared service secret은 executor authority를 부여하지 않는다.

`ADR-014`에 따라 v1은 historical fixture와 이미 기록된 result에만 사용하며 새 lifecycle expiry boundary를 설정해서는 안 된다. 새 executor output은 [`execution-result-v2`](../contracts/enforcement/execution_result_v2.schema.json)를 MUST 사용한다. 이는 모든 v1 field를 유지하고 required millisecond UTC `readback_started_at`, `readback_completed_at`을 더한다. 두 값은 고정 nft JSON read-back을 bracket하고 `started_at <= readback_started_at <= readback_completed_at <= completed_at`을 MUST 만족한다. v2는 `Ed25519("sentinelflow execution-result-v2\n" || SHA256(JCS(payload)))`로 서명하며 v1과 별도 signing domain이다. Signed active v2 read-back에서 lifecycle은 `expiry_lower = readback_started_at + remaining_ttl_seconds`, `expiry_upper = readback_completed_at + remaining_ttl_seconds + 1 second`를 계산한다. Upper guard는 nftables의 integer-second remaining-time projection만 보정한다. Storage와 scheduler는 두 bound 또는 동등한 lossless representation을 보존해야 하고 outer execution interval에서 exact expiry instant 하나를 manufacture해서는 안 된다.

Recovery-bundle export와 verification은 exact signed `execution-result-v2` byte를 보존하고 그 read-back bracket을 persisted `execution_result_readback_bounds_000034` row와 대조한다. Dispatcher crash recovery도 exact persisted JCS, digest, signature 및 bound가 일치할 때에만 v2 terminal result를 수용하며 exact replay는 다른 lifecycle mutation 없이 반환한다. Bound가 missing, malformed 또는 mismatched이면 fail closed하며 outer result timestamp에서 추론할 수 없다. Historical v1 record는 bound row 없이만 export할 수 있고 v2 lifecycle evidence로 reinterpret해서는 안 된다.

## 6. Gateway 요청·응답 흐름

1. `net/http.Server`가 구성된 `MaxHeaderBytes=32768`과 5 s header-read limit 아래에서 유일한 request parser로 동작한다. 구성값은 exact raw-wire-byte 보장이 아니며 SentinelFlow raw parser가 accepted byte를 재판단하지 않는다. v0.1은 origin-form HTTP/1.1만 수용한다. Optional TLS는 ALPN `http/1.1`만 advertise하고 Go HTTP/2 auto-configuration은 disabled다. HTTP/1.0, HTTP/2 cleartext preface, `CONNECT` authority-form, absolute-form, asterisk-form, `Upgrade`/WebSocket/h2c, request trailer, malformed framing은 proxy 전에 거부한다.
2. Middleware가 inbound `X-SentinelFlow-Request-ID`, `X-SentinelFlow-Trace-ID`, `X-Request-ID`, `X-Trace-ID`, `traceparent`, `tracestate`를 제거한 뒤 새 `request_id`와 `trace_id`를 생성한다. Client-supplied request/trace identity는 canonical이 아니다.
3. `net/netip`로 `RemoteAddr`를 parse하고 port를 제거하며 IPv4-mapped IPv6를 unmap한 뒤 canonical address를 serialize한다. v0.1은 trusted-proxy chain을 수용하지 않는다.
4. Section 5.1의 exact ASCII/case/trailing-dot/port rule로 Host를 normalize하고 `public_hosts`와 match한다. Unknown host에는 `421 Misdirected Request`, invalid/ambiguous Host에는 `400`을 반환하며 어느 경우도 forward하지 않는다.
5. Malformed/conflicting framing, `Transfer-Encoding`과 `Content-Length`의 동시 존재, unsupported transfer coding, obs-fold, invalid header octet은 Go parser rejection에 의존한다. SentinelFlow는 parsed canonical `http.Request`만 평가한다. Equal duplicate `Content-Length`는 pinned Go parser가 accept/canonicalize한 경우에만 canonical value 하나로 진행하며 raw byte를 재해석하지 않는다. Security-sensitive forwarding/identity/framing header를 지목하는 `Connection` token을 거부한다. Inbound `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, 모든 standard hop-by-hop header, `Connection`이 지목한 나머지 모든 header를 제거한다. Request trailer는 거부한다. 유일하게 지원하는 expectation은 case-insensitive exact `100-continue`이며 나머지는 `417`을 반환한다. Transport는 1초 `ExpectContinueTimeout`을 사용하고 upstream `100`을 relay하며, origin이 응답하지 않으면 해당 bound 후 body streaming을 시작한다.
6. Canonical peer, allowlisted public host, 실제 listener scheme으로 `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`를 다시 생성한다. 새로 생성한 두 ID를 origin에 `X-SentinelFlow-Request-ID`, `X-SentinelFlow-Trace-ID`로 전달한다.
7. 4 KiB request-target와 2 KiB classification-path bound를 강제한다. Malformed percent escape, raw/percent-encoded backslash, percent-encoded slash, NUL/C0/DEL byte, literal 또는 once-decoded `.`/`..` path segment를 거부한다. Classifier는 unreserved percent escape를 한 번 decode하고 남은 escape를 uppercase하며 repeated slash를 collapse한다. Double decode는 하지 않는다. Scheme, authority, upstream Host만 fixed configured origin으로 rewrite한다. Origin behavior를 위해 검증된 path/query는 보존하지만 raw path, target, query는 절대 보존하지 않는다.
8. Declared `Content-Length`가 10 MiB를 넘으면 origin에 연결하기 전에 `413 Content Too Large`로 거부한다. Unknown-length/chunked body는 동일한 hard limit로 stream을 감싼다. 초과 시 upstream request를 취소하고 response가 commit되지 않았으면 `413`을 반환하며, 이미 commit됐으면 stream을 종료한다. Body byte는 inspection/storage하지 않는다.
9. 30 s total request context와 30 s upstream timeout을 적용한다. 전용 transport는 `DisableCompression=true`이고 `Accept-Encoding`을 주입하지 않으며 자동 decompress 없이 content encoding을 pass-through한다. Response hop-by-hop header와 response `Connection`이 지목한 header를 제거하고 request-correlated `100 Continue`만 relay하며 `101 Switching Protocols`를 포함한 나머지 모든 upstream 1xx를 거부하고 response trailer와 `Trailer`를 버린다. Opaque body를 stream하고 content를 보존하지 않는다.
10. Bounded canonical comparison path를 `path-catalog-v1`으로 classify한다. Configured enum `route_label`, `path_catalog_version`, `suspicious_path_id`만 저장하고 exact path는 절대 저장하지 않는다. Built-in suspicious ID는 `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, `backup_archive`이며 나머지는 `none`이다. Fixed pattern은 각각 `/admin` 또는 `/administrator` prefix, `/.env`, `/.git/config`, `/wp-admin` 또는 `/wp-login.php`, `/phpmyadmin` prefix, `/server-status`, `/actuator/env`, filename suffix `.bak`, `.backup`, `.old`, `.zip`이고 ASCII case-insensitive하게 비교한다. Configured login-route map은 `login`, `other` 같은 allowlisted label만 만들며 catalog와 함께 versioning한다.
11. Response metadata가 결정된 후 `EventSink.TryEnqueue`를 호출한다. `degraded` 또는 `dropped`는 metric을 증가시키지만 그 외 유효한 origin response를 변경하지 않는다.

Static outcome에는 HIL이 필요 없다. Malformed/out-of-contract syntax/target에는 `400`/`414`, unsupported expectation에는 `417`, non-allowlisted Host에는 `421`, oversized body에는 `413`, unsupported HTTP version에는 `505`, upstream timeout에는 `504`를 사용한다. Origin resolution/address/connection failure 또는 unsupported upstream protocol response에는 `502`를 반환한다. Adaptive AI policy는 이러한 response를 만들지 않는다.

## 7. 비동기성, 상태, 일관성

EventSink, API, PostgreSQL, worker, OpenAI service가 unavailable이어도 Gateway는 유효한 트래픽을 계속 전달할 수 있다. Healthy-load 목표는 4 GB reference environment에서 초당 500 request 동안 event drop 0건이다. 지속적인 outage에서는 bounded queue가 observation을 drop할 수 있지만 origin traffic에 backpressure를 가하거나 남은 sample을 complete evidence로 조용히 취급해서는 안 된다.

- Event idempotency key: Schema version, Gateway instance ID, generated event ID의 SHA-256
- Internal batch idempotency key: Sender ID + sender epoch + batch ID. Receiver는 monotonic per-epoch sequence와 exact raw-body digest도 추적한다.
- Job idempotency key: Job type + aggregate ID + aggregate version
- Enforcement idempotency key: Policy ID + policy version + generated/canonical command digest + evidence/validation snapshot digest
- Event와 outbox insertion: 하나의 PostgreSQL transaction. Duplicate event/batch key는 effect 중복 없이 acknowledge한다.
- Job delivery: `FOR UPDATE SKIP LOCKED`를 통한 at least once. Unique constraint와 state transition이 effect를 제한한다.
- Worker outbox fencing: lease는 최대 60초이며 모든 completion은 strict expiry 전 exact lease token에 바인딩된다. Expired work는 대기 없이 reclaim할 수 있고 crashed final attempt는 같은 transaction에서 dead-letter evidence와 함께 `dead`로 이동하며, idempotency key가 달라도 unique business-effect key가 두 번째 domain effect를 방지한다.

Incident state는 `open → analyzing → review_ready → closed`이며 `analysis_failed`는 유일하게 집행하지 않는 AI failure state다. 필수 reason은 `budget_exhausted`, `input_too_large`, `network_error`, `http_408`, `http_409`, `rate_limited`, `server_error`, `timeout`, `refused`, `incomplete`, `schema_invalid`, `evidence_invalid`, `unsupported_action`, `cancelled`, `configuration_error` 중 하나이며, reason이 새 idempotent attempt가 `analyzing`으로 돌아갈 수 있는지와 시점을 결정한다. Candidate state는 `generated → parsing → canonical|invalid → validating → valid|stale`이다. Policy/action state는 `draft → validating → valid|invalid|stale → approved|rejected → queued → active → expired|failed|revoked|indeterminate`이다. Server가 allowed transition과 optimistic version을 강제한다.

Correlation은 각 Gateway, auth, source-health record timestamp를 server `received_at`과 비교한다. Future 60초 초과 또는 past 5분 초과 record는 `trust_state=untrusted`, `trust_reason=timestamp_skew`로 저장한다. Audit을 위해 보존하지만 detection, analysis evidence, validation, enforcement에 기여할 수 없고 조용히 drop하거나 shift하지 않는다. Source-health degradation, missing referenced row, duplicate conflict, pending/failed auth binding, incomplete rule window는 evidence sufficiency를 실패시킨다.

## 8. 최소화된 이벤트 계약

Persistence는 arbitrary request JSON이 아니라 typed allowlisted column을 사용한다. 새 field가 우발적으로 retained evidence가 되지 않도록 unknown contract field는 internal API boundary에서 거부한다.

### 8.1 Gateway 이벤트 `gateway-http-v1`

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

Persisted Gateway allowlist는 정확히 schema/trace/idempotency ID, start/end timestamp, canonical source IP, bounded method, 고정된 `HTTP/1.1` protocol label, configured route label, path-catalog version, suspicious-path enum, configured host/service label, status, request/response byte count, latency다. Event에는 exact normalized/decoded/raw path, request target, query, request·response body, cookie, `Authorization`, username, user agent, referrer, forwarding-header input, arbitrary header가 절대 포함되지 않는다.

`host`는 untrusted raw Host text가 아니라 normalize된 matched allowlist value다. Route와 suspicious-path value는 request data에서 복사한 string이 아니라 startup-frozen catalog member여야 한다. Count는 non-negative integer이며 latency는 monotonic clock에서 산출하고 timestamp는 UTC다.

### 8.2 인증 이벤트 `auth-event-v1`

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

인증된 allowlisted internal application만 이 contract를 submit할 수 있다. `outcome`은 `failed` 또는 `succeeded`다. `account_hash`는 저장소 밖 secret으로 application이 계산한 stable HMAC-SHA-256 value다. Raw username, email, credential, token, password field는 금지한다. `source_ip`는 canonical이어야 하며 정제된 Gateway forwarding value에서 유래해야 한다.

Gateway event가 아직 없으면 auth event는 최대 5분 동안 `binding_state=pending`이 된다. Reconciliation에는 exact `gateway_request_id`, `trace_id`, canonical `source_ip`, `service_label`, configured login `route_label` 일치가 필요하다. `verified` binding만 attack evidence를 지원할 수 있다. Mismatch는 permanently `untrusted`가 되고 unresolved pending binding은 `untrusted`로 expire된다. Failed 또는 unverified event는 attack threshold에 기여하지 않지만 target에 대한 pending/untrusted `succeeded` event가 하나라도 있으면 historical-impact validation을 보수적으로 차단한다.

두 internal event endpoint는 최대 100 record·256 KiB JSON batch를 수용한다. `X-Sentinel-Sender-ID`는 `^[a-z0-9][a-z0-9._-]{0,63}$`와 일치하는 1–64자의 lowercase ASCII이고, `X-Sentinel-Timestamp`는 Unix second를 나타내는 ASCII decimal digit 1–12개, `X-Sentinel-Nonce`는 128 random bit로 decode되는 정확히 22자의 unpadded base64url, `X-Sentinel-Signature`는 정확히 64자의 lowercase hexadecimal이어야 한다. Sender별 HMAC key는 CSPRNG로 만든 최소 32-byte value를 base64로 구성한다. Lowercase-hex signature는 `HMAC-SHA256(secret, endpoint_path + "\n" + sender_id + "\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(raw_body)))`다. `endpoint_path`는 literal internal path이며 signing-input의 첫 field이고 `sender_id`는 exact header value다. Checked event schema와 vector는 [`contracts/events/`](../contracts/events/)와 [`contract_vectors_v1.json`](../contracts/vectors/contract_vectors_v1.json)이다.

Authentication order는 고정한다. Bounded header/base64 syntax를 검증하고 sender header와 literal endpoint로 bound key를 lookup하며 ±60 s authentication timestamp를 확인하고 raw-body size를 강제해 SHA-256을 계산한 뒤 signature를 constant time으로 비교한다. 그 다음 strict body를 parse하고 header/body `sender_id`가 byte-identical한지 요구한다. 이후에만 하나의 transaction이 nonce를 5분 unique replay store에 atomically insert하고 전체 batch를 validate/persist하며 이후 validation failure는 nonce도 batch와 함께 rollback한다. 따라서 invalid authentication이 nonce cache를 소진시킬 수 없다. Gateway와 application sender에는 별도 configured secret ID를 사용한다. Secret value, authentication metadata, signature를 evidence로 저장하지 않는다. `contracts/vectors/`의 golden vector `event-batch-hmac-v1`이 endpoint, sender header, raw body byte, body digest, signing input, signature를 고정한다.

### 8.3 Internal batch envelope `event-batch-v1`

`/internal/v1/gateway-events`와 `/internal/v1/auth-events`는 동일한 typed envelope를 사용한다.

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

`records`에는 1개부터 100개까지의 item이 포함되며 exact raw request body는 최대 256 KiB다. Configured stable `sender_id`는 하나의 endpoint, allowlisted record schema set, HMAC key ID에 바인딩된다. `sender_epoch`는 boot마다 random이고 `sequence`는 해당 epoch 안에서 monotonic한 unsigned counter다. Gateway sender는 `gateway-http-v1`과 자체 `source-health-v1`을 submit할 수 있고 application sender는 `auth-event-v1`과 자체 `source-health-v1`을 submit할 수 있다. 각각 독립적인 checkpoint, epoch, sequence-gap, degradation state를 갖는다. Unknown sender, header/body sender mismatch, wrong endpoint의 sender, mixed/disallowed record type, unknown field, invalid epoch/sequence는 persistence 전에 거부한다.

Retry는 `sender_epoch`, `batch_id`, `sequence`, exact body byte를 보존하되 새로운 `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, signature를 사용한다. Receiver validation과 receipt, 모든 record, outbox effect, gap state, acknowledgement state는 하나의 transaction에서 commit한다. Newly accepted batch 또는 exact duplicate는 `202`만 반환하며 minimal acknowledgement는 sender/epoch/batch/sequence/body digest와 `accepted` 또는 `duplicate`다. Exact duplicate는 동일한 acknowledgement를 반환한다. Batch ID 또는 sender/epoch/sequence를 다른 digest로 재사용하면 `409`를 반환하고 security-audit하며 partial effect는 없다. Schema, sender, record, HMAC, replay, bound, unknown-field failure는 partial effect 없이 `422`를 반환한다. Gap이 기록된 동안에도 later batch를 수용할 수 있고 Gateway는 closure를 기다리지 않는다.

### 8.4 Source-health 이벤트 `source-health-v1`

이 typed event는 source ID, sender epoch, occurrence 및 degraded interval time, state(`degraded`, `lost`, `recovered`), cause enum(`queue_overflow`, `delivery_outage`, `rejected_batch`, `sequence_gap`, `permanent_loss`, `unclean_restart`, `unknown_loss`, `recovered`), dropped/unknown count, 알려진 경우 exact batch sequence range, bounded detail code를 기록한다. Request data는 포함하지 않는다. Open interval, permanent loss, unknown loss, 0이 아닌 drop count는 겹치는 모든 detection·historical-impact window를 incomplete로 표시한다.

## 9. 결정론적 탐지와 상관

모든 threshold는 inclusive이고 configuration-versioned이며 event time으로 평가하고, 별도 언급이 없으면 canonical `source_ip`와 `service_label`로 grouping한다.

| Rule | 근거와 threshold | Signal |
| --- | --- | --- |
| `path_scan.v1` | 60 s 내 동일한 `path-catalog-v1`의 non-`none` `suspicious_path_id` 8개 모두 | `path_scan` |
| `request_burst.v1` | 10 s 내 Gateway event 120개 이상 | `request_burst` |
| `login_bruteforce.v1` | 60 s 내 configured login `route_label`이고 status `401` 또는 `403`인 Gateway response 10개 이상 | `brute_force` |
| `credential_stuffing.v1` | 5 min 내 distinct `account_hash` 8개 이상에 걸친 binding-`verified` `failed` auth event 20개 이상 | `credential_stuffing` |

각 signal은 rule ID/version, exact window, metric, source/service key, evidence event ID, source-health status를 저장한다. Evidence set이 degradation과 겹치거나 untrusted timestamp/binding을 포함하거나 retained event에서 threshold를 재현할 수 없으면 enforcement 목적으로 rule을 fire할 수 없다.

동일한 canonical source의 signal은 window가 겹치거나 간격이 5분 이하일 때 merge한다. Account hash, path, service는 supporting relation이며 동일 인물의 증거가 아니다. Related signal이 15분 동안 새로 없으면 incident를 close한다. Close 후 30분 안에 related signal이 도착하면 같은 incident version을 reopen하고, 이후 signal은 새 incident를 만든다.

## 10. 영속 데이터와 보존

| Entity | Core field | 불변 조건 |
| --- | --- | --- |
| `gateway_events` | `gateway-http-v1` allowlisted field, catalog enum, received time, trust state/reason | Exact path, body, query, cookie, authorization, raw target, arbitrary header column 없음. Skewed record는 보존하지만 evidence로 사용하지 않음 |
| `auth_events` | `auth-event-v1` field, received time, trust state/reason, binding state/deadline/reason | Opaque account hash만 저장. Attack evidence에는 authenticated source, replay check, trusted time, verified relation 필수 |
| `ingest_batches` | sender, epoch, batch ID, sequence, raw-body digest, sent/received time, acknowledgement | Sender/epoch별 batch와 sequence unique, whole-batch atomicity, conflicting digest 거부·audit |
| `source_health_intervals` | instance, cause, start/end, drops, batch range | Overlap은 enforcement evidence를 incomplete로 만듦 |
| `signals` | rule/version, window, metrics, source/service, evidence IDs | Complete evidence에서 threshold 재현 가능 |
| `incidents` | kind, state, first/last seen, source/service, deterministic score, version | AI field는 observed fact가 아님 |
| `incident_events` | incident ID, event type/ID, relation | Composite unique, immutable relation reason |
| `ai_analyses` | incident/version, model/options, input/schema/output digests, result/error | Strict complete output만 usable |
| `command_candidates` | evidence snapshot/refs, generated bytes/digest, AST, canonical bytes/digest, grammar | Immutable one-statement artifact. Content digest는 non-unique forensic index이고 candidate와 evidence/analysis binding이 identity를 제공함 |
| `policy_proposals` | policy/version/digest, incident, command/evidence digests, TTL, state | Exact `block_ip` artifact만 허용 |
| `policy_validations` | artifact/input/config/tool digests, checks, impact, snapshot digest, `valid_until` | 하나의 exact artifact에 대한 모든 required check commit |
| `validation_attempt_claims/results/gates` | policy/analysis/incident/version, terminal state/failure, prepared/terminal digest, ordered gate result | Immutable valid/invalid/interrupted attempt evidence. Raw prepared/terminal JSON은 API payload가 될 수 없음 |
| `decision_challenges` | nonce digest, session/actor, decision, exact artifact digest/version, issued/expiry/consumed time | 5-minute single-use exact-artifact challenge. Raw nonce는 한 번만 반환하고 저장하지 않음 |
| `approval_decisions` | exact digests, challenge, actor, decision, reason/digest, time, `decision_valid_until` | Exact version당 final decision 1개, challenge를 atomically consume, validation보다 오래 지속 불가 |
| `enforcement_actions` | canonical bytes/digest, approval/snapshot refs, target, state/times | Exact-IP read-back과 exact HIL reference 필수. 반복되는 content digest는 action 또는 authority identity를 재사용하지 않음 |
| `revocation_operations` | action/target/original digest, actor/reason, artifact/capability/result digest, state | Deterministic `nft-revoke-v1`, AI-generated 또는 add approval로 authorize 금지 |
| `inspection_authorizations` | system purpose, action/policy/original authorization, evidence/validation/artifact/live-schema/idempotency digest, scheduler, validity | Non-HIL read-only, administrator nonce/reason 없음, mutation/TTL refresh 금지 |
| `execution_capabilities` | canonical capability/signature/artifact byte와 digest, expiry, nonce, add/revoke/inspect operation, result attestation | Dispatcher-only creation, durable single-use/replay evidence, inspect는 read-only |
| `audit_events` | sequence, actor, action, object/digests, time, trace ID | Application API를 통해 append-only |
| `ai_budget_ledger` | UTC date, model/rate-card version, limit, reserved/settled/consumed USD | Atomic worst-case reservation, over-budget attempt 금지 |
| `outbox_jobs` | kind, aggregate/version/operation, attempts, lease token/owner/expiry, state, error evidence | Idempotency와 business-effect key unique. Lease completion은 token/expiry-fenced이며 terminal crash/dead-letter transition은 atomic |
| `admin_sessions` | opaque token digest, CSRF digest, `authenticated_at`, created/last/expiry, revoked | Plaintext session token 또는 password 없음. Rotation은 password-authentication time을 갱신하지 않음 |

권장 index는 `gateway_events(source_ip, started_at)`, `gateway_events(service_label, started_at)`, `auth_events(source_ip, occurred_at, outcome, binding_state)`, `auth_events(source_ip, account_hash, occurred_at)`, `ingest_batches(sender_id, sender_epoch, sequence)`, `incidents(state, last_seen)`, `execution_capabilities(capability_id)`, `outbox_jobs(state, available_at)`를 포함한다.

v0.1 retention은 다음으로 고정한다.

- Gateway/auth event, ingest-batch receipt, source-health interval, signal evidence, evidence snapshot: 7일
- Incident, AI analysis/budget ledger, command candidate, policy proposal/validation/decision, enforcement/revocation action, capability, signed result attestation: 30일
- Audit event: 90일
- Expired session, nonce, transient queue data: security/recovery window 종료 즉시 삭제

Retention job은 audit row에 참조에 필요한 digest를 보존하되 삭제된 sensitive data를 audit payload로 복사하지 않는다. 삭제는 idempotent하고 audit되며 backup/restore test 대상이다.

Migration 31은 generated/canonical candidate content, enforcement-action canonical content, inspection-artifact content의 기존 global uniqueness constraint를 non-unique lookup index로 대체한다. 반복 content 때문에 폐기된 uniqueness model을 복원할 수 없으면 downgrade는 SQLSTATE `55000`으로 fail closed한다. Migration 32는 API-only `read_policy_validation_attempt_000032(policy_id)` security-definer projection을 추가한다. `sentinelflow_api`는 이 function을 execute할 수 있지만 세 raw attempt table을 select할 수 없고 function은 `prepared_snapshot` 또는 `terminal_mutation` JSON 대신 digest를 반환한다. Terminal state, failure code, prepared digest 또는 completion time의 claim/result mismatch는 SQLSTATE `55000`을 발생시키고 management API는 generic `503 service_unavailable` boundary만 노출한다.

## 11. GPT-5.6 분석 계약

AI worker는 다음의 고정 v0.1 request-policy excerpt로 Responses API를 사용한다.

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

Request builder는 [`contracts/ai/sentinelflow_analysis_v1.schema.json`](../contracts/ai/sentinelflow_analysis_v1.schema.json)의 immutable content를 parse해 `text.format.schema`에 삽입해야 하며 empty·runtime-generated·remotely fetched·caller-supplied schema는 금지한다. 해당 파일은 generated Go/TypeScript output type의 single source이고 digest를 각 analysis에 기록한다. 모든 property를 required로 두고 모든 object level에서 additional property를 거부하며 classification/policy/command enum을 고정하고 두 `target_ip` field를 `format: ipv4`로 제한하며 candidate `timeout`을 `^[1-9][0-9]{0,4}[smh]$`로 제한하고 text, evidence array, `ttl_seconds`, command field bound를 고정한다. Application validation은 여전히 IPv4와 TTL을 canonicalize하고 세 level의 evidence-set equality를 확인하며 command grammar를 parse하고 semantic mismatch를 거부한다. Schema conformance만으로는 policy를 절대 승인하지 않는다.

Exact input contract는 checked-in strict [`sentinelflow_analysis_input_v1.schema.json`](../contracts/ai/sentinelflow_analysis_input_v1.schema.json)이고 유일한 system instruction은 checked-in byte-exact [`sentinelflow_system_prompt_v1.txt`](../contracts/ai/sentinelflow_system_prompt_v1.txt)다. Startup은 두 pinned SHA-256 digest를 모두 검증하며 runtime, caller, evidence, remote text는 instruction을 교체하거나 append할 수 없다. Input schema는 schema/incident/attempt/version/time, prompt/output-schema version, source/service/window, detector configuration, `source_health_status=complete`, sorted `signals`, sorted `evidence_refs`, historical impact, allowed-policy field를 요구하며 unknown field를 거부한다.

Compact input은 immutable incident version의 모든 relevant deterministic signal object와 signal마다 정확히 하나인 output-addressable `evidence_refs` item을 포함한다. 이는 raw event reference가 아니라 deterministic-signal reference다. 각 `evidence_id`는 대응 `signal_id`와 byte-equal하고 동일한 rule, signal/evidence digest, complete expanded-event count를 가진다. Validation과 audit에서 server는 각 reference를 해당 signal의 complete retained event-ID set에 one-to-one으로 resolve한다. Model은 bounded reference만 받고 sampled raw-event subset은 받지 않는다. `signals`는 `signal_id`, `evidence_refs`는 `evidence_id` 기준으로 unique하고 UTF-8 byte lexicographic order로 sorted된다. Signal, reference, server-side expansion을 sample, truncate, silent reorder할 수 없다. Complete strict model input은 reference 최대 50개, UTF-8 JSON serialize 후 최대 12 KiB다. 별도의 `evidence-snapshot-v1` sorted-unique server-side event expansion은 120-event burst를 unbounded snapshot 없이 표현할 수 있도록 ID 1,000,000개로 제한한다. Reference, byte 또는 expansion limit 중 하나라도 넘으면 OpenAI call을 시작하지 않고 incident에 typed `analysis_failed/input_too_large`를 기록하며 worker는 fit을 위해 truncate하지 않는다. Request/response body, query, cookie, authorization, raw header, raw username, account hash, arbitrary log text, raw event row를 포함하지 않는다.

Output은 explanation, classification, confidence, uncertainty, false-positive factor, evidence ID, structured `block_ip` policy 하나, `nft-blacklist-v1` candidate 하나를 허용한다. JSON Schema validation에 더해 application은 top-level, policy, candidate evidence array가 sorted, unique하며 complete input `evidence_refs`와 byte-identical하기를 요구한다. Unsorted, duplicate, missing, extra, differently encoded reference는 silent normalize하지 않고 `evidence_invalid`다. Policy와 command는 동일한 canonical IPv4 target도 참조해야 한다.

Live AI에는 input, cached-input, output의 USD per one million token을 담은 operator-supplied versioned rate card도 필요하다. Missing, zero/negative, unparseable, unversioned rate는 live AI를 disable하고 `configuration_error` reason의 `analysis_failed`를 저장한다. Documentation에서 추론하거나 provider price로 hard-code하지 않는다. Configurable demo ledger limit의 default는 UTC day당 USD 10이다.

각 attempt 전에 하나의 PostgreSQL transaction이 UTC-day/model/rate-card ledger를 lock하고 worst case를 reserve한다. 12,288 input token unit에는 input과 cached-input rate 중 큰 값을 적용하고 2,048 output token unit을 더해 ledger의 fixed micro-USD precision에서 올림한다. Retry는 별도 attempt이며 별도 reservation이 필요하다. Completed response는 provider usage로만 settle한다. Noncached input은 `input_tokens - input_tokens_details.cached_tokens`, cached input은 `input_tokens_details.cached_tokens`, output은 `output_tokens`이며 malformed 또는 missing usage는 full reservation을 consume한다. Settlement는 unused reservation을 release한다. Trusted usage가 없는 timeout 또는 transport outcome도 full reservation을 보수적으로 consume한다. Reservation이 daily limit을 넘으면 call을 시작하지 않고 incident를 `budget_exhausted` reason의 `analysis_failed`로 저장한다. Reservation이 atomic하므로 concurrency 2도 overspend할 수 없다.

각 attempt의 timeout은 30 s다. Incident version당 total attempt는 initial call과 retry 하나를 합쳐 최대 2회다. Retry는 network error 또는 OpenAI response status `408`, `409`, `429`, `5xx`에만 bounded jitter를 두고 정확히 한 번 허용한다. Validation error, refusal, manual API repetition은 이 cap을 우회할 수 없다. Oversized complete input, refusal, incomplete response, exhausted timeout, unknown field, schema error, missing reference, evidence mismatch, unsupported action, configuration error, exhausted budget은 항상 enumerated reason을 가진 unified non-enforcing `analysis_failed` state를 사용하고 valid policy를 만들지 않는다. Model, reasoning effort, prompt/input-schema/output-schema/rate-card version, token usage, reservation/settlement, input/output digest를 content secret 없이 audit한다. Gateway code에서 GPT를 synchronous하게 호출하지 않는다.

Migration 33은 별도의 pre-provider race를 해결한다. Leased queued `analyze` job에 attempt claim이 없고 immutable `incident_version_history`가 해당 aggregate version의 존재를 증명하며 current incident가 전진했다면 security-definer prepare boundary가 job을 complete하고 digest-bound `analysis_superseded` audit event 하나를 emit하며 provider claim이나 dead letter를 만들지 않는다. Current incident version, evidence version, state는 변경하지 않는다. Aggregate가 존재한 적 없는 job은 계속 `no_call`을 반환하고 unresolved `analysis_incident_missing` dead-letter evidence가 되며 supersession audit을 emit하지 않는다. Existing in-flight claim과 intentional `analysis_superseded` dead letter는 rewrite하지 않는다. Activated-demo wrapper는 provider-free supersession path에서도 자기 exact analysis capability use를 verify하고 record한다.

`cmd/openaismoke`는 동일한 checked artifact와 고정 synthetic RFC 5737 path-scan input을 사용하는 explicit opt-in, one-attempt, non-mutating contract probe다. `SENTINELFLOW_OPENAI_LIVE_SMOKE=1`과 `OPENAI_API_KEY`를 요구하고 database, HIL, dispatcher, executor path가 없으며 safe status/provenance digest만 출력한다. Disabled 및 missing-key behavior에는 local fail-closed evidence가 있다. 1회의 billable live attempt는 `openai_responses`/`gpt-5.6-sol`에서 `status=ok`, evidence reference 1개와 schema-valid generated/canonical command digest를 반환했고 control plane을 mutate하지 않았다.

## 12. 정책 검증, HIL, nftables

### 12.1 Artifact와 canonical form

`ADR-012`로 hardening된 `ADR-010`에 따라 v0.1은 owned set에서 IPv4 add-element operation 하나만 허용한다. 아래 RFC 5737 address는 syntax illustration이며 12.2절의 isolated demo/test exception에서만 실행할 수 있다.

```text
add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }
```

Canonical byte는 BOM 없는 UTF-8이고 leading/trailing space, comment, tab, extra statement가 없으며 정확히 하나의 LF byte로 끝난다. Exact canonical byte sequence의 SHA-256은 `sha256:` prefix를 붙인 lowercase hexadecimal로 encode한다. Structured policy는 `60..86400` 범위의 required integer `ttl_seconds`를 사용하며 default는 `1800`이다. Candidate grammar는 `[1-9][0-9]{0,4}[smh]`와 match하는 lowercase TTL token 하나만 수용한다. Checked arithmetic은 범위 안에 있어야 하고 parsed second는 policy `ttl_seconds`와 같아야 한다. Canonical serialization은 정확히 나누어지는 가장 큰 unit을 사용한다. 3600으로 나누어지면 hour, 아니면 60으로 나누어질 때 minute, 그 외에는 integer second를 사용한다. 따라서 minimum/default/maximum canonical value는 `1m`, `30m`, `24h`다. Golden vector `ttl-canonical-v1`이 accepted/rejected token과 canonical output을 고정한다. IPv6와 그 밖의 모든 family/table/set/action을 거부한다.

Checked policy, [`evidence-snapshot-v1`](../contracts/enforcement/evidence_snapshot_v1.schema.json), [`validation-snapshot-v1`](../contracts/enforcement/validation_snapshot_v1.schema.json), [`enforcement-authorization-v1`](../contracts/enforcement/enforcement_authorization_v1.schema.json), capability, [`hil-reason-v1`](../contracts/enforcement/hil_reason_v1.schema.json) object는 human-authored string을 Unicode NFC로 normalize한 뒤 RFC 8785 JCS를 사용한다. Digest form은 canonical byte의 정확히 `sha256:`와 64자의 lowercase hexadecimal이고 `reason_digest`는 exact NFC UTF-8 reason을 대상으로 한다. Producer는 signing 전에 canonicalize하고 validator는 signed object를 조용히 변경하지 않고 reserialize해 byte equality를 요구한다. AI input, 세 AI output level, policy, candidate 및 evidence snapshot의 evidence-reference array는 unique하고 UTF-8 byte lexicographic order로 sorted되며 contract가 반복하는 곳에서 byte-identical해야 한다. Validation, challenge, decision, authorization 및 capability object는 array를 복사하지 않고 exact `evidence_snapshot_digest`를 전달하며 각 stage가 digest를 byte-for-byte 보존해야 한다. Duplicate, unsorted, re-encoded, missing, extra 또는 digest-substituted evidence는 silent repair 없이 fail closed한다. Checked contract-vector bundle이 NFC/JCS/digest behavior를 고정한다.

### 12.2 순서가 고정된 hard-gate validation

1. Strict Structured Output, required policy/command field, canonical IPv4, TTL bound, immutable evidence-snapshot membership을 검사한다.
2. `nft-blacklist-v1`로 parse한다. Unsupported token, extra statement, alternate table/set, multiple address, missing timeout, shell syntax, include, variable, redirection, pipeline, substitution, comment, NUL, hidden trailing input을 거부한다.
3. Typed AST를 만들고 allowlisted operation 정확히 하나인지 확인하며 policy/command target과 evidence-set equality를 요구하고 canonical byte로 serialize한 뒤 generated/canonical digest를 계산한다.
4. 모든 evidence ID가 immutable analysis input에 존재하고 동일한 source로 resolve되며 적어도 하나의 deterministic rule threshold를 재현하고 degraded source-health interval과 겹치지 않는지 증명한다. Missing 또는 insufficient evidence는 fail closed한다.
5. Canonical global-unicast IPv4를 요구한다. Authoritative strict [`protected_ipv4_v1.json`](../contracts/enforcement/protected_ipv4_v1.json)은 adjacent schema로 검증하며 immutable built-in CIDR/range, reason, demo-exception flag를 포함한다. Pinned static JCS digest는 `sha256:d3dfb63a573925e19f29e8595fd5574bc441a9c468d2f9ef6d2f004abb101104`다. 별도 effective object는 [`protected_ipv4_effective_config_v1.schema.json`](../contracts/enforcement/protected_ipv4_effective_config_v1.schema.json)으로 검증하고 static digest, unique sorted operator addition, selected demo exception, current management/origin/Gateway/executor/administrator-path address를 바인딩한 뒤 JCS digest를 계산한다. Validation, challenge/decision, authorization, capability의 validation digest가 static/effective digest를 모두 바인딩한다. Unspecified, loopback, private, link-local, CGNAT, benchmarking, documentation, multicast/reserved와 모든 effective protected address를 거부하며 `IsGlobalUnicast`에만 의존하지 않는다. Configuration은 protection을 추가할 수만 있고 built-in entry를 제거할 수 없다. Isolated demo/test profile은 namespace/host-difference proof 뒤 RFC 5737 exception flag가 있는 entry만 선택할 수 있고 production은 이를 절대 활성화하지 않는다.
6. Executor가 유일한 privileged bootstrap provisioner다. Gateway readiness 전에 explicit bootstrap mode가 full stateless namespace ruleset을 inventory하고 byte-exact [`nft_base_chain_v1.nft`](../contracts/enforcement/nft_base_chain_v1.nft)를 raw-file digest `sha256:2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488`로 검증한 뒤 owned table이 없을 때만 owned table/set/chain/rule을 생성한다. Raw digest는 live-schema digest로 사용하지 않는다. Signed read-back은 `inet sentinelflow`만 checked [`nft_base_chain_v1.live.json`](../contracts/enforcement/nft_base_chain_v1.live.json)으로 projection하고 [`nft_base_chain_live_v1.schema.json`](../contracts/enforcement/nft_base_chain_live_v1.schema.json)으로 검증하며 handle/counter를 제외한다. Pinned JCS digest는 `sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997`이다. 두 digest를 모두 요구한다. Full before/after inventory에서 모든 foreign table이 unchanged여야 한다. Restart 때 exact existing owned schema는 base file load나 element TTL refresh 없이 검증하고 partial, extra, duplicated 또는 drifted owned state는 fail closed하며 repair하지 않는다. Normal add/revoke/inspect request는 table, set, chain, base rule을 생성하거나 변경할 수 없다. Check/application 전에 signed inspect로 live digest를 검증한 뒤 fixed-binary `nft --check -f -`를 canonical artifact byte stdin으로 실행한다. Profile startup 전에 capture한 host namespace ruleset digest는 validation과 teardown 시 byte-for-byte invariant여야 한다.
7. Target에 대해 이전 24시간의 retained Gateway/auth evidence를 평가한다. Target의 `verified`, pending, untrusted `succeeded` auth event가 하나라도 있으면 validation을 차단하며 verified failed event만 attack evidence를 지원할 수 있다. Missing history, pending binding, retention gap, source degradation, unavailable impact input도 fail closed한다. Asserted demo/test profile에서만 signed strict [`demo-history-v1` manifest](../contracts/enforcement/demo_history_manifest_v1.schema.json)가 concrete [`demo_history_dataset_v1.json`](../contracts/fixtures/demo_history_dataset_v1.json) locator와 schema에 synthetic complete coverage를 바인딩할 수 있다. Exact field는 `schema_version`, `manifest_id`, `profile`, `clock_at`, `dataset_id`, `dataset_schema_version`, `dataset_digest`, `dataset_record_count`, `import_id`, `coverage_start`, `coverage_end`, `path_catalog_version`, `source_health_digest`, `issued_at`이고 pinned dataset JCS digest는 `sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00`다. Import commit은 exact canonical imported row의 digest를 저장하고 이를 `import_id`, dataset ID/digest, fixed locator에 transactionally bind하므로 arbitrary database seed는 complete history로 인정하지 않는다. Application fake time은 fixture event/coverage time만 정의하고 security freshness와 kernel expiry는 bounded real time을 사용한다. Checked [`demo_history_manifest_v1.json`](../contracts/fixtures/demo_history_manifest_v1.json)은 fixture-only이고 actual demo run은 run-scoped signing key와 manifest를 생성한다. Production은 이 fixture contract를 거부한다.

   `ADR-013`에서 이 proof는 staged authority lifecycle을 통해서만 usable해진다. Demo preparation은 서로 다른 nonzero 32-byte analysis/validation capability를 만든다. Migration은 그 `sha256:` digest만 받고 한 번 pin한 뒤 exact SCRAM credential과 server-side 최대 5분 `VALID UNTIL`로 `sentinelflow_demo_importer`를 연다. Importer는 fixed public bundle을 검증하고 한 번 import하거나 exact completed state에만 attach한 다음 committed fence statement 두 개를 실행한다. 먼저 `NOLOGIN`/password-null/epoch-expired로 만들고 그 다음 session termination과 zero-peer-session을 검증한다. Narrow handoff는 inert importer를 확인하고 `sentinelflow_demo_activator`만 잠깐 연다. Activator는 proof를 재검증하고 동일한 claim과 `clock_timestamp()` activation 뒤 정확히 1시간 expiry를 가진 analysis activation 하나와 validation activation 하나를 atomically 생성한다. 그 뒤 같은 two-phase ordering으로 두 role을 fence한다.

   Analysis/validation service는 각자 자기 capability만 mount한다. Prepare path는 exact existing unexpired consumer activation에만 attach하고 job/aggregate version의 append-only use를 기록할 수 있으며 import, create, refresh, swap 또는 repair할 수 없다. Missing, wrong, stale, expired, partially created 또는 drifted state는 typed non-enforcing result를 반환한다. In-place renewal은 없다. Activation expiry 뒤 recovery는 profile 중지, 전체 disposable demo environment/volume 삭제, 새 signed run/distinct capability 생성 및 fresh isolated PostgreSQL cluster에서 migration/import/activation 재실행을 요구한다.
8. Checked immutable validation snapshot은 policy, incident/evidence snapshot, analysis input/version, generated candidate, canonical byte, grammar/parser/validator version, protected-IPv4 static/effective digest, raw base-file/deterministic live-schema digest, nft binary/version, impact dataset/import locator/ID/digest/result, `valid_until`을 포함한다.
9. Validation `valid_until`을 snapshot 생성 후 5분으로 설정한다. Evidence, generated/canonical diff, target, TTL, impact, check, digest, remaining validity를 관리자에게 표시한다.
10. Exact artifact에 대한 HIL approval/rejection만 수용한다. Approval validity는 최대 5분이며 `decision_valid_until`은 approval time + 5분과 validation `valid_until` 중 이른 시각이다.
11. 유일하게 허용되는 initial execution 직전에 dispatcher가 모든 version/digest, HIL actor/reason, 두 validity timestamp, protected configuration, owned-set schema, nft version policy, evidence-health status, 요청한 전체 relative TTL을 재검사한 뒤 Section 5.3 capability를 발급한다. Relative timeout artifact는 crash/recovery를 포함해 절대 reapply하지 않는다.
12. Executor가 capability syntax/signature/digest를 검증하고 freshness 전에 journal을 lookup하며 SHA-256을 재계산한다. Known exact capability는 terminal/signed-inspect resolution을 반환한다. Unseen capability만 expiry/single use와 target absence를 확인하고 exact `started` record를 durably commit한 뒤 shell 없이 고정 `nft -f -`를 canonical byte stdin으로 한 번 호출하고 exact target membership과 remaining kernel timeout의 signed inspect result를 얻어 `terminal`을 durably commit한다. `ADR-014`에 따라 새 terminal output은 signed read-back interval을 포함한 `execution-result-v2`이고 v1은 historical-only다. Byte-identical duplicate는 nft를 호출하거나 kernel timeout을 갱신하지 않으며 conflicting replay는 실패한다.

Executor는 GPT prose, generated raw candidate, shell command line, arbitrary nft input, stale approval, 다른 byte sequence, non-capability request를 거부한다. Digest/schema/read-back mismatch는 success가 아니라 failure다. `ADR-014`에 따라 reconciliation은 v2 active read-back을 signed `expiry_lower`/`expiry_upper` interval로 해석한다. Lower보다 엄격히 전에 completion된 absence는 `missing_early`, upper 이상에서 시작한 absence는 `expired`, upper 이상에서 시작한 active는 `late_active`다. Boundary-overlapping, missing, invalid, unavailable, mismatched observation은 `indeterminate`다. Upper 전에 시작한 valid active observation만 active state를 보존한다. `missing_early`, `late_active`, indeterminate path는 fail closed하고 alert/audit하며 절대 re-add하지 않는다. Reapplication에는 newly generated candidate, new validation snapshot, new HIL decision, new capability가 필요하다. Reconciliation은 valid active state를 관측하거나 expired/unapproved residue만 제거할 수 있고 TTL 연장, approval 합성, missing state 복원을 할 수 없다.

Read-only inspection은 HIL decision이 아니다. System scheduler는 `reconciliation`, `expiry_confirmation`, `operator_status` 목적에만 [`inspection-authorization-v1`](../contracts/enforcement/inspection_authorization_v1.schema.json)을 만들 수 있다. 이는 original add authorization/artifact, action/policy/version, evidence/validation/live-schema digest, fixed inspect artifact, idempotency key, 짧은 validity에 바인딩되고 dispatcher가 signed inspect capability를 발급한다. 이 authority에는 administrator decision nonce나 administrator reason이 없으며 add, revoke, TTL refresh, schema alteration, mutation artifact substitution을 허용하지 않는다.

### 12.3 결정론적 revoke

Revocation은 model output도 original add approval도 아닌 별도 typed `nft-revoke-v1` operation을 사용한다. Authenticated administrator가 revocation endpoint로 active enforcement action ID, target, original canonical add digest, actor, 비어 있지 않은 reason을 submit한다. 하나의 transaction에서 API가 active state, CSRF/session/re-auth/nonce/idempotency를 검증하고 authorization/audit를 기록하며 deterministic canonical delete artifact를 만든다.

```text
delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }
```

Dispatcher는 이 authorized revoke job만 읽고 action/target/original add digest/revocation artifact digest/actor/reason에 바인딩된 별도 operation capability에 서명한다. Executor는 fixed delete grammar만 허용하고 shell 없이 고정 `nft -f -`를 호출하며 별도 signed inspect capability/result lifecycle로 absence를 확인한다. Already absent는 original idempotent revoked result를 반환하며 add를 authorize하지 않는다. Conflicting target/digest reuse는 실패·감사한다. Successful, failed, indeterminate revocation은 add execution과 동일한 durable two-phase replay journal 및 executor-signed result rule을 사용한다.

### 12.4 관리자 인증과 결정 무결성

v0.1은 관리자 한 명을 지원한다. `ADMIN_PASSWORD_ARGON2ID_HASH`는 Argon2id PHC hash로만 제공하고 source에 저장하거나 log로 기록하지 않는다. Memory 64 MiB, time cost 3, parallelism 2, 16-byte salt, 32-byte derived key보다 낮은 parameter는 startup에서 거부한다. Argon2 작업 전에 in-memory limiter가 canonical direct source당 분당 최대 5회, process 전체 분당 최대 20회 login attempt를 허용한다. Rate-limited response에는 `Retry-After`를 포함하고 모든 invalid user/password case는 동일한 generic failure를 사용하며 persistent account lockout은 없다. Server는 absolute limit 8시간·idle limit 30분의 random opaque server-side session을 사용한다. Persisted session timestamp는 issuance 전에 PostgreSQL microsecond precision의 canonical UTC로 고정해 insert/read-back과 optimistic CAS가 같은 record를 비교하게 한다. Login과 privileged action 후 session을 rotate한다. Cookie는 `HttpOnly`, `SameSite=Strict`, `Path=/`이고 `Domain`은 없으며 TLS가 active이면 `Secure`다.

상태를 변경하는 모든 browser request는 origin-checked synchronizer CSRF token을 `X-CSRF-Token`에 포함해야 한다. Approval, rejection, revocation은 login limit과 별도로 session당 분당 5회 limit을 공유한다. Decision 전에 authenticated client가 intended decision, expected policy/action version, policy/evidence/generated/canonical/validation digest를 포함한 exact-artifact challenge를 요청한다. Validation digest는 protected-IPv4 static/effective configuration과 raw/live owned-schema digest를 transitively bind하고 submitted NFC reason은 consumed decision에서 별도로 digest한다. Stored challenge는 [`hil_challenge_v1.schema.json`](../contracts/enforcement/hil_challenge_v1.schema.json), consumed decision은 [`hil_decision_v1.schema.json`](../contracts/enforcement/hil_decision_v1.schema.json), structured reason은 [`hil_reason_v1.schema.json`](../contracts/enforcement/hil_reason_v1.schema.json)을 따른다. `admin_sessions.authenticated_at`이 15분보다 오래됐으면 challenge issuance는 typed `step_up_required`를 반환한다. 이때에만 password step-up이 Argon2id를 검증하고 `authenticated_at`을 갱신하며 session을 rotate한 뒤 challenge를 발급한다. Fresh session은 challenge를 얻기 위해 password를 다시 보내지 않으며 rotation만으로 `authenticated_at`이 갱신되지 않는다.

Challenge는 session, actor, object/version, intended decision, 모든 exact artifact digest, issue time, 5-minute expiry, consumed state에 바인딩된 CSPRNG opaque nonce digest를 저장하고 raw nonce는 정확히 한 번만 반환한다. Decision 또는 revocation request는 해당 nonce, `Idempotency-Key`, 동일한 exact field, 비어 있지 않은 reason을 제출한다. 하나의 transaction이 freshness와 byte identity를 확인하고 nonce를 consume하며 authorization/audit를 기록하고 approved job을 생성한다. Stale, mutated, expired, missing, replayed challenge는 approval 없이 실패한다. Used idempotency key는 identical request에만 원래 result를 반환하고 conflicting replay를 거부한다. Optimistic concurrency로 artifact version마다 final HIL decision 하나와 active action version마다 revocation authorization 하나만 허용한다.

### 12.5 Audit 실패 의미론

Required pre-application 또는 pre-revocation audit/outbox write와 approved-job creation은 하나의 transaction이다. 실패하면 capability도 execution도 없다. Nft mutation은 성공했지만 result persistence가 실패하면 state를 `indeterminate`로 만들고 이후 transition을 중단하며 alert를 발생시키고 durable executor replay journal과 새로 authorize한 signed inspect lifecycle로 add를 reapply하지 않고 해결한다. Process output이 성공처럼 보였다는 이유만으로 success를 기록하지 않는다.

## 13. REST, internal API, SSE 계약

External base path는 `/api/v1`, internal service path는 `/internal/v1`이다. JSON은 UTC RFC 3339 timestamp, opaque ID, cursor pagination, raw evidence나 internal detail이 없는 `{code,message,trace_id,details}` error를 사용한다.

| Method / path | 목적 | 핵심 계약 |
| --- | --- | --- |
| `POST /api/v1/session/login` | Single-admin login | TLS/local demo boundary를 통한 password, session + CSRF token, rate-limited |
| `POST /api/v1/session/logout` | Session revoke | Session, Origin, CSRF 필수 |
| `GET /api/v1/incidents` | Filtered paginated list | state, kind, source, service, time filter |
| `GET /api/v1/incidents/{id}` | Fact, signal, analysis, policy summary | Observed/deterministic/AI/human/action section 분리 |
| `GET /api/v1/incidents/{id}/events` | Minimized evidence | Typed allowlisted field만 사용, raw request data 없음 |
| `POST /api/v1/incidents/{id}/analyses` | Analysis request/retry | Idempotency key와 expected incident version |
| `GET /api/v1/policies/{id}` | Exact policy/command/validation view | Evidence와 모든 generated/canonical/config/validation digest·validity, valid/invalid/interrupted terminal evidence용 minimized `latest_validation_attempt` |
| `POST /api/v1/policies/{id}/validations` | Exact artifact validation | Expected policy/evidence/generated/canonical digest |
| `POST /api/v1/policies/{id}/decision-challenges` | Exact-artifact HIL challenge 발급 | Session + Origin + CSRF, typed stale-`authenticated_at` response에서만 password step-up, exact version/digest/decision, 아직 reason 또는 `reason_digest` 없음 |
| `POST /api/v1/policies/{id}/decisions` | HIL approve 또는 reject | Session + Origin + CSRF + idempotency + single-use challenge nonce + byte-identical exact digest/decision/reason |
| `GET /api/v1/enforcement-actions/{id}` | Apply/expiry/read-back status | Target, state, time, safe error code |
| `POST /api/v1/enforcement-actions/{id}/revocation-challenges` | Exact-action revocation challenge 발급 | Session + Origin + CSRF, conditional password step-up, exact action/version/target/original digest, 아직 reason 또는 `reason_digest` 없음 |
| `POST /api/v1/enforcement-actions/{id}/revocations` | Deterministic active-rule removal | Session + Origin + CSRF + single-use challenge nonce + idempotency + byte-identical action/target/original digest + reason |
| `GET /api/v1/audit-events` | Audit query | Actor/object/trace/time filter, minimized payload |
| `POST /internal/v1/gateway-events` | Gateway/source-health batch persistence | Exact HMAC `event-batch-v1`, sender/epoch/sequence/idempotency, atomic 1–100 record/256 KiB |
| `POST /internal/v1/auth-events` | Application auth outcome persistence | Exact HMAC `event-batch-v1`, sender/epoch/replay guard, atomic 1–100 `auth-event-v1` record/256 KiB |
| `GET /health/live`, `/health/ready` | Unit별 health | Gateway readiness는 configuration/origin, control readiness는 DB/worker 확인 |

Stale version, digest/challenge mismatch, conflicting idempotency key/batch digest, mutation, consumed challenge, duplicate final decision에는 `409`, typed contract/schema/grammar/safety/internal-batch failure와 expired/malformed challenge에는 `422`, authentication/authorization/CSRF failure에는 `401/403`, rate limiting에는 `429`와 `Retry-After`를 사용한다. `step_up_required`는 `authenticated_at`이 stale일 때만 사용하는 typed authentication response다. Internal batch는 atomic accepted 또는 exact-duplicate result에만 `202`를 반환하며 partial accepted/duplicate/rejected count를 반환하지 않는다.

`latest_validation_attempt`는 `validation_attempt_id`, exact policy/analysis/incident/version binding, terminal `state`, optional `failure_code`와 `failed_gate`, prepared/terminal mutation digest, `completed_at`, ordered gate name/state/result/digest list만 포함한다. Go는 requested policy에 대한 해당 binding, 합법적인 terminal policy/decision/lifecycle 조합, canonical gate prefix를 검증한다. Failed terminal gate는 마지막이어야 하고 attempt failure와 일치해야 한다. TypeScript decoder가 exact binding과 gate check를 반복한다. Valid HIL path는 여전히 별도 immutable `latest_validation` snapshot을 요구한다. Invalid 또는 interrupted attempt evidence는 read-only UI evidence이고 HIL을 disable해야 하며 validation snapshot을 합성하거나 repair할 수 없다.

Incident detail은 base incident row와 함께 `evidence_version`을 capture하고 해당 exact observed version으로 `latest_analysis`를 query하며 그 version 안에서만 attempt를 정렬한다. 다른 version의 numerically latest analysis로 대체하지 않는다. Subsequent read는 captured evidence-version argument를 사용하므로 statement 사이 concurrent incident advance가 newer analysis를 older observed projection에 섞지 못한다. Captured version에 analysis row가 없으면 `latest_analysis`를 omit한다. Provider provenance는 exact하다. Live row는 `openai_responses`를 사용하고 deterministic stub row는 model, reasoning effort 또는 rate-card version을 주장할 수 없다.

Frontend API error는 handwritten exact-field decoder로 decode하며 runtime schema compilation이나 `eval` family code를 사용하지 않는다. Administrator Web deployment는 CSP header를 정확히 하나 emit한다: `default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. Checked deployment parser는 duplicate, multiline, missing, weakened, unpinned directive를 거부한다. Production verification은 emitted JavaScript chunk 전체에서 `eval`, `Function` constructor, string-form timer, WebAssembly dynamic-code-generation marker를 scan한 뒤 exact header 아래 built application을 Chromium으로 load한다. `'unsafe-eval'`은 금지한다.

`GET /api/v1/events/stream`은 `id`, `event`, `data`, heartbeat comment가 있는 `text/event-stream`을 반환한다. Client는 `Last-Event-ID`로 재연결하고 replay gap 뒤 REST snapshot을 다시 읽는다. Event type은 `incident.created|updated`, `analysis.completed|failed`, `policy.validation_updated`, `approval.recorded`, `enforcement.updated`, `source.degraded|recovered`다. Payload는 event/resource ID, time, version, trace ID, 최소 summary만 포함한다. SSE는 command channel이 아니다.

## 14. 장애 모델, 보안, 관측성

| 조건 | 필수 동작 |
| --- | --- |
| Malformed HTTP, ambiguous framing, unknown Host, configured limit | Static server policy로 거부하고 adaptive policy를 만들지 않음 |
| Origin connection failure/timeout | `502`/`504` 반환, queue가 수용하면 minimized event emit |
| Event queue saturation 또는 control-plane outage | Forwarding 지속, degraded interval 시작, drop/degradation metric 증가, affected window에서 block 생성 금지 |
| Gateway process crash | Origin은 private 유지, orchestrator가 Gateway restart, ready 전 health 실패, direct-origin fallback 없음 |
| Database outage | Internal ingestion은 bound 안에서만 실패/buffer, Gateway forwarding 지속, 신규 enforcement 없음 |
| Unclean Gateway restart 또는 permanent batch gap | `unclean_restart` unknown-range loss 또는 exact lost range를 영구 기록, later traffic은 backpressure 없이 진행, overlapping evidence는 block authorize 불가 |
| Event timestamp가 future 60 s/past 5 min을 벗어남 | Untrusted `timestamp_skew`로 저장, detection/analysis/validation/enforcement에서 제외, drop/shift 금지 |
| Worker restart 또는 duplicate job | Lease recovery 후 idempotent rerun |
| AI input이 50 evidence ref/12 KiB 초과 또는 prompt/input schema digest 불일치 | Call 금지, typed `analysis_failed/input_too_large` 또는 `configuration_error`, truncate/runtime instruction 수용 금지 |
| OpenAI missing rate/budget/timeout/rate limit/refusal/incomplete/output-schema error | Atomic reservation, 허용 시 별도 과금 retry 한 번, 이후 unified `analysis_failed`, policy가 validation에 도달하지 않음 |
| Auth binding pending/mismatched/expired 또는 successful-auth history | Attack evidence에서 제외, unverified success가 impact를 보수적으로 invalidate, approval/execution disabled |
| Command grammar, consistency, protected range, nft check, impact, digest, mutation failure | Candidate invalid/stale, exact reason audit, approval/execution 없음 |
| Validation attempt invalid 또는 interrupted | Bound minimized `latest_validation_attempt`만 반환하고 terminal gate evidence를 render하며 HIL disabled 유지, validation snapshot 또는 authority 생성 금지 |
| Validation-attempt claim/result projection mismatch | SQLSTATE `55000`으로 fail closed하고 raw table 또는 JSON detail 없이 generic management API `503` 반환 |
| HIL challenge가 stale, mutated, expired, consumed 또는 replayed | 거부·audit, decision/approved job/capability/execution 생성 금지 |
| Validator 또는 executor unavailable | Approval disabled 또는 queued work 미실행 유지, still-valid recheck 필요 |
| UDS framing/schema/signature/deadline 위반 또는 unsigned inspect result | Exchange 종료, 상황에 따라 failure/indeterminate 분류, mutation/success transition 금지 |
| Journal checksum/sequence/version/torn-tail 또는 fsync uncertainty | Executor readiness fail closed, explicit recovery 요구, truncate-and-continue/mutation 금지 |
| Bootstrap raw-file 또는 live-schema digest mismatch | Gateway profile unready 유지, normal capability로 schema repair 금지, host namespace 불변 |
| Pre-application audit/outbox failure | Enqueue 또는 execute하지 않음 |
| Post-application persistence failure | `indeterminate`, transition 중지, alert, read-back, durable recovery |
| Duplicate add capability/artifact | Nft invoke나 timeout refresh 없이 original journaled result 반환 |
| Expected expiry 전 active rule 소실 | `failed` 표시, alert, auto-readd 금지, new candidate/validation/HIL 필요 |
| Nft application 후 crash | Replay journal과 signed inspect로 relative-timeout add reapply 없이 state 해결 |
| Revocation request 또는 replay | 별도 `nft-revoke-v1` authorization/capability, exact duplicate는 original removal result 반환, add approval 재사용 금지 |
| SSE disconnect | `Last-Event-ID`로 reconnect 후 REST snapshot reload |

Security control은 origin-form HTTP/1.1 parsing, explicit framing/hop/target test, strict private-origin resolution, direct-peer-only identity, regenerated forwarding header, request/path bound, typed path classification, service HMAC/replay protection, atomic batch와 loss interval, minimized storage, prompt-injection isolation, strict Structured Outputs, atomic AI budget reservation, nft grammar fuzzing, exact-digest HIL, CSRF/origin/session/login limit, Ed25519 single-use capability, private UDS, durable replay journal, fixed-binary shell-free execution, read-only filesystem, least-privilege DB role, minimal executor capability를 포함한다. Gateway·control-plane container에는 `NET_ADMIN`이 없고 executor sidecar만 shared Gateway demo namespace 안에서 이를 가진다.

Required Gateway metric은 request count/status/latency, proxy error, active connection, target/protocol/body/host/timeout rejection, queue depth, enqueue outcome, dropped event, batch latency/error/retry, epoch/sequence gap, source degraded duration을 포함한다. Control-plane metric은 auth binding state, event lag, signal/incident count, AI reservation/settlement/budget/latency/error/token, validation failure reason, approval latency, dispatcher/capability/replay outcome, active/expired/revoked/early-missing rule, outbox lag, audit recovery, SSE client를 포함한다.

JSON log는 time, component, outcome, duration, safe resource ID, trace ID를 포함한다. Exact/raw/decoded path, raw URL, query, body, cookie, authorization, arbitrary header, account hash, service HMAC, generated session/CSRF token, AI secret, canonical command byte를 포함해서는 안 된다. OpenTelemetry는 safe ID를 통해 request ID와 incident를 연결할 수 있으며 동일한 attribute denylist를 따른다.

## 15. 배포, 격리, 성능

구현된 Docker Compose topology는 PostgreSQL, migration과 capability-digest pinning, one-shot history importer, authority handoff 및 demo activator, API, private demo origin, Gateway와 namespace-sharing executor, networkless validator와 validation worker, detector, retention/lifecycle/control-metrics worker, Prometheus, dispatcher, frontend, profile-selected simulator 및 정확히 하나의 stub 또는 live analysis worker를 포함한다. Executor의 유일한 normalized Compose dependency object는 `gateway`를 대상으로 `condition: service_started`, `required: true`, `restart: true`를 가진다. 이는 startup/restart ordering만 고정하며 health assertion이나 privilege grant가 아니다. `cmd/ingestor`는 default v0.1 profile에 없으며 나중에 optional adapter profile로 추가할 수 있다.

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

Gateway만 protected TCP port `8080`을 publish하며 protected application client는 Gateway에 직접 연결한다. Isolated demo client는 edge network에서 source `203.0.113.20`을 사용하고 shared Gateway namespace의 protected port에 직접 도달하므로 set membership drop이 demonstrated request path에 영향을 준다. Gateway와 executor는 해당 network namespace만 공유한다. Gateway에는 Linux capability가 없고 executor만 그 안에서 `NET_ADMIN`을 가진다. Executor의 explicit bootstrap mode가 Gateway readiness 전에 pinned table/set/`gateway_input` rule을 만드는 유일한 privileged provisioner이고 normal capability handling은 owned schema를 verify하고 use만 한다. Profile start/teardown은 canonical host-namespace nft JSON digest를 비교하며 host ruleset이 바뀌면 run을 실패시킨다.

Configured certificate/key pair가 있으면 Gateway가 TLS를 직접 terminate할 수 있다. 이 v0.1 protected path 앞에는 Nginx, load balancer, CDN 또는 그 밖의 trusted identity hop을 두지 않는다. 별도 `web` service가 administrator frontend를 serve하고 management network에서 management API/SSE traffic을 proxy하지만 protected-traffic identity source가 될 수 없다. `demo-app` service는 정확히 origin과 ingest network에 join한다. HTTP application listener는 `172.30.0.10:8081`에만 bind하고 auth-event producer는 API `172.31.0.10:8082`에만 연결하며 host port를 선언하지 않는다. API internal ingestion listener는 `172.31.0.10:8082`에만 bind한다. 별도 management listener는 `172.34.0.10:8083`에 bind하고 Compose가 host `127.0.0.1`에만 publish한다. Gateway는 edge, origin, ingest 및 private observability network에 join하고 PostgreSQL, worker, management, AI egress 또는 dispatcher UDS에 접근할 수 없다. Prometheus는 observability에 publish되지 않고 validator는 `network_mode: none`이며 validator UDS만 validation worker와 공유한다.

Database access는 service-scoped credential/grant를 가진 distinct migration-owner, API read/write, worker job, read/report, dispatcher, demo-importer 및 demo-activator role을 사용한다. Demo role 두 개는 PostgreSQL cluster-global이고 평상시 inert이며 별도 server-bounded five-minute bootstrap stage 동안에만 authenticate할 수 있다. 이후 exact `NOLOGIN`/password-null/epoch-expired state와 zero other session을 요구한다. PostgreSQL cluster 하나당 isolated demo profile 하나가 supported boundary다. Dispatcher role은 restricted approved-outbox view만 select하고 narrow stored operation으로 dispatch/result state만 update할 수 있으며 general incident, evidence, session, arbitrary job은 읽지 못한다. Gateway와 executor에는 database credential이 없다. Gateway에는 internal event credential만 준다. Worker에는 OpenAI key와 AI rate card를 주지만 dispatch signing key나 `NET_ADMIN`은 주지 않는다. Analysis/validation worker는 서로 다른 demo-history activation volume을 받고 둘 다 importer/activator credential을 받지 않는다. Dispatcher에는 restricted DB role, Ed25519 private dispatch key, executor-result public key, UDS mount만 준다. Executor에는 dispatch public verify key, 별도 executor-result private signing key, replay-journal volume, UDS mount, namespace-local nft capability만 준다. Dispatcher와 executor에는 OpenAI/admin/general DB secret을 주지 않는다. Ed25519 private file은 single-link, owner-only `0400`/`0600`, auxiliary header가 없는 단일 PKCS#8 PEM block이고 public file은 single-link, group/world non-writable, auxiliary header가 없는 단일 PKIX PEM block이다. 둘 다 non-owner file, symlink, extra block/data, wrong algorithm, public/private role confusion을 거부한다.

Minimum reference environment는 Linux, Docker 24+, Compose v2, nftables, RAM 4 GB다. Development는 stub AI와 dry-run executor를 사용한다. Asserted demo/test profile은 fixture event generation, deterministic detector window, history coverage에만 application fake clock을 inject할 수 있다. HIL/step-up/validation/capability freshness, UDS deadline, executor journal time, nftables kernel expiry는 bounded test tolerance가 있는 real UTC와 monotonic time을 사용하며 fake clock은 이를 extend/rewind할 수 없다. Namespace/schema/host-invariance check 뒤에 이 profile만 signed concrete 24-hour dataset/import fixture와 RFC 5737 exception을 enable한다. Production은 fake-clock, fixture, documentation-range, host-enforcement switch를 거부한다. v0.1에는 host-enforcement profile을 제공하지 않는다. Secret file에는 이름/placeholder만 두고 real value는 Git 밖에 유지한다.

`NFR-012` acceptance는 warm-up 후 동일한 direct origin을 기준으로 4 GB reference environment에서 초당 500 request일 때 Gateway added latency p95 5 ms 이하다. Run은 valid response parity, Gateway-induced 5xx 0건, EventSink/control plane healthy 상태의 event drop 0건으로 5분간 지속되어야 한다. 별도 outage run은 EventSink delivery가 실패할 때 forwarding이 계속됨을 증명한다. Drop과 degradation은 보여야 하고 신규 block은 생성되지 않아야 한다.

## 16. 테스트 전략과 식별자

- `UT-001` optional source parser; `UT-002` event normalization; `UT-003` threshold boundary; `UT-004` correlation window
- `UT-005` exact checked input schema/prompt, complete sorted signal/evidence ref, no truncation, typed `input_too_large`; `UT-006` strict AI output과 sorted/unique/byte-identical evidence array; `UT-007` policy/command parser; `UT-008` protected network/historical impact와 signed-proof claim, distinct consumer capability, exact activation attach/use, expiry, no refresh
- `UT-009` state transition/idempotency; `UT-010` expiry calculation; `UT-011` outbox/lease/retry
- `UT-012` administrator session/CSRF/replay, `authenticated_at`, conditional password step-up, exact challenge, pre-Argon2 login/HIL limiter, generic failure/`Retry-After`; `UT-013` strict UDS frame/envelope, add/revoke/inspect capability, exact two-phase journal/fsync, torn-tail failure, once-only mutation, v2 read-back-interval/signing-domain validation; `UT-014` retention/masking/audit와 signed-result integrity
- `UT-015` resource/performance limit; `UT-016` nft grammar/AST/canonicalization, NFC/JCS/lower-hex digest, protected-IPv4 contract, raw-file/live-schema digest separation
- `UT-017` direct-peer identity, IPv4 mapping, inbound request/trace-ID 제거, origin ID/header sanitation과 regeneration
- `UT-018` route/path-catalog classification과 persistence/telemetry exact-path minimization denylist
- `UT-019` Host/private-origin resolution과 32 KiB/10 MiB/4 KiB/2 KiB/5 s/30 s/60 s Gateway bound
- `CT-001` normalized event schema; `CT-002` AI I/O; `CT-003` CSP-safe exact error decoder, minimized `latest_validation_attempt`, exact policy/analysis/incident/version binding, current-observed-evidence `latest_analysis`, generic projection-failure `503`을 포함한 REST/error; `CT-004` SSE reconnection
- `CT-005` generated client/mock parity; `CT-006` authorization/error mapping; `CT-007` strict 4-byte-BE/16-KiB/2-s UDS, add/revoke HIL과 non-HIL inspection authority, unpadded-base64url capability/artifact/result schema와 Ed25519 signature; `CT-008` AI policy/command/canonical/HIL artifact, JCS evidence equality, budget ledger
- `CT-009` `event-batch-v1`, `gateway-http-v1`, path enum, 두 producer의 source-health, 1..100-record/256-KiB bound, lowercase sender header/body/endpoint binding, exact HMAC, atomic `202` ACK, retry/dedup/`409` conflict/`422` invalid, sequence gap, checkpoint, timestamp skew, unknown-field rejection
- `CT-010` authenticated `auth-event-v1`과 application source-health/checkpoint, endpoint/header/body sender/epoch binding, exact HMAC/replay, pending/verified/untrusted binding, account-hash, outcome, retry/dedup/conflict, sequence contract
- `IT-001` optional TCP log ingestion; `IT-002` optional UDP log ingestion; `IT-003` event→DB; `IT-004` detect→correlate; `IT-005` AI stub
- `IT-006` protected contract, raw/live schema digest, auth race, concrete signed 24h dataset/import fixture, five-minute importer/activator lease, two-phase role/session fencing, atomic one-hour consumer pair, API-only terminal-attempt projection, raw-table/JSON denial, claim/result mismatch fail-closed behavior, exact ACL, PostgreSQL cluster/multi-database guard를 포함한 validation chain; `IT-007` approval→dispatcher→isolated nft와 signed inspect lifecycle, deterministic revocation, command content digest 반복 시 fresh authority identity, exact v2 signed result byte/digest persistence; `IT-008` application fake time과 독립적인 real-kernel expiry/audit/once-only reconciliation, signed lower/upper-bound로 legitimate active, true early-missing, true expiry, late-active, boundary-overlapping indeterminate observation을 분류
- `IT-009` outbox crash/restart와 queued stale-analysis provider-free supersession, true-missing dead letter, unchanged current incident; `IT-010` authentication/exact-challenge issue/consume/step-up concurrency; `IT-011` executor journal crash/torn-tail/fsync recovery와 signed inspect reconciliation; `IT-012` retention/backup/restore
- `IT-013` AI candidate→validation→HIL→Ed25519 dispatcher→shell-free executor, result attestation, budget reservation
- `IT-014` origin-form HTTP/1.1 Gateway→fixed RFC1918 origin response parity와 asynchronous classified minimized event persistence
- `IT-015` EventSink/API/PostgreSQL outage/restart에서 traffic forwarding, permanent/unknown loss와 atomic ACK state 기록, 신규 enforcement 억제
- `E2E-001` credential stuffing; `E2E-002` path scanning; `E2E-003` request burst; `E2E-004` normal traffic/false positive
- `E2E-005` investigation; `E2E-006` approval/rejection; `E2E-007` lifecycle/SSE; `E2E-008` bound invalid/interrupted validation evidence와 disabled HIL을 포함한 UI state matrix; `E2E-009` accessibility/cross-browser와 exact deployment-CSP Chromium 실행 및 all-chunk dynamic-code-generation scan
- `E2E-010` evidence-bound command와 exact-artifact HIL/revocation; `E2E-011` fresh disposable profile→signed history import→atomic one-hour analysis/validation activation→isolated RFC5737 client→Gateway attack→incident→HIL→dispatcher→temporary namespace nft→host change 없는 TTL expiry, expired activation은 full reset 요구
- `E2E-012` public origin bypass attempt 실패와 Gateway path 정상 동작
- `SEC-001` malicious evidence; `SEC-002` prompt injection; `SEC-003` approval replay/concurrency; `SEC-004` secret/redaction
- `SEC-005` protected CIDR; `SEC-006` least privilege/no arbitrary command와 API의 raw validation-attempt table/JSON 거부; `SEC-007` unsafe evidence/XSS; `SEC-008` unauthorized decision UI/API, invalid/interrupted attempt에서 disabled HIL, generic projection-integrity failure
- `SEC-009` CSRF/replay/login과 HIL rate limit/conditional step-up/exact single-use challenge; `SEC-010` Ed25519 add/revoke HIL과 non-HIL read-only inspect capability/private UDS/journal/result/bootstrap least privilege; `SEC-011` command injection/mismatch/additional statement/post-approval mutation/JCS-NFC-digest/evidence-order/content-digest-as-authority/duplicate TTL-refresh attempt
- `SEC-012` origin-form/version/upgrade/trailer/expect/smuggling/framing/equal-or-conflicting Content-Length/encoding/hop/compression/Host confusion, direct-peer/forged identity, DNS rebinding과 mixed A/AAAA rejection을 위한 differential raw-socket Go-parser oracle
- `SEC-013` exact-path/body/query/cookie/authorization/header leakage scan과 origin/network/DB/UDS/host-ruleset bypass
- `SEC-014` demo-history bootstrap role/ACL/session/mount/capability isolation, wrong/stale/expired secret rejection, committed two-phase fence race resistance, raw-capability persistence 금지, activation refresh 금지, cluster-global multi-database fail-closed behavior
- `REC-001` optional ingestion restart; `REC-002` duplicate job; `REC-003` executor crash; `REC-004` database/SSE reconnect
- `REC-005` SSE replay-gap/snapshot; `REC-006` expiry downtime/early-missing/orphan/revocation without re-add, v2 missing/invalid/reversed read-back bracket 및 boundary-overlap indeterminate handling 포함; `REC-007` database와 capability-journal backup/restore, v2 signed read-back-bracket과 persisted-bound equality 및 fail-closed mismatch 포함; `REC-008` timeout refresh 없는 canonical approval/capability replay/restart 및 content 반복 시 fresh authority chain 요구
- `REC-009` Gateway/EventSink/control-plane clean/unclean restart, sender epoch/checkpoint, out-of-order atomic batch ACK와 permanent loss closure가 request backpressure 없이 재개되고 incomplete evidence에서 block을 재구성하지 않음
- `REC-010` renewal 없는 exact completed demo-history import/activation-pair reattachment, failed/importing/drifted/partial/expired state는 non-enforcing 유지, post-expiry recovery는 full disposable profile/volume reset과 reseal 요구

릴리스 E2E는 두 namespace 경우를 구분한다. Gateway-owned namespace가 살아 있는 동안 dispatcher와 executor를 재시작한 뒤 active element가 존재하고 TTL이 증가하지 않으며 새 add가 없음을 요구한다. Gateway container restart는 별도 recovery 경우다. 이는 그 namespace를 폐기하므로 element는 absent로 남아야 하고 자동 재추가되어서는 안 되며 기록된 expiry 전에 signed `inspect_absent`를 통해 early-missing failure/audit 경로로 수렴해야 한다.

HTTP target/path/Host/nft parser에는 table/fuzz test와 pinned Go `net/http` oracle에 대한 differential raw-socket test를 사용하고 detector/fixture history에만 application fake clock, signed concrete demo dataset/import, AI에는 stub, PostgreSQL에는 real role/migration, nft에는 disposable shared Gateway namespace, proxy integration에는 real RFC1918 private origin을 사용한다. Kernel TTL과 security freshness test는 bounded real time을 사용한다. Default CI는 external OpenAI를 stub한다. Secret-gated opt-in smoke test는 pinned Responses API request와 operator rate card를 검증할 수 있지만 merge prerequisite가 되지는 않는다.

Security test는 Go가 accept/reject하는 equal/conflicting `Content-Length`/`Transfer-Encoding`, duplicate/invalid Host, 모든 non-origin target form, HTTP version/upgrade/trailer/expect case, hop/forged request/trace/forwarding header, ambiguous encoded path, oversized/slow body·header, compressed/streamed response, DNS rebinding/mixed address answer, event/challenge/capability replay, malformed/oversized/trailing UDS frame, unsigned inspect, torn/corrupt journal tail, bootstrap/live-schema mismatch, UDS/network isolation, host-ruleset invariance, storage/log/trace leakage를 실행해야 한다. Browser test는 별도 frontend/UI task로 유지하고 loading, empty, error, disabled, success, stale, step-up, permission-denied, revocation, expiry state를 다룬다.

현재 local evidence는 final root backend/data/contract/security/recovery/frontend gate, RUN25 fast Compose evidence, active/revoked action state에 대한 fast browser QA 및 control-plane mutation 없이 `status=ok`을 반환한 1회의 billable `openai_responses`/`gpt-5.6-sol` synthetic `path_scan` result를 포함한다. Previously recorded v2 repair는 이제 Linux native v6 E2E exit `0`도 보유한다. TTL 재적용 없이 실제 kernel TTL expiry, signed absent inspection, audit/recovery/forwarding convergence 및 cleanup 뒤 변경되지 않은 semantic host nftables를 관측했다. Current-tree five-minute 4 GB Linux performance gate도 `GATE_VERDICT=pass`, p95 `533us`, outage overhead `436us`로 exit `0`을 기록했다. Fast browser QA는 sanitized active/revoked screenshot과 함께 exit `0`을 기록했지만 non-release UI evidence다. Current-SHA committed clean-checkout/CI, final release capture 및 release decision은 unresolved다.

`./scripts/check-demo-e2e.sh --fast --browser-qa-hold-seconds 900` RUN25(log SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`)는 fast-path evidence로 유지한다. Repair된 current tree는 이어서 Linux native v6 E2E를 exit `0`으로 실행했다. Unprivileged-Gateway/executor-`NET_ADMIN` boundary, private-origin isolation, coverage/scenario/HIL/recovery/outage forwarding, 실제 kernel TTL expiry, signed read-only absent inspection, audit convergence, TTL 재적용 부재 및 cleanup 뒤 unchanged semantic host nftables를 검증했다. 같은 current tree는 five-minute 4 GB Linux performance gate를 p95 `533us`, outage overhead `436us`, `GATE_VERDICT=pass`로 실행했다. 1회의 billable live `openai_responses`/`gpt-5.6-sol` probe도 persistence 또는 HIL/dispatcher/executor path 없이 `status=ok`을 반환했다. Fast browser QA도 sanitized active/revoked screenshot과 함께 exit `0`을 기록했지만 final release capture 또는 별도 frontend/UI completion을 대체하지 않는다. Current-SHA clean-checkout/CI, release capture/submission evidence 및 release decision은 unqualified다.

## 17. PRD와 ADR 추적성

| Requirement / decision | 설계 절 | 검증 |
| --- | --- | --- |
| `FR-001`~`FR-004` event contract, normalization, persistence | 5, 7, 8, 10, 13 | UT-002/011/014/018, CT-001/009/010, IT-003/014/015, REC-007/009 |
| `FR-005`~`FR-007` deterministic rule과 correlation | 7, 9 | UT-003/004, IT-004, E2E-001~004, REC-009 |
| `FR-008`~`FR-010` compact GPT와 fact separation | 3, 10, 11 | UT-005/006, CT-002/008, IT-005, SEC-002/011/013 |
| `FR-011`~`FR-012` policy와 ordered validation | 10~12 | UT-007/008/016, CT-007/008, IT-006/013, SEC-005/006/010/011/014, REC-010 |
| `FR-013`~`FR-016` HIL, nft, expiry, audit | 5, 7, 10, 12~16 | UT-009/010/012~014/016, CT-007/008, IT-007/008/010~013, E2E-006/007/010/011, SEC-009~011, REC-003/006/008 |
| `FR-017`~`FR-018` dashboard와 SSE | 5, 13, 16 | CT-003~006, E2E-005~009, REC-004/005 |
| `FR-019`~`FR-020` attack과 normal simulation | 9, 15, 16 | E2E-001~004/011/012 |
| `FR-021` evidence-bound command generation | 3, 10~12 | UT-006/016, CT-002/008, IT-005/013, E2E-010/011, SEC-002/011 |
| `FR-022` primary inline fixed-upstream Gateway | 2~6, 15 | UT-019, CT-009, IT-014/015, E2E-011, NFR-012 load gate |
| `FR-023` peer identity, header sanitation, private origin | 3~6, 15 | UT-017/019, IT-014, E2E-012, SEC-012/013 |
| `FR-024` minimized request/response event | 3, 6, 8, 10, 14 | UT-018, CT-009, IT-014, SEC-013 |
| `FR-025` asynchronous isolation과 degradation | 3~7, 14, 15 | CT-009, IT-015, E2E-011, REC-009 |
| `FR-026` authenticated application auth-event adapter | 4, 5, 8, 9, 13~15 | CT-009/010, IT-015, E2E-001, SEC-004/013, REC-009 |
| `NFR-001`~`NFR-011` safety, privilege, traceability, recovery, testability | 3~16 | SEC-001~014, REC-001~010 |
| `NFR-012` Gateway latency/load/forwarding availability | 5~7, 14~16 | UT-015/019, IT-014/015, performance와 outage gate |
| `NFR-013` proxy protocol correctness와 security | 3, 5, 6, 14, 16 | UT-017/019, IT-014, SEC-012 |
| `NFR-014` data minimization과 origin isolation | 3~6, 8, 10, 14~16 | UT-018, CT-009/010, E2E-012, SEC-013 |
| `ADR-010` exact evidence-bound nft artifact | 3, 10~12 | UT-007/008/016, CT-008, IT-006/007/013, SEC-005/006/010/011 |
| `ADR-011` Gateway-first hybrid architecture | 2~9, 13~16 | UT-017~019, CT-009/010, IT-014/015, E2E-011/012, SEC-012/013, REC-009 |
| `ADR-012` frozen v0.1 security와 execution contract | 3~16 | UT-005/006/012~019, CT-002/007~010, IT-006~015, E2E-010~012, SEC-005/006/009~013, REC-003/006~009 |
| `ADR-013` staged non-renewable demo-history authority | 5, 10, 12, 15~16 | UT-008, IT-006, E2E-011, SEC-014, REC-010 |

## 18. 확정 기본값과 미결정 사항

### 18.1 v0.1 확정 사항

`ADR-011`은 Gateway-first hybrid boundary를 고정한다. Go ReverseProxy, 하나의 고정 private upstream, direct-peer identity, regenerated forwarding header, minimized typed event, non-blocking bounded EventSink, 결정론적 rule threshold 4개, authenticated auth event, asynchronous GPT configuration을 사용하며 raw packet sensor나 adaptive Gateway deny artifact는 두지 않는다. `ADR-010`은 exact-artifact nftables path를 고정한다. Accepted `ADR-012`는 affected `ADR-006`, `ADR-010`, `ADR-011` clause를 supersede하고 여기 설명한 proxy protocol, event completeness, dispatcher/executor authority, once-only TTL/recovery, revocation, demo isolation, AI budget, administrator limit을 고정한다. `ADR-013`은 demo-only five-minute importer/activator lease, committed two-phase session fencing, distinct digest-bound consumer capability, one-hour non-renewable activation pair 및 full-reset expiry behavior를 추가로 고정한다. 이 TDD의 limit, time window, model/option, TTL, retention period, single-admin mode, performance acceptance value는 open placeholder가 아니라 implementation default다.

이러한 default를 변경하려면 PRD/TDD/Tasklist를 동기화하고, trust boundary 또는 enforcement semantics를 바꾸는 경우 superseding 또는 amended ADR과 negative test를 추가해야 한다.

### 18.2 Open, post-v0.1 또는 근거 의존 사항

1. Production TLS certificate lifecycle, external load balancer compatibility, explicit trusted-proxy mode. v0.1에는 trusted-proxy mode가 없다.
2. 미래의 모든 HTTP/2 또는 HTTP/3 노출. v0.1은 HTTP/1.1만 명시적으로 advertise하고 accept한다.
3. Load evidence 이후 queue/batch capacity tuning. Tuning이 request-path blocking을 추가하거나 incomplete-evidence enforcement를 허용해서는 안 된다.
4. Post-v0.1 optional log/Syslog adapter set, raw-evidence policy, source-specific normalization.
5. 별도 raw-packet sensor architecture와 privilege boundary.
6. 별도 `http-deny-v1` L7 artifact, validator, approval, distribution, rollback, Gateway cache design.
7. IPv6 nftables grammar/set, multi-origin routing, multi-node ordering, multi-tenant isolation, multi-admin RBAC/step-up authentication.
8. Production backup/export integrity level, long-term audit anchoring, deployment-specific protected CIDR.
9. 모든 production, renewable, multi-database 또는 cross-run history-attestation authority. v0.1 demo role과 activation pair를 재사용하거나 승격할 수 없다.

v0.1 구현 중 이를 암묵적으로 확정하지 않는다. 범위를 확장하기 전에 해당 ADR에 option, evidence, safety impact, compatibility, rollback을 기록한다.
