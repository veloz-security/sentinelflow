# SentinelFlow 5일 Gateway-First Leaf-Agent Swarm WBS

[English](WBS.md) | **한국어**

> 실행 구간: 2026-07-18 ~ 2026-07-22 (Asia/Seoul)
>
> 목표: 구현 완료된 단일 노드 Gateway-first hybrid SentinelFlow v0.1 릴리스 후보
>
> 완료 판정 기준: [TASKLIST.ko.md](./TASKLIST.ko.md)
>
> 실행 상태: release stabilization 진행 중. Tasklist completion은 evidence와 prerequisite를 계속 요구함

## 1. 재기준화 결정

2026-07-18 Gateway-first queue는 실행되지 않은 2026-07-17 log-first queue를 대체했다. 이후 Gateway-first swarm이 shared workspace에 integrated implementation과 local verification evidence를 만들었다. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`는 publish된 baseline이고 외부 clean clone이 `make check`를 통과했으며 post-repair CI rerun은 pending이다. 기존 Syslog/parser Task ID의 의미는 P2 선택형 adapter로 보존하지만 이번 5일 queue와 모든 release gate에서 제외한다.

릴리스는 하나의 fixed private upstream 앞에 inline으로 놓이지만 unprivileged인 reverse-proxy data plane을 구현한다. HTTP request를 직접 관측하고 privacy-minimized event를 비동기로 방출하며 narrow authenticated application-auth event를 받은 뒤 기존 deterministic detection, evidence-bound AI command, ordered validation, exact-artifact administrator HIL, isolated nftables executor model을 유지한다. 이 프로젝트는 general-purpose origin server, raw-packet IPS 또는 adaptive L7 enforcement system이 아니다.

이 문서는 추가 계획 작업이 아니라 실제 구현 일정이다. 결과에는 runnable code, test, browser evidence, recovery/security evidence, synchronized documentation이 있어야 한다. Scaffold, mock-only UI, synthetic shortcut 또는 더 작은 demo MVP는 release contract를 만족하지 않는다.

## 2. 동시성과 지속 relay

Runtime slot은 네 개다.

- `ROOT`: 장시간 orchestration, contract ownership, integration, documentation, release-control slot 하나;
- leaf worker: dependency-ready이고 서로 겹치지 않는 implementation, independent-certification 또는 repair package를 항상 채우는 concurrent slot 세 개;
- queue: 하루 6 wave × 3 worker × 5일 = 정확히 90개 initial leaf(`A001`~`A090`). Tasklist-completion leaf 75개와 그 자체로 Tasklist ID를 완료하지 않는 support/attack-corpus/repair leaf 15개;
- leaf duration: 1~4시간. 4시간 안에 reviewable increment를 인계하지 못하면 split 또는 replace;
- relay duration: runtime continuity가 허용하면 하루 18~24시간 계속하고 accepted integration마다 checkpoint;
- extension: failure는 `Axxx-Rn` 또는 `A091+` repair leaf를 만들고 P0 scope를 줄이지 않은 채 calendar를 연장.

`ROOT`는 `READY`, `RUNNING`, `REVIEW`, `RETRY`, `BLOCKED`, `DONE` queue를 유지하고 wave 종료 전에 다음 prompt를 준비하며 모든 diff를 review하고 dependency order로 integrate한 뒤 affected shard를 재실행한다. Agent status는 completion evidence가 아니다.

### 2.1 현재 실행 checkpoint

Snapshot: 2026-07-20 (Asia/Seoul). 90-leaf table은 dependency 및 ownership plan으로 유지하며 original wave 이후 runtime repair/certification leaf는 descriptive name을 사용할 수 있다. 현재 four-slot roster는 다음과 같다.

| Slot | Active package | Ownership | Current status |
| --- | --- | --- | --- |
| `ROOT` | Orchestration, integration, release control | Shared contract, final gate, cross-package decision | Running. 모든 handoff를 검증하고 publish authority를 유지함 |
| Leaf 1 | `compose_browser_qa` | Local-only Compose browser runner와 exact active/revoked action-state evidence | 최신 macOS fast 실행이 active/revoked browser QA를 통과했다. Revoked phase는 login 재시도나 limit 변경 없이 고정 61초 pre-hash login-window wait를 사용하며 release-level browser certification/screenshot은 pending임 |
| Leaf 2 | `clean_checkout_gate` | Clean checkout과 CI reproducibility, publication authority 없음 | Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`를 clean temporary directory에 외부 clone했고 status는 전후 clean이며 `make check`를 통과했다. Post-repair CI rerun, Linux 및 release gate는 open으로 유지함 |
| Leaf 3 | `docs_sync_current_evidence` | `README.md`와 PRD/ADR/TDD/Tasklist/WBS/readiness 영문·한글 pair | Running. Browser-QA result, exact executor dependency policy 및 open release gate를 동기화하며 task completion은 변경하지 않음 |

완료된 `docker_none_semantics_review`는 `RUN4`가 사용하는 compatibility rule을 독립적으로 제한했다. Running `network_mode:none` container는 EndpointID가 Docker built-in `none` network membership에 정확히 결속되고 address, MAC, DNS, alias, IPAM state가 모두 inert인 경우에만 허용한다. 이 검토는 repair의 선행조건이지 E2E 성공 evidence가 아니다.

현재 execution wave 상태는 다음과 같다.

| Wave | State | Integrated evidence / remaining boundary |
| --- | --- | --- |
| Contract and implementation wave | Published baseline과 local integration | Gateway-first contract, provider-free stale queued-analysis supersession·staged signed-history activation·repeated-content-digest identity·API-only projection을 포함한 33개 migration, backend/control plane, UI, dispatcher/executor, recovery, export, observability, test harness가 존재함. `d66c4b8a4842ad4226cb741e35331ba5b9068520`은 clean-clone `make check` evidence가 있고 post-repair CI rerun은 pending임 |
| Frontend contract certification | Final root rerun passed | Final root rerun이 Vitest file 39개/test 363개와 deployment-CSP Chromium 1/1을 보고했다. CSP-safe error decoder, exact header parser, all-production-chunk dynamic-code-generation scan이 존재한다. 이후 macOS runner가 active/revoked browser QA를 통과했지만 full frontend state/accessibility/visual/release evidence는 pending임 |
| Backend and safety certification | Final root rerun passed | Backend 88-package gate와 PostgreSQL 17.10 33-migration/72-table verifier의 final root rerun이 fresh/restart-noop·`33→24→33`·ACL·sqlc·repeated-content identity·API projection·stale-analysis supersession check를 포함해 통과했다. Native Linux와 release-duration condition은 open임 |
| Compose E2E repair/certification | RUN25 fast와 이후 browser runner 통과, release qualification open | SHA-256 `4702571db361b411449dadc789995348f0254f0a07a1a2aefda36a79b070b877`인 RUN25는 build/start, health/authority/private-origin isolation, exact coverage, 다섯 scenario 전체, stable binding, exact HIL add/inspect/revoke, digest-mismatch rejection, outage forwarding, restart/reconciliation 및 cleanup을 통과했다. 이후 macOS `--run-browser-qa` 실행은 고정 61초 pre-hash login-window wait 뒤 active/revoked browser QA를 통과했다. `--fast`는 native expiry 대신 revoke하고 macOS는 host-ruleset invariance를 인증하지 못함 |
| Supply chain and final release | 이전 full supply-chain 및 clean-clone evidence 유지, final release open | 이전 full rerun 3은 reproducible image/SBOM/Trivy/runtime/lifecycle cleanup을 통과했고 publish된 baseline clean clone도 `make check`를 통과했다. 남은 목표는 post-repair CI rerun, default native-expiry/native host evidence, live OpenAI opt-in, 4 GB performance, final doc/screenshot 및 release decision임 |

Tasklist checkbox는 이 wave ledger보다 엄격하다. Complete 항목은 `M0-001`, `M0-002`, `M0-009`, `M0-015`, `M0-017`, `M0-019`뿐이다. `M0-005`에는 여전히 live OpenAI result가 없고 post-repair CI rerun, native host-nft, reusable worktree, Compose mutation 및 five-minute 4 GB performance evidence가 미완료다. 따라서 현재 release classification은 **Still implementing**이다.

이전 full supply-chain gate는 Docker-mutating E2E work 전에 완료되고 cleanup됐다. 다음 default native-expiry run은 fresh global baseline을 capture하고 다른 Docker-mutating gate와 직렬 실행해야 한다.

## 3. 고정 구현 계약

### 3.1 Gateway data plane

- 보호 application traffic은 Gateway에 직접 도달한다. Cleartext는 origin-form HTTP/1.1만 받고 optional TLS도 Gateway에서 terminate하며 ALPN `http/1.1`만 advertise/accept하고 HTTP/2·h2c·다른 target form은 모두 거부한다. Nginx identity hop은 없으며 trusted proxy chain은 post-v0.1이다.
- Startup에 고정된 `http://` upstream 하나, configured non-broad RFC 1918 origin CIDR, normalized ASCII host allowlist만 지원한다. 모든 DNS result와 dial address는 해당 CIDR 안의 IPv4여야 하고 public·loopback·link-local·metadata·IPv6·mixed·rebinding answer는 fail closed하며 environment proxy는 꺼지고 origin은 public/client network에서 접근할 수 없다.
- Socket peer가 canonical client identity다. Inbound forwarding 및 SentinelFlow request/trace header는 버리고 Gateway가 forwarding header와 `X-SentinelFlow-Request-ID`·`X-SentinelFlow-Trace-ID`를 재생성해 `demo-app`에 전파하며 같은 ID를 `gateway-http-v1`에 한 번 방출한다.
- `gateway-http-v1`은 고정 `protocol: HTTP/1.1`을 쓴다. Exact path data는 bounded transient classifier 안에서만 존재하고 persistence와 AI에는 `route_label`, `path_catalog_version=path-catalog-v1`, fixed `suspicious_path_id` 하나만 전달하며 query string, body, cookie, Authorization 값, exact path, raw credential을 저장하지 않는다.
- 한도는 header `32 KiB`, body `10 MiB`, header timeout `5s`, upstream timeout `30s`, idle timeout `60s`다. Go `net/http` parser test와 byte-crafted differential raw-socket origin-observation harness가 rejection과 origin interpretation이 desynchronize하지 않음을 증명해야 한다.
- Gateway와 `demo-app` event producer는 각각 health-only durable checkpoint, random 128-bit per-boot sender epoch, monotonic sequence, authenticated `source-health-v1`을 소유하고 이는 event spool이 아니다. Delivery는 queue `10,000`, batch 최대 `100`/`256 KiB`, flush `100ms`, endpoint-bound `POST /internal/v1/gateway-events` 또는 `/auth-events`를 사용하며 retry는 exact body/epoch/batch/sequence를 유지한다. Control-plane outage에는 valid traffic을 forward하고 새 block을 만들지 않으며 enforcement evidence가 될 수 없는 gap/degradation/loss를 노출한다.
- Exact `X-Sentinel-Sender-ID`는 body sender와 endpoint/key mapping에 일치해야 한다. 두 endpoint는 ≥32 random byte로 decode되는 endpoint-bound Base64 HMAC key, exact 128-bit unpadded-Base64url nonce, future 최대 `+60s`/past `5m` 비대칭 event skew를 사용한다. Bounded syntax/sender/endpoint/time/body 검사와 constant-time HMAC 뒤 authenticated nonce와 all-or-nothing `202`를 원자 commit하며 invalid auth는 replay capacity를 소비하지 않는다. Auth binding은 최대 `5m`이고 request ID·trace ID·canonical IP·exact `service_label=demo-app`·login-route가 일치해야 한다.
- Gateway에는 database credential/reachability와 `NET_ADMIN`이 모두 없고 Gateway network namespace를 공유하는 executor sidecar만 namespace-local `CAP_NET_ADMIN`을 받는다.

### 3.2 탐지와 lifecycle 기본값

- Path scan: canonical source IP별 `60s` 동안 distinct suspicious path `8`개;
- request burst: source IP별 `10s` 동안 request `120`개;
- brute force: source IP별 `60s` 동안 login-route `401/403` response `10`회;
- credential stuffing: source IP별 `5m` 동안 failure `20`회와 distinct keyed account hash `8`개;
- correlation: canonical source IP와 `5m`; quiet `15m` 뒤 close하고 `30m` 내 reopen;
- retention: 모든 normalized event/evidence `7d`, incident/AI output/policy `30d`, audit `90d`.

### 3.3 AI, HIL, executor 기본값

- OpenAI: `gpt-5.6-sol` Responses API, immutable checked-in schema와 prompt, strict Structured Outputs, `store: false`, reasoning `medium`, tools 없음, stable sorted-unique evidence ref 최대 `50`개/deterministic input `12 KiB`, output `2,048` token, timeout `30s`, concurrency `2`, classified `408/409/429/5xx`에만 retry 1회로 총 2회. Overflow 또는 missing evidence는 call 전에 실패하고 truncate·drop·reorder하지 않으며 configurable demo daily operator budget USD `10` 소진 시 fail closed한다.
- Command와 digest: `inet sentinelflow blacklist_ipv4`만 대상으로 하는 `nft-blacklist-v1` candidate 하나. Structured `ttl_seconds`는 `60..86400`, default `1800`, candidate TTL은 `[1-9][0-9]*(s|m|h)`이고 canonical output은 largest exact unit을 쓴다. Policy·sorted evidence·validation·normalized non-empty reason·HIL authorization은 versioned RFC 8785 JCS와 domain-separated lowercase `sha256:` digest 및 byte-exact vector를 사용한다. Artifact-content digest는 row/lifecycle/authority identity가 아닌 non-unique integrity/lookup value이며 command 또는 inspect byte가 반복돼도 fresh evidence-bound ID, authorization 및 capability를 요구한다. Validation validity는 `5m`, impact lookback은 `24h`다.
- Investigation projection: successful HIL-authorizing validation snapshot과 terminal fail-closed `latest_validation_attempt`는 서로 다른 API contract다. API role만 bounded typed projection을 실행할 수 있고 raw attempt table과 prepared/terminal JSON은 denied 상태를 유지하며 claim/result mismatch는 inconsistent state를 노출하지 않고 generic `503`으로 fail closed한다. Frontend presentation은 별도 dependent workstream이다.
- History: verified·pending·untrusted successful auth, source-loss interval 또는 insufficient history는 approval을 차단한다. Asserted demo/test profile만 exact `demo-app` dataset row/ID·record count/digest·source-health digest·`path-catalog-v1`·deterministic 24-hour coverage에 결속된 signed JCS `demo-history-v1`을 허용한다. Distinct five-minute importer/activator PostgreSQL lease는 committed inert two-phase role/session fence로 종료되고 atomic pair 하나가 analysis/validation에 별도 digest-bound capability를 정확히 1시간 제공한다. Consumer는 attach/use만 하고 refresh는 없으며 expiry는 full disposable profile/volume reset과 reseal을 요구한다. Production은 전체 mechanism을 거부한다.
- Protected target: versioned `protected-ipv4-v1`과 그 digest는 unspecified·loopback·private·link-local·CGNAT·benchmarking·documentation·multicast·reserved·origin/Gateway/executor·management/current-administrator-path target·모든 IPv6를 거부한다. `PROTECTED_CIDRS`는 additive다. 격리 demo는 namespace와 host-ruleset-diff assertion 뒤 RFC 5737만 허용할 수 있고 exact digest가 validation·HIL·capability에 결속된다.
- Administrator: Argon2id PHC 최소 memory `64 MiB`, time `3`, parallelism `2`, salt `16` byte, key `32` byte. Opaque server-side session max `8h`/idle `30m`이며 독립 `authenticated_at`을 갖고 rotation은 이를 refresh하지 않으며 `15m` 뒤 password step-up이 필요하다. Origin-checked synchronizer CSRF와 session/operation/exact-artifact에 결속된 random single-use 최대 `5m` challenge가 approve/reject/revoke를 보호하고 idempotency와 `5/min/session` 제한을 적용한다.
- Authority bridge: minimal non-AI `cmd/dispatcher`만 restricted approved-outbox view와 Ed25519 dispatch key를 사용한다. Add·revoke·read-only inspect는 ≤`60s` single-use RFC 8785 JCS capability와 separately signed result를 사용한다. Private UDS는 4-byte unsigned big-endian length-prefixed request 하나와 response 하나를 각각 최대 `16 KiB`, `2s` deadline으로 허용한 뒤 닫고 strict schema/vector가 zero·short·oversized·second·trailing·unknown·duplicate·non-canonical·replayed·invalidly signed input을 거부한다.
- Executor bootstrap과 journal: Gateway traffic 전에 executor만 byte-exact `nft-base-chain-v1`을 설치하고 raw SHA-256 `2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488`와 별도로 pin한 canonical live read-back digest를 검증한 뒤 readiness를 노출한다. Mutation 전에 checksummed length/version-delimited full-request `started` record가 exact capability/signature/artifact byte를 저장하고 file과 parent directory를 fsync하며 signed terminal result도 fsync한다. Torn/corrupt tail 또는 fsync uncertainty는 truncation 없이 readiness를 실패시킨다. Duplicate와 recovery는 signed read-only inspect만 사용하고 add를 다시 호출하거나 TTL을 refresh하지 않으며 `nft-revoke-v1`은 별도 authorization으로 delete만 가능하다.
- Time: deterministic application time은 fixture·history·validation·approval test에 쓸 수 있지만 minimum `60s` nftables timeout은 actual kernel/monotonic time으로 만료해야 한다. Fake clock 또는 time namespace를 kernel-expiry evidence로 사용할 수 없다.

## 4. Leaf 계약과 소유권

모든 leaf는 base commit, exclusive writable path, frozen input contract, Tasklist ID, deliverable, positive/negative test command, stop condition, handoff target을 받는다. Focused commit 또는 explicit no-change finding, changed path, 정확한 test output, failure-path evidence, compatibility impact, remaining risk를 반환한다.

| Domain | 소유 경로와 경계 |
| --- | --- |
| `FOUNDATION` | Go module, command, config, build/CI. Dependency lock owner는 한 명 |
| `CONTRACT` | `gateway-http-v1`, `auth-event-v1`, OpenAPI, AI/policy/command/HIL/executor schema. 변경은 `ROOT` 승인 |
| `GATEWAY` | Reverse proxy, peer identity, header policy, async emitter. AI·UI·policy·`NET_ADMIN` 없음 |
| `DATA` | `db/`, migration, repository, retention, outbox. Migration owner 한 명 |
| `DETECT` | Aggregation, detector, correlation, state machine. Fixed-clock contract |
| `AI` | Compact input과 untrusted structured analysis/command candidate. Validation·approval·execution·UI 없음 |
| `POLICY` | Parser, AST, canonical byte/digest, protected target, impact, validation snapshot |
| `EXECUTOR` | Isolated authenticated transport, fixed nft invocation, read-back, expiry/recovery |
| `API` | Admin auth, REST/SSE, HIL endpoint, health/degradation DTO. Frontend 구현 없음 |
| `FRONTEND` | `web/` 전용: IA, component, client state, accessibility, browser test. Backend/domain 변경 없음 |
| `OPS-QA` | Compose/network isolation, benchmark, security, recovery, browser, supply-chain, release evidence |
| `DOCS` | README와 bilingual docs. Integrated evidence로만 업데이트 |

Merge train은 `contract → data/migration → Gateway/producer/domain → API/SSE → frontend → Compose/integration → independent security/recovery/browser certification → evidence/docs` 순서다. Backend와 frontend leaf는 소유권을 공유하지 않으며 integration leaf는 양쪽을 검증하되 누락 구현을 대신 완료하지 않는다.

## 5. Release gate

1. **Day 1:** scope와 ADR-012/ADR-013 architecture, build/contract foundation, sender/checkpoint/HMAC/skew 및 request/trace contract, storage/outbox/auth-event boundary, Linux/nft raw/live-schema와 administrator challenge contract, fixed-upstream proxy core, 독립 frontend shell이 reviewable하고 어떤 leaf도 prerequisite보다 먼저 실행되지 않는다.
2. **Day 2:** asynchronous Gateway/`demo-app` event, source health, private-origin 및 Go-parser/differential-raw-socket protocol/security/load gate, 네 deterministic detector, simulator primitive, immutable-schema/prompt/no-truncation AI adapter/provenance가 통과한다.
3. **Day 3:** AI degradation/adversarial/golden 검사와 JCS policy/evidence/validation digest·`protected-ipv4-v1`·staged non-renewable signed history·immutable snapshot·bypass test까지의 전체 ordered policy pipeline이 통과하고 merge-train, worktree, migration-recovery, evidence-ledger foundation도 통합된다.
4. **Day 4:** challenge/password-step-up exact HIL, hardened administrator session, executor-only base-chain bootstrap, strict-UDS add/revoke/inspect, full torn-record-safe journal, signed read-only recovery, real-kernel expiry, audit, safety-path E2E, investigation/SSE API, contract-backed frontend review state가 통과하고 Gateway에는 executor privilege가 없다.
5. **Day 5:** 실제 frontend integration, concrete-history simulator, Compose, private-origin/control-plane-outage E2E, contract/security/recovery/real-expiry/load/soak/browser suite, operational hardening, clean-checkout command, evidence, release regression이 통과한다. P0 실패가 하나라도 있으면 relay를 연장한다.

확장 gate는 기존 suite에 더해 `UT-017~019`, `CT-009~010`, `IT-014~015`, `E2E-011~012`, `SEC-012~014`, `REC-009~010`을 포함한다.

## 6. 90개 Leaf 구현 Queue

Wave는 fixed wall-clock start가 아니라 dependency target이다. Cross-leaf prerequisite는 반드시 더 이른 wave에서 완료되어야 한다. Leaf 하나 안의 여러 Tasklist ID는 왼쪽에서 오른쪽으로 strict 실행하며 owner 하나를 공유하고 같은 wave의 sibling은 절대 prerequisite가 아니다. `ROOT`는 뒤의 독립 leaf를 당길 수 있지만 dependent leaf를 일찍 실행하거나 두 leaf에 같은 path를 맡길 수 없다.

Support leaf에는 Tasklist completion ID가 없다. 이미 고정된 input으로 bounded corpus, independent check 또는 repair-ready evidence를 준비할 뿐 prerequisite를 만족하거나 자기 production code를 인증하거나 canonical completion leaf를 대체할 수 없다.

### Day 1 — Baseline, contract, storage, proxy foundation

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D1-W1` | `A001` — `M0-001` → `M0-002`; scope 뒤 architecture decision 고정 (`CONTRACT`, `DOCS`) | `A002` — read-only repository/decision inventory와 conflict report. Support 전용 (`OPS-QA`) | `A003` — toolchain, PostgreSQL, browser, Linux namespace, nft capability preflight. Support 전용 (`OPS-QA`) |
| `D1-W2` | `A004` — `M0-003` → `M0-006`; backend skeleton 뒤 backend quality gate (`FOUNDATION`) | `A005` — `M0-009`; leaf queue와 exclusive path ownership (`OPS-QA`) | `A006` — `M0-007` → `M0-008`; 독립 frontend skeleton 뒤 browser/a11y quality gate (`FRONTEND`) |
| `D1-W3` | `A007` — `M0-017` → `M0-019`; measurable budget 뒤 Gateway boundary/default (`CONTRACT`) | `A008` — `M0-004` → `M0-005`; safe config 뒤 callable-model preflight (`FOUNDATION`, `AI`) | `A009` — `M0-010`; shared schema, mock, invalidation registry (`CONTRACT`) |
| `D1-W4` | `A010` — `M1-001` → `M1-009`; normalized Gateway/`demo-app` schema, generated ID, checkpoint/source-health, sender/endpoint HMAC/skew vector (`CONTRACT`) | `A011` — `M0-013` → `M0-016`; Linux/nft probe 뒤 raw/live-schema, strict-UDS, grammar/TTL contract (`EXECUTOR`, `OPS-QA`) | `A012` — `M0-015`; Argon2id/session/independent-reauth/challenge/CSRF/rate contract (`API`, `CONTRACT`) |
| `D1-W5` | `A013` — `M1-002` → `M1-003` → `M1-007`; migration, repository, least-privilege DB role (`DATA`) | `A014` — `M0-014`; transactional outbox/topology decision (`DATA`, `CONTRACT`) | `A015` — `M2-010` → `M2-011`; fixed-upstream proxy, regenerated request/trace ID, direct-peer/header policy (`GATEWAY`) |
| `D1-W6` | `A016` — `M1-006`; transactional outbox, lease, retry, dead letter (`DATA`) | `A017` — `M2-014`; `demo-app` auth-event HMAC ingest, checkpoint/source health, exact binding, keyed account hash (`API`) | `A018` — `M7-008`; 독립 design system과 application shell (`FRONTEND`) |

### Day 2 — Gateway 완료, deterministic detection, frozen AI handoff

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D2-W1` | `A019` — `M2-012` → `M2-013`; 동일 request/trace ID, minimized observation, bounded async sender-ID/endpoint HMAC delivery와 source health (`GATEWAY`) | `A020` — `M2-015`; private-origin network와 direct-bypass proof (`OPS-QA`) | `A021` — `M0-011`; root merge train과 sharded CI gate (`OPS-QA`) |
| `D2-W2` | `A022` — `M3-001`; fixed-window aggregation과 exact detector default (`DETECT`) | `A023` — `M2-016` → `M2-017`; Go-parser/differential raw-socket desync suite 뒤 `500 RPS` availability/load gate (`GATEWAY`, `OPS-QA`) | `A024` — `M1-005`; `7d`/`30d`/`90d` retention과 restricted-value deletion (`DATA`) |
| `D2-W3` | `A025` — `M3-003`; brute-force detector boundary suite (`DETECT`) | `A026` — `M3-004`; path-scan taxonomy와 detector (`DETECT`) | `A027` — `M3-005`; request-burst detector (`DETECT`) |
| `D2-W4` | `A028` — `M3-002` → `M3-006`; credential stuffing 뒤 source-IP/`5m` Gateway/auth correlation (`DETECT`) | `A029` — `M8-001`; normal Gateway/`demo-app` checkpoint/source-health baseline simulator (`OPS-QA`) | `A030` — `M9-004`; MIT/public-notice 검증 (`DOCS`) |
| `D2-W5` | `A031` — `M4-001` → `M4-002`; immutable schema/prompt, stable evidence, no-truncation input, inspected Responses request/retry (`AI`) | `A032` — `M8-002` → `M8-005`; credential-stuffing 뒤 brute-force simulator (`OPS-QA`) | `A033` — `M8-003`; path-scan simulator (`OPS-QA`) |
| `D2-W6` | `A034` — `M4-003` → `M4-004` → `M4-009`; strict analysis/command schema, provenance, evidence-bound candidate (`AI`) | `A035` — `M8-004`; request-burst simulator (`OPS-QA`) | `A036` — `M3-007`; suppression과 false-positive reason (`DETECT`) |

### Day 3 — AI assurance와 ordered policy validation

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D3-W1` | `A037` — `M5-001` → `M5-002`; constrained policy 뒤 versioned RFC 8785 JCS/domain-separated digest와 state (`POLICY`) | `A038` — `M3-008`; durable detector/correlator worker (`DETECT`) | `A039` — `M4-006`; injection과 invented-evidence corpus (`AI`, `OPS-QA`) |
| `D3-W2` | `A040` — `M5-003` → `M5-005`; schema gate 뒤 strict parser/AST/canonical byte (`POLICY`) | `A041` — `M4-007`; versioned model/schema/grammar/operator budget (`AI`) | `A042` — `M10-002`; threshold comparison과 false-positive tuning (`DETECT`, `OPS-QA`) |
| `D3-W3` | `A043` — `M5-011` → `M5-004`; consistency 뒤 versioned/digest-bound `protected-ipv4-v1` gate (`POLICY`) | `A044` — `M0-012`; reproducible leaf handoff와 evidence ledger (`OPS-QA`) | `A045` — `M0-018`; recyclable worktree와 deterministic integration harness (`OPS-QA`) |
| `D3-W4` | `A046` — `M5-006` → `M5-007`; owned-set `nft --check` 뒤 concrete signed `demo-app` dataset/`24h` impact gate (`POLICY`, `DATA`) | `A047` — `M1-008`; migration과 backup/restore recovery (`DATA`, `OPS-QA`) | `A048` — `M3-009`; close `15m`/reopen `30m` state machine (`DETECT`) |
| `D3-W5` | `A049` — `M5-008` → `M5-010`; ordered audit 뒤 JCS evidence/validation digest와 immutable `5m` snapshot (`POLICY`) | `A050` — `M4-005`; typed AI outage/budget degradation (`AI`) | `A051` — `M4-008`; deterministic golden corpus와 opt-in live smoke (`AI`, `OPS-QA`) |
| `D3-W6` | `A052` — `M5-009`; bypass, mutation, timeout, TOCTOU negative (`POLICY`, `OPS-QA`) | `A053` — parser/command mutation corpus와 canonical-byte oracle. Support 전용 (`POLICY`, `OPS-QA`) | `A054` — protected-target/CIDR/impact edge corpus와 expected-decision oracle. Support 전용 (`POLICY`, `OPS-QA`) |

### Day 4 — Exact HIL, isolated enforcement, API, contract-backed UI

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D4-W1` | `A055` — `M6-001` → `M6-002` → `M6-014`; independent `authenticated_at`, challenge/reauth API, JCS reason/HIL authorization binding (`API`) | `A056` — challenge/reauth/concurrency/replay/rate/digest-swap vector. Support 전용 (`API`, `OPS-QA`) | `A057` — strict UDS framing/schema/key/digest-mutation adversarial corpus. Support 전용 (`EXECUTOR`, `OPS-QA`) |
| `D4-W2` | `A058` — `M6-003` → `M6-009`; executor-only base-chain bootstrap/raw-live digest, strict-UDS signed add/revoke/inspect (`EXECUTOR`) | `A059` — `M6-013`; Argon2id/session/reauth/challenge/CSRF/replay/rate negative (`API`, `OPS-QA`) | `A060` — administrator challenge/abuse-state model과 typed failure-code oracle. Support 전용 (`API`, `OPS-QA`) |
| `D4-W3` | `A061` — `M6-004` → `M6-010` → `M6-005`; full fsynced journal, signed inspect/read-back, raw-live proof, real-kernel expiry/revoke (`EXECUTOR`) | `A062` — namespace/host diff, signed inspect, actual-`60s` expiry/revoke failure-injection harness. Support 전용 (`EXECUTOR`, `OPS-QA`) | `A063` — audit/full-journal torn-record/fsync/crash/recovery oracle. Support 전용 (`DATA`, `OPS-QA`) |
| `D4-W4` | `A064` — `M6-006` → `M6-011`; full JCS-digest/add-revoke-inspect lifecycle audit 뒤 audit-write integrity (`DATA`, `API`) | `A065` — permission/reauth/challenge/loading/empty/error/success frontend fixture. Support 전용 (`FRONTEND`) | `A066` — unauthorized SSE, replay-gap, reconnect contract probe. Support 전용 (`API`, `OPS-QA`) |
| `D4-W5` | `A067` — `M7-001` → `M7-004`; reauth/challenge/inspect lifecycle API 뒤 authorized SSE replay (`API`) | `A068` — `M6-007` → `M6-012`; signed read-only inspect reconciliation 뒤 recovery/dead-letter alert (`EXECUTOR`) | `A069` — cross-layer ID/JCS/digest/schema/contract drift auditor. Support 전용 (`CONTRACT`, `OPS-QA`) |
| `D4-W6` | `A070` — `M6-008`; challenge/HIL/strict-UDS/full-journal/inspect/real-expiry safety-path E2E (`OPS-QA`) | `A071` — `M7-011` → `M7-015` → `M7-012`; digest review, inert command preview, challenge/password-step-up decision UX (`FRONTEND`) | `A072` — `M7-009` → `M7-010`; incident list 뒤 Gateway/auth/AI evidence detail (`FRONTEND`) |

### Day 5 — Integrated UI, simulation, 운영, release

| Wave | Worker A | Worker B | Worker C |
| --- | --- | --- | --- |
| `D5-W1` | `A073` — `M8-006`; staged importer/handoff/activator, separate one-hour consumer activation, executor bootstrap, strict UDS/full journal, real-kernel-expiry Compose integration (`OPS-QA`) | `A074` — `M7-003`; integrated exact-command/challenge review flow (`FRONTEND`) | `A075` — `M7-002` → `M7-007`; real-contract investigation 뒤 SSE reconnect/gap UX (`FRONTEND`) |
| `D5-W2` | `A076` — `M9-001` → `M10-003` → `M10-007`; deployment, executor-bootstrap/real-expiry soak, torn-journal/DB restore proof (`OPS-QA`) | `A077` — `M7-013` → `M7-005`; signed-inspect/journal/audit component 뒤 integrated lifecycle (`FRONTEND`) | `A078` — `M8-011`; raw-socket, AI-no-truncation, challenge/JCS/UDS/journal/expiry security suite (`OPS-QA`) |
| `D5-W3` | `A079` — `M7-006` → `M7-014`; 전체 UI state/a11y 뒤 independent browser/visual/contract QA (`FRONTEND`, `OPS-QA`) | `A080` — `M8-007` → `M9-002`; full Gateway/HIL/inspect/real-expiry acceptance 뒤 clean-checkout command (`OPS-QA`, `DOCS`) | `A081` — `M8-009`; byte-exact HMAC, AI, JCS digest, UDS, journal, history, add/revoke/inspect compatibility (`CONTRACT`, `OPS-QA`) |
| `D5-W4` | `A082` — `M9-003`; sanitized current screenshot과 topology (`FRONTEND`, `DOCS`) | `A083` — `M8-008` → `M10-006`; performance gate 뒤 frontend performance/a11y/visual hardening (`FRONTEND`, `OPS-QA`) | `A084` — `M10-001` → `M10-004`; lifecycle observability 뒤 retention/export operation (`DATA`, `OPS-QA`) |
| `D5-W5` | `A085` — `M9-005` → `M9-006` → `M10-005`; security evidence, status reconciliation, supply-chain hardening (`OPS-QA`, `DOCS`) | `A086` — `M8-010`; full merge-train regression (`OPS-QA`) | `A087` — independent secret/license/evidence/README-claim audit. Support 전용이며 finding은 repair leaf를 생성 (`DOCS`, `OPS-QA`) |
| `D5-W6` | `A088` — `M9-009` → `M9-007` → `M9-008`; convergence audit, submission evidence, release decision (`OPS-QA`, `DOCS`) | `A089` — security-failure reproduction과 repair standby. Support 전용이며 release approval 아님 (`OPS-QA`) | `A090` — browser/recovery/doc-parity reproduction과 repair standby. Support 전용이며 release approval 아님 (`FRONTEND`, `DOCS`, `OPS-QA`) |

Queue는 same-wave sibling이 concurrent라는 보수적 규칙에서 topologically valid하다. `A088`만 release-decision leaf이고 모든 external prerequisite가 `D5-W5`까지 완료된 뒤 세 ID를 왼쪽에서 오른쪽으로 실행한다. `A089`와 `A090`은 release를 승인할 수 없고 재현된 defect는 decision을 무효화해 `A091+` repair work를 만든다.

## 7. Coverage와 제외

- Queue는 Tasklist의 P0 120개를 각각 정확히 한 번 mapping한다.
- P2 17개인 `M1-004`, `M2-001~009`, `M11-001~007`은 mapping하지 않고 release decision에 영향을 주지 않는다.
- Frontend/UI 작업은 명시적 `FRONTEND` leaf에만 있고 backend, Gateway, policy, executor, data leaf는 UI를 구현하지 않는다.
- `http-deny-v1`, trusted proxy chain, raw-packet sensor는 별도 future work이며 nftables HIL artifact 또는 Gateway privilege boundary를 공유하지 않는다.

## 8. 중단과 복구 규칙

| Trigger | 필수 대응 |
| --- | --- |
| Baseline 미commit 또는 worktree divergence | Code leaf를 중단하고 reviewed baseline 하나를 만든 뒤 worktree recycle |
| Contract drift 또는 overlapping edit | Affected leaf를 freeze하고 `ROOT`가 canonical contract를 선택한 뒤 더 작은 owner로 respawn |
| Model contract unavailable | Offline deterministic work를 계속하되 live-AI release gate는 block하고 secret hygiene 유지 |
| Gateway가 control plane을 기다리거나 spoofed identity를 받고 origin이 public | Downstream release work를 중단하고 Gateway/security repair 우선 |
| Validation/HIL bypass 또는 digest mutation | Executor를 disconnect하고 contract-mocked frontend만 진행하며 repair 후 independent retest |
| Gateway가 `NET_ADMIN`을 얻거나 host nftables 변경 | Enforcement work 중단, isolation 복구, evidence 보존, independent security review 요구 |
| Day 5 P0 failure 또는 unreproducible evidence | Release/scope 축소 금지. Complete 또는 genuinely blocked까지 `A091+` repair 지속 |

## 9. 증거와 Release Decision

Accepted leaf마다 date, leaf ID, base/result commit, path, command, exact result, traceability ID, remaining risk, next package를 기록한다. `ROOT`가 integrated gate를 재실행하고 independent leaf가 security, recovery, browser, release-sensitive behavior를 인증한다.

최종 evidence bundle에는 sender/header/skew와 source-health vector, raw-socket origin observation, deterministic no-truncation AI request capture, JCS policy/evidence/validation/reason/HIL vector, `protected-ipv4-v1`과 raw/live base-chain digest, challenge/re-auth negative case, strict UDS framing, full/torn-journal recovery, signed read-only inspect, actual kernel expiry의 wall-clock record가 있어야 한다. Mock·agent report·deterministic application clock은 이 integrated artifact를 대체할 수 없다.

최종 분류는 다음 중 하나다.

- **Complete v0.1:** P0 120개 completion criteria와 5개 daily gate 모두 reproducible integrated evidence를 가짐.
- **Still implementing:** 하나 이상의 release-blocking package가 남아 relay를 계속함.
- **Blocked:** 외부 prerequisite가 진행을 막고 안전한 in-scope 대안이 없음.

“Demoable MVP” 성공 상태는 없다. 이 WBS 통과는 Git tag, push, publication, submission을 준비하지만 권한을 부여하지 않는다.
