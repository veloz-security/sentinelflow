# SentinelFlow 제품 요구사항 문서 (PRD)

[English](PRD.md) | **한국어**

| 항목 | 내용 |
| --- | --- |
| 문서 상태 | Draft |
| 기준 문서 | [`README.md`](../README.md) |
| 대상 릴리스 | SentinelFlow v0.1 단일 노드 reference implementation / 실험적 연구 릴리스 |
| 최종 갱신일 | 2026-07-19 |
| 제품 범주 | Explainable AI security gateway / Developer Tools |

> "SentinelFlow is an explainable AI security gateway that observes web traffic through an inline reverse proxy, correlates structured evidence, and applies temporary response actions only after strict validation and administrator HIL approval."
>
> — [`README.md`](../README.md)

## 1. 문서 목적과 해석 규칙

이 문서는 `README.md`에 기술된 SentinelFlow의 제품 의도를 구현·검증 가능한 요구사항으로 정리한다. v0.1 목표는 구현 완료된 단일 노드 reference release다. 실제 코드, 영속화, REST/SSE, 브라우저 UI, OpenAI adapter, 격리 nftables 집행, 복구, 성능 및 보안 증거가 함께 동작해야 한다. 이는 production readiness, 고가용성, multi-tenancy 또는 호스트 방화벽 배포를 주장하는 것이 아니다. 현재 구현은 존재하지만 Section 12의 남은 release gate 때문에 complete release를 주장할 수 없다. 이 문서의 요구사항은 다음 기준으로 해석한다.

- **근거**: README의 명시적 문장을 짧게 직접 인용한다.
- **MUST**: v0.1 구현 완료 릴리스 후보에서 반드시 충족해야 하는 요구사항이다.
- **SHOULD**: 릴리스에 필요한 권장 요구이며, 이 PRD와 공개 제한사항을 갱신하는 명시적 제품 결정이 있을 때만 연기할 수 있다.
- **설계 제안**: README에 없는 구체값이나 인터페이스이며 검토 후 확정해야 한다.
- **미결정**: 제품 책임자 또는 구현 검증을 통해 결정해야 한다.

README의 예시 명령, 화면, 배포 상세는 현재 구현과 재실행 증거가 확인한 범위에서만 완료 기능으로 간주한다. Smoke 결과는 더 엄격한 release condition을 충족하지 않는다.

저장소와 README는 프로젝트가 MIT [`LICENSE`](../LICENSE)를 따른다고 명시한다. 최종 제출 metadata와 dependency notice도 이 file과 일치해야 한다.

## 2. 제품 요약

SentinelFlow는 Gateway-first hybrid 보안 시스템이다. v0.1의 주 HTTP sensor는 고정된 단일 private upstream 앞에 배치하는 inline Go reverse proxy이며, 범용 origin web server가 아니다. Gateway는 트래픽에서 sanitized request/response metadata를 직접 만들고 normalized event를 비동기로 발행한다. 인증된 application auth-event adapter는 credential-stuffing 분석에 필요한 account-aware evidence를 제공한다. Nginx access-log 및 Syslog/firewall-log adapter는 post-v0.1 호환 입력으로 남지만 primary ingress가 아닌 optional P2 작업이다.

결정론적 탐지와 상관 분석은 비동기 GPT-5.6 분석 전에 실행된다. GPT-5.6은 공격 가능성과 불확실성을 설명하고 evidence-bound blacklist policy와 제한된 nftables command candidate 하나를 생성한다. 후보는 strict parsing, canonicalization, evidence consistency, safety validation과 관리자 Human-in-the-Loop(HIL)가 exact artifact를 digest로 결속해 승인하기 전까지 신뢰하지 않는 data다. 이후에만 별도 격리 executor가 canonical byte를 받고 digest를 재계산해 shell 없이 임시 규칙을 적용할 수 있다. Gateway 자체에는 `NET_ADMIN` capability가 없다.

### 2.1 제품 흐름

`Client → SentinelFlow Gateway → fixed private upstream` 및 비동기 경로 `sanitized Gateway metadata + authenticated application auth events → normalized events → deterministic detection → source-IP correlation → GPT-5.6 explanation and constrained nftables blacklist command candidate → command grammar/canonicalization and policy-evidence-command consistency → protected-network, owned-set syntax, and impact validation → exact artifact의 digest 기준 administrator HIL approval → isolated shell-free temporary nftables enforcement`

HTTP request path는 GPT-5.6, PostgreSQL 또는 관리자 승인을 기다리지 않는다. 이 순서는 안전 경계이므로 control-plane stage를 생략하거나 GPT-5.6에 직접 실행 권한을 부여하거나 Gateway에 firewall privilege를 부여해서는 안 된다.

## 3. 문제 정의

보안 담당자는 지연되거나 이질적이거나 불완전한 외부 로그에만 의존하지 않고 하나의 source IP가 수행한 path scan, 반복 인증 실패, 다계정 시도와 비정상 request burst를 연결해야 한다. Log-only architecture는 제품이 중요한 request를 관찰하기 전에 parser와 delivery 복잡성을 만든다. Inline Gateway는 request boundary에서 일관된 event를 생성하고, 인증된 application adapter는 HTTP proxy가 안전하게 추론할 수 없는 account semantics를 제공한다.

핵심 제품 문제는 다음 일곱 가지다.

1. 보호 대상 application은 새 origin server를 도입하지 않고도 일관되고 즉시 사용 가능한 HTTP evidence가 필요하다.
2. Gateway가 normalization boundary를 소유하지 않으면 client identity와 forwarding header를 신뢰할 수 없다.
3. 개별 request 및 authentication event만으로는 상관된 공격 sequence가 드러나지 않는다.
4. AI explanation은 유용하지만 untrusted evidence, hallucination, 과도한 response 위험이 있다.
5. Firewall action은 관리자 잠금, 정상 사용자 차단, 광범위 rule 적용을 유발할 수 있다.
6. Inline data plane은 control plane, database, AI 또는 approval outage 중에도 forwarding을 계속해야 한다.
7. Demo, security test와 regression test를 위해 정상·공격 traffic을 재현할 수 있어야 한다.

## 4. 목표와 비목표

### 4.1 v0.1 실제 구현 목표

- Origin-server framework가 되지 않고 하나의 allowlisted private fixed upstream 앞에서 inline Go reverse proxy를 실행한다.
- Incoming forwarding header를 제거하고 TCP peer에서 canonical client identity를 산출하며 trusted forwarding header를 재생성하고 minimized request/response metadata를 비동기로 발행한다.
- Traffic forwarding을 PostgreSQL, AI, administrator decision 및 bounded event queue와 독립시킨다. Degradation과 event loss를 노출하되 valid traffic을 차단하지 않는다.
- Account-aware credential-stuffing evidence를 위한 authenticated application auth event를 수신한다.
- Frozen deterministic threshold로 path scanning, request burst, brute-force login, credential stuffing을 탐지하고 canonical source IP로 incident를 correlate한다.
- Responses API의 `gpt-5.6-sol`로 evidence-linked explanation, uncertainty, possible false positive, constrained policy 및 evidence-bound nftables command candidate 하나를 생성한다.
- Command를 parsing·canonicalization하고 immutable evidence membership과 policy/evidence/command consistency를 확인한 뒤 protected network·owned-set schema 대상 nftables syntax·historical impact를 검증한다.
- v0.1 단일 administrator가 exact artifact를 검토하고 HIL로 명시적으로 승인 또는 거부한다.
- 승인된 차단은 격리된 환경에서 임시 적용되고 자동 만료되며 감사된다.
- 정상, 공격, outage, backpressure, protocol-security, approval 및 expiry scenario를 반복 가능한 simulation과 test로 재현한다.

### 4.1.1 현재 구현 목표 (2026-07-19)

현재 delivery 목표는 승인된 안전 경계를 유지하면서 통합 구현을 재현 가능하고 release-qualified한 v0.1 기준선으로 전환하는 것이다.

1. Gateway data plane은 non-blocking·unprivileged로 유지하고 deterministic detection → AI → exact-artifact HIL → isolated shell-free enforcement → bounded TTL → read-only inspection → fail-closed recovery 순서를 보존한다.
2. Backend/control-plane과 frontend/UI/UX workstream을 독립적으로 유지하고 검증된 상태 변경을 영문·한글 문서에 함께 동기화한다.
3. Signed demo history에서 add, inspect, revoke, outage, restart, audit, cleanup까지의 mutation path를 재현한다. RUN25 fast evidence는 fast path를 포함하고, current-tree native v6 evidence는 TTL expiry, signed absence, recovery, forwarding, audit 및 host-ruleset invariance를 포함한다.
4. Native kernel expiry, host-ruleset invariance 및 five-minute 500-RPS/4-GB performance gate에 대한 독립 Linux evidence를 보존하되 final release는 별도 gate로 유지한다.
5. Committed clean checkout에서 gate를 재현하고 live OpenAI smoke는 명시적·과금되는 opt-in으로만 실행한다. 기본 mode는 deterministic stub으로 유지한다.
6. 최종 release evidence, screenshot, command, limitation 및 decision을 준비하되 모든 release-blocking prerequisite의 evidence가 생기기 전에는 완료를 주장하지 않는다.

### 4.2 비목표

- 모든 공격 탐지 또는 제로 오탐을 보장하지 않는다.
- 범용 origin web server, production WAF, high-availability proxy 또는 multi-tenant service로 운영하지 않는다.
- Raw packet capture, HTTP 하위 payload inspection, eBPF/XDP sensing 또는 in-process packet analyzer는 제공하지 않는다.
- v0.1에서 learned behavioral baseline 또는 multi-node operation은 제공하지 않는다.
- nftables 이외의 WAF·방화벽·클라우드 집행은 v0.1 범위 밖이다.
- AI가 방화벽을 직접 변경하거나 스스로 승인하거나 임의 shell 명령을 실행하지 않는다. AI의 명령 생성은 실행 권한을 부여하지 않는다.
- Gateway의 direct adaptive L7 denial은 제공하지 않는다. 향후 `http-deny-v1` action은 별도 artifact contract와 ADR이 필요하다.
- 호스트 수준의 프로덕션 집행을 기본 사용 경로로 제공하지 않는다.
- Nginx access-log, Syslog/firewall-log, Traefik, Apache, SSH, raw-packet, OpenSearch, SIEM 또는 cloud WAF adapter는 v0.1 완료 조건이 아니다.

> "Raw packet capture and analysis are not part of v0.1."
>
> — [`README.md`](../README.md)

## 5. 대상 사용자와 핵심 작업

### 5.1 보안 분석가

- Gateway 및 authenticated application event에서 상관된 incident를 조사한다.
- 정량 signal과 보존된 minimized evidence를 확인한다.
- AI 설명과 오탐 가능성을 검토해 대응 필요성을 판단한다.

### 5.2 보안 관리자 / 승인자

- 대상, 근거, 예외 CIDR, 기간, canonical nftables command, command digest 및 예상 영향을 검토한다.
- 정확히 검증된 command를 HIL로 승인 또는 거부하고 사유를 남긴다.
- 적용 상태, 자동 만료, 실패, 감사 기록을 확인한다.

### 5.3 개발자 / 데모 운영자

- Docker Compose로 격리된 데모 환경을 실행한다.
- Private demo upstream을 Gateway 뒤에 배치하고 재현 가능한 정상·공격 simulation을 실행한다.
- Proxy, protocol-security, event, detection, correlation, policy 및 enforcement를 자동 테스트한다.

## 6. 범위

### 6.1 입력 원천과 경계

- **v0.1 primary sensor:** 하나의 allowlisted host 및 하나의 fixed private upstream에서 생성되는 SentinelFlow Gateway request/response metadata
- **v0.1 required enrichment:** pseudonymous account hash가 포함된 authenticated application auth event
- **Optional P2/post-v0.1 adapter:** Nginx access log, TCP/UDP Syslog 및 Linux firewall/nftables syslog
- **v0.1 제외:** raw packet capture/analysis 및 direct adaptive L7 enforcement

### 6.2 탐지 시나리오

| 시나리오 | 핵심 신호 | 기대 결과 |
| --- | --- | --- |
| Credential stuffing | 하나의 canonical source IP에서 5분 내 authenticated app failure 20회 이상 및 account hash 8개 이상 | 다계정 공격 후보 사건 생성 |
| Brute-force login | 하나의 canonical source IP에서 60초 내 configured authentication route의 Gateway `401`/`403` response 10회 이상 | Brute-force 후보 사건 생성 |
| Automated path scanning | 하나의 canonical source IP에서 60초 내 configured suspicious path 8개 이상 | Path-scan 후보 사건 생성 |
| Abnormal request burst | 하나의 canonical source IP에서 10초 내 Gateway request 120회 이상 | Automated-abuse 또는 application-layer DoS 후보 incident |

Incident는 canonical source IP와 5분 overlap으로 correlate하고 related event가 15분 동안 없으면 close하며 closure 후 30분 이내 matching evidence가 도착하면 reopen한다.

## 7. 기능 요구사항

### 7.1 Optional legacy 수집과 공통 정규화

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-001 | SHOULD | Post-v0.1 adapter는 Gateway request path의 dependency가 되지 않고 TCP와 UDP로 Syslog를 수신해야 한다. | 두 transport의 P2 adapter fixture가 source와 receive time과 함께 처리되고 malformed message가 Gateway 또는 control plane을 중단하지 않는다. |
| FR-002 | SHOULD | Post-v0.1 source-specific parser는 Nginx access log와 Linux/nftables event를 지원해야 하며, authenticated application event는 FR-026에서 별도로 구현한다. | 구현된 optional adapter별 normal, edge, malformed 및 redaction fixture가 canonical Gateway identity contract를 변경하지 않고 통과한다. |
| FR-003 | MUST | Gateway 및 application-auth record를 공통 event schema로 정규화하고 minimized source-specific evidence만 보존해야 한다. | Core Event Model field를 저장·조회할 수 있고 prohibited HTTP field는 persist되지 않으며 parse failure와 missing field를 추적할 수 있다. |
| FR-004 | MUST | 정규화 이벤트와 사건을 PostgreSQL에 영속화해야 한다. | 재시작 후에도 사건과 연결 증거를 조회할 수 있고 중복 처리 정책이 테스트된다. |

Optional legacy adapter는 기존 ID와 의미를 유지하지만 P2/post-v0.1 작업이며 Gateway-first release gate를 지연시킬 수 없다.

### 7.2 Gateway-first ingress 및 authenticated application event

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-022 | MUST | SentinelFlow Gateway는 하나의 private fixed upstream 앞에서 inline Go reverse proxy로 실행되고 범용 origin server가 아닌 v0.1 primary HTTP sensor 역할을 해야 한다. | Protected app traffic은 Gateway에 직접 도달하고 optional TLS는 Gateway에서 terminate하며 allowed request는 end-to-end로 proxy되고 arbitrary upstream selection, origin file serving, dynamic virtual hosting 및 upstream direct public access가 없으며 admin UI는 별도 endpoint를 사용할 수 있다. |
| FR-023 | MUST | Gateway는 TCP peer에서 canonical client identity를 산출하고 forwarding 및 SentinelFlow identity header를 sanitize하며 확정된 HTTP/1.1 host/origin contract만 수용해야 한다. | Spoofed forwarding/request/trace header는 identity를 바꿀 수 없고 Gateway는 private application에 새 request/trace ID를 제공한다. Go `net/http`만 framing parser로 사용하며 raw-socket differential test는 rejected 또는 safely normalized input이 origin에 최대 한 request로 도달함을 증명한다. Normalized ASCII allowlisted Host와 origin-form HTTP/1.1만 허용되고 fixed upstream의 모든 DNS/dial address는 non-broad RFC 1918 `origin_cidrs` 안에 남는다. |
| FR-024 | MUST | Gateway는 승인된 metadata만 포함하는 versioned sanitized request/response event를 비동기로 발행해야 한다. | `gateway-http-v1`에는 ID/time, canonical source IP, allowlisted host/service, method, fixed `HTTP/1.1`, `route_label`, `path_catalog_version`, allowlisted `suspicious_path_id` 또는 `none`, response status, byte count 및 latency가 포함된다. Exact/raw/decoded path, query string, body, cookie, `Authorization` 및 raw secret-bearing header는 persist되거나 AI context에 들어가지 않는다. |
| FR-025 | MUST | Gateway data plane은 database, AI, HIL 및 enforcement control plane과 격리되고 이들의 outage 또는 bounded-queue saturation 중에도 valid traffic을 계속 forwarding해야 한다. | Request path는 control plane을 기다리지 않는다. `event-batch-v1`은 bounded header sender ID와 endpoint/body digest를 인증하고 header/body sender equality, per-boot epoch, sequence, atomic acknowledgement 및 producer별 checkpoint/source health를 사용하되 event spool은 사용하지 않는다. Saturation, gap, restart loss 또는 receipt 기준 +60초/-5분 밖 record time은 enforcement를 뒷받침할 수 없는 untrusted/incomplete coverage를 만들고 approved TTL rule은 계속 만료된다. |
| FR-026 | MUST | Authenticated application auth-event adapter는 configured authentication route에 대한 신뢰 가능한 account-aware success/failure evidence를 제공해야 한다. | Demo application의 HTTP listener는 origin network address에만 bind하고 producer는 ingest-network API listener에만 도달한다. Gateway가 생성한 request/trace ID, 자체 checkpoint/source-health 및 HMAC replay protection을 사용한다. Pending binding은 최대 5분이고 request ID, trace, source IP, `demo-app` service 및 route가 정확히 일치해야 한다. Verified failure만 attack evidence를 뒷받침하고 mismatch/expiry는 enforcement할 수 없으며 unverified success는 impact approval을 차단한다. |

### 7.3 탐지와 상관 분석

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-005 | MUST | AI 호출 전에 canonical source IP별 measurable Gateway 및 verified-auth signal을 계산해야 한다. | 동일 입력에 동일 signal이 산출된다. `path-catalog-v1`은 `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, `backup_archive`를 고정하며 exact fixture가 8 IDs/60s, burst 120/10s, exact `/login` route 10 `401/403`/60s 및 8 account hash에 걸친 verified failure 20건/5m를 검증한다. |
| FR-006 | MUST | FR-005의 frozen deterministic threshold와 event-time window로 suspicious activity를 탐지해야 한다. | 모든 scenario는 threshold에서 정확히 탐지되고 바로 아래에서는 탐지되지 않으며 정의된 duplicate/order behavior를 허용하고 normal-fixture 결과를 별도 보고한다. |
| FR-007 | MUST | Event를 canonical source IP와 5분 overlap으로 correlate하고 incident는 15분 idle 후 close하며 closure 후 30분 내 matching evidence가 도착하면 reopen해야 한다. | Related Gateway/auth fixture가 stored relation reason과 함께 하나의 incident로 결합되고 unrelated source IP는 분리되며 close, late-event 및 reopen boundary test가 통과한다. |

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> — [`README.md`](../README.md)

### 7.4 AI 분석과 설명

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-008 | MUST | 비동기 AI adapter는 Responses API의 `gpt-5.6-sol`을 reasoning `medium`, `store: false`, no tools 및 immutable checked-in input schema, prompt, strict `sentinelflow_analysis_v1` output artifact로 호출해야 한다. | Contract test가 모든 digest와 outgoing request를 검사한다. Immutable incident version의 enforcement-eligible signal reference 전체를 stable-ID 순으로 truncation 없이 포함하고 duplicate/out-of-order/50개 초과/12 KiB 초과 input은 typed failure가 된다. 완전한 server-side event expansion은 sorted-unique ID 최대 1,000,000개이며 초과 시 sampling하지 않고 `input_too_large`로 실패한다. Concurrency는 2이고 UTC day당 USD 10 budget은 versioned rate와 atomic reservation/settlement를 사용한다. Immutable history가 overtaken을 증명하는 queued version은 provider claim 또는 dead letter 전에 audited `analysis_superseded`로 완료되고 current incident를 mutate하지 않으며, 실제 missing aggregate는 unresolved fail-closed evidence로 남는다. |
| FR-009 | MUST | AI 분석은 incident summary, likely classification, evidence, confidence/uncertainty, possible false positive, proportionate response recommendation 및 FR-021 command candidate를 포함해야 한다. | Output evidence array는 duplicate-free, strictly sorted 및 byte-identical이어야 한다. 30초 attempt 한 번과 classified transient retry 최대 한 번만 허용하고 refusal, incomplete response, timeout, `input_too_large`, schema/evidence-reference failure 또는 budget exhaustion은 typed reason의 유일한 non-enforcing `analysis_failed` state를 설정하며 enforcement를 만들지 않는다. |
| FR-010 | MUST | AI 결과는 관찰된 결정론적 신호 및 증거와 구분되어 표시되어야 한다. | 화면/API에서 관찰 사실, 모델 해석, 미확인 사항을 식별할 수 있다. `latest_analysis`는 incident와 observed evidence-version binding이 current incident projection과 일치할 때만 노출되고 read는 cross-statement consistent하다. |

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> — [`README.md`](../README.md)

Fixed adapter contract는 공식 [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models) 및 [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)를 따른다. Model 또는 schema-version 변경 시 contract revalidation과 문서 갱신이 필요하다. Opt-in `cmd/openaismoke`는 로컬에서 disabled 및 missing-key fail-closed 동작을 증명했고, synthetic `path_scan`과 evidence reference 1개에 대해 `openai_responses`가 `gpt-5.6-sol`을 수락한 1회의 검증된 billable·non-mutating live result도 있다. persistence, HIL, dispatcher 또는 executor path에는 도달하지 않았다.

### 7.5 정책 안전성, 승인과 집행

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-011 | MUST | 대응 제안은 제한된 정책과 schema-bounded nftables 명령 후보를 포함해야 하며 unrestricted shell command여서는 안 된다. | 지원하지 않는 action, 잘못된 IP/CIDR/기간, 추가 statement, shell syntax 및 허용 문법 밖의 command field는 거부된다. |
| FR-012 | MUST | Policy와 command candidate는 structured-output/schema validation, command parsing/canonicalization, policy/evidence/command consistency, protected-network check, owned-set schema 대상 nftables syntax validation, historical-impact analysis를 순서대로 통과해야 한다. | Policy, sorted-unique evidence, validation, normalized reason 및 authorization은 versioned JCS/lowercase SHA-256 contract를 사용한다. Protected-IPv4 file, raw base-chain SHA, canonical live-schema digest, check 및 24-hour impact를 하나의 5분 immutable snapshot에 결속한다. Artifact-content digest는 row, lifecycle 또는 authorization identity가 아닌 non-unique integrity/lookup value이므로 동일한 byte를 반복해도 fresh evidence-bound workflow ID와 authority를 요구한다. Asserted demo profile에서 historical completeness는 5분 one-shot lease로 import된 fresh run-scoped signed proof와 unexpired exact one-hour consumer activation을 추가로 요구하며, failed, stale, missing, timed-out, expired, ambiguous 또는 claim/result-mismatched result는 HIL과 enforcement를 막는다. |
| FR-013 | MUST | 인증된 v0.1 administrator는 HIL을 통해 정확히 검증된 artifact를 검토하고 결정해야 한다. | Argon2id/session/CSRF contract를 적용한다. Exact session/operation/artifact에 결속된 5분 one-use challenge를 발급하고 독립 `authenticated_at`이 15분을 넘으면 password step-up을 요구하며 session rotation은 이를 갱신하지 않는다. Decision consumption은 challenge, idempotency, exact JCS digest, normalized nonempty reason 및 optimistic concurrency를 요구한다. |
| FR-014 | MUST | 격리 executor는 dispatcher가 승인한 정확한 canonical nftables add artifact만 fixed shell-free argument로 실행해야 한다. | Minimal dispatcher는 restricted authorized-operation view를 읽고 private UDS로 strict 16-KiB, 4-byte-big-endian-framed request를 보낸다. Executor만 raw/live base-chain contract를 bootstrap/verify하고 one mutation 전에 exact capability/signature/artifact byte 전체를 포함한 checksummed record를 file/directory fsync한다. Corrupt/torn replay는 fail closed하고 host access 없이 signed result를 반환한다. |
| FR-015 | MUST | 임시 rule은 자동 만료되고 안전한 read-only reconciliation과 별도의 manual revocation을 지원해야 한다. | Native timeout이 rule을 제거한다. 새 executor output은 `execution-result-v2` read-back start/completion time과 positive remaining TTL에 서명하고 lifecycle은 여기서 exact timestamp 하나를 추정하지 않고 lower/upper expiry bound를 보존한다. 별도 서명된 `nft-inspect-v1`은 fixed read-back만 수행하고 mutation할 수 없다. True premature disappearance는 failed/alerted 처리하고 자동 재추가하지 않으며 boundary-overlapping 또는 invalid evidence는 indeterminate/fail closed다. Reapplication에는 새 validation/HIL이 필요하다. Deterministic `nft-revoke-v1`은 owned set에서만 삭제하고 독립 authorize, idempotent read-back 및 audit를 수행한다. |
| FR-016 | MUST | 근거, AI 분석, 명령 후보, canonical command, 검증, HIL 승인/거부, 적용, inspect 및 만료의 전 수명주기를 감사할 수 있어야 한다. | Secret을 노출하지 않고 incident/policy ID로 전체 timeline, canonical JCS byte/digest, signature, journal sequence 및 read-back outcome을 조회할 수 있다. |
| FR-021 | MUST | GPT-5.6은 하나의 canonical IPv4 source address와 bounded timeout을 갖는 evidence-bound `nft-blacklist-v1` command candidate를 생성해야 한다. | 모든 evidence ID가 immutable incident/analysis-input snapshot에 속하고 같은 canonical source address로 resolve되며 policy와 command가 같은 evidence set/target을 사용하고 timeout은 최소 1분, 기본 30분, 최대 24시간이며 command는 `inet sentinelflow blacklist_ipv4`만 대상으로 add-element statement 하나만 포함하고 UTF-8/LF canonical byte와 SHA-256 digest로 처리되며 FR-012/FR-013 전에는 실행되지 않는다. |

### 7.6 조사 UI와 데모

| ID | 우선순위 | 요구사항 | 인수 기준 |
| --- | --- | --- | --- |
| FR-017 | MUST | Dashboard에서 Gateway health/degradation, incident list/detail, normalized minimized event, deterministic signal, AI explanation, evidence-bound blacklist policy, generated/canonical command, command digest, successful validation snapshot, terminal fail-closed validation attempt, HIL approval 및 lifecycle state를 제공해야 한다. | Demo review는 raw prepared/terminal JSON이나 validation-attempt table direct access를 노출하지 않으면서 immutable HIL-authorizing snapshot과 typed failed-attempt projection을 구분하고, 실행될 exact artifact를 숨기거나 dropped telemetry와 forwarded traffic을 혼동하지 않고 완료할 수 있다. Backend/API projection과 frontend/UI/UX presentation은 별도로 소유·검증한다. Production은 `'unsafe-eval'`이 없는 exact checked deployment CSP를 사용하고 API-error decoding은 static이며 emitted JavaScript chunk 전체를 dynamic code generation 대상으로 scan하고 Chromium이 해당 header 아래 built bundle을 실행한다. |
| FR-018 | MUST | Authenticated Server-Sent Events로 server-side state change를 UI에 전달하되 command channel이 되어서는 안 된다. | `GET /api/v1/events/stream`이 ADR-008 event type을 ID 및 heartbeat와 함께 emit하고 reconnect는 `Last-Event-ID`를 사용하며 replay gap은 authorized REST snapshot을 reload하고 client는 resource version으로 deduplicate하며 SSE message가 approve 또는 enforce할 수 없다. |
| FR-019 | MUST | Credential-stuffing, brute-force, path-scanning 및 request-burst simulator는 Gateway와 auth-event adapter를 통해 repeatable traffic을 전송해야 한다. | 문서화된 각 command를 재실행할 수 있고 direct upstream access 없이 exact threshold-boundary fixture에 도달한다. |
| FR-020 | MUST | Normal, attack, outage, saturation, malformed-protocol, spoofed-header, upstream-failure, expiry 및 revocation simulation은 expected outcome을 정의해야 한다. | Asserted demo profile은 disposable RFC 5737 client subnet/source, shared Gateway/executor namespace, application test clock, canonical 24-hour dataset/import ID에 결속된 signed manifest, raw/live base-chain digest 및 host-ruleset before/after evidence를 사용한다. Native nft expiry는 injected clock 대신 bounded real-time Linux test로 검증한다. |

## 8. 비기능 요구사항

| ID | 우선순위 | 요구사항 | 검증 방법 |
| --- | --- | --- | --- |
| NFR-001 | MUST | **안전 실패**: 검증 오류, AI 오류, 승인 부재 시 집행하지 않아야 한다. | 오류 주입 통합 테스트 |
| NFR-002 | MUST | **최소 권한**: Model, Gateway, API 및 general worker에는 executor signing key/capability가 없고 minimal dispatcher만 approved exact job을 서명하며 namespace-sharing executor만 `NET_ADMIN`을 가진다. Demo-history import와 activation은 분리된 short-lived PostgreSQL role 및 서로 다른 analysis/validation capability를 사용하고 long-running worker는 import, activate 또는 다른 consumer capability를 읽을 수 없다. | Credential, mount, DB-role, capability, session 및 execution-path review |
| NFR-003 | MUST | **격리**: Executor sidecar는 Gateway network namespace만 공유하고 digest-owned protected-port input chain이 timeout set을 소비하며 host nftables는 변경하지 않는다. | Traffic-block proof 및 host ruleset before/after comparison |
| NFR-004 | MUST | **입력 보안**: Gateway metadata, application auth event, optional log 및 모든 evidence를 data로 취급하고 embedded text를 model instruction으로 실행하지 않아야 한다. | Prompt-injection 및 malicious-event fixture test |
| NFR-005 | MUST | **비밀 관리**: API 키와 자격 증명을 저장소·로그·모델 출력에 노출하지 않아야 한다. | secret scan, 설정 검토 |
| NFR-006 | MUST | **설명 가능성과 추적성**: 모든 판단과 정책은 근거 이벤트, 신호, 검증 결과, 행위자에 연결되어야 한다. | 사건별 감사 추적 테스트 |
| NFR-007 | MUST | **가역성**: 차단 규칙에는 만료 시간이 있고 제거 결과가 감사되어야 한다. | 시간 기반 수명주기 테스트 |
| NFR-008 | MUST | **결정성**: 동일 이벤트·설정에 대한 정규화, 신호 계산, 규칙 탐지 결과가 재현 가능해야 한다. | golden/fixture 회귀 테스트 |
| NFR-009 | MUST | **복구성**: 재시작, 중복 메시지, torn journal record, SSE 재연결 및 demo-history bootstrap retry가 incident, mutation, TTL refresh, import 또는 activation refresh를 중복 생성하지 않아야 한다. Expired demo-history activation은 전체 disposable profile/volume reset과 새 signed run을 요구한다. | Restart, replay, journal-corruption, signed-inspect, staged-role-fence, activation-expiry 및 full-reset integration test |
| NFR-010 | MUST | **호환성**: 최소 Linux, Docker Engine 24+, Compose v2, 4GB RAM, 최신 브라우저에서 데모가 실행되어야 한다. | 지원 환경 smoke test |
| NFR-011 | MUST | **테스트 가능성**: 백엔드, 프론트엔드, 통합 테스트 명령이 실제 구현과 일치하고 자동 실행 가능해야 한다. | 문서 명령 CI 실행. Long Compose run은 305-second wait 전에 migrated PostgreSQL에서 evidence SQL을 parse한다. |
| NFR-012 | MUST | **Gateway latency 및 forwarding availability**: 4GB reference host의 500 requests/second에서 Gateway-added p95 latency는 5ms 이하여야 하고 event drop은 0이어야 하며, control-plane failure 또는 bounded-queue saturation은 otherwise-valid traffic을 차단하지 않아야 한다. | Repeatable load test와 database/AI/worker/queue fault injection |
| NFR-013 | MUST | **Proxy correctness/security**: Go `net/http`만 framing authority로 사용한다. Origin-form HTTP/1.1, ASCII Host normalization, target/path bound, forwarding/identity/hop header, 100-continue, no trailer/upgrade/auto-decompression, streaming/timeout 및 upstream single-request normalization은 하나의 pinned-toolchain contract를 가져야 한다. | Raw-socket differential proxy test, malformed-message suite, origin request-count proof 및 security review |
| NFR-014 | MUST | **Minimization/origin isolation**: Observed exact path와 prohibited HTTP content는 persist되거나 AI에 들어가지 않고 reviewed synthetic parser fixture에만 exact path를 허용한다. Unpublished private-HTTP origin은 origin address에만 bind하고 auth producer는 ingest에만 도달하며 Gateway에는 `NET_ADMIN` 또는 DB reachability가 없다. | Schema/redaction, synthetic-fixture review, DNS/dial/listener/network reachability 및 capability test |

> "The default demo keeps the upstream private and runs nftables enforcement only inside an isolated container or network namespace."
>
> — [`README.md`](../README.md)

### 8.1 확정된 v0.1 operating bound

| 영역 | v0.1 bound |
| --- | --- |
| Header parser setting | Go `http.Server.MaxHeaderBytes=32768`; selected Go toolchain의 raw-socket test로 실제 accept/reject boundary를 고정하며 raw-wire exact 32-KiB limit로 주장하지 않는다. |
| Request target / classification path | 최대 4 KiB / 2 KiB. Exact path는 persist하지 않는다. |
| Request body | 최대 10 MiB. Bound 내 content는 proxy하지만 persist하거나 AI로 전달하지 않는다. |
| Header-read timeout | 5초 |
| Upstream/request timeout | 30초 |
| Idle timeout | 60초 |
| Reference load | 4GB single-node reference host에서 500 requests/second |
| Gateway overhead | Reference load에서 p95 5ms 이하 |
| Reference load event delivery | Drop 0. Target 밖 bounded-queue saturation은 관찰 가능하고 valid traffic을 차단하지 않는다. |
| AI request | 30초 timeout 및 transient retry 1회 |
| AI worker 및 demo budget | Concurrent analysis 2개. UTC day당 USD 10이며 versioned operator token rate와 atomic conservative reservation을 사용한다. |
| Validation 및 HIL decision validity | 최대 5분. Approval은 validation보다 오래 유효할 수 없다. |
| Evidence lookback | Impact analysis에 24시간 |

## 9. 주요 사용자 여정과 인수 시나리오

### 9.1 공격 사건 조사 및 승인

1. 운영자가 SentinelFlow Gateway를 통해 private demo upstream으로 attack traffic을 보내고, 해당하는 경우 authenticated adapter가 account-aware auth outcome을 발행한다.
2. Gateway는 valid traffic을 forwarding하고 control plane을 기다리지 않고 minimized event를 비동기로 발행한다.
3. 결정론적 엔진이 신호를 계산하고 사건을 생성한다.
4. Correlation은 Gateway와 authenticated application evidence를 canonical source IP로 연결한다.
5. `gpt-5.6-sol`이 bounded structured incident summary를 비동기로 분석한다.
6. 분석가는 화면에서 사실, AI 해석, 불확실성, 오탐 가능성을 검토한다.
7. GPT-5.6이 제한된 policy/command candidate를 반환하면 server가 parsing/canonicalization·evidence consistency를 확인하고 모든 required ordered validation stage를 실행한다.
8. 관리자는 evidence·generated/canonical diff·impact·digest·validity를 검토하고 HIL로 exact artifact를 승인 또는 거부한다.
9. Minimal dispatcher가 승인된 exact digest에 대한 short-lived single-use capability를 서명하고, 그 capability와 canonical byte만 UDS를 통해 shell-free 격리 executor에 전달되어 임시 적용되고 read-back된다.
10. 규칙이 자동 만료되고 전체 과정이 감사 기록에 남는다.

### 9.2 위험 policy 또는 command 거부

- Protected target, invalid IP, unbounded duration, unsupported action, additional nft statement, shell token, invalid syntax, unrelated evidence, policy/command mismatch 또는 post-validation digest mutation을 포함한 policy/command pair를 준비한다.
- 시스템은 해당 검증 단계에서 정책을 실패 처리한다.
- Failed/stale artifact는 승인·집행할 수 없고 swapped approval digest도 거부된다.
- 원인과 입력, 결과는 비밀을 제외하고 감사된다.

### 9.3 모델 장애 또는 악성 로그

- Authenticated event 또는 optional log에 model-manipulation text를 포함하거나 OpenAI API를 unavailable 상태로 만든다.
- 결정론적 탐지와 사건 증거는 유지된다.
- 모델 출력이 없거나 스키마에 맞지 않으면 분석 상태가 명확히 실패로 표시된다.
- 시스템은 AI 분석을 우회해 정책을 자동 집행하지 않는다.

### 9.4 Control-plane outage 및 queue saturation

- PostgreSQL, AI worker 또는 administrator UI를 unavailable 상태로 만들거나 bounded event queue를 saturate한다.
- Gateway는 otherwise-valid traffic을 fixed upstream으로 계속 proxy하고 deterministic protocol/size/timeout control만 적용한다.
- New adaptive block은 생성되지 않고 이미 approved된 nftables rule은 TTL까지 계속 적용된 뒤 만료된다.
- Queue depth, dropped-event count 및 degraded state를 관찰·감사할 수 있고 recovery가 missing evidence를 만들어내지 않는다.

## 10. 제품 UX 요구사항

대시보드는 최소한 다음 정보를 구분해 보여야 한다.

- 사건 상태, 탐지 유형, 시간창, 관련 원천과 대상
- Gateway health, forwarding status, queue depth, dropped-event count 및 degradation reason
- Normalized event 및 보존된 minimized evidence
- 결정론적 수치와 탐지 규칙
- GPT-5.6의 설명, 신뢰/불확실성, 오탐 가능성
- 정책 대상, 예외 CIDR, action, duration, generated command candidate, canonical command 및 digest
- 검증 단계별 결과와 과거 영향
- HIL 승인/거부 actor, time, reason, policy 및 generated/canonical command digest, evidence/validation snapshot digest, validity window
- 적용 규칙, 적용 상태, 만료 시각과 실제 제거 결과

**설계 제안:** 색상만으로 상태를 구분하지 않고 텍스트 레이블을 병행한다. Generated command와 canonical command를 차이 표시와 함께 보여주고 모든 필수 검증 전에는 승인 control을 비활성화한다. Command를 편집하면 approval-ready artifact를 변경하지 않고 새 후보를 만들어 검증을 처음부터 다시 수행한다.

## 11. 데이터, 보안 및 개인정보 요구사항

- Approved normalized metadata와 minimized evidence만 persist한다. Query string, request/response body, cookie, `Authorization` 및 raw secret-bearing header는 persist하거나 AI context에 넣어서는 안 된다.
- Normalized event/evidence는 7일, incident/AI analysis/policy는 30일, audit record는 90일 보존한 후 tested lifecycle job으로 삭제한다.
- OpenAI API 키, 데이터베이스 암호는 환경 설정 또는 비밀 저장소로 주입하고 저장소에 커밋하지 않는다.
- 모델 요청/응답 로깅 시 비밀과 불필요한 원문을 제거한다.
- AI 생성 command를 신뢰하지 않는 데이터로 취급하고 provenance와 digest는 보존하되 shell에는 절대 전달하지 않는다.
- Normal enforcement는 canonical global-unicast IPv4만 허용하고 unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, RFC 5737 documentation, configured management, Gateway/upstream/executor, current-administrator-path target 및 모든 IPv6를 거부한다. `PROTECTED_CIDRS`는 protection을 추가만 할 수 있다. Isolated demo/test profile은 namespace 및 host-ruleset-diff assertion 후 RFC 5737 target만 허용할 수 있다.
- v0.1은 Argon2id password hash, Secure/HttpOnly/SameSite session cookie, CSRF 및 replay protection이 적용된 administrator identity 하나를 사용한다. Multi-role 및 separation-of-duties authorization은 post-v0.1이다.
- Private upstream은 demo network 외부에 publish해서는 안 되고 Gateway는 untrusted forwarding header를 제거한 뒤 자체 header를 재생성해야 한다.

## 12. 성공 기준과 릴리스 게이트

### 12.1 v0.1 실제 구현 및 릴리스 성공 기준

| 기준 | 통과 조건 |
| --- | --- |
| End-to-end | Normal traffic과 네 attack simulation이 Gateway를 통해 private upstream에 도달하고 event generation부터 incident investigation까지 재현되며 approved path는 isolated application과 expiry까지 도달한다. |
| Gateway safety | Spoofed forwarding header, unlisted host, malformed protocol, oversized input, upstream failure, control-plane outage 및 queue saturation이 privilege expansion 없이 명시된 proxy/rejection/degradation behavior를 보인다. |
| Data minimization | Prohibited HTTP field가 persistence, AI request, log, audit payload, fixture 또는 screenshot에 나타나지 않는다. |
| 설명 가능성 | 사건 상세에서 탐지 신호, 증거, AI 해석, 불확실성, 오탐 가능성을 구분해 확인한다. |
| 정책 안전성 | 유효한 policy/command pair는 통과하고 command injection·policy mismatch·protected target·additional statement·unsafe fixture는 해당 단계에서 거부된다. |
| 인간 통제 | Exact policy·generated/canonical command·evidence/validation snapshot digest를 결속한 HIL 승인 전에는 rule이 적용되지 않고 rejection·expiry·post-approval mutation invalidation이 동작한다. |
| 가역성 | 승인된 임시 규칙이 지정 시각에 만료되고 감사 기록에 남으며 expiry classification은 추정한 single timestamp가 아닌 signed v2 read-back bound를 사용한다. |
| 격리 | 데모 전후 호스트 nftables 상태가 변경되지 않는다. |
| 회귀 검증 | 최종 문서의 backend, frontend, integration test 명령이 성공한다. |
| 문서 정확성 | 설치·데모 명령과 스크린샷이 실제 구현과 일치하며 placeholder 표시가 제거 또는 갱신된다. |

현재 evidence는 final root backend/data/contract/security/recovery/frontend gate, RUN25 fast Compose E2E, 이전 clean-clone/hosted-CI evidence 및 synthetic `path_scan`/evidence reference 1개에 대해 `openai_responses`/`gpt-5.6-sol`이 `status=ok`을 반환하고 control-plane mutation이 없었던 1회 billable live OpenAI probe를 포함한다. Current uncommitted implementation은 migration 34와 `execution-result-v2`를 추가했다. Executor-signed read-back lower/upper expiry bound, result/bound reuse 금지, TTL refresh 금지, bounded diagnostic projection을 구현했다. Current-tree Linux native v6 E2E는 exit `0`으로 실제 kernel TTL expiry, signed absent inspection, audit/recovery/forwarding convergence 및 cleanup 뒤 변경되지 않은 semantic host nftables를 증명했다. Current-tree five-minute 4 GB Linux performance gate도 `GATE_VERDICT=pass`, p95 `533us`, outage overhead `436us`로 exit `0`을 기록했다. Fast browser QA는 sanitized active/revoked screenshot과 함께 exit `0`을 기록했지만 non-release UI evidence다. 이 evidence는 여전히 release table을 충족하지 않는다. Current-SHA committed clean-checkout/CI, final release screenshot/submission evidence 및 release decision은 pending이다. 상세 경계는 [구현 준비도](./IMPLEMENTATION_READINESS.ko.md)에 기록한다.

### 12.2 제품 지표 — 설계 제안

확정된 release target 외에도 v0.1에서는 다음을 반드시 계측한다.

- 시나리오별 탐지 성공/실패와 정상 fixture 오탐 수
- Gateway request volume, p50/p95/p99 added latency, upstream error, queue depth, event drop 및 degraded duration
- Event publication → incident creation → AI analysis → validation 단계별 latency
- AI 응답 스키마 실패율 및 재시도율
- 정책 검증 단계별 실패 수
- 승인·거부 비율과 승인까지 걸린 시간
- 임시 규칙 적용·만료 성공률

## 13. 의존성, 가정과 제약

- OpenAI API 네트워크 연결과 GPT-5.6 자격 증명이 AI 분석에 필요하다.
- Primary data plane은 하나의 allowlisted host 및 하나의 fixed private upstream을 사용하는 Go reverse proxy다.
- PostgreSQL은 selected event, incident, policy 및 audit store다.
- Linux/nftables는 집행 테스트에 필요하다.
- 기본 데모 환경은 Docker 및 Docker Compose에 의존한다.
- Selected v0.1 deployment는 single-node이며 minimum 4GB RAM이다.
- README의 기술 스택(Go/chi/pgx/sqlc, React/TypeScript/Vite/MUI, SSE)은 구현 ADR에서 채택 상태를 관리한다.

## 14. 위험과 완화

| 위험 | 영향 | 필수 완화 |
| --- | --- | --- |
| 악성·오형식 로그 | 파서 장애, 모델 조작 | 입력 제한, 안전 파싱, 신뢰하지 않는 데이터 취급 |
| Forwarding-header spoofing 또는 origin bypass | 잘못된 attribution 또는 evasion | TCP-peer canonical identity, forwarding header strip/regenerate, allowlisted host, unpublished fixed upstream |
| Proxy parsing ambiguity 또는 request smuggling | Cross-boundary request confusion | Strict Go HTTP parsing, hop-by-hop sanitation, differential malformed-message/desynchronization test |
| Control-plane outage 또는 queue saturation | Telemetry loss 또는 delayed detection | Valid traffic forwarding, observable bounded queue/drop state, new adaptive block 금지, 정상 TTL expiry |
| Sensitive HTTP data 수집 | Credential 또는 personal-data exposure | Query, body, cookie, authorization 또는 raw secret-bearing header의 persistence/AI 전송 금지 |
| 잘못된 상관 | 사건 왜곡 | 결정론적 연결 이유, minimized evidence, 회귀 fixture |
| AI hallucination/schema drift | 잘못된 explanation·policy·command candidate | Structured I/O, schema rejection, fact/interpretation separation |
| AI command injection, unrelated evidence 또는 policy/command mismatch | 의도하지 않은 firewall 변경 | Strict grammar, AST canonicalization, immutable evidence membership, 단일 owned set, snapshot/digest binding, syntax/impact check, HIL approval, shell-free execution |
| 오탐 차단 | 정상 사용자 영향 | 과거 영향 분석, 보호망, 관리자 승인, 임시 규칙 |
| 관리자 잠금 | 운영 접근 상실 | 관리망 보호, 격리, 만료, rollback 검증 |
| 과도한 권한 또는 forged/replayed execution | 호스트 손상 또는 unauthorized/duplicate block | Restricted dispatcher view, 분리된 Ed25519 key pair, JCS-signed one-shot capability/result, private UDS, two-phase journal, namespace-only executor capability |
| 키 유출 | 계정·비용·데이터 위험 | 저장소 외부 비밀 관리, 로그 redaction, secret scan |
| API 장애 | 분석 중단 | 결정론적 결과 유지, 명시적 `analysis_failed` 상태, 자동 집행 금지 |

## 15. 해결된 결정과 post-v0.1 trigger

기존 v0.1 blocker는 아래와 같이 확정했다. 마지막 네 row는 명시적 post-v0.1 decision trigger이며 single-node reference implementation을 차단하지 않는다.

| ID | 확정 사항 또는 open trigger | 상태 |
| --- | --- | --- |
| OQ-001 | Path scan `8 distinct configured paths/60s`, burst `120 requests/10s`, brute force `10 configured-auth-route 401/403 responses/60s`, credential stuffing `20 failures across 8 account hashes/5m`. | 2026-07-18 해결 |
| OQ-002 | Canonical source IP와 5분 overlap으로 correlate하고 15분 idle 후 close하며 closure 후 30분 내 reopen한다. | 2026-07-18 해결 |
| OQ-003 | Responses API의 `gpt-5.6-sol`, reasoning `medium`, `store: false`, checked-in input schema/prompt/output schema, silent truncation 없는 sorted complete signal reference, no tools, reference 50개/input 12 KiB/output 2,048 token cap, 30초 timeout, transient retry 1회, concurrency 2 및 versioned rate card와 atomic reservation을 사용하는 UTC day당 USD 10. | 2026-07-18 해결 |
| OQ-004 | v0.1 administrator 1명, Argon2id password hash, Secure/HttpOnly/SameSite cookie, CSRF, 독립 저장 `authenticated_at`, 15분 뒤 password step-up 및 validity 최대 5분인 server-issued exact-artifact one-use challenge. | 2026-07-18 해결 |
| OQ-005 | Versioned JCS-digested protected-range contract에 따라 canonical global-unicast IPv4만 허용한다. `PROTECTED_CIDRS`는 protection을 추가만 하고 isolated demo/test profile은 isolation assertion 뒤 RFC 5737 range 세 개만 제거할 수 있다. | 2026-07-18 해결 |
| OQ-006 | Historical-impact lookback은 24시간이며 target의 successful authentication evidence와 insufficient 또는 ambiguous evidence는 blocking이다. | 2026-07-18 해결 |
| OQ-007 | Executor-only bootstrap이 `inet sentinelflow blacklist_ipv4`의 raw/live protected-port chain contract를 검증하고 restricted dispatcher와 framed-UDS executor가 add를 한 번만 apply한다. 별도 signed read-only `nft-inspect-v1`으로 inspect하고 re-add/TTL refresh는 하지 않으며 별도 authorized `nft-revoke-v1`으로만 제거한다. | 2026-07-18 해결 |
| OQ-008 | Event/evidence 7일, incident/AI/policy 30일, audit 90일. Prohibited raw HTTP field는 보존하지 않는다. | 2026-07-18 해결 |
| OQ-009 | 4GB reference host에서 500 requests/second, Gateway overhead p95 5ms 이하, target에서 event drop 0. Saturation은 visible해야 하고 valid traffic을 차단하지 않는다. | 2026-07-18 해결 |
| OQ-010 | README가 MIT `LICENSE`를 참조한다. Dependency notice는 final release에서 재검증한다. | 2026-07-17 해결, 릴리스 검사 잔여 |
| OQ-011 | `nft-blacklist-v1`, `inet sentinelflow blacklist_ipv4`, parsed timeout과 같은 integer `ttl_seconds` 60..86400, largest exact `h`/`m` unit 또는 integer `s` canonicalization, UTF-8/LF byte, SHA-256, validation 및 approval validity 최대 5분. | 2026-07-18 해결 |
| OQ-012 | Production TLS ownership, certificate rotation, horizontal scaling 및 high availability는 production positioning 전 운영 증거와 follow-up ADR이 필요하다. | Open post-v0.1 trigger |
| OQ-013 | Adaptive Gateway `http-deny-v1` action은 별도 typed artifact, validator, digest/HIL contract, test 및 follow-up ADR이 필요하며 nftables approval로 이를 authorize할 수 없다. | Open post-v0.1 trigger |
| OQ-014 | Raw-packet/eBPF/XDP sensor는 별도 least-privilege component여야 하고 privacy, capacity, trust-boundary 및 failure-mode 결정을 follow-up ADR에 기록해야 한다. | Open post-v0.1 trigger |
| OQ-015 | Production 또는 renewable history-attestation mechanism은 demo-only five-minute importer/activator lease와 one-hour non-renewable activation을 별도로 검토된 authority, rotation, revocation, multi-database, recovery 및 audit design으로 대체해야 한다. v0.1은 expiry 뒤 full disposable reset과 reseal만 허용한다. | Open post-v0.1 trigger |

## 16. 요구사항 추적성

| 제품 영역 | 요구사항 | 설계/결정 | 검증/작업 |
| --- | --- | --- | --- |
| Gateway ingress, identity, minimization 및 isolation | FR-022~FR-025 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| Auth event 및 optional adapter | FR-001~FR-004, FR-026 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| 탐지·상관 | FR-005~FR-007 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| AI 설명 및 command generation | FR-008~FR-010, FR-021 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| 정책·HIL 승인·집행 | FR-011~FR-016, FR-021 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| UI·데모 | FR-017~FR-020 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |
| 품질·보안 | NFR-001~NFR-014 | [`ADR.ko.md`](ADR.ko.md), [`TDD.ko.md`](TDD.ko.md) | [`TASKLIST.ko.md`](TASKLIST.ko.md) |

## 17. 관련 문서

- 제품 근거: [`README.md`](../README.md)
- 아키텍처 결정: [`ADR.ko.md`](ADR.ko.md)
- 기술 설계: [`TDD.ko.md`](TDD.ko.md)
- 구현 작업 목록: [`TASKLIST.ko.md`](TASKLIST.ko.md)
- 현재 증거 및 blocker: [`IMPLEMENTATION_READINESS.ko.md`](IMPLEMENTATION_READINESS.ko.md)
