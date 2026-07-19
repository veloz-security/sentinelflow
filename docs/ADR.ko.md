# SentinelFlow 아키텍처 결정 기록 (ADR)

[English](ADR.md) | **한국어**

| 항목 | 내용 |
| --- | --- |
| 문서 상태 | Draft |
| 기준 문서 | [`README.md`](../README.md) |
| 대상 범위 | SentinelFlow v0.1 단일 노드 reference implementation / 실험적 연구 릴리스 |
| 작성일 | 2026-07-19 |
| 연관 문서 | [`PRD.ko.md`](PRD.ko.md) · [`TDD.ko.md`](TDD.ko.md) · [`TASKLIST.ko.md`](TASKLIST.ko.md) · [`IMPLEMENTATION_READINESS.ko.md`](IMPLEMENTATION_READINESS.ko.md) |

> "SentinelFlow is an explainable AI security gateway that observes web traffic through an inline reverse proxy, correlates structured evidence, and applies temporary response actions only after strict validation and administrator HIL approval."
>
> 출처: [README](../README.md)

## 1. 목적과 상태 해석

이 문서는 `README.md`의 SentinelFlow 설계 원칙·trust boundary·architecture와 여기에 기록한 명시적 project-owner decision을 하나의 ADR 모음으로 정리한다. 프로젝트에는 이제 통합 prototype이 있지만 일부 release command와 environment-specific evidence는 아직 검증되지 않았다. 따라서 이 문서의 `채택됨`은 product 또는 safety decision이 implementation baseline으로 확정되었다는 뜻이며 그 자체로 release 또는 운영 검증 완료를 뜻하지 않는다.

상태는 다음과 같이 구분한다.

- **채택됨 — 구현 검증 필요**: README 또는 명시적 project-owner decision이 principle, contract 또는 trust boundary를 확정했다. 코드와 test로 준수 여부를 확인해야 한다.
- **제안됨**: README가 `planned`, `intended`, `expected`, `target` 등으로 설명했다. 구현 과정에서 변경될 수 있다.
- **미결**: README만으로 선택할 수 없는 상세다. 이 문서에서 임의로 확정하지 않는다.
- **대체됨**: 후속 ADR이 결정 전체 또는 명시된 일부를 변경할 때 사용한다. ADR-010은 ADR-003과 ADR-004의 명령 생성 경계만 대체하며, ADR-011은 optional adapter와 공통 정규화를 유지한 채 log-first primary-ingress 가정만 대체하고, ADR-012는 ADR-006·ADR-010·ADR-011에서 명시한 executor authority 및 recovery reapplication mechanics만 대체하며 compatible edge와 delivery contract는 축소하거나 완성한다.

## 2. 결정 목록

| ID | 제목 | 상태 | 관련 요구사항 |
| --- | --- | --- | --- |
| [ADR-001](#adr-001-결정론적-탐지를-ai-분석보다-먼저-수행한다) | 결정론적 탐지 우선 | Accepted(채택됨) — 구현 검증 필요 | FR-005~FR-007, FR-025~FR-026, NFR-008 |
| [ADR-002](#adr-002-공통-스키마로-정규화하고-minimized-evidence를-보존한다) | 정규화 및 minimized evidence 저장 | Accepted(채택됨) — source priority는 ADR-011에서 갱신, path representation은 ADR-012에서 축소 | FR-001~FR-004, FR-024, FR-026, NFR-014 |
| [ADR-003](#adr-003-gpt-56의-역할과-신뢰-경계를-제한한다) | GPT-5.6 역할 제한 | Accepted(채택됨) — 명령 생성 경계는 ADR-010이 대체 | FR-008~FR-010, FR-021, FR-024~FR-025, NFR-004~NFR-005, NFR-014 |
| [ADR-004](#adr-004-임의-명령-대신-구조화-정책과-검증-파이프라인을-사용한다) | 구조화 정책 및 검증 | Accepted(채택됨) — 명령 생성 경계는 ADR-010이 대체 | FR-011~FR-012, FR-021, NFR-001~NFR-002 |
| [ADR-005](#adr-005-관리자-승인-전에는-정책을-집행하지-않는다) | 인간 승인 | Accepted(채택됨) — 구현 검증 필요 | FR-013, FR-021, NFR-001~NFR-002, NFR-006 |
| [ADR-006](#adr-006-nftables-집행은-임시가역적으로-수행하고-데모를-격리한다) | 임시 nftables 및 격리 | Accepted(채택됨) — 명시된 실행/복구 mechanics는 ADR-012가 대체 | FR-014~FR-016, NFR-001~NFR-003, NFR-006~NFR-009 |
| [ADR-007](#adr-007-go와-react-stack을-명시적-process와-module-경계로-사용한다) | 기술 스택 및 모듈 경계 | Accepted(채택됨) — 구현 증거 존재, release 검증 미완료 | FR-001~FR-026, NFR-002, NFR-010~NFR-014 |
| [ADR-008](#adr-008-sse를-administrator-state-delivery-mechanism으로-사용한다) | Server-Sent Events | Accepted(채택됨) — 구현 검증 필요 | FR-017~FR-018, FR-025, NFR-009 |
| [ADR-009](#adr-009-전-수명주기를-감사하고-로그와-비밀을-신뢰-경계-밖에-둔다) | 감사 및 보안 통제 | Accepted(채택됨) — 구현 검증 필요 | FR-003, FR-008~FR-016, FR-021, FR-024~FR-026, NFR-001~NFR-007, NFR-014 |
| [ADR-010](#adr-010-근거-기반-ai-생성-nftables-blacklist-명령-후보를-hil로-승인한다) | HIL 기반 AI 생성 nftables blacklist 명령 후보 | Accepted(채택됨) — 명시된 executor/recovery mechanics는 ADR-012가 대체 | FR-011~FR-016, FR-021, NFR-001~NFR-009 |
| [ADR-011](#adr-011-data-plane과-control-plane을-분리한-gateway-first-hybrid-architecture를-채택한다) | Gateway-first hybrid data/control-plane 분리 | Accepted(채택됨) — edge/delivery mechanics는 ADR-012가 구체화하고 executor-authority clause는 대체 | FR-022~FR-026, NFR-001~NFR-002, NFR-012~NFR-014 |
| [ADR-012](#adr-012-gateway-edge-delivery-once-only-enforcement-protocol을-확정한다) | Gateway edge, delivery integrity, exact AI/HIL contract 및 once-only enforcement protocol | Accepted(채택됨) — 구현 증거 존재, integrated release 검증 미완료 | FR-008~FR-016, FR-020~FR-026, NFR-001~NFR-003, NFR-006~NFR-009, NFR-012~NFR-014 |
| [ADR-013](#adr-013-renewable-worker-privilege-없이-demo-history-authority를-stage하고-expire한다) | Staged non-renewable signed demo-history authority | Accepted(채택됨) — targeted implementation evidence 존재, release 검증 미완료 | FR-012, FR-020, NFR-001~NFR-002, NFR-006, NFR-008~NFR-011 |

FR/NFR 식별자는 [`PRD.ko.md`](PRD.ko.md)의 기능·비기능 요구사항을 기준으로 한다. 범위 표기 `FR-005~FR-007`은 두 끝을 포함한 연속 ID 전체를 뜻한다.

---

## ADR-001: 결정론적 탐지를 AI 분석보다 먼저 수행한다

### 상태

**채택됨 — 구현 검증 필요.** Deterministic-first 처리는 안전 원칙이며 v0.1 threshold와 incident lifecycle을 확정했다.

### 맥락

서로 다른 로그의 개별 이벤트는 중요도가 낮아 보일 수 있다. 모든 원시 로그를 바로 모델에 전달하면 README가 요구하는 측정 가능한 근거와 재현 가능한 처리 순서를 보장하기 어렵다.

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> 출처: [README](../README.md)

### 결정

**확정된 원칙**은 다음과 같다.

1. Minimized Gateway 및 authenticated application event에서 canonical source IP별 measurable signal을 먼저 계산한다.
2. Model 분석 전에 deterministic event-time rule을 실행한다. Path scan은 60초 내 configured suspicious path 8개, burst는 10초 내 request 120회, brute force는 60초 내 configured authentication route의 `401`/`403` response 10회, credential stuffing은 5분 내 failure 20회 및 account hash 8개 이상이다.
3. Canonical source IP와 5분 overlap으로 correlate하고 15분 idle 후 close하며 matching evidence가 closure 후 30분 내 도착하면 reopen한다.
4. AI 설명과 관찰된 신호를 구분하여, 사건의 탐지 근거가 모델 출력에만 의존하지 않게 한다.

Duplicate, late-event 및 order semantic은 deterministic해야 하고 exact boundary에서 test한다. Configured suspicious path 및 authentication route는 versioned input이며 reviewed decision 없이 frozen numeric default를 변경하지 않는다.

### 대안

- **원시 로그 전체를 AI에 직접 전송**: README가 명시적으로 선택하지 않은 방식이다.
- **학습형 기준선만 사용**: MVP의 알려진 한계가 규칙 기반 임계값이라고 명시되어 있어 현재 범위가 아니다. 향후 조직별 행동 기준선은 Roadmap 후보다.
- **수동 상관 분석만 제공**: 프로젝트의 핵심 흐름인 자동 탐지·상관과 맞지 않아 현재 설계에 포함되지 않는다.

README는 대안 간 정량 비교 결과를 제공하지 않는다.

### 결과

- 동일 입력과 설정에 대한 신호·탐지 결과를 반복 검증할 수 있어야 한다.
- GPT-5.6 장애가 탐지 근거 자체를 없애지 않는다.
- 규칙 유지·튜닝 비용이 생기며, 제한된 규칙은 알려지지 않은 공격을 놓치거나 오탐을 만들 수 있다.
- 이 결정은 모든 공격 탐지를 보장하지 않는다.

---

## ADR-002: 공통 스키마로 정규화하고 minimized evidence를 보존한다

### 상태

**채택됨 — source priority는 ADR-011에서 갱신하고 path representation은 ADR-012에서 축소, 구현 검증 필요.** Shared normalization과 evidence traceability는 계속 채택 상태다. ADR-011은 Gateway metadata를 primary source로 만들고 Nginx/Syslog receiver를 optional P2/post-v0.1 adapter로 이동하며, ADR-012는 exact-path persistence를 금지해 minimization 원칙을 구현한다.

### 맥락

Gateway traffic, authenticated application event 및 optional future log adapter는 서로 다른 형식을 사용한다. 계산과 상관 분석에는 공통 field가 필요하지만 raw HTTP content는 피할 수 있는 secret, privacy, storage 및 prompt-injection 위험을 만든다.

### 결정

v0.1 결정은 다음과 같다.

1. Gateway는 versioned normalized request/response event를 직접 발행하고 authenticated application adapter는 versioned auth event를 발행한다. Optional source-specific parser는 향후 Nginx 및 Syslog/firewall record를 같은 envelope로 mapping할 수 있다.
2. `gateway-http-v1` evidence는 schema/event/request/trace/idempotency identifier, start/end time, canonical TCP-peer source IP, allowlisted host/service label, method, query string 없는 normalized path, fixed `HTTP/1.1` protocol, response status, request/response byte count 및 latency로 제한한다. `auth-event-v1`은 available한 경우 known Gateway request binding, configured route, outcome 및 stable nonreversible HMAC account hash를 추가하고 unknown binding은 untrusted 상태로 enforcement를 지원할 수 없다.
3. Query string, request/response body, cookie, `Authorization` 및 raw secret-bearing header는 persist하거나 AI로 전달하지 않는다. HTTP traffic이 proxy를 통과했다는 이유로 raw evidence를 보존하지 않는다.
4. PostgreSQL은 normalized event, incident, AI/policy artifact 및 audit data를 저장하며 event/evidence는 7일, incident/AI/policy는 30일, audit는 90일 보존한다.
5. Parse, validation, duplicate 및 drop outcome은 prohibited content를 보존하지 않고 추적 가능해야 한다.

Schema versioning, timestamp normalization, deduplication key, masking, access control, indexing 및 partitioning은 implementation contract이며 collected data를 확장할 권한이 아니다.

**구체화 기록(2026-07-18):** 과거 결정 2의 `normalized path` 문구는 exact-path field를 허용하지 않는다. ADR-012는 current representation을 `route_label`, `path_catalog_version`, `suspicious_path_id`로 축소하며, 이는 ADR-002의 normalization 및 minimization 결정을 대체하지 않고 강화한다.

### 대안

- **원천별 형식만 저장**: cross-source aggregation model에 선택되지 않았다.
- **Full HTTP request와 response 보존**: minimization을 위반하고 secret 및 personal data를 불필요하게 노출하므로 거부한다.
- **PostgreSQL 이외 저장소**: OpenSearch는 Roadmap 후보이며 PostgreSQL은 selected v0.1 store다. Benchmark superiority를 주장하지 않는다.

### 결과

- 탐지와 상관 로직이 원천별 형식에서 분리될 수 있다.
- Incident에서 normalized value와 minimized source evidence 및 provenance를 함께 추적할 수 있어야 한다.
- Prohibited content를 처음부터 보존하지 않으므로 일부 forensic detail을 의도적으로 사용할 수 없다.
- 선택된 schema와 retention behavior를 구현·검증하기 전에는 migration 및 API contract를 완료로 간주할 수 없다.

---

## ADR-003: GPT-5.6의 역할과 신뢰 경계를 제한한다

### 상태

**채택됨 — 명령 생성 경계는 ADR-010이 대체.** Compact input, 비신뢰 로그 처리, 직접 권한 금지, 안전 실패 원칙은 유지한다. ADR-010은 모델 출력을 policy-only 제안에서 근거 기반 nftables command candidate까지 확장한다.

### 맥락

맥락 설명과 오탐 검토에는 모델 추론이 유용하지만, 로그에는 프롬프트 주입 문자열이 포함될 수 있고 모델은 환각할 수 있다. 방화벽 집행 권한을 모델에 부여하면 잘못된 상관이나 설명이 운영 변경으로 이어질 수 있다.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> 출처: [README](../README.md)

### 결정

**확정된 원칙**은 다음과 같다.

1. `gpt-5.6-sol`은 deterministic detection과 incident correlation 후 Responses API를 통해 비동기로 실행된다.
2. Model에는 evidence reference 최대 50개와 input 12 KiB 이하의 compact versioned incident summary를 전달한다. Query string, body, cookie, `Authorization` 및 raw secret-bearing header는 summary에 들어갈 수 없다.
3. 모델 역할에는 사건 요약, 공격 유형 분류, 근거 설명, 불확실성·잠재 오탐 기술, 제한된 policy 제안과 ADR-010에 따른 근거 기반 nftables blacklist command candidate 생성이 포함된다.
4. 로그 내용은 신뢰할 수 없는 데이터로 취급하며, 로그 속 텍스트를 모델 지시로 취급하지 않는다.
5. 모델에 shell 또는 방화벽 직접 실행 권한을 부여하지 않는다. Command candidate는 신뢰하지 않는 데이터이며 후속 검증과 HIL 승인을 대체할 수 없다.
6. Request는 reasoning `medium`, `store: false`, strict Structured Outputs `text.format`, no tools 및 output 최대 2,048 token을 사용한다. Attempt 하나의 timeout은 30초이고 classified `408`/`409`/`429`/`5xx` transient error retry는 한 번만 허용한다. Worker concurrency 기본값은 analysis 2개이고 configurable demo operator budget 기본값은 UTC day당 USD 10이다. 이는 API price claim이 아닌 operator guardrail이다.
7. Refusal, incomplete output, timeout/retry exhaustion, schema failure, invalid evidence reference 또는 operator-budget exhaustion은 `budget_exhausted` 같은 typed reason이 있는 유일한 non-enforcing `analysis_failed` state를 만든다. Deterministic evidence는 유지되고 failed analysis는 enforcement artifact를 진행할 수 없다.

Request/response 및 schema version은 compatibility boundary다. Model, prompt, schema, limit, timeout 또는 retry 변경 시 contract test와 문서 갱신이 필요하다. 구현은 공식 [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models) 및 [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)를 따른다. Opt-in smoke command는 존재하지만 live billable result는 아직 release evidence가 아니다.

### 대안

- **모든 원시 로그를 모델에 전달**: README가 명시적으로 배제한 방향이다.
- **모델에 셸·방화벽 실행 권한 부여**: 안전 모델과 직접 충돌하므로 배제한다.
- **AI를 전혀 사용하지 않음**: 탐지는 가능하지만 프로젝트가 목표로 하는 맥락 설명과 제한된 정책 추천을 제공하지 못해 현재 제품 범위에 선택되지 않았다.
- **다른 모델 또는 로컬 모델**: v0.1에서 선택하지 않았다. 대체하려면 명시적 model-contract decision과 revalidation이 필요하다.

### 결과

- 모델 출력은 관찰 사실과 분리된 해석·추천으로 표시되어야 한다.
- 모델 오류나 스키마 실패는 안전하게 실패하고 자동 집행으로 우회되어서는 안 된다.
- 구조화 입력은 공격 표면과 비용을 제한하지만, 요약 과정에서 일부 맥락이 누락될 수 있다.
- GPT-5.6 분석에는 네트워크와 API 자격 증명이 필요하며, 탐지 보장 수단이 아니다.

---

## ADR-004: 임의 명령 대신 구조화 정책과 검증 파이프라인을 사용한다

### 상태

**채택됨 — 명령 생성 경계는 ADR-010이 대체.** Unrestricted shell command 금지와 순서형 검증 단계는 유지한다. ADR-010은 policy-only/결정론적 translation 가정을 strict parsing되는 AI 생성 nftables command candidate로 대체한다.

### 맥락

자연어 또는 모델 생성 셸 명령을 그대로 실행하면 범위가 과도하거나 보호 네트워크를 차단하는 규칙이 집행될 수 있다. 정책 의도, 대상, 제외 범위, 동작, 기간, 승인 요구를 기계적으로 검사할 수 있는 제한된 표현이 필요하다.

### 결정

**확정된 원칙**은 다음과 같다.

1. AI 대응 제안은 unrestricted shell이 아니라 제한된 구조화 정책과 ADR-010의 schema-bounded nftables command candidate로 표현한다.
2. Policy/command pair는 structured-output/schema validation, command parsing/canonicalization, policy/evidence/command consistency, protected-network check, owned-set nftables syntax validation, historical-impact analysis를 순서대로 통과해야 한다. Missing, stale, failed, timed-out 또는 ambiguous result는 fail closed한다.
3. 검증 실패 정책은 집행 대상으로 진행하지 않는다.
4. 검증된 policy/command pair도 [ADR-005](#adr-005-관리자-승인-전에는-정책을-집행하지-않는다)와 ADR-010에 따라 policy·generated/canonical command·evidence/validation snapshot digest를 결속한 exact artifact HIL 승인을 받아야 한다.

v0.1 policy는 하나의 canonical IPv4 source를 대상으로 `block_ip`만 허용한다. TTL은 최소 1분, 기본 30분, 최대 24시간이고 validation은 최대 5분 유효하다. Historical impact는 24시간 lookback을 사용하고 target과 연결된 successful authentication evidence는 blocking이며 insufficient 또는 ambiguous evidence는 fail closed한다. Gateway-local `http-deny-v1`을 포함한 future action은 별도 artifact contract 및 follow-up ADR이 필요하고 nftables approval로 허용할 수 없다.

### 대안

- **파싱하지 않은 model-generated command를 실행하거나 shell로 호출**: Safety Model과 ADR-010이 명시적으로 배제한다.
- **자유 형식 자연어를 승인 후 실행**: 기계적 스키마·구문 검증 요구를 충족하지 않아 선택되지 않았다.
- **관리자가 nftables를 직접 작성**: 운영상 가능한 별도 절차지만 SentinelFlow의 selected structured validation flow를 대체하지 않는다.

### 결과

- 모델 출력과 실제 방화벽 표현 사이에 검증 가능한 계약이 생긴다.
- 보호 범위, 동작, 지속 시간을 정책 단계에서 거부할 수 있어야 한다.
- 정책 스키마에 없는 대응은 MVP에서 표현할 수 없다.
- Schema, command parser/canonicalizer, validator, impact analysis, HIL binding, executor contract를 함께 versioning하고 test해야 한다.

---

## ADR-005: 관리자 승인 전에는 정책을 집행하지 않는다

### 상태

**채택됨 — 구현 검증 필요.** 최종 집행 결정은 관리자에게 있다는 제품·안전 원칙이다.

### 맥락

잘못된 상관, 모델 환각, 오탐 또는 과도한 방화벽 규칙은 정상 사용자 차단과 관리자 잠금을 일으킬 수 있다. 자동 검증만으로 조직별 맥락과 업무 영향을 모두 판단할 수 있다는 근거는 README에 없다.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> 출처: [README](../README.md)

### 결정

**확정된 원칙**은 다음과 같다.

1. Immutable evidence snapshot, 제안 policy, generated/canonical command, 관련 digest, validation result, expected impact와 validity를 관리자에게 제시한다.
2. 명시적 승인 전에는 규칙을 적용하지 않는다.
3. 관리자는 policy version/digest·generated/canonical command digest·evidence/validation snapshot digest·actor·reason·validity를 결속해 HIL로 exact artifact를 승인 또는 거부하며 최종 집행 결정은 모델이 아닌 관리자 통제 아래 둔다.
4. 기본값은 자동 프로덕션 집행 금지다.
5. 승인도 command grammar·schema·protected network·syntax·consistency·impact validation failure를 우회할 수 없고 command·policy·validator·configuration·analysis input·evidence 변경 시 승인이 무효화된다.
6. v0.1은 administrator identity 하나를 사용한다. Argon2id PHC hash는 minimum memory 64 MiB, time cost 3, parallelism 2, salt 16 bytes, key 32 bytes로 environment configuration을 통해 주입하고 password 자체는 repository configuration에 넣지 않는다.
7. Authentication은 absolute 8시간 및 idle 30분 lifetime의 opaque server-side session을 만들고 login과 privilege action에서 rotate한다. Cookie는 HttpOnly, SameSite=Strict이며 TLS 사용 시 Secure다. State-changing request는 synchronizer-token CSRF protection을 사용한다.
8. Approve, reject 및 revoke operation은 session당 분당 5회로 제한하고 session age가 15분을 넘으면 reauthentication을 요구한다. Decision은 session, exact artifact digest 및 5-minute validation window에 결속된 single-use nonce를 소비하고 `Idempotency-Key`, expected policy version/digest, decision 및 nonempty reason을 제공한다. Identical idempotent retry에는 original result를 반환하고 conflicting reuse, stale session, nonce replay 또는 artifact mismatch는 fail closed하고 audit한다. Optimistic concurrency는 artifact version별 final HIL decision 하나만 허용한다.

Validation snapshot의 `valid_until`은 validation 후 최대 5분이다. Approval은 `decision_valid_until = min(validation.valid_until, decision_time + 5m)`으로 정한다. Execution과 recovery는 두 timestamp가 모두 미래인지 확인하므로 approval은 validation validity를 연장할 수 없다.

Multiple administrator, role, separation of duties, external identity provider, notification 및 SLA는 post-v0.1 작업이며 single-admin reference implementation에서 제공한다고 주장할 수 없다.

### 대안

- **검증 통과 후 완전 자동 집행**: README의 기본 안전 모델과 충돌하므로 선택하지 않는다.
- **AI가 자체 승인**: 인간 통제와 모델 신뢰 경계를 위반하므로 배제한다.
- **추천만 제공하고 집행 기능 제거**: 안전한 축소 대안이지만, 승인 후 임시 집행까지 시연하려는 MVP 흐름에는 선택되지 않았다.

### 결과

- 오탐과 업무 맥락을 집행 전에 사람이 검토할 수 있다.
- 승인 행위자, 시각, 대상 정책과 결정 결과를 감사 가능하게 연결해야 한다.
- 대응에 사람의 대기 시간이 추가되며 무인 자동 대응은 MVP 기본 경로가 아니다.
- 인증과 권한 검증이 구현되지 않은 상태에서는 승인 UI만으로 안전 경계를 충족했다고 볼 수 없다.

---

## ADR-006: nftables 집행은 임시·가역적으로 수행하고 데모를 격리한다

### 상태

**채택됨 — 구현 검증 필요.** Temporary rule, automatic expiry 및 isolated demo enforcement는 확정했지만 검증되지 않았다. ADR-012는 결정 6의 direct executor-delivery mechanics, 결정 7의 privilege topology, 아래 recovery-reapplication 문장만 대체한다. Fixed-binary, shell-free, read-back, lifetime, isolation 및 audit 원칙은 계속 채택 상태다.

### 맥락

차단 규칙은 정상 트래픽과 관리자 접근을 막을 수 있다. 특히 데모가 호스트 방화벽을 직접 변경하면 개발 환경까지 손상할 수 있으므로, 적용 범위와 수명을 제한해야 한다.

> "The default demo keeps the upstream private and runs nftables enforcement only inside an isolated container or network namespace."
>
> 출처: [README](../README.md)

### 결정

**확정된 원칙**은 다음과 같다.

1. v0.1 enforcement는 pre-created `inet sentinelflow blacklist_ipv4` set을 대상으로 하며 rule lifetime은 최소 1분, 기본 30분, 최대 24시간이다.
2. 임시 규칙은 자동 만료되고 적용부터 만료까지 감사 가능한 수명주기를 가져야 한다.
3. 기본 데모 집행은 호스트 방화벽을 수정하지 않는 컨테이너 또는 네트워크 네임스페이스에서 실행한다.
4. Enforcement는 canonical global-unicast IPv4만 허용하고 unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, configured management CIDR, Gateway/upstream/executor address, current administrator path 및 모든 IPv6를 거부한다. Built-in protection은 `PROTECTED_CIDRS`로 제거할 수 없고 configuration은 range를 추가만 한다.
5. 프로덕션 호스트 수준 집행은 기본 경로가 아니며, 구현·권한·보호 네트워크·rollback·감사 설정 검토 없이는 활성화하지 않는다.
6. Executor는 HIL 승인된 canonical command artifact만 fixed `nft` binary와 fixed argument로 shell 없이 실행하고 실제 rule과 timeout을 read back한다.
7. Gateway, API, AI adapter 및 general worker에는 `NET_ADMIN`이 없고 별도 isolated executor만 최소 required capability를 가진다.

RFC 5737 documentation range는 normal profile에서 보호한다. Isolated demo/test profile은 namespace isolation과 before/after host-ruleset assertion 통과 후 해당 documentation range만 명시적으로 허용할 수 있다. Atomic application, failed-expiry retry, rule conflict 및 concurrent approval은 exact-artifact gate로 제한되는 implementation detail이다. Initial execution과 recovery reapplication은 current digest, 두 5-minute validity timestamp, protected configuration, owned-set schema 및 remaining TTL을 다시 확인한다. Roadmap policy rollback은 완료 기능이 아니다.

**대체 기록(2026-07-18):** 위 문장은 ADR-006의 결정 이력으로 보존한다. 구현은 ADR-012를 따라야 한다. Restricted dispatcher가 exact signed capability를 발급하고 executor만 namespace-local `NET_ADMIN`을 가지며 relative-timeout add는 recovery 중 절대 재적용하지 않는다.

### 대안

- **영구 규칙 적용**: 임시·가역적 원칙과 맞지 않아 선택하지 않는다.
- **기본 데모에서 호스트 nftables 직접 변경**: README가 격리 환경을 기본값으로 요구하므로 선택하지 않는다.
- **집행 없는 관찰 전용 데모**: 더 작은 안전 범위지만 README의 승인 후 임시 적용 시연 흐름에는 선택되지 않았다.
- **다른 방화벽·클라우드 WAF 집행**: Known Limitations와 Roadmap에 따라 MVP 범위 밖이다.

### 결과

- 잘못된 차단의 지속 시간을 제한하고 호스트 데모 위험을 줄인다.
- 자동 만료와 실패 복구를 시간 기반 통합 테스트로 검증해야 한다.
- 격리된 데모의 성공은 프로덕션 호스트 집행의 안전성을 증명하지 않는다.
- 최소 권한 집행 구성요소와 일반 API·AI 구성요소 사이에 권한 경계가 필요하다.

---

## ADR-007: Go와 React stack을 명시적 process와 module 경계로 사용한다

### 상태

**채택됨 — 구현 증거 존재, release 검증 미완료.** v0.1 stack과 top-level process/module boundary를 구현했다. 88-package backend gate와 PostgreSQL 17.10 33-migration/72-table verifier의 final root rerun, API-only validation-attempt projection, production-CSP Chromium gate를 포함한 현재 frontend unit 39-file/363-test suite, 여러 isolated runtime gate 및 이전에 완료한 supply-chain/image gate의 local evidence가 있다. RUN25 fast는 mutation/outage/restart path를 다뤘고 이후 macOS `--run-browser-qa` 실행은 revoked phase의 고정 61초 pre-hash login-window 대기와 함께 active/revoked browser QA를 통과했다. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`의 외부 clean clone도 `make check`를 통과했다. Default native expiry, post-repair CI rerun, native host-ruleset, live OpenAI 및 4-GB performance gate는 open이다.

### 맥락

Gateway proxying, event publication, storage, detection, correlation, AI, validation, approval, enforcement, simulation 및 UI는 availability와 privilege requirement가 다르다. 명시적 code/process boundary는 parallel implementation, outage test 및 security review를 가능하게 한다.

### 결정

v0.1 결정은 다음과 같다.

1. Inline Gateway와 backend service에는 Go `1.25.12` 및 `net/http`를 사용하고 control plane에는 `github.com/go-chi/chi/v5` `v5.3.1`, `github.com/jackc/pgx/v5` `v5.9.2`, sqlc configuration을 갖춘 SQL query source, PostgreSQL 및 OpenAI Responses API를 사용한다.
2. 프론트엔드는 React `19.2.7`, TypeScript `6.0.2`, Vite `8.1.5`, MUI `7.3.8`을 사용한다.
3. Isolated reference deployment에 Docker, Docker Compose, Linux 및 nftables를 사용한다. Nginx와 Syslog는 primary runtime dependency가 아닌 optional P2/post-v0.1 adapter다.
4. `cmd/gateway`, `cmd/api`, `cmd/worker`, `cmd/dispatcher`, `cmd/executor`, `cmd/simulator` 및 focused validation, lifecycle, retention, recovery, observability, export, history, smoke command에 distinct entry point를 유지하고 `cmd/ingestor` 작업은 optional P2로 둔다.
5. `internal/gateway`, `ai`, `api`, `correlation`, `detection`, `enforcement`, `events`, `ingestion`, `policy`, `repository`, `validation`에 domain boundary와 해당 domain 주변 focused adapter를 유지한다. Gateway code는 request path에 AI, database, approval 또는 executor capability를 import할 수 없다.
6. DB 마이그레이션·쿼리·스키마, 웹, 배포, 샘플, 스크립트, 문서를 별도 최상위 영역으로 둔다.
7. React/TypeScript/Vite/MUI frontend implementation은 `web/`에 두고 frozen REST/SSE contract를 consume한다. Frontend/UI task는 backend, AI, data, validation, enforcement 및 infrastructure task와 분리하며 authorization 또는 enforcement behavior를 재정의할 수 없다.
8. Executor process와 IPC contract를 Gateway/API/AI/general worker에서 격리한다. Executor만 minimal nftables capability를 받고 Gateway와 control-plane process는 `NET_ADMIN` 없이 실행한다.

ADR-011은 asynchronous data/control-plane boundary, 하나의 fixed private upstream 및 Gateway의 `NET_ADMIN` 금지를 확정한다. Internal API, transaction/job implementation, configuration mechanics, migration mechanics, frontend state 및 detailed container topology는 선택된 boundary 안에서 구현하고 test로 증명해야 한다.

### 대안

- **단일 프로세스·단일 패키지 구조**: Required data/control/executor boundary를 붕괴시키므로 선택하지 않았다.
- **다른 백엔드·프론트엔드 프레임워크**: v0.1에서 선택하지 않았으며 comparative benchmark 우위를 주장하지 않는다.
- **OpenSearch 또는 SIEM 중심 저장·분석**: Roadmap 후보이며 MVP 계획이 아니다.

이 대안은 selected v0.1 baseline 밖에 있으며 benchmark로 열등하다고 주장하는 것은 아니다.

### 결과

- 선택된 package name은 수집부터 집행까지의 책임과 trust boundary를 드러낸다.
- 여러 실행 진입점과 데이터베이스·웹 빌드는 배포 및 통합 테스트 복잡도를 늘릴 수 있다.
- Directory 존재만으로 selected module/process boundary 준수를 증명할 수 없다.
- 구현 중 경계를 바꾸면 후속 ADR로 이유와 영향을 기록해야 한다.

---

## ADR-008: SSE를 administrator state-delivery mechanism으로 사용한다

### 상태

**채택됨 — 구현 검증 필요.** SSE는 v0.1 administrator state-delivery mechanism이다. 이는 implementation contract를 확정하지만 endpoint, replay, browser 또는 recovery behavior가 동작한다는 증거는 아니다.

### 맥락

Incident creation, source degradation, AI completion/failure, policy validation, approval, application 및 expiry는 시간에 따라 변한다. Administrator는 timely update가 필요하지만 이 notification channel이 command 또는 safety-decision channel이 되어서는 안 된다.

### 결정

1. `GET /api/v1/events/stream`은 `id`, `event`, `data` 및 heartbeat comment가 있는 authenticated `text/event-stream` record를 반환한다.
2. Event type은 `incident.created|updated`, `analysis.completed|failed`, `policy.validation_updated`, `approval.recorded`, `enforcement.updated`, `source.degraded|recovered`다.
3. Payload는 event/resource ID, time, version, trace ID 및 minimal summary만 포함한다. Raw HTTP content, secret, executable command byte 또는 approval authority를 포함하지 않는다.
4. Client는 `Last-Event-ID`로 reconnect한다. Replay window로 gap을 채울 수 없으면 authorized REST snapshot을 reload하고 snapshot을 current state로 취급한다.
5. Delivery는 at-least-once notification이다. Client는 event/resource version으로 deduplicate하고 SSE message에서 incident, approval 또는 enforcement를 만들지 않는다.
6. SSE는 command channel이 아니다. Approval/rejection/revocation은 authenticated, CSRF/replay-protected REST operation이고 enforcement는 exact-artifact HIL 뒤에 있다.

### 대안

- **Periodic polling:** 가능한 fallback이지만 primary state delivery가 아니라 REST snapshot recovery에만 선택한다.
- **WebSocket:** One-way administrator notification에 필요하지 않고 v0.1에 불필요한 bidirectional channel을 추가한다.
- **Manual refresh:** Reference demo의 visible degradation 및 lifecycle transition에 충분하지 않다.

### 결과

- Authentication, replay-gap, deduplication 및 browser lifecycle behavior에는 contract, recovery 및 end-to-end test가 필요하다.
- REST는 authoritative state/mutation interface이고 SSE loss는 policy를 authorize하거나 조용히 변경할 수 없다.
- Reference topology는 stream의 proxy buffering을 disable해야 하고 resource/connection bound는 required operational configuration이다.
- State delivery는 [ADR-005](#adr-005-관리자-승인-전에는-정책을-집행하지-않는다)의 approval 또는 [ADR-006](#adr-006-nftables-집행은-임시가역적으로-수행하고-데모를-격리한다)의 enforcement safety boundary를 우회할 수 없다.

---

## ADR-009: 전 수명주기를 감사하고 로그와 비밀을 신뢰 경계 밖에 둔다

### 상태

**채택됨 — 구현 검증 필요.** Auditability, minimization 및 core security control을 single-node reference에 맞게 확정했다. Production-grade audit와 compliance는 Roadmap 항목이다.

### 맥락

MVP는 malformed proxy input, forwarding-header spoofing, request smuggling, evidence prompt injection, 잘못된 correlation, AI hallucination, false-positive blocking, administrator lockout, broad rule, API-key leakage, telemetry drop 및 privileged-container abuse를 threat로 본다. Lifecycle과 degradation evidence가 없으면 잘못된 action 또는 missing incident 원인을 재구성할 수 없다.

### 결정

**확정된 원칙**은 다음과 같다.

1. Gateway metadata, application auth event, optional log 및 모든 evidence를 신뢰하지 않는 data로 취급하고 embedded text를 model instruction으로 해석하지 않는다.
2. API 키와 자격 증명은 저장소 밖에 두며 로그·모델 컨텍스트·감사 데이터에 노출하지 않는다.
3. Query string, request/response body, cookie, `Authorization` 또는 raw secret-bearing header를 persist하거나 AI로 전달하지 않는다. Prohibited content 없이 event drop과 degradation을 기록한다.
4. 제한된 policy/command schema, canonicalization, policy/evidence/command consistency, protected CIDR, owned-set syntax validation, impact analysis, exact-artifact HIL approval, temporary rule, automatic expiry, isolation을 방어 계층으로 유지한다.
5. Normalized minimized evidence, model analysis, command candidate, canonical command와 digest, policy proposal, 단계별 검증, HIL 승인·거부, 적용, 실패, 만료를 audit trail로 연결한다.
6. 감사 기록은 observed fact, model interpretation, human decision, enforcement outcome 및 data-plane degradation을 구분해야 한다.

Execution 전에는 durable enforcement job과 필수 pre-application audit record가 함께 commit되어야 하며 실패하면 enforcement는 fail closed다. nftables apply attempt 뒤 audit persistence가 실패하면 result를 `indeterminate`로 두고 후속 transition을 막고 alert를 발생시키며 durable outbox와 ruleset read-back으로 복구하고 조용히 success 처리하지 않는다. Event/evidence는 7일, incident/AI/policy는 30일, audit는 90일 보존한다. Tamper-resistant external archival, compliance export 및 multi-party audit control은 Roadmap 작업이다.

### 대안

- **최종 방화벽 상태만 기록**: 제안부터 만료까지의 auditable lifecycle 요구를 충족하지 않아 선택하지 않는다.
- **원본 로그를 지시문과 분리하지 않고 모델에 전달**: Threat Model 완화책과 충돌하므로 배제한다.
- **비밀을 저장소 또는 일반 로그에 저장**: README가 명시적으로 배제한다.
- **외부 SIEM에만 감사 위임**: SIEM integration은 Roadmap이며 MVP의 기본 전제가 아니다.

### 결과

- 사건 ID와 정책 ID를 통해 근거부터 집행·만료까지 시간순으로 재구성할 수 있어야 한다.
- Audit data 자체가 IP, account hash, path 및 minimized evidence 등 sensitive data를 포함할 수 있어 access control과 masking이 필요하다.
- Safety control 또는 pre-application audit failure는 enforcement를 중단하고 post-attempt audit failure는 durable reconciliation에 들어가며 복구 전까지 release-blocking 상태를 유지한다.
- MVP 감사 추적은 프로덕션 규제 준수 또는 침해 불가능성을 자동으로 보장하지 않는다.

---

## ADR-010: 근거 기반 AI 생성 nftables blacklist 명령 후보를 HIL로 승인한다

### 상태

**채택됨 — 구현 검증 필요.** 이 결정은 2026-07-17에 명시적으로 승인되었다. ADR-003과 ADR-004의 policy-only/결정론적 명령 생성 경계만 대체한다. ADR-012는 아래 결정 8과 결정 9의 direct executor-delivery 및 recovery-reapplication mechanics만 다시 대체한다. AI candidate, compact input, 비신뢰 data, 직접 권한 금지, validation, HIL, expiry 및 audit 요구는 그대로 유효하다.

### 맥락

제품은 AI가 근거 기반 incident 분석을 관리자가 직접 검토할 수 있는 실제 nftables blacklist command로 변환해야 한다. Policy-only 제안은 후속 translator 실행 전까지 정확한 executable artifact를 숨기지만 model-to-shell 직접 실행은 command injection, 과도한 변경, approval drift 위험을 허용할 수 없게 만든다.

> "The model does not receive unrestricted shell access and does not directly modify a firewall."
>
> 출처: [README](../README.md)

### 결정

1. GPT-5.6은 deterministic detection과 correlation 뒤에만 실행하고 stable evidence reference가 포함된 compact structured incident summary를 받는다.
2. Structured output은 설명, uncertainty, false-positive analysis, 제한된 `block_ip` policy와 근거 기반 nftables blacklist command candidate를 포함한다.
3. Command family는 `nft-blacklist-v1`이다. v0.1 candidate는 canonical global-unicast IPv4 source address 정확히 하나를 최소 1분, 기본 30분, 최대 24시간 timeout과 함께 pre-created `inet sentinelflow blacklist_ipv4` set에 추가할 수 있다. IPv6 evidence는 탐지할 수 있지만 v0.1 enforcement candidate를 만들 수 없다. 다른 table·chain·rule·set을 생성·삭제·flush·rename·수정할 수 없다.
4. Candidate는 신뢰하지 않는 text다. Strict parser는 additional statement, unsupported token, variable, include operation, shell metacharacter, redirection, pipeline, command substitution, token 은닉 comment, timeout 누락, 예상하지 않은 table/set name, multiple address를 거부한다.
5. Parser는 typed AST를 만들고 다른 action을 발명하지 않은 채 LF line ending의 canonical UTF-8 command 하나로 serialize한다. Consistency는 모든 cited evidence ID가 immutable incident/analysis-input snapshot에 속하고 모든 cited source address가 policy target과 같으며 policy와 command가 같은 evidence set/target을 사용하고 timeout이 policy와 configured bound에 맞을 것을 요구한다. Server는 SHA-256 generated/canonical command digest를 계산한다.
6. 하나의 immutable artifact가 structured-output/schema validation, command grammar/canonicalization 및 policy/evidence/command consistency, protected-network check, 동일한 pre-created owned-set schema를 둔 격리 `nft --check -f -`, 24-hour historical-impact analysis를 순서대로 통과해야 한다. Target과 연결된 successful authentication evidence는 blocking이다. Missing, stale, failed, timed-out, insufficient 또는 ambiguous result는 fail closed다.
7. Validation snapshot digest는 policy digest·incident/evidence snapshot digest·analysis input/version·generated-candidate digest·canonical byte/digest·grammar/parser/validator version·protected-range configuration·owned-set schema·nft binary version·impact input/result·validation 후 최대 5분인 `valid_until`을 commit한다. 관리자는 evidence·generated/canonical diff·TTL·exclusion·impact·digest를 본다. HIL은 snapshot과 policy version/digest·generated/canonical digest·actor·reason·validation expiry 또는 decision 후 5분보다 늦지 않은 `decision_valid_until`을 결속하며 dependent change는 full revalidation/reapproval을 요구한다.
8. Model은 candidate를 approve·enqueue·execute할 수 없다. 격리 executor는 canonical byte와 HIL-approved digest를 받고 digest를 재계산한 뒤 fixed `nft` binary와 fixed argument를 호출해 shell 없이 그 byte만 standard input으로 전달한다.
9. Initial execution 또는 recovery reapplication 직전에 executor는 policy/analysis version, 모든 command/evidence/validation digest, HIL identity와 두 validity timestamp, protected-range/owned-set-schema configuration, remaining TTL을 재검사한다. Applied rule과 timeout을 read back하며 mismatch는 failure다. Reconciler도 같은 gate를 통과한 경우에만 missing state를 repair하며 stale/expired approval을 사용하지 않는다.
10. Audit record는 evidence snapshot·model/prompt/schema version·generated candidate digest·canonical byte/digest·validation snapshot·HIL actor/reason/time/validity·executor result·read-back·expiry·revocation·recovery outcome을 보존한다.

**대체 기록(2026-07-18):** 결정 8의 executor 직접 전달과 결정 9의 recovery reapplication은 과거 결정이다. ADR-012는 private UDS를 통한 dispatcher-signed single-use capability 전달과 relative-timeout artifact를 절대 다시 추가하지 않는 read-back-only crash resolution을 요구한다.

Canonical v0.1 shape은 `add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }`이다. Normal profile은 unspecified, loopback, private, link-local, CGNAT, benchmarking, multicast/reserved, configured management, Gateway/upstream/executor, current-administrator path와 함께 RFC 5737 documentation range를 보호한다. Isolated demo/test profile은 namespace 및 host-ruleset-diff assertion 후 RFC 5737 target만 허용할 수 있고 `PROTECTED_CIDRS`는 protection을 추가만 하며 built-in을 제거하지 못한다. Future IPv6 family는 follow-up ADR이 필요하다.

### 대안

- **결정론적 command generation만 유지**: model boundary는 더 작지만 AI가 관리자 검토용 nftables command를 생성한다는 선택된 product behavior를 만족하지 못한다.
- **Model response를 shell로 직접 실행**: grammar enforcement, digest binding, least privilege, HIL integrity를 우회하므로 거부한다.
- **관리자가 command를 직접 작성**: human control은 유지하지만 의도한 AI 생성 evidence-bound response artifact를 제거하고 repeatability를 낮춘다.
- **Machine validation 뒤 자동 실행**: 필수 HIL 결정을 제거하므로 거부한다.

### 결과

- 관리자는 결정 전에 실제 실행될 정확한 command와 evidence·impact를 검토할 수 있다.
- AI output schema, command grammar, canonicalizer, validator version, approval record, executor protocol, audit chain이 하나의 compatibility boundary가 된다.
- Command injection, policy/command mismatch, validation 후 변경, stale approval, replay, read-back mismatch에 전용 negative/recovery test가 필요하다.
- AI command generation은 여전히 firewall authority가 아니며 독립 검증과 HIL 승인을 받은 canonical artifact만 격리 executor에 도달한다.
- 허용 nftables capability는 의도적으로 좁으며 general firewall-management interface가 아니다.

---

## ADR-011: Data plane과 control plane을 분리한 Gateway-first hybrid architecture를 채택한다

### 상태

**채택됨 — 구현 검증 필요.** 2026-07-18 승인되었다. 이 결정은 v0.1 primary sensor를 external Nginx/Syslog ingestion에서 inline Gateway로 변경하고 authenticated application auth event를 유지하며 legacy log adapter를 optional P2/post-v0.1 작업으로 남긴다. ADR-012는 결정 8의 direct executor-delivery/privilege mechanics만 대체한다. 결정 2부터 결정 6의 compatible origin, protocol, exact-path, batch authentication 및 auth-binding detail은 축소하거나 완성하지만 Gateway-first 선택, direct-peer identity, asynchronous separation, performance gate, hybrid-source position 또는 scope는 대체하지 않는다.

### 맥락

Log-first prototype은 request를 관찰하기 전에 external formatting, transport, parsing 및 delivery를 기다려야 한다. General-purpose origin server를 만들면 application hosting 책임까지 맡게 된다. Inline reverse proxy는 기존 application으로 forwarding하면서 일관된 boundary에서 HTTP를 관찰할 수 있지만 availability 및 protocol-security에 민감하므로 AI, persistence, approval 또는 firewall execution과 failure/privilege boundary를 공유할 수 없다.

> "The request path never waits for GPT-5.6, PostgreSQL, or administrator approval."
>
> "Raw packet capture and analysis are not part of v0.1."
>
> 출처: [README](../README.md)

### 결정

1. **Primary data plane:** v0.1은 정확히 하나의 fixed private upstream 앞에 inline reverse proxy인 Go `SentinelFlow Gateway`를 추가한다. Configured host 하나를 allowlist한다. Gateway는 general origin server, static-file host, arbitrary forward proxy, dynamic service router 또는 production WAF가 아니다. Upstream은 unpublished 상태로 reference network 내부에서만 접근할 수 있다.
2. **Identity 및 origin trust:** v0.1의 `canonical_source_ip`는 canonicalized TCP peer address다. Gateway는 모든 incoming `Forwarded` 및 `X-Forwarded-*` header를 제거하고 allowlisted `Host`를 검증하며 trusted local state에서 forwarding header를 재생성한다. Request input으로 upstream을 선택하지 않는다. Protected application traffic은 Gateway에 직접 도달하고 optional TLS도 Gateway에서 terminate한다. Nginx는 v0.1 upstream identity hop이 아니며 trusted proxy chain은 post-v0.1이다. Admin UI는 별도 endpoint일 수 있다.
3. **Protocol bound:** maximum header는 32 KiB, maximum request body는 10 MiB, header-read timeout은 5초, upstream/request timeout은 30초, idle timeout은 60초다. Protocol-invalid, oversized 및 timed-out request는 deterministic server-safety control로 거부할 수 있으며 이 control은 AI adaptive enforcement가 아니다.
4. **Minimized event contract:** Response 또는 terminal proxy outcome 뒤 Gateway는 schema/event/request/trace/idempotency identifier, start/end time, canonical source IP, allowlisted host/service label, method, query string 없는 normalized path, fixed `HTTP/1.1` protocol, response status, request/response byte count 및 latency만 담은 `gateway-http-v1`을 비동기로 발행한다. Query string, body, cookie, `Authorization` 및 raw secret-bearing header는 persist하거나 AI로 전달하지 않는다.
5. **Bounded delivery:** Default in-memory queue는 event 10,000개를 보관하고 최대 100 record로 batch하며 100ms 안에 flush한다. Sender backoff는 100ms~5초로 제한하고 v0.1은 durable disk spool을 두지 않는다. `event-batch-v1`은 sender/batch ID, monotonic per-sender sequence, sent time 및 최대 100 typed record 또는 256 KiB를 포함한다. Endpoint-scoped sender는 timestamp, nonce 및 body digest에 HMAC-SHA256을 사용한다. Receiver는 constant time으로 verify하고 clock skew ±60초만 허용하며 nonce를 5분 보관한다. Retry는 body, batch ID, sequence를 유지하고 fresh authentication value를 사용한다. Receiver는 batch/record를 deduplicate하고 다른 byte로 batch ID를 재사용하면 거부하며 sequence gap을 enforcement evidence가 될 수 없는 incomplete evidence로 취급한다. Queue depth, lag, rejected batch, sequence gap 및 event drop을 관찰할 수 있어야 한다.
6. **Required auth semantic:** Proxy는 account identity 또는 login-outcome semantic을 안전하게 추론할 수 없으므로 authenticated application auth-event adapter를 P0로 유지한다. Allowlisted `auth-event-v1`은 schema/event/Gateway-request/trace/idempotency identifier, occurred time, sanitized Gateway forwarding에서 파생한 canonical source IP, configured service/route label, outcome 및 stable nonreversible HMAC account hash를 포함한다. Raw username/credential은 금지되고 unknown Gateway request binding은 untrusted 상태로 enforcement를 지원할 수 없다. Adapter는 위 authenticated replay-resistant batch contract를 사용한다.
7. **Asynchronous isolation:** Gateway forwarding은 PostgreSQL, deterministic worker, GPT-5.6, validation, administrator 또는 executor를 기다리지 않는다. 이들의 outage 또는 queue saturation 중에도 otherwise-valid traffic은 계속 흐르고 new adaptive block은 생성되지 않으며 existing approved nftables rule은 정상 만료되고 degradation/drop을 보고한다. Recovery는 missing evidence를 만들어낼 수 없다.
8. **Privilege split:** Gateway에는 `NET_ADMIN`, shell, approval, policy-validation 또는 executor capability가 없다. API, AI adapter 및 general worker에도 executor privilege가 없다. ADR-010의 HIL-approved canonical byte와 digest는 별도 isolated executor만 받을 수 있다.
9. **Performance gate:** 4GB single-node reference host에서 500 requests/second일 때 Gateway-added p95 latency는 5ms 이하고 event drop은 0이다. Target 밖 saturation도 관찰할 수 있어야 하고 valid traffic을 차단하지 않아야 한다.
10. **Hybrid source:** Nginx access-log 및 TCP/UDP Syslog/firewall-log receiver/parser는 기존 requirement와 ID를 유지하지만 optional P2/post-v0.1 adapter로 이동한다. Gateway-derived canonical identity를 변경하거나 v0.1 release를 차단할 수 없다.
11. **Scope boundary:** Raw packet capture/analysis는 v0.1 범위가 아니다. eBPF/XDP 또는 packet sensor는 자체 privacy, capacity 및 failure ADR이 있는 별도 least-privilege component여야 한다. Adaptive Gateway-local `http-deny-v1`도 future work이며 distinct typed artifact, validator, digest/HIL binding 및 ADR이 필요하고 nftables approval로 authorize할 수 없다.
12. **Release position:** v0.1은 implementation-complete single-node reference/demo이며 production WAF, managed origin server, high-availability proxy 또는 production TLS operation 주장이 아니다. Production TLS ownership, certificate rotation, horizontal scaling, failover 및 HA에는 follow-up evidence와 decision이 필요하다.

**대체 및 구체화 기록(2026-07-18):** 결정 8의 direct executor-authority 문구는 대체된 이력으로 남긴다. 결정 2부터 결정 6은 architecture level에서 계속 채택 상태이고 private origin, HTTP edge, path minimization, batch/HMAC/checkpoint 및 pending-auth binding contract의 더 좁은 구현 기준은 ADR-012다.

### 대안

- **Log/Syslog 분석을 primary sensor로 유지:** Intrusive하지 않지만 source format, delivery 및 latency dependency가 남고 direct demo path가 약하다.
- **General-purpose origin web server 구축:** Application hosting, framework behavior 및 origin migration이 security product scope 밖이므로 거부한다.
- **AI 또는 database decision을 request path에 배치:** Control-plane latency와 outage가 application availability failure가 되므로 거부한다.
- **Gateway 내부 raw-packet analysis:** HTTP proxy와 packet sensing의 privilege, privacy, performance 및 failure boundary가 다르므로 v0.1에서 거부한다.
- **Gateway의 direct L7 또는 nftables block:** Exact-artifact HIL과 least-privilege boundary를 붕괴시키므로 거부한다.

### 결과

- HTTP request evidence는 external log parsing보다 즉시 사용 가능하고 structured, reproducible하며 demo하기 쉽다.
- Gateway가 availability-critical해지므로 release 전에 protocol-security, backpressure, upstream-failure 및 load evidence가 필요하다.
- Account-aware credential stuffing에는 authenticated application contract가 계속 필요하고 proxy가 username이나 authentication semantic을 만들어내지 않는다.
- Data minimization은 secret과 불필요한 personal data 수집을 막기 위해 forensic depth를 의도적으로 줄인다.
- Optional legacy adapter는 v0.1 critical path를 지배하지 않고 hybrid extensibility를 보존한다.
- 이 architecture만으로 production WAF efficacy, HA, TLS operation 또는 raw-packet visibility가 증명되지는 않는다.

---

## ADR-012: Gateway edge, delivery, once-only enforcement protocol을 확정한다

### 상태

**채택됨 — 구현 증거 존재, integrated release 검증 미완료.** 최종 권장 architecture와 구현 준비 요청의 일부로 project owner가 2026-07-18 승인했다. 88-package backend gate, PostgreSQL 17.10 33-migration/72-table verifier, repeated-content-digest identity test, API-only terminal validation-attempt projection, focused frontend/harness suite 및 RUN25 fast mutation/browser/outage/restart evidence가 local implementation evidence를 제공한다. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`의 외부 clean clone도 `make check`를 통과했다. Default native-expiry, native host-ruleset, post-repair CI rerun, live OpenAI 및 release-duration gate는 open이다. 이 ADR은 ADR-006, ADR-010, ADR-011에서 명시한 executor-authority 및 recovery-reapplication mechanics만 대체한다. Edge, origin, minimization, delivery 및 auth-binding clause는 compatible earlier contract를 축소하거나 완성한다. 해당 ADR의 product goal, trust boundary, validation order, HIL requirement, Gateway-first 선택 또는 optional-adapter position은 대체하지 않는다.

### 맥락

ADR-006, ADR-010, ADR-011은 temporary isolated nftables enforcement, HIL 아래 exact AI-generated artifact, Gateway-first split을 선택했다. 그러나 원래 문구에는 implementation-sensitive ambiguity가 남았다. Worker가 executor에 직접 전달하는 것으로 보일 수 있고, recovery가 relative timeout을 다시 적용하는 것으로 보일 수 있으며, hooked rule 없이 timeout set만 존재할 수 있고, exact path가 persistence에 들어갈 수 있으며, batch, origin, protocol 및 crash behavior에 byte-exact interoperability contract가 없었다. 이 ambiguity는 privilege와 recovery boundary를 가로지르므로 implementation-local convention이 아니라 accepted decision으로 해결해야 한다.

### 결정

1. **대체 및 구체화 범위:** Former direct executor-authority 및 recovery-reapplication mechanics만 대체한다. 그 밖에는 compatible Gateway edge, origin, minimization, event-batch authentication 및 auth-binding contract를 축소하거나 완성하고 dispatcher/executor, namespace, replay, TTL 및 revocation mechanics의 구현 기준이 된다. ADR-006은 temporary, reversible, isolated enforcement를 계속 규정한다. ADR-010은 evidence-bound AI candidate, validation order, exact HIL binding, model authority 금지를 계속 규정한다. ADR-011은 Gateway-first data/control-plane split, direct-peer identity, non-blocking request path, hybrid source position 및 release scope를 계속 규정한다.
2. **HTTP edge 및 fixed private origin:** cleartext는 origin-form HTTP/1.1만 수용하고 optional TLS는 `http/1.1`만 advertise한다. Go `net/http`만 framing parser로 사용하며 middleware raw pre-parser를 금지한다. `http.Server.MaxHeaderBytes=32768`은 configured parser bound이지 byte-exact raw-wire claim이 아니며 selected Go version의 raw-socket differential test가 rejected 또는 safely normalized input이 origin request 최대 하나가 됨을 고정한다. HTTP/1.0, HTTP/2/h2c, unsupported target/upgrade/trailer/`Expect` form 및 allowlist에 없는 ASCII Host는 거부한다. Inbound forwarding 및 SentinelFlow request/trace ID를 제거하고 private application에 새 request/trace ID를 제공한다. 하나의 `http://` origin은 configured non-broad RFC 1918 IPv4 CIDR로 resolve/dial 제한하고 environment proxy를 비활성화한다.
3. **Exact-path minimization:** observed exact raw, normalized 또는 decoded path는 bounded Gateway classifier 내부에만 일시적으로 존재한다. Persistence, AI input, ordinary log, trace, audit payload, screenshot 및 captured fixture에는 configured `route_label`, `path_catalog_version=path-catalog-v1`, 하나의 `suspicious_path_id`만 전달한다. Reviewed synthetic exact path는 versioned parser/catalog test input에서만 허용한다. Fixed ID는 `admin_console`, `env_file`, `git_config`, `wp_admin`, `phpmyadmin`, `server_status`, `actuator_env`, `backup_archive`이고 non-match는 `none`이다.
4. **Atomic authenticated event delivery:** process boot마다 random 128-bit `sender_epoch`를 만들고 sequence는 1부터 시작한다. Retry는 exact body/epoch/batch/sequence를 유지한다. `X-Sentinel-Sender-ID`는 `[a-z0-9][a-z0-9._-]{0,63}`에 맞는 1~64 lowercase ASCII이고 body를 읽기 전에 sender/endpoint-scoped 최소 32-byte Base64 key를 선택한다. Signature는 `hex(HMAC-SHA256(key, endpoint_path + "\n" + sender_id + "\n" + timestamp + "\n" + nonce + "\n" + hex(SHA256(raw_body))))`이며 constant-time verify 뒤 body sender가 header와 byte-equal해야 한다. Nonce insert와 whole-batch persistence/ack는 atomically commit한다. Gateway와 auth producer는 각각 non-spooling checkpoint를 소유하고 endpoint-scoped `source-health-v1`을 emit할 수 있으며 loss는 incomplete로 남는다. HMAC request skew는 ±60초다. Receipt 기준 future 60초 또는 past 5분 밖 record time은 untrusted로 persist하고 detection, analysis, validation 또는 enforcement를 지원할 수 없다.
5. **Pending application-auth binding:** Gateway는 inbound request/trace ID를 제거하고 private application에 새 `X-SentinelFlow-Request-ID`와 `X-SentinelFlow-Trace-ID`를 제공한다. Demo application HTTP listener는 origin-network address에만 bind하고 authenticated producer는 ingest network에도 join해 API ingest-only address에 도달하며 어느 listener도 host port를 노출하지 않는다. Auth event는 5분 pending일 수 있고 request ID, trace ID, source IP, `demo-app` service 및 route가 정확히 일치해야 verified가 된다. Verified failure만 detection을 지원하고 mismatch/expiry는 untrusted이며 pending/untrusted success는 impact validation을 차단한다.
6. **단일 authority bridge:** minimal non-AI `cmd/dispatcher`만 restricted authorized-operation view와 dispatch private key를 읽는다. Exact approved job에서만 `add`, 별도 administrator authorization에서만 `revoke`, existing action에 결속된 lifecycle/reconciliation row에서만 `inspect`를 발급할 수 있으며 inspect는 read-only이고 mutation authority를 상속할 수 없다. Executor에는 verification/result key, replay journal, private UDS 및 namespace-local nft capability만 있다. 다른 component에는 이 privilege가 없고 dispatcher는 별도 서명된 모든 result를 검증한다.
7. **Canonical signed message 및 transport:** Strict checked-in schema가 모든 capability/result/envelope field, type, enum, nullable value, timestamp, digest, nonce 및 signature encoding을 정의한다. Policy, sorted-unique evidence snapshot, validation snapshot, NFC-normalized administrator reason, HIL authorization, capability, result, protected-range configuration 및 demo-history manifest는 RFC 8785/JCS와 lowercase `sha256:` digest를 사용한다. Artifact-content digest는 byte를 증명하며 non-unique lookup key일 수 있지만 database-row, lifecycle 또는 authorization identity가 아니다. 따라서 command 또는 inspect byte가 반복돼도 fresh evidence-bound candidate, policy, validation, challenge, decision, authorization, schedule/action 및 capability identity를 요구한다. Evidence array는 strictly ascending, duplicate-free, analysis/policy/command 간 byte-identical이어야 하고 invalid order는 repair하지 않고 거부한다. Private UDS는 4-byte unsigned big-endian length 뒤 최대 16 KiB strict UTF-8 JSON인 request 하나와 response 하나만 2-second I/O deadline 및 unpadded Base64url byte/signature field로 전달한다. Unknown/duplicate field, malformed/oversized frame, non-canonical byte, signature failure 또는 trailing frame은 mutation 전에 fail closed한다.
8. **Namespace 및 owned blocking schema:** executor sidecar만 Gateway network namespace를 공유하고 Gateway capability는 0이며 executor만 namespace-local `NET_ADMIN`을 가진다. Executor의 유일한 Compose dependency object는 `gateway`를 기준으로 `condition: service_started`, `required: true`, `restart: true`로 normalized한다. 이는 정확한 startup/restart ordering edge일 뿐 health assertion이나 privilege grant가 아니다. Executor bootstrap만 privileged provisioner다. Bootstrap 전후 complete stateless namespace ruleset을 inventory하고 raw `nft_base_chain_v1.nft` SHA를 load 전에 검증한 다음 owned table, timeout set, input hook/priority/policy, protected port 및 drop expression의 별도 canonical live-structure contract를 read back해 JCS digest한다. Foreign table은 adopt, rewrite 또는 normalize하지 않고 canonical state가 변하지 않아야 한다. Steady-state verification은 owned `inet sentinelflow` table만 읽는다. Restart 때 exact existing schema는 verify-only이며 element TTL을 갱신하지 않는다. Partial, extra, duplicated 또는 drifted owned schema는 자동 repair 없이 fail closed한다. Validator와 dispatcher는 두 digest를 모두 결속하고 host rule은 byte-for-byte 변하지 않는다. Versioned protected-IPv4 contract도 JCS digest하며 configuration은 range를 추가만 할 수 있고 isolated demo exception은 namespace/host invariance proof 뒤 RFC 5737 range 세 개만 제거할 수 있다.
9. **Exact TTL serialization:** structured `ttl_seconds`는 60부터 86,400까지의 integer다. Candidate token은 lowercase unit 하나를 가진 `[1-9][0-9]{0,4}[smh]`와 일치해야 한다. Checked arithmetic으로 second로 변환한 결과가 policy `ttl_seconds`와 같아야 한다. Canonical output은 정확히 나누어지는 가장 큰 unit을 사용한다. 3,600으로 나누어지면 hour, 그렇지 않고 60으로 나누어지면 minute, 그 외에는 second를 사용한다. Command token, policy value, validation snapshot, capability-bound artifact 및 read-back expectation이 정확히 일치해야 한다.
10. **Two-phase once-only replay journal:** Journal lookup은 freshness 또는 mutation보다 먼저 수행한다. Mutation 전에 executor는 exact capability JCS byte, detached signature, exact canonical artifact byte, 모든 capability/artifact digest, operation, target, schema, receive/deadline time 및 monotonic journal sequence를 포함한 checksummed `started` record를 append하고 file과 containing directory를 fsync한다. Terminal도 exact signed result byte를 같은 방식으로 저장한다. Startup은 checksum, sequence continuity, signature, digest 및 canonical byte를 검증하며 torn/corrupt tail은 fail closed하고 자동 truncate하지 않는다. Started-only record는 add 재호출 없이 read-back/classify할 충분한 persisted authority를 가진다. Duplicate/restart/reconciliation은 TTL을 갱신하지 않으며 새 add에는 새 candidate, validation, HIL authorization 및 capability가 필요하다.
11. **별도 mutation 및 observation operation:** `nft-revoke-v1`은 별도 administrator authorize되고 action/target/original digest/reason에 결속되며 delete만 수행한다. `nft-inspect-v1`은 existing action lifecycle row에서만 생성하는 별도 signed JCS artifact이고 fixed `nft --json list set inet sentinelflow blacklist_ipv4` read-back에만 mapping된다. Active/absent/mismatch/indeterminate를 보고할 수 있지만 add, delete, extend 또는 approval synthesis는 할 수 없다. Native timeout이 automatic expiry를 제공하고 bounded real-time Linux test가 kernel expiry를 검증한다. Early disappearance 또는 unexpected residue는 fail/alert 처리하고 automatic re-add는 없다.
12. **Golden interoperability evidence:** Checked-in byte-exact vector는 `event-batch-hmac-v1`, `capability-add-v1`, `capability-revoke-v1`, `capability-inspect-v1`, applied/recovered/revoked/inspect execution result, UDS frame, `demo-history-v1`, `ttl-canonical-v1`을 포함한다. Public test-only key와 deterministic byte가 JCS, digest, signature, framing, nullable field, authentication order, journal recovery 및 TTL conversion을 고정한다. Generated Go/TypeScript fixture는 동일 bundle에서 파생되고 repository check가 이를 regenerate 또는 verify한다.
13. **HIL challenge contract:** API는 session digest, operation, resource/version, validation snapshot 및 exact artifact digest에 결속된 5-minute single-use challenge를 발급한다. 독립 저장한 `authenticated_at`이 15분보다 오래되면 password step-up을 요구하고 성공한 step-up만 이를 갱신하며 session-token rotation만으로는 갱신하지 않는다. Decision/revocation은 CSRF, origin, idempotency, normalized reason 및 final optimistic transition과 함께 challenge를 atomically consume한다.
14. **Exact AI request contract:** Checked-in `sentinelflow_analysis_input_v1` 및 system-prompt artifact를 output schema와 함께 digest-pin한다. Builder는 한 incident version의 enforcement-eligible signal reference 전체를 stable ASCII reference ID 순으로 넣고 silent truncate 또는 repair하지 않는다. Signal reference는 server-side에서 complete immutable event set으로 expand되므로 120-event burst가 model reference 120개를 필요로 하지 않는다. Sorted-unique server-side expansion은 event ID 최대 1,000,000개이며 초과 시 sampling하지 않고 `input_too_large`로 실패한다. Duplicate, out-of-order, 50개 초과 또는 12-KiB 초과 model input도 typed failure가 되고 policy를 만들지 않는다.
15. **Demo-history 및 clock boundary:** Signed demo manifest는 dataset schema/version/digest, record count, source-health digest, import ID, coverage interval, path-catalog version 및 run profile로 하나의 checked-in canonical synthetic dataset에 결속한다. Production은 이를 거부한다. Injected application time은 deterministic event, retention, validation 및 authorization test에만 사용하고 native nft timeout/expiry는 bounded real-time Linux run에서 검증한다.

### 대안

- **General worker가 shared HMAC secret으로 executor를 호출:** AI/job process에 넓은 database access와 execution authority를 함께 부여하고 asymmetric result attestation을 제공할 수 없어 거부한다.
- **Crash 뒤 missing relative-timeout artifact를 다시 추가:** 승인된 duration을 조용히 갱신하며 “적용되지 않음”과 “적용 후 사라짐”을 구분할 수 없어 거부한다.
- **Protected-port input-chain rule 없이 timeout set만 사용:** Set membership만으로 Gateway traffic이 차단됨을 증명할 수 없어 거부한다.
- **편의를 위해 normalized path 또는 durable event record 저장:** Exact-path minimization을 위반하거나 health checkpoint를 선언되지 않은 sensitive-data spool로 만들기 때문에 거부한다.
- **General HTTP version, request-selected origin 또는 public/mixed DNS result 허용:** Frozen v0.1 security boundary 밖으로 proxy와 SSRF behavior를 확장하므로 거부한다.
- **Executor result에 dispatch key 재사용:** Dispatcher가 success를 위조할 수 있어 authority separation을 검증할 수 없으므로 거부한다.
- **Go 앞에 두 번째 raw HTTP parser 추가:** Parser disagreement가 방지하려는 smuggling boundary를 만들므로 거부한다. Pinned Go parser와 end-to-end raw-socket test가 authority다.
- **Browser가 자체 HIL nonce를 만들거나 inspect가 add approval을 재사용:** Server-side exact-artifact freshness를 증명하지 못하고 inspect는 independently signed non-mutating이어야 하므로 거부한다.

### 결과

- Crash recovery는 availability보다 bounded authority와 명시적 `indeterminate`/failed outcome을 우선하므로 관리자가 새 action을 만들고 승인해야 할 수 있다.
- JCS schema, asymmetric key, restricted DB view, private UDS, two-phase journal 및 golden vector로 implementation/operation 작업이 늘지만 authorization과 result provenance를 독립적으로 시험할 수 있다.
- No-spool Gateway는 request-path availability를 보존하는 대신 evidence gap을 명시하고 new enforcement를 억제한다.
- Exact-path minimization은 의도적으로 forensic detail을 줄이며 route 및 suspicious-path classification이 v0.1 detector에 충분해야 한다.
- Namespace demo는 frozen reference topology만 증명한다. Host enforcement 또는 production WAF 주장을 허가하지 않는다.
- 더 큰 checked-in contract pack과 real-time Linux expiry gate가 작업량을 늘리지만 implementer-dependent serialization, sender lookup, HIL, recovery 및 lifecycle interpretation을 제거한다.

---

## ADR-013: Renewable worker privilege 없이 demo-history authority를 stage하고 expire한다

### 상태

**채택됨 — integrated database evidence 존재, release 검증 미완료.** Asserted v0.1 demo profile의 architecture로 확정한다. PostgreSQL 17.10 verifier는 fresh/restart-noop과 `33→24→33`을 포함한 33 migration/72 table을 통과했고 staged activation 및 recovery evidence는 유지된다. RUN25 fast는 signed-history activation, exact HIL mutation/inspect/revoke, browser, outage, restart 및 cleanup path를 통과했다. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`의 외부 clean clone도 `make check`를 통과했다. Default native-expiry, native host-ruleset, post-repair CI rerun, live OpenAI 및 4-GB performance gate는 pending이다. 이 ADR은 ADR-012의 demo-history clause를 구체화하며 production에서 signed fixture를 허용하지 않는다.

### 맥락

RUN6는 Gateway/auth coverage readiness와 모든 simulator scenario를 증명했지만 모든 attack analysis가 `history_incomplete`를 보아 HIL 전에 실패했다. Signed manifest만으로는 충분하지 않다. Long-running worker가 history를 import, activate, refresh 또는 substitute할 수 있으면 deterministic fixture가 renewable enforcement authority로 바뀔 수 있다. PostgreSQL login role은 cluster-global이므로 session fencing 없는 database-local grant는 database 간에 남거나 transaction commit과 race할 수 있다.

Demo에는 freshly sealed public proof 하나에서 least-privilege consumer 둘로 이어지는 짧고 auditable한 bridge가 필요하다. Bounded run 뒤 fail closed해야 하며 production history-assertion service로 확장되어서는 안 된다.

### 결정

1. **Demo-only 및 disposable:** 이 mechanism은 asserted isolated demo profile에만 존재한다. Production은 fixture key, deterministic-clock manifest, activation capability, importer role 및 activator role을 거부한다. SentinelFlow demo profile 하나가 isolated PostgreSQL cluster authority lifecycle 하나를 소유한다.
2. **Distinct secret 및 digest-only persistence:** Demo preparation은 서로 다른 nonzero 32-byte capability 두 개를 생성하고 analysis와 validation에 하나씩 할당한다. Handoff는 lowercase `sha256:` digest만 migration/bootstrap authority에 노출한다. Raw capability byte는 별도 read-only volume에 남고 PostgreSQL, log, output 또는 다른 consumer에 저장되지 않는다.
3. **Five-minute staged database lease:** `sentinelflow_demo_importer`와 `sentinelflow_demo_activator`는 connection limit 2와 exact per-database timeout을 가진 cluster-global `NOINHERIT`, non-superuser, non-owner role이다. 평상시 `NOLOGIN`, password-null, epoch-expired다. Bootstrap은 현재 stage만 SCRAM credential과 최대 5분 `VALID UNTIL`로 열 수 있고 다른 role은 inert로 유지한다.
4. **Activation 전 fresh import:** Migration은 두 capability digest와 importer lease를 atomically pin한다. One-shot history importer는 먼저 connect하고 exact run-scoped Ed25519/JCS envelope, fixed dataset locator/digest, 24-hour coverage, import ID, source-health proof 및 immutable imported row를 검증한 뒤 해당 import 하나를 생성하거나 exact completed recovery state에만 attach한다. General worker는 모든 legacy import 및 validation-binding grant를 잃는다.
5. **Committed two-phase fencing:** 모든 success 또는 authenticated failure 뒤 phase one은 applicable role을 exact attribute의 `NOLOGIN`, password-null, epoch-expired로 commit한다. Commit 후에만 phase two가 다른 importer/activator session을 terminate하고 부재를 검증한다. Sole caller도 그 뒤 close한다. 이 순서가 last session scan과 transaction commit 사이의 login race를 막는다. Connection setup이 성공하지 못하면 five-minute `VALID UNTIL`이 outer bound다.
6. **Atomic one-hour consumer pair:** Importer fencing 뒤 narrow handoff가 pinned digest와 inert importer를 검증하고 activator만 잠깐 연다. `cmd/demoactivator`는 exact public proof를 재검증하고 raw capability 두 개를 읽어 manifest issue 뒤 5분 이내에 같은 claim, activation time 및 expiry를 가진 analysis activation 하나와 validation activation 하나를 생성한다. Pair는 activation 뒤 정확히 1시간에 expire하며 partial creation, mismatched claim, second pair 또는 extension은 거부한다.
7. **Create/refresh가 아닌 attach/use:** Long-running analysis와 validation process는 자기 capability만 mount한다. Byte-exact existing unexpired activation에만 attach하고 job/aggregate version 하나에 대한 append-only use를 기록할 수 있다. 어떤 worker도 history import, pair creation, expiry renewal, consumer identity exchange, silent order/digest repair 또는 missing/expired activation 계속 사용을 할 수 없다.
8. **Fail-closed recovery:** Exact completed import recovery와 exact pair reattachment는 idempotent다. Failed, importing, drifted, partially activated, stale 또는 expired state는 in-place repair하지 않는다. One-hour expiry 뒤 operator는 profile을 중지하고 전체 disposable demo state와 volume을 제거하며 새 run/capability를 생성하고 fresh cluster에서 migrate/import/activate해야 한다. Partial reseal, database reuse 또는 activation-only restart는 지원하지 않는다.
9. **Cluster-wide migration guard:** Migration startup, downgrade 및 production transition은 PostgreSQL cluster 전체에서 두 role을 normalize하고 retained session을 terminate하며 membership/elevated attribute를 거부하고 zero peer session을 검증한다. Migration owner는 fixed-name fencing function의 session superuser이고 `PUBLIC`과 unrelated role에는 execute grant가 없다. Evidence-bearing activation 또는 use가 있으면 downgrade를 차단한다.
10. **Independent evidence requirement:** Targeted unit/PostgreSQL integration test가 wrong capability, expired lease/activation, role-attribute drift, retained session, 한 cluster를 공유하는 database 둘, handoff 전후 failure, exact ACL, empty down/up, downgrade guard 및 no secret leakage를 다룬다. Static Compose policy는 exact command, dependency object, environment owner, complete mount inventory, authority-volume alias/write leak 부재를 증명해야 한다. RUN25는 fast mutation/outage/restart evidence를 제공하지만 default native-expiry, native host-ruleset, post-repair CI rerun, performance 및 final release gate를 대체하지 않는다.

### 대안

- **General worker가 signed history를 import하고 validate:** Long-running AI/validation process가 database write authority를 유지하고 자체 enforcement evidence를 갱신할 수 있어 거부한다.
- **Shared activation secret 하나 mount:** Analysis와 validation을 독립적으로 attribute할 수 없고 least-privilege consumer가 아니므로 거부한다.
- **Raw capability를 PostgreSQL 또는 environment output에 저장:** Database reader 또는 diagnostic path가 두 consumer 중 하나를 impersonate할 수 있어 거부한다.
- **한 transaction에서 role fence와 session scan 수행:** Role change가 commit되기 전에 new authentication이 race할 수 있어 거부한다.
- **Expired activation을 in-place renew:** 원래 five-minute proof freshness와 disposable run boundary를 old state에서 안전하게 재구성할 수 없어 거부한다.
- **Unrelated concurrent demo profile이 PostgreSQL cluster 하나 공유:** Login role과 `VALID UNTIL`이 cluster-global이므로 v0.1에서 거부한다.

### 결과

- Demo는 long-running worker에 import 또는 activation authority를 주지 않고 bounded, independently testable evidence bridge를 얻는다.
- Startup에 one-shot service, capability volume, role transition 및 failure gate가 늘어난다. Ambiguity가 있으면 analysis/validation이 enforcement-eligible 상태가 되지 않는다.
- Demo run은 activation 뒤 의도적으로 1시간으로 제한된다. Expiry recovery는 safety 때문에 full disposable reset과 reseal을 요구하므로 운영 부담이 크다.
- PostgreSQL cluster reuse와 rolling renewal은 지원하지 않는다. Production-grade attestation service, rotation, revocation 및 multi-database tenancy는 OQ-015와 follow-up ADR이 필요하다.
- Targeted database/static-policy evidence는 이 boundary를 독립적으로 검증하고 RUN25가 fast mutation/browser/outage evidence를 제공하지만 native expiry와 나머지 release gate가 통과할 때까지 release status는 **Still implementing**이다.

---

## 3. 확정된 v0.1 결정과 후속 ADR trigger

Detection threshold/lifecycle, Gateway identity/protocol bound, minimized event delivery, AI model/request/failure behavior, single-admin authentication, retention, nftables grammar/TTL/digest, validation/approval validity, protected-target policy, impact lookback, dispatcher/executor separation/recovery, non-renewable demo-history activation 및 performance target은 ADR-001부터 ADR-013에서 확정했다. Schema field mechanics, migration layout, queue implementation, UI composition 및 test harness detail은 이 결정을 구현해야 하며 변경 권한을 주는 미결사항이 아니다.

Product-level post-v0.1 trigger는 다음 세 가지뿐이다.

1. **Production TLS 및 HA:** TLS ownership, certificate lifecycle, horizontal scaling, failover 및 production availability claim은 follow-up ADR과 operational evidence가 필요하다.
2. **Adaptive `http-deny-v1`:** Gateway-local adaptive denial은 distinct artifact, validator, exact digest/HIL binding, authorization model, negative test 및 follow-up ADR이 필요하다. Nftables approval은 이를 authorize하지 않는다.
3. **Raw-packet sensor:** eBPF/XDP/raw-packet component는 별도 least-privilege process와 privacy, retention, capacity, protocol interpretation 및 failure isolation을 다루는 follow-up ADR이 필요하다.
4. **Production 또는 renewable history attestation:** Reusable, renewable, cross-database 또는 production history authority는 별도 identity, rotation, revocation, recovery 및 audit ADR이 필요하다. Demo-only importer/activator role과 activation capability를 그 service로 승격할 수 없다.

Roadmap item은 별도 승인 없이는 현재 결정에 포함되지 않는다. 이 ADR은 accepted intent와 implementation contract를 설명한다. 현재 verification evidence와 release limitation은 별도 [구현 준비도](./IMPLEMENTATION_READINESS.ko.md)에 기록하며 local implementation evidence 자체로 ADR status를 바꾸지 않는다.
