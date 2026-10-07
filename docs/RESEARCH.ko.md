# SentinelFlow 보안 연구

[English](./RESEARCH.md)

SentinelFlow는 **벨로즈(Veloz)** 소유의 MIT 라이선스 방어용 보안 게이트웨이이며 [devwooops/sentinelflow 저장소](https://github.com/veloz-security/sentinelflow)에서 유지보수한다. 회사 웹사이트는 [sec.veloz.kr](https://sec.veloz.kr)이다. 보안 제보는 [SECURITY.md](../SECURITY.md)를 따르거나 [security@veloz.kr](mailto:security@veloz.kr)로 연락한다.

이 문서는 연구자, 평가자, 잠재적 기여자가 검토할 수 있는 엔지니어링 결과를 제시한다. 인증, 고객 배포, 독립 감사 또는 특정 공급사 프로그램의 승인을 주장하지 않는다. 실험적 `v0.1.0-rc.1` 공개는 작업의 재현을 돕지만 구현 검증 완료 v0.1 릴리스 게이트를 완료하지 않는다.

## 1. 연구 질문

보안 게이트웨이는 모델에 직접 집행 권한을 주거나 HTTP 요청 경로에 모델 지연을 추가하지 않으면서 어떻게 LLM으로 탐지된 사건을 설명하고 제한된 대응을 제안할 수 있는가?

구현은 세 경계를 탐구한다. 요청 내용 보존 대신 최소화된 관측, AI 해석에 앞서는 결정적 증거, 정확한 산출물에 대한 사람의 승인 이후 격리된 임시 집행이다. [PRD](./PRD.ko.md), [아키텍처 결정](./ADR.ko.md), [기술 설계](./TDD.ko.md)는 의도한 계약을 정의한다. 코드와 재현 가능한 테스트는 구현된 동작을 입증한다.

## 2. 구현과 테스트 연결

| 연구 영역 | 구현 | 재현 및 실패 사례 |
| --- | --- | --- |
| HTTP 신원과 고정 origin | [Gateway](../internal/gateway/handler.go), [origin 정책](../internal/gateway/origin.go), [경로 분류](../internal/gateway/path.go) | [Gateway 테스트](../internal/gateway/gateway_test.go), [통합 게이트](../internal/gateway/integration_gate_test.go), [origin 테스트](../internal/gateway/origin_test.go): 위조 헤더, 프로토콜 경계, origin 제한, control-plane 성능 저하 중 전달 |
| 인증된 최소화 증거 | [타입이 있는 이벤트](../internal/events/types.go), [HMAC 검증](../internal/ingestion/hmac.go), [송신자 checkpoint](../internal/eventsender/checkpoint.go) | [이벤트 테스트](../internal/events/events_test.go), [HMAC 테스트](../internal/ingestion/hmac_test.go), [checkpoint 테스트](../internal/eventsender/sender_test.go): 잘못된 필드, 인증/replay 실패, 재시작 및 손실 의미 |
| AI 이전 결정적 탐지 | [탐지기](../internal/detection/detector.go), [상관 분석](../internal/correlation/correlate.go), [AI adapter](../internal/ai/client.go), [strict output schema](../contracts/ai/sentinelflow_analysis_v1.schema.json) | [탐지기 테스트](../internal/detection/detector_test.go), [AI adapter 테스트](../internal/ai/client_test.go): 임계값, 잘못된/거부된/불완전한 출력, 증거 일관성 및 공급자 실패 |
| 제한된 명령과 정확한 승인 | [명령 parser](../internal/policy/parser.go), [검증](../internal/validation/consistency.go), [HIL 결정](../internal/hil/decision.go) | [정책 테스트](../internal/policy/policy_test.go), [보호 대상 테스트](../internal/validation/protected_test.go), [HIL 안전 테스트](../internal/hil/safety_test.go): 추가 구문, 불일치 증거, 보호 주소, 오래되거나 바꿔치기된 산출물 |
| 격리된 실행과 복구 | [executor](../internal/enforcement/executor/service.go), [journal](../internal/enforcement/journal/journal.go), [lifecycle](../internal/lifecycleruntime/runtime.go) | [executor 복구](../internal/enforcement/executor/recovery_test.go), [journal 손상](../internal/enforcement/journal/corruption_test.go), [만료 경계 통합](../internal/lifecyclestore/expiry_bounds_v1_integration_test.go): replay, 손상, 서명된 read-back 경계, TTL 갱신 금지 |

테스트 링크는 실행 가능한 검사를 가리키며, 파일의 존재만으로 특정 릴리스가 통과했다고 주장하지 않는다. [CI](../.github/workflows/ci.yml), [릴리스 안내](./RELEASE.ko.md), [Implementation Readiness](./IMPLEMENTATION_READINESS.ko.md)는 명령, 증거 범위, 남은 검증 작업을 제시한다.

## 3. 대응 권한 경계

대응 경로는 순서를 지킨다. Structured-output 및 명령 parsing/canonicalization → policy/evidence/command 일관성 → 보호 네트워크 검사 → 소유 schema 기반 nftables 구문 검증 → 과거 영향 분석 → digest로 정확한 산출물에 대한 관리자 승인 → 격리된 shell-free 임시 실행 → 만료와 감사 순서다.

모든 선행조건이 통과해야 하며 승인은 실패한 검증을 무시할 수 없다. 모델은 executor 또는 서명 권한을 받지 않는다. 최소 dispatcher가 수명이 짧은 exact capability에 서명하고 executor가 검증, 작업 journal 기록, 고정 nftables operation 호출, 결과 서명을 수행한다. 중복 또는 crash 복구는 차단을 다시 추가하거나 TTL을 갱신할 수 없다. 읽기 전용 inspect와 결정적 revoke는 별도 typed operation이다.

[기존 위협 모델](../README.md#threat-model)은 request smuggling, 신원 위조, origin 우회, 증거 오염, prompt injection, 오래된 승인, 권한 분리, crash 복구를 다룬다. Gateway, capability, history authority, expiry-bound의 근거는 [결정 기록](./ADR.ko.md)의 ADR-011부터 ADR-014를 참조한다.

## 4. 증거 재현과 해석

[릴리스 안내](./RELEASE.ko.md)의 격리된 stub-analysis profile부터 시작한다. Clean checkout에서 저장소 gate를 실행하고 commit, tool version, 명령, 종료 상태, 정제된 결과를 보관한다. [Compose E2E harness](../scripts/check-demo-e2e.sh)는 통합 workflow를 실행하며 실제 kernel expiry와 host nftables 불변성에는 적합한 Linux 환경이 필요하다. [성능 gate](../scripts/check-gateway-performance.sh)는 smoke 검사와 5분 4 GB 릴리스 검증을 구분한다.

합성 fixture와 결정적 모델 stub은 반복 재현을 지원한다. Stub 결과는 실제 공급자 호환성을 입증하지 않는다. Live OpenAI 테스트는 별도 opt-in이며 운영자 credential과 rate card가 필요하고 API 비용이 발생할 수 있다. Readiness 기록에 공개된 과거 결과는 기록된 tree와 환경에 한정되며 이후 commit의 증거가 자동으로 되지 않는다.

## 5. 한계와 공개 범위

현재 범위는 고정된 private upstream 하나, direct TCP-peer client identity, 네 fixed-threshold detector, Linux nftables 집행을 갖춘 single-node HTTP/1.1 gateway다. Raw packet capture, payload inspection, multi-tenant 운영, 고가용성 또는 범용 WAF 대체 기능은 제공하지 않는다. Credential-stuffing 탐지에는 인증된 application event가 필요하다. 오탐과 bounded queue 포화 중 event loss는 가능하며 불완전한 증거는 새 adaptive block을 승인할 수 없다.

회사 소유 표기는 귀속을 설명하며 실제 운영 도입을 입증하지 않는다. 이 저장소와 tag 산출물은 버전, 날짜, 한계, 실제 검증 증거를 함께 밝혀 공개된 보안 엔지니어링 작업으로 인용할 수 있다. 공급사 프로그램의 자격과 승인은 프로그램 운영자가 별도로 판단한다. 실험적 공개 경계는 [릴리스 안내](./RELEASE.ko.md)를 참조한다.
