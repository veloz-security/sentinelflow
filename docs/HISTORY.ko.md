# 프로젝트 이력과 출처

[English](./HISTORY.md)

## 1. 시작

SentinelFlow는 **OpenAI Build Week**의 **Developer Tools** 부문을 위해 준비한 설명 가능한 보안 게이트웨이 프로토타입으로 시작했다. 저장소의 최초 commit 날짜는 2026-07-15다. 이 배경은 프로젝트 이력에 남으며 공개 소개를 보안 연구 중심으로 바꾼다고 제출, 수상 또는 외부 평가를 완료했다는 뜻은 아니다.

초기 구현은 고정된 private upstream 하나 앞의 inline Go HTTP reverse proxy, 결정적 탐지, 구조화된 AI 분석, 정확한 산출물에 대한 관리자 승인, 격리된 임시 nftables 집행에 초점을 맞추게 됐다. 선택적 log adapter와 raw-packet sensing은 v0.1 릴리스 요구사항 밖에 남는다. [결정 기록](./ADR.ko.md)은 아키텍처 이력과 이전 결정을 대체하는 결정을 보존한다.

## 2. 개발 방식

Codex는 제품과 아키텍처 계약, 범위가 한정된 구현 패키지, 코드와 테스트, 보안 및 복구 검토, 브라우저 검사, 영문/한글 문서 동기화를 지원했다. Agent의 완료 진술은 검증 증거가 아니다. Root integrator가 통합 결과를 검토하고 관련 검사를 다시 실행해야 한다.

Runtime에서 GPT-5.6은 결정적 탐지 이후 간결하고 구조화된 incident fact를 분석한다. 출력은 신뢰하지 않는 제한된 데이터이며 shell, 승인, 서명 또는 firewall 권한을 받지 않는다. [연구 문서](./RESEARCH.ko.md)는 구현과 테스트 경계를 설명한다.

## 3. 소유권과 공개 연구 게시

SentinelFlow는 **벨로즈(Veloz)** 소유이며 [devwooops/sentinelflow](https://github.com/devwooops/sentinelflow)를 통해 공개 유지보수한다. 회사 웹사이트는 [sec.veloz.kr](https://sec.veloz.kr), 보안 연락처는 [security@veloz.kr](mailto:security@veloz.kr)다. 소유자는 2026-10-07 공개 문서 업데이트를 위해 이 귀속 정보를 확인했다. 프로젝트는 기존 [MIT License](../LICENSE)로 계속 제공한다.

2026-10-07 구조 정리는 독자가 작업을 검토하고 이름이 지정된 버전을 재현할 수 있도록 연구, 출처, 릴리스 지침, 기여 안내, 보안 제보를 분리한다. 첫 공개 패키지는 실험적 `v0.1.0-rc.1` 사전 릴리스를 목표로 한다. 공개는 production readiness, 고객 도입, 인증, 완료된 독립 감사 또는 공급사 접근 프로그램 승인을 주장하지 않는다.

## 4. 증거와 미완료 작업

[Tasklist](./TASKLIST.ko.md), [WBS](./WBS.ko.md), [Implementation Readiness](./IMPLEMENTATION_READINESS.ko.md)는 구현 의존성, 기록된 검증 결과, 열린 gate를 유지한다. 과거 local 또는 CI 성공은 식별된 revision과 환경에만 해당하는 증거다. 연구 사전 릴리스 게시는 M9-008 또는 전체 v0.1 수용 절차를 완료하지 않으며 Build Week 제출 증거는 별도의 과거 계획 산출물로 남는다.

패키징 산출물, 재현 가능한 검사, 남은 검증을 구분하려면 [릴리스 안내](./RELEASE.ko.md)를 참조한다. 실제 commit과 게시 기록은 [Git 이력](https://github.com/devwooops/sentinelflow/commits/main/)과 [GitHub Releases](https://github.com/devwooops/sentinelflow/releases)를 참조한다.
