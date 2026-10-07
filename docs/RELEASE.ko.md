# 실험적 연구 릴리스 안내

[English](./RELEASE.md)

## 1. 릴리스 분류

`v0.1.0-rc.1`은 벨로즈(Veloz) 소유 SentinelFlow의 **실험적 연구 사전 릴리스**다. 검토와 격리된 평가를 위해 소스 코드 및 Linux command binary를 패키징한다. Production 지원 약속, 인증 또는 구현 검증 완료 v0.1 릴리스 기준 전체가 완료됐다는 증거가 아니다.

게시 상태, tag, commit, 첨부 checksum, 검증 기록의 기준은 [GitHub release 기록](https://github.com/veloz-security/sentinelflow/releases)이다. 패키지 또는 tag만으로 M9-008이 완료되지 않는다. [PRD](./PRD.ko.md), [TDD](./TDD.ko.md), [Tasklist](./TASKLIST.ko.md), [WBS](./WBS.ko.md)의 모든 수용 및 안전 gate는 그대로 유효하다. [Readiness 기록](./IMPLEMENTATION_READINESS.ko.md)은 과거 증거와 남은 검증을 구분한다.

## 2. 산출물과 무결성

| 산출물 | 내용 |
| --- | --- |
| `sentinelflow-v0.1.0-rc.1-source.tar.gz` | `sentinelflow-v0.1.0-rc.1/` 아래 명시적 committed source snapshot |
| `sentinelflow-v0.1.0-rc.1-linux-amd64.tar.gz` | `bin/` 아래 Linux amd64 command binary, license, `THIRD_PARTY_NOTICES.json`, `licenses/`, release metadata |
| `sentinelflow-v0.1.0-rc.1-linux-arm64.tar.gz` | `bin/` 아래 Linux arm64 command binary, license, `THIRD_PARTY_NOTICES.json`, `licenses/`, release metadata |
| `RELEASE-INFO.json` | 버전, source revision, build metadata |
| `SHA256SUMS` | 패키징 산출물의 SHA-256 checksum |

macOS에서의 cross-compilation은 Linux binary가 빌드됨을 확인하며 Linux에서 올바르게 실행됨을 입증하지 않는다. Release 증거에 명시적으로 기록하지 않았다면 Linux binary runtime 검사는 unverified로 취급한다.

Binary archive에는 container image, 사전 빌드한 web UI, database 또는 구성된 배포가 들어 있지 않다. 완전한 reference 환경에는 아래 source-based Compose workflow를 사용한다. 의존성과 image 요구사항은 저장소에서 계속 고정한다.

사용하려는 release의 첨부 asset을 한 디렉터리에 모두 내려받은 뒤 Linux에서 압축을 풀기 전에 검증한다.

```bash
sha256sum --check SHA256SUMS
```

Checksum은 손상을 탐지하며 독립적인 게시자 서명이 아니다. 저장소, tag, source revision, release 기록이 사용하려던 대상인지 확인한다.

## 3. 격리된 Linux 평가

최소 4 GB RAM, Docker 24+, Docker Compose v2, Go `1.25.13`, Node.js, npm이 있는 disposable Linux 환경을 사용한다. 저장소 CI는 Node.js `24.13.0`을 고정한다. 집행에는 Linux network namespace와 nftables가 필요하다. 기본 demo의 management port는 loopback에 bind되고 executor는 host namespace가 아닌 Gateway namespace를 공유한다.

게시된 tag에서 시작한다.

```bash
git clone --branch v0.1.0-rc.1 --depth 1 https://github.com/veloz-security/sentinelflow.git
cd sentinelflow
./scripts/prepare-demo.sh
COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --env-file .env.demo \
  --file deployments/compose.yaml \
  --profile stub-ai up --build
```

압축 해제한 source directory에서도 같은 startup command를 사용한다. `prepare-demo.sh`는 backend image를 빌드하고 nftables binary identity를 검증한 뒤 ignored local bundle을 생성한다. `.env.demo`, `secrets/demo`, `data/demo-history` 덮어쓰기를 거부한다. 생성한 secret은 Git과 공개 증거 밖에 둔다.

기본 port에서는 [local 관리자 UI](http://localhost:4173)를 연다. 생성한 관리자 credential은 local `secrets/demo/admin-credentials.json`에 있으며 screenshot, log, report에 넣지 말고 비공개로 읽는다. Gateway는 `localhost:8080`에서 listen하고 management API는 `127.0.0.1:8083`에 bind된다. Private demo application에는 공개된 host port가 없다.

`stub-ai` profile은 결정적 합성 분석을 사용하며 OpenAI key가 필요 없다. 검증, HIL, 격리된 실행 경계는 유지한다. Live analysis는 운영자 credential과 rate card가 필요한 별도 opt-in profile이며 stub 성공을 live-provider 검증으로 표현해서는 안 된다.

Volume을 유지하며 이 Compose project를 중지하려면 다음을 실행한다.

```bash
COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --env-file .env.demo \
  --file deployments/compose.yaml \
  --profile stub-ai down
```

서명된 demo-history activation은 1시간 뒤 만료되고 제자리 갱신할 수 없다. 만료된 demo authority에는 완전한 disposable profile/volume reset과 새로 sealed한 run이 필요하며 project 중지 및 재시작은 이를 갱신하지 않는다. 데이터를 reset하기 전에 [기술 배포 계약](./TDD.ko.md)을 따른다.

## 4. 재현 가능한 패키징

패키징에는 Git, Bash, Python 3.8+, tar, `go.mod`에 고정된 Go toolchain, 네트워크 접근 또는 채워진 module cache가 필요하다. Untracked file도 없는 clean committed checkout에서 실행하고 checkout 밖의 새로운 절대 output directory를 선택한다.

```bash
./scripts/build-release.sh v0.1.0-rc.1 /tmp/sentinelflow-v0.1.0-rc.1-artifacts
```

Output path는 이미 존재해서는 안 된다. Source archive는 선택한 Git commit에서 생성하며 ignored 및 untracked local file은 제외한다. Script는 Linux amd64와 arm64 command를 빌드하고 결정적인 archive, metadata, checksum을 만든다. `SOURCE_DATE_EPOCH`를 제공하면 source commit timestamp와 일치해야 한다. 패키징은 service를 실행하거나 firewall policy를 적용하거나 GitHub release를 게시하지 않는다.

패키징 회귀 검사는 별도로 실행한다.

```bash
./scripts/check-release.sh
```

Disposable committed fixture에서 두 번 빌드하고 결과 산출물을 비교하며 잘못된 입력을 검사한다. [Release workflow](../.github/workflows/release.yml)는 수동 dispatch 시 내려받을 수 있는 CI artifact를 생성하며 maintainer가 검토한 prerelease와 증거를 별도로 게시한다.

## 5. 검증과 정식 수용

게시 전에 정확한 commit과 적용되는 검사의 성공을 기록한다. 저장소는 다음 gate를 제공한다.

```bash
make check
make check-integration
./scripts/check-release.sh
./scripts/check-demo-e2e.sh
make check-gateway-performance
```

`make check`는 backend, contract, documentation, frontend, security, supply chain, threshold tuning을 다룬다. `make check-integration`은 database, nftables namespace, image, observability, recovery, export 검사를 다룬다. 마지막 두 명령은 적합한 Linux 환경이 필요하다. E2E gate는 실제 kernel expiry와 host nftables 불변성을 증명해야 하며 기본 performance gate는 5분 4 GB reference run을 요구한다. `--fast` E2E와 performance smoke mode는 개발 증거일 뿐이다. 각 test harness는 자체 disposable resource를 관리하며 실행 전에 선행조건을 살펴본다.

Supply-chain scanner는 2026-07-18 날짜로 고정된 Trivy database를 사용한다. 이 검사를 다시 실행하면 해당 snapshot에 대한 일관성을 확인하며 2026년 10월 현재 취약점 안전성을 보장하지 않는다.

실험적 공개는 정확한 source revision에 대해 실행한 검사와 아직 검증하지 않은 검사를 명시해야 한다. 과거 local 결과와 이전 CI run을 현재 release 증거로 자동 승격하지 않는다. 전체 v0.1 검증에는 canonical document의 모든 acceptance, failure/recovery, real-browser, 정제된 release-capture, dependency, final-decision 기준도 필요하다. 연구 패키징은 그 작업을 완료 처리하지 않는다.

## 6. 한계와 지원

Reference implementation은 하나의 고정 private upstream과 HTTP/1.1, Linux nftables 임시 대응, 관리자 한 명을 지원한다. Production HA, payload inspection, raw-packet sensing, multi-tenant 지원 또는 범용 WAF 동등성은 제공하지 않는다. 오탐과 관측 가능한 event loss가 발생할 수 있다. 전체 [알려진 한계](../README.md#known-limitations)와 [보안 정책](../SECURITY.md)을 검토한다.

일반적인 재현 가능한 결함은 버전과 정제된 증거를 포함해 저장소에 보고한다. 취약점 의심 사항은 [security@veloz.kr](mailto:security@veloz.kr)로 비공개 제보한다. 회사 웹사이트는 [sec.veloz.kr](https://sec.veloz.kr)이며 이 release는 외부 프로그램 승인이나 인증을 의미하지 않는다.

## 회사 조직으로 저장소 이전

2026-10-07 소유자가 회사 조직 [veloz-security](https://github.com/veloz-security)를 생성했다. 기존 [SentinelFlow](https://github.com/veloz-security/sentinelflow)와 [pktide](https://github.com/veloz-security/pktide) repository를 재생성하지 않고 GitHub repository-transfer API로 이전했다. 두 repository의 ID, branch/tag commit SHA, release ID, pull-request ID, 공개 상태 및 administrator 권한이 유지됐다. 기존 pktide tag와 release도 보존했다. M9-013에 이 검증을 기록한다.

SentinelFlow의 local `origin`과 공개 repository/release link는 이제 조직 주소를 사용한다. 별도로 검토한 module migration 전까지 GitHub redirect를 통해 Go module import path `github.com/devwooops/sentinelflow`를 유지한다. Repository 소유권 변경은 runtime 또는 enforcement contract를 변경하지 않는다. MIT 저작자 고지를 보존한다.
