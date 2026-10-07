# SentinelFlow 구현 준비도

[English](./IMPLEMENTATION_READINESS.md)

마지막 업데이트: 2026-07-20

## 게시된 연구 릴리스 (2026-10-07)

[v0.1.0-rc.1](https://github.com/veloz-security/sentinelflow/releases/tag/v0.1.0-rc.1)을 `1ae56b965355bd82d051a4794db26c72d2bb704d`에서 실험적 연구 prerelease로 게시했다. [Exact-source hosted CI](https://github.com/veloz-security/sentinelflow/actions/runs/37592532654)가 backend, database, frontend, recovery, 새로운 image security evidence 및 결정적 packaging을 포함한 11개 job을 모두 통과했다. 업로드한 asset 5개의 digest와 size는 검증한 local output과 일치한다. 별도 publication/maintenance 범위에서 M9-010, M9-011, M9-012, M9-013, M9-014를 완료했다. 구현 검증 완료 full v0.1의 P0 prerequisite, 최종 acceptance/performance rehearsal 및 release-capture 의무는 open이며 7월 runtime 결과를 새로운 10월 검증으로 바꾸어 주장하지 않는다.

## 공개 연구 배포 checkpoint (2026-10-07)

SentinelFlow는 벨로즈(Veloz) 소유이며 공식 사이트는 [sec.veloz.kr](https://sec.veloz.kr)이다. 소유자는 [security@veloz.kr](mailto:security@veloz.kr)을 보안 문의 주소로 제공했다. 소유자가 공개 구조 정리와 릴리스 게시를 요청했다. `v0.1.0-rc.1`은 구현 검증 완료 v0.1 릴리스와 별개인 실험적 연구 배포다. Production, 고객 실적, 인증 또는 CVP 승인 주장은 하지 않는다. Runtime과 enforcement contract는 변경하지 않는다.

Implementation checkpoint `b125adec66864c87f5d37f15049514381dd9e4f3`에는 migration 34와 v2 expiry repair가 이미 commit되어 있으며 [CI run 29709922172](https://github.com/veloz-security/sentinelflow/actions/runs/29709922172)이 해당 commit의 10개 shard를 모두 통과했다. 아래의 이전 “current-tree” 결과는 2026년 7월 snapshot이며 새로운 10월 rerun이 아니다. Release record는 자신의 exact commit과 verification을 명시해야 한다. 기존 P0 prerequisite와 full v0.1 acceptance gate는 독립적으로 충족될 때까지 open으로 유지한다. [Release guide](./RELEASE.ko.md), [research evidence](./RESEARCH.ko.md), ADR-015 및 M9-010을 참조한다.

공개 배포용 patch maintenance는 ADR-016을 따른다. Go `1.25.13`, `golang.org/x/text` `v0.39.0` 및 동일 major 내 frontend dependency 수정은 새로운 backend(M9-011) 및 독립 frontend(M9-012) 검증이 필요하다. 기존 safety contract와 full release gate는 유지한다.

10월 검증: M9-011은 patched 88-package backend gate, 새로운 govulncheck, infrastructure contract 25/25, backend image build 및 unprivileged read-only/no-network runtime probe를 통과했다. M9-012는 optional npm peer normalization 후 npm audit(finding 0건), Vitest 39 file/363 test, CSP 1/1, 실제 browser test 88개 및 Linux visual 4/4를 통과했다. 이 독립 P1 maintenance task는 기존 P0 prerequisite graph를 완료하지 않는다. M9-013 이전과 M9-010 실험적 게시를 검증했다.

Release image evidence 갱신은 ADR-016 아래 M9-014로 추적한다. 2026-10-07 immutable scanner database가 만료된 7월 snapshot을 교체하지만 7일 freshness, critical-vulnerability rejection, digest/metadata verification 및 image binding 요구는 유지한다. 이 package에서 Leaf 3은 scripts/check-images.sh와 scripts/supply-chain-policy{,.test}.mjs만 소유하고 ROOT는 canonical 문서와 최종 게시를 소유한다.

## 1. 준비도 선언

SentinelFlow는 architecture readiness에서 integrated implementation과 release stabilization 단계로 이동했다. Gateway-first data plane, control-plane service, database, administrator UI, dispatcher/executor boundary, recovery/export/observability tooling 및 test harness가 shared workspace에 존재한다. 하지만 아직 complete v0.1 release를 주장하지 않는다.

Tasklist completion은 code 존재보다 엄격하다. 기존 P0 graph에서 모든 deliverable과 prerequisite를 충족한 항목은 `M0-001`, `M0-002`, `M0-009`, `M0-015`, `M0-017`, `M0-019`뿐이다. Commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`는 publish된 baseline이며 외부 clean clone이 `make check`를 통과했다. Hosted CI run `29696139988`은 implementation checkpoint `5ef870155bc59e6ac3c30279a7cd8be8d0249887`에서 10개 shard를 모두 통과했지만 `M0-006`과 `M0-008`은 `M0-003`과 `M0-007`이 unchecked prerequisite이므로 unchecked로 유지한다. M0가 완료되지 않았으므로 local implementation evidence가 강한 항목도 기존 downstream P0 M1–M10 checkbox는 open으로 유지한다.

## 2. 동결된 구현 기준선

- `cmd/gateway`는 하나의 고정 private upstream을 위한 1차 HTTP sensor이자 reverse proxy다.
- `gateway-http-v1`, `auth-event-v1`, source health, sender checkpoint 및 retry-safe `event-batch-v1` envelope은 v0.1 입력 contract다.
- Internal request는 endpoint와 bounded sender header를 HMAC에 결속한다. Gateway와 auth producer는 각각 loss를 노출하고 record time이 +60초/-5분 밖이면 non-enforcing이다.
- Nginx/Syslog/firewall-log adapter, raw packet sensing 및 `http-deny-v1`은 post-v0.1 작업이다.
- Request path는 PostgreSQL, GPT-5.6, policy validation, administrator approval 및 nftables와 독립적이다.
- GPT는 Responses API를 통해 explicit `gpt-5.6-sol`과 strict Structured Outputs를 도구 없이 사용한다.
- AI output은 계속 untrusted이고 accepted `nft-blacklist-v1` exact-artifact HIL path가 유일한 adaptive enforcement path다.
- Gateway에는 `NET_ADMIN`이 없고 namespace-sharing executor만 이를 가지며 restricted authorized-operation view를 사용하는 minimal non-AI dispatcher만 private UDS를 통해 typed add, revoke 또는 read-only inspect artifact를 authorize할 수 있다.
- Executor bootstrap은 `inet sentinelflow`만 소유하고 foreign table을 보존하며 exact existing schema를 TTL refresh 없이 검증한다. Partial, extra, duplicate 또는 drifted owned state에서는 repair 없이 fail closed한다.
- Dispatcher capability, executor-signed result, protected-range/live-schema contract, HIL snapshot 및 demo-history manifest는 해당되는 경우 separate Ed25519 key, RFC 8785/JCS byte, golden vector 및 replay-safe two-phase journal을 사용한다.
- Asserted demo profile은 distinct five-minute PostgreSQL importer/activator lease를 통해 signed history를 stage한다. Migration은 서로 다른 analysis/validation capability digest만 pin하고 one-shot service는 peer session을 terminate하기 전에 `NOLOGIN`/password-null/epoch-expired fencing을 commit하며 atomic consumer pair는 정확히 1시간 유지되고 refresh할 수 없다.
- Analysis와 validation은 각자의 raw 32-byte capability만 mount하고 exact unexpired activation만 attach/use할 수 있다. Expiry, partial state, drift 또는 wrong capability는 fail closed하고 expiry 뒤 recovery는 complete disposable profile/volume reset과 새 sealed run을 요구한다.
- Recovery는 indeterminate state를 read back할 뿐 relative TTL을 re-add하거나 refresh하지 않는다. Manual removal은 별도 deterministic `nft-revoke-v1` artifact다.
- Lifecycle inspect는 별도 서명된 read-only `nft-inspect-v1` operation이며 native expiry는 bounded real-time Linux gate로 남는다.
- Previously recorded lifecycle repair는 `execution-result-v2`를 추가한다. Executor-signed millisecond `readback_started_at`/`readback_completed_at`가 read-back lower/upper expiry bound를 만들고 migration `000034_execution_result_v2_expiry_bounds`가 이를 별도로 저장한다. v1 historical record는 보존하고 result/bound reuse를 거부하며 이후 inspect가 TTL을 refresh하지 못하도록 original active read-back만 bind한다. Focused recovery-bundle 및 migration-chain test는 signed v2 bracket/bound equality, second lifecycle mutation 없는 exact replay, persisted v2 terminal result의 crash recovery를 검증하며 backup preflight도 v1/v2 shape와 bound를 검증한다. Current-tree Linux native v6 E2E도 실제 kernel expiry, signed absent inspection, audit/recovery/forwarding convergence 및 cleanup 뒤 unchanged semantic host nftables로 exit `0`을 기록했다. 이는 runtime evidence이며 release authorization은 아니다.
- HIL challenge는 exact session, operation, resource/version, validation snapshot 및 artifact digest를 bind한다. NFC-normalized reason과 `reason_digest`는 challenge가 아니라 consumed decision에 처음 들어간다.
- Artifact-content digest는 row, lifecycle 또는 authorization identity가 아니라 integrity value이자 non-unique lookup key다. 이후 workflow에서 동일한 add 또는 inspect byte를 사용해도 fresh evidence-bound candidate, policy, validation, challenge, decision, authorization, schedule/action 및 capability ID를 요구한다.
- Management API는 successful HIL-authorizing validation snapshot과 typed terminal `latest_validation_attempt`를 구분한다. Migration-owned security-definer projection은 API role만 실행할 수 있고 raw attempt table과 prepared/terminal JSON은 denied 상태를 유지하며 claim/result mismatch는 generic `503` response로 fail closed한다.
- Migration 33은 immutable history가 해당 version 존재와 current incident advance를 증명할 때만 provider claim/dead letter 전에 queued analysis를 audited `analysis_superseded`로 완료한다. Current incident는 변경하지 않고 실제 missing aggregate는 unresolved `analysis_incident_missing` evidence로 남는다.
- Incident detail은 base read가 capture한 evidence version에 `latest_analysis`를 bind하고 해당 version 안에서만 attempt를 정렬하며 later statement에서도 captured binding을 보존하므로 concurrent evidence advance가 newer analysis를 대체하지 못한다.
- Frontend는 CSP-safe static API-error decoder를 사용한다. Deployment는 `'unsafe-eval'`이 없는 exact CSP 하나를 pin하고 verification은 해당 header를 parse하며 emitted production JavaScript chunk 전체의 dynamic code generation을 scan하고 동일 header 아래 built application을 Chromium으로 실행한다.
- Frontend/UI/UX implementation은 Gateway, backend, AI, policy, executor 및 infrastructure workstream과 분리한다.

Normative detail은 [PRD.ko.md](./PRD.ko.md), [ADR.ko.md](./ADR.ko.md), [TDD.ko.md](./TDD.ko.md)에 있다. Work order와 evidence-bound completion은 [TASKLIST.ko.md](./TASKLIST.ko.md), [WBS.ko.md](./WBS.ko.md)에 있다.

## 3. 구현된 저장소 기준선

| 영역 | 구현 artifact | 현재 evidence 상태 |
| --- | --- | --- |
| Workflow 및 configuration | `AGENTS.md`, `.gitignore`, `.env.example`, typed safe configuration | 존재함. Secret-bearing local file은 ignored 상태이고 documentation evidence 밖에 유지함 |
| Contract | AI input/prompt/output, event, HIL/JCS, protected IPv4, nft base/live schema, UDS, capability/result, journal, history, vector | Contract-vector gate 통과 |
| Backend 및 data plane | Go `1.25.13`, Gateway, API, worker, detector, validator, dispatcher, executor, simulator, lifecycle, retention, recovery, export, metrics, smoke command | 88개 `cmd`/`internal` package 대상 backend format/vet/staticcheck/test/build gate 통과 |
| Database | PostgreSQL role, SQL query source/sqlc configuration, `000034_execution_result_v2_expiry_bounds`를 포함한 up migration 34개, staged demo-history activation, repeated-content-digest identity, API-only validation-attempt projection, stale-analysis supersession 및 verification fixture | Publish된 final root PostgreSQL 17.10 33-migration/72-table verifier가 fresh/restart-noop·`33→24→33`·ACL·sqlc·digest-identity·projection·raw-access-denial·supersession check를 통과했다. Current M34 database-chain test는 v2 bounds/no-reuse contract를 통과했지만 native release result는 아님 |
| Frontend | React/TypeScript/Vite/MUI administrator investigation, HIL, lifecycle, revocation, SSE, failure state 및 strict production CSP | Final root verification이 Vitest file 39개/test 363개와 deployment-CSP Chromium 1/1을 보고했으며 release-level browser certification은 pending임 |
| Deployment | Application image, one-shot history importer/handoff/activator와 isolated analysis/validation capability volume을 포함한 Compose topology, isolated network/UDS/volume, Prometheus | RUN25 fast는 mutation/outage/restart path를 다뤘고 이후 macOS `--run-browser-qa` 실행은 login 재시도나 limit 변경 없이 revoked phase의 고정 61초 pre-hash login-window 대기 후 active/revoked browser QA를 통과했지만 default native-expiry와 native host-ruleset evidence는 open임 |
| Operations | Backup/restore, minimized export, retention, observability, threshold report, performance harness | Recovery, export, observability, threshold 및 performance-smoke evidence 통과 |
| Documentation | README 및 strict English/`.ko.md` PRD, ADR, TDD, Tasklist, WBS, readiness pair | Integrated evidence에 맞게 갱신. 이 변경 후 documentation gate rerun 필요 |

AI contract는 공식 [`gpt-5.6-sol` model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol), [model catalog](https://developers.openai.com/api/docs/models) 및 [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)와 일치한다. 이는 contract evidence이며 live API result가 아니다.

## 4. 검증된 로컬 증거

다음 evidence를 2026-07-18–19 현재 shared workspace에서 관찰했다.

| Gate | 관찰 결과 | Qualification boundary |
| --- | --- | --- |
| Host/toolchain | `Darwin 24.6.0 arm64`, Go `1.25.12`, Node `24.13.0`, npm `11.6.2`, Docker client/server `29.4.0`, Compose `5.1.2` | Development host이며 native Linux release host가 아님 |
| Backend | 88 package에서 formatting, vet, staticcheck, test 및 모든 `cmd` build 통과, publish된 baseline의 clean clone도 `make check` 통과, hosted CI run `29696139988`이 backend shard 통과 | Native Linux release-host qualification은 별도임 |
| Contract/security | Contract vector, secret scan, `govulncheck`, npm audit 통과 | Runtime lifecycle 또는 Compose mutation E2E를 대체하지 않음 |
| Database | Final root PostgreSQL 17.10 verifier가 fresh/restart-noop·`33→24→33`·ACL·sqlc, recurring-content/fresh-authority, API-only terminal-attempt projection, raw-table denial, mismatch fail-closed behavior 및 queued stale-analysis provider-free supersession/true-missing dead-letter case를 포함한 33 migration/72 table을 통과했고 publish된 baseline의 clean clone도 `make check` 통과, hosted CI run `29696139988`이 database shard 통과 | Native Linux release-host qualification은 별도임 |
| Recovery/export/observability | Backup/restore가 63.742초에 통과했고 minimized export, Prometheus configuration/runtime 및 alert check도 통과함. Focused v2 recovery-bundle test가 signed read-back bracket과 persisted bound를 검증하고 backup preflight가 v1/v2 representation을 검증함 | Full Compose lifecycle E2E 또는 full v2 backup/restore runtime qualification을 대체하지 않음 |
| nftables | Disposable namespace preflight와 executor targeted unit/race/integration/security check 통과. Current-tree Linux native v6 E2E는 real TTL expiry와 signed absence 뒤 cleanup 시 semantic host nftables unchanged 상태로 exit `0`을 기록함 | 이 runtime evidence는 release를 authorize하거나 current-SHA CI를 대체하지 않음 |
| Performance | Fixed 5-second `500 RPS` smoke mode와 outage correctness 통과; current-tree five-minute 4 GB Linux release gate가 `GATE_VERDICT=pass`, p95 `533us`, outage overhead `436us`로 exit `0`을 기록함 | 이 runtime evidence는 release를 authorize하거나 current-SHA CI를 대체하지 않음 |
| Frontend local | Final root verification이 CSP-safe error decoding, exact deployment-header validation, every-production-chunk dynamic-code-generation scan을 포함한 Vitest file 39개/test 363개와 production-CSP Chromium 1/1을 보고했고 fast browser QA가 sanitized active/revoked capture와 함께 exit `0`을 기록함 | Capture는 non-release UI evidence이며 complete release-level browser certification/screenshot은 pending이고 frontend는 backend/API completion과 분리됨 |
| E2E harness | Root rerun이 long coverage wait 전 migrated-PostgreSQL evidence-SQL parse/zero-row preflight를 포함한 demo helper 39/39와 shell-contract 6/6(합계 46 test)을 통과했다. Current bounded diagnostic은 cleanup 전에 redacted lifecycle state/result/audit evidence를 보고한다 | Static/helper evidence와 새 diagnostic은 rerun 및 통과한 native Linux release qualification을 대체하지 않음 |
| Supply chain | 세 번째 full run에서 static 18/18, package 354개/relationship 354개의 reproducible source SBOM, reproducible backend/PostgreSQL/Web image, runtime fail-fast probe, shipped image 4개 대상 frozen Trivy/SPDX/evidence binding과 CRITICAL 0개, PostgreSQL fresh/migrate/restart/wrong-owner-fail-closed lifecycle 및 cleanup 통과, publish된 baseline의 clean clone도 `make check` 통과, hosted CI run `29696139988`이 supply-chain shard 통과 | Native Linux release-host qualification은 별도임 |
| OpenAI smoke | Disabled 및 missing-key path가 network request 없이 fail closed하고, 1회의 explicit billable synthetic non-mutating `openai_responses`/`gpt-5.6-sol` attempt가 evidence reference 1개와 schema-valid command digest로 `status=ok`을 반환함 | Probe는 persistence, HIL, dispatcher 또는 executor path가 없고 그 자체로 release를 authorize하지 않음 |
| Compose E2E | RUN25 fast는 fast-path evidence로 유지한다. Current-tree Linux native v6 E2E는 real kernel expiry, signed absent inspection, audit/recovery/forwarding convergence 및 cleanup 뒤 semantic host nftables unchanged를 exit `0`으로 증명했다. Fast browser QA는 sanitized active/revoked capture와 함께 exit `0`을 기록함 | Fast browser capture는 non-release UI evidence이며 current-SHA clean-checkout/CI, final release capture/submission evidence 및 release decision은 open임 |

기존 ignored local credential과 generated demo-secret path는 출력하거나 문서에 복사하거나 billable call에 사용하지 않았다.

## 5. 남은 릴리스 입력 및 blocker

| Input 또는 gate | 필요한 용도 | 현재 상태 |
| --- | --- | --- |
| Committed clean baseline 및 CI | `M0-006`, `M0-008`, downstream reproducibility, final merge train | Publish된 commit `d66c4b8a4842ad4226cb741e35331ba5b9068520`; 외부 clean clone이 전후 clean 상태였고 `make check`를 통과했다. Hosted CI run `29696139988`은 `5ef870155bc59e6ac3c30279a7cd8be8d0249887`에서 10개 shard를 모두 통과했으며 Tasklist prerequisite completion은 별도임 |
| Live OpenAI opt-in result | `M0-005` callable-model/runtime evidence | 1회의 explicit billable synthetic non-mutating `openai_responses`/`gpt-5.6-sol` call이 `status=ok`을 반환했지만 `M0-004` prerequisite가 unchecked이므로 `M0-005`는 open임 |
| Dedicated 4 GB Linux runner 또는 VM | Native host-nft diff, real kernel expiry, capability/recovery proof, five-minute performance | Current-tree native v6 E2E와 five-minute performance gate가 모두 exit `0`을 기록했다. v6는 bounded v2 expiry/signed absence/recovery/forwarding/audit 및 semantic host invariance를 증명했고 performance는 `GATE_VERDICT=pass`, p95 `533us`, outage `436us`를 보고함 |
| Compose mutation E2E | Exact signed-history activation → challenge/HIL → dispatcher → add/inspect/revoke/expiry lifecycle | Current-tree native v6 E2E가 expiry, signed absence, audit/recovery/forwarding convergence 및 semantic host invariance를 exit `0`으로 증명했다. 이는 final clean-checkout/CI 또는 release decision을 대체하지 않음 |
| Clean-input preflight | `scripts/check-clean-input.sh`가 tracked plus unignored candidate input을 외부 temporary snapshot으로 복사한 뒤 gate를 실행함 | 최신 full run이 candidate source file 905개를 복사하고 manifest SHA-256 `2c395c3c5e3d28e908513e3304f5896ac7ae1eebe9a88dc80c543fe8baa73150`를 기록한 뒤 `make check`를 통과했다. 이는 source-only pre-commit evidence이며 committed-checkout, CI, Linux 또는 release evidence가 아님 |
| Reusable isolated worktree pool | `M0-018` leaf reproducibility | 구축하지 않음. Swarm은 scoped ownership이 있는 shared workspace를 사용함 |
| Live screenshot/submission/clean rehearsal | M9 packaging 및 release decision | Fast QA가 sanitized active/revoked screenshot만 생성했으며 final release screenshot, submission evidence 및 release decision은 생성하거나 주장하지 않음 |
| TLS certificate/key | Optional Gateway TLS mode | 의도적으로 없음 |

이 blocker는 accepted contract를 약화하거나 smoke evidence를 release evidence로 취급해 우회해서는 안 된다.

## 6. 현재 구현 wave

Active wave는 RUN25 이후 release stabilization이다. Final root backend, publish된 PostgreSQL 17.10 33-migration/72-table, frontend CSP/unit/browser, contract-vector 및 E2E helper/shell gate에 targeted evidence가 있고 previously recorded M34/v2 implementation은 bounded expiry persistence/diagnostic을 추가하며 focused unit/contract/database-chain test가 통과했다. Publish된 baseline의 clean-clone `make check` evidence와 hosted CI run `29696139988`의 `5ef870155bc59e6ac3c30279a7cd8be8d0249887` 대상 10개 shard 통과도 있다. Serialized Linux native v6 rerun은 native expiry, host-ruleset invariance 및 4 GB performance qualification을 통과했고, 1회의 billable live `openai_responses`/`gpt-5.6-sol` probe도 control-plane mutation 없이 `status=ok`을 반환했다. 남은 목표는 current-SHA clean-checkout/CI, release screenshot/submission evidence 및 release packaging/decision이며 fast Compose browser evidence는 non-release UI proof로 남는다. Detailed roster, wave ledger, ownership 및 final gate는 [WBS.ko.md](./WBS.ko.md)에 있다.

구현 검증 완료 full v0.1은 **Still implementing** 상태이며 실험적 연구 배포는 ADR-015를 따른다. 이 문서는 branch, commit, push, pull request, tag, deployment, billable OpenAI call 또는 external submission을 authorize하지 않는다.

## 7. 검증 명령

구현된 local gate:

```bash
make check-backend
make check-contracts
make check-database
make check-frontend
npm --prefix web run test:browser:functional:linux
npm --prefix web run test:browser:csp
make check-security
make check-observability
make check-export
make check-recovery
make check-nft-namespace
SENTINELFLOW_GATEWAY_PERF_MODE=smoke make check-gateway-performance
make check-docs
```

Pending release-sensitive gate:

```bash
make check-supply-chain
./scripts/check-demo-e2e.sh --fast
./scripts/check-demo-e2e.sh
make check-gateway-performance
```

Default performance command는 fixed five-minute release mode이며 documented 4 GB reference host에서 실행해야 한다. `--fast`는 native TTL expiry만 skip하므로 release substitute가 아니다. OpenAI probe는 billable이고 explicit opt-in을 요구하므로 automatic gate에서 의도적으로 제외한다.
