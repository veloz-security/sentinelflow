# SentinelFlow security research

[한국어](./RESEARCH.ko.md)

SentinelFlow is an MIT-licensed defensive security gateway owned by **Veloz (벨로즈)** and maintained in the [devwooops/sentinelflow repository](https://github.com/devwooops/sentinelflow). The company website is [sec.veloz.kr](https://sec.veloz.kr). Security reports should follow [SECURITY.md](../SECURITY.md) or contact [security@veloz.kr](mailto:security@veloz.kr).

This document presents inspectable engineering work for researchers, evaluators, and potential contributors. It does not claim a certification, customer deployment, independent audit, or acceptance into any vendor program. The experimental `v0.1.0-rc.1` publication makes the work easier to reproduce; it does not complete the implementation-qualified v0.1 release gates.

## 1. Research question

How can a security gateway use an LLM to explain detected incidents and propose a limited response without giving the model direct enforcement authority or placing model latency on the HTTP request path?

The implementation explores three boundaries: minimized observations instead of retained request content; deterministic evidence before AI interpretation; and exact-artifact human approval followed by isolated, temporary enforcement. The [PRD](./PRD.md), [architecture decisions](./ADR.md), and [technical design](./TDD.md) define the intended contracts. Code and reproducible tests establish the implemented behavior.

## 2. Implementation and test map

| Research area | Implementation | Reproduction and negative cases |
| --- | --- | --- |
| HTTP identity and fixed origin | [Gateway](../internal/gateway/handler.go), [origin policy](../internal/gateway/origin.go), [path classification](../internal/gateway/path.go) | [Gateway tests](../internal/gateway/gateway_test.go), [integration gate](../internal/gateway/integration_gate_test.go), [origin tests](../internal/gateway/origin_test.go): forged headers, protocol bounds, origin restrictions, forwarding during control-plane degradation |
| Authenticated minimized evidence | [typed events](../internal/events/types.go), [HMAC verification](../internal/ingestion/hmac.go), [sender checkpoints](../internal/eventsender/checkpoint.go) | [event tests](../internal/events/events_test.go), [HMAC tests](../internal/ingestion/hmac_test.go), [checkpoint tests](../internal/eventsender/sender_test.go): invalid fields, authentication/replay failures, restart and loss semantics |
| Deterministic detection before AI | [detectors](../internal/detection/detector.go), [correlation](../internal/correlation/correlate.go), [AI adapter](../internal/ai/client.go), [strict output schema](../contracts/ai/sentinelflow_analysis_v1.schema.json) | [detector tests](../internal/detection/detector_test.go), [AI adapter tests](../internal/ai/client_test.go): thresholds, malformed/refused/incomplete output, evidence consistency and provider failure |
| Bounded command and exact approval | [command parser](../internal/policy/parser.go), [validation](../internal/validation/consistency.go), [HIL decision](../internal/hil/decision.go) | [policy tests](../internal/policy/policy_test.go), [protected-target tests](../internal/validation/protected_test.go), [HIL safety tests](../internal/hil/safety_test.go): extra syntax, inconsistent evidence, protected addresses, stale or substituted artifacts |
| Isolated execution and recovery | [executor](../internal/enforcement/executor/service.go), [journal](../internal/enforcement/journal/journal.go), [lifecycle](../internal/lifecycleruntime/runtime.go) | [executor recovery](../internal/enforcement/executor/recovery_test.go), [journal corruption](../internal/enforcement/journal/corruption_test.go), [expiry-bound integration](../internal/lifecyclestore/expiry_bounds_v1_integration_test.go): replay, corruption, signed read-back bounds, no TTL refresh |

The test links identify executable checks; their presence alone is not a claim that a particular release passed them. [CI](../.github/workflows/ci.yml), [release guidance](./RELEASE.md), and [Implementation Readiness](./IMPLEMENTATION_READINESS.md) identify commands, evidence scope, and remaining qualification work.

## 3. Response-authority boundary

The response path is ordered: structured-output and command parsing/canonicalization → policy/evidence/command consistency → protected-network checks → owned-schema nftables syntax validation → historical-impact analysis → administrator approval of the exact artifact by digest → isolated shell-free temporary execution → expiry and audit.

Every prerequisite must pass; approval cannot override failed validation. The model receives no executor or signing authority. A minimal dispatcher signs a short-lived exact capability, and the executor verifies it, journals the operation, invokes only fixed nftables operations, and signs the result. Duplicate or crash recovery cannot re-add a block or refresh its TTL. Read-only inspection and deterministic revocation are separate typed operations.

The [existing threat model](../README.md#threat-model) covers request smuggling, identity forgery, origin bypass, evidence poisoning, prompt injection, stale approval, privilege separation, and crash recovery. See ADR-011 through ADR-014 in the [decision record](./ADR.md) for the Gateway, capability, history-authority, and expiry-bound rationale.

## 4. Reproducing and interpreting evidence

Start with the isolated stub-analysis profile in the [release guide](./RELEASE.md). Run the repository gates from a clean checkout and retain the commit, tool versions, command, exit status, and sanitized results. The [Compose E2E harness](../scripts/check-demo-e2e.sh) exercises the integrated workflow; native kernel expiry and host nftables invariance require a qualifying Linux environment. The [performance gate](../scripts/check-gateway-performance.sh) distinguishes smoke checks from the five-minute 4 GB release qualification.

Synthetic fixtures and deterministic model stubs support repeatability. A stub result does not establish live provider compatibility. Live OpenAI testing is separately opt-in, requires operator credentials and a rate card, and may incur API charges. Published historical results in the readiness ledger are scoped to the recorded tree and environment; they are not automatically evidence for later commits.

## 5. Limitations and publication scope

The current scope is a single-node HTTP/1.1 gateway with one fixed private upstream, direct TCP-peer client identity, four fixed-threshold detectors, and Linux nftables enforcement. It does not offer raw packet capture, payload inspection, multi-tenant operation, high availability, or a general-purpose WAF replacement. Credential-stuffing detection needs authenticated application events. False positives and event loss during bounded-queue saturation remain possible; incomplete evidence cannot authorize a new adaptive block.

Company ownership describes attribution, not proof of operational adoption. This repository and its tagged artifacts may be cited as published security engineering work, with the version, date, limitations, and actual verification evidence. Vendor-program eligibility and acceptance are separate decisions by the program operator. See [project history](./HISTORY.md) for provenance and [release guidance](./RELEASE.md) for the experimental publication boundary.
