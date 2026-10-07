# Project history and provenance

[한국어](./HISTORY.ko.md)

## 1. Origin

SentinelFlow began as an explainable security-gateway prototype prepared for **OpenAI Build Week**, in the **Developer Tools** category. The initial repository commit is dated 2026-07-15. This origin remains part of the project history; moving the public introduction toward the security research does not imply that a submission, award, or external evaluation was completed.

The initial implementation focus became an inline Go HTTP reverse proxy in front of one fixed private upstream, deterministic detection, structured AI analysis, exact-artifact administrator approval, and isolated temporary nftables enforcement. Optional log adapters and raw-packet sensing remain outside the v0.1 release requirements. The [decision record](./ADR.md) preserves the architectural history and superseding decisions.

## 2. Development method

Codex assisted with product and architecture contracts, bounded implementation packages, code and tests, security and recovery review, browser checks, and English/Korean documentation synchronization. Agent completion statements are not verification evidence: the root integrator must inspect the integrated result and rerun the relevant checks.

At runtime, GPT-5.6 analyzes compact structured incident facts after deterministic detection. Its output is untrusted and constrained; it does not receive shell, approval, signing, or firewall authority. [Research notes](./RESEARCH.md) explain the implementation and test boundaries.

## 3. Ownership and public research publication

SentinelFlow is owned by **Veloz (벨로즈)** and maintained publicly through [devwooops/sentinelflow](https://github.com/veloz-security/sentinelflow). The company website is [sec.veloz.kr](https://sec.veloz.kr), and the security contact is [security@veloz.kr](mailto:security@veloz.kr). The owner confirmed this attribution for the 2026-10-07 public-documentation update. The project remains available under the existing [MIT License](../LICENSE).

The 2026-10-07 restructuring separates research, provenance, release instructions, contribution guidance, and security reporting so that readers can inspect the work and reproduce a named version. The intended first public package is the experimental `v0.1.0-rc.1` prerelease. Its publication does not assert production readiness, customer adoption, certification, a completed independent audit, or acceptance into a vendor access program.

## 4. Evidence and unfinished work

The [Tasklist](./TASKLIST.md), [WBS](./WBS.md), and [Implementation Readiness](./IMPLEMENTATION_READINESS.md) retain implementation dependencies, recorded verification results, and open gates. Historical local or CI success is evidence for the identified revision and environment only. Publication of a research prerelease does not complete M9-008 or the full v0.1 acceptance process; Build Week submission evidence remains a separate historical deliverable.

Use the [release guide](./RELEASE.md) to distinguish packaged artifacts, reproducible checks, and outstanding qualification. Use [Git history](https://github.com/veloz-security/sentinelflow/commits/main/) and [GitHub Releases](https://github.com/veloz-security/sentinelflow/releases) for the actual commit and publication record.
