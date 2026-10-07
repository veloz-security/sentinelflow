# Security Policy

## Reporting a vulnerability

SentinelFlow is owned by [Veloz (벨로즈)](https://sec.veloz.kr). Report suspected vulnerabilities privately to [security@veloz.kr](mailto:security@veloz.kr). Include the affected tag or commit, component, expected and observed behavior, impact, and a minimal synthetic reproduction where possible. Do not send production traffic, credentials, session data, customer information, or real authentication events. Coordinate disclosure before publishing details that put users at risk.

The repository maintainer is [@devwooops](https://github.com/devwooops). No response-time SLA, bug bounty, security certification, or production support commitment is offered by this experimental release.

## Supported versions

The `v0.1.0-rc.1` research prerelease and current development branch are evaluation software. Reports are welcome for both; no stable production-supported release or guaranteed backport window exists. Use the release's exact commit when reporting an issue. Known limitations are documented in the [release guide](docs/RELEASE.md) and [README](README.md#known-limitations).

## System and trust boundaries

The public Gateway proxies HTTP/1.1 to one fixed private upstream. Gateway metadata, authenticated application events, retained evidence, and AI output remain untrusted data. PostgreSQL, AI analysis, validation, HIL approval, and enforcement are outside the forwarding path. The administrator, deployment secrets, restricted dispatcher signer, isolated executor signer, and host/container isolation are distinct trust boundaries.

See the [threat model](README.md#threat-model), [architecture decisions](docs/ADR.md), [technical contracts](docs/TDD.md), and [repository invariants](AGENTS.md#security-and-safety-invariants). These contracts describe required behavior; tests and documentation do not establish that a control is immune to bypass.

## Required security properties

- Deterministic signals precede AI; the model has no direct approval, shell, or firewall authority.
- Minimized evidence excludes observed exact paths, queries, bodies, cookies, authorization material, and raw accounts.
- Strict grammar, evidence consistency, protected-network, syntax, impact, and exact-artifact administrator approval gates precede isolated shell-free enforcement. Missing or ambiguous evidence fails closed.
- Only the minimal dispatcher signs mutation capabilities, only the isolated executor receives namespace enforcement privileges, and the host firewall remains unchanged.
- Every block has finite native expiry. Duplicate delivery, crashes, and reconciliation never re-add or refresh a rule; inspection is separately authorized and read-only.
- Control-plane failure cannot create a new adaptive block or synchronously stop valid Gateway forwarding.

## Reportable findings and limitations

Report reachable violations of these properties, including identity/origin bypass, parser disagreement, sensitive-data exposure, approval/digest bypass, privilege escalation, unauthorized mutation, TTL refresh, and unsafe recovery. Explain the prerequisites and affected trust boundary; severity depends on demonstrated impact and reachability.

The single-node, single-administrator, fixed-upstream, Linux/nftables scope and incomplete full v0.1 release qualification are disclosed limitations, not blanket vulnerability exclusions. No additional finding class is excluded by this policy. Test only systems you own or are explicitly authorized to assess; a public repository is not authorization to probe Veloz infrastructure or other deployments.
