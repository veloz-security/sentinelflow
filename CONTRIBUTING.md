# Contributing to SentinelFlow

SentinelFlow is an experimental MIT-licensed security gateway owned by Veloz (벨로즈). Contributions are reviewed in the [devwooops/sentinelflow repository](https://github.com/devwooops/sentinelflow). Read the [research overview](./docs/RESEARCH.md), [release scope](./docs/RELEASE.md), and [repository instructions](./AGENTS.md) before changing behavior.

## Propose a focused change

For ordinary defects or proposals, open a repository issue with the affected version, expected behavior, observed behavior, and a minimal synthetic reproduction. Send suspected vulnerabilities through [SECURITY.md](./SECURITY.md); do not disclose secrets or sensitive exploit details in public issues.

Identify the affected requirements, architecture decisions, tests, and Tasklist items. Runtime, trust-boundary, or enforcement changes need the appropriate PRD/ADR/TDD updates and failure-path tests. Preserve the ordered safety gates and the separation between Gateway, control plane, dispatcher, and executor. Discuss a new contract before implementing an incompatible behavior change.

## Implement and verify

Keep changes narrow and preserve unrelated work. Backend and frontend/UI work must have separate tasks, explicit API handoff, and independent verification. Update English and Korean document pairs in the same change; IDs, status, priorities, dependencies, and completion criteria must match.

Run the relevant checks from the [README](./README.md#testing). Documentation changes require at least:

```bash
node scripts/validate-docs.mjs
node scripts/generate-contract-vectors.mjs --check
npx --yes markdownlint-cli --disable MD013 MD024 -- README.md AGENTS.md docs/*.md
git diff --check
```

Code changes also require relevant unit, contract, integration, security, and recovery tests. UI changes require frontend tests and real browser verification. Linux enforcement and release-performance gates require the documented Linux environment; report unavailable checks as unverified.

Never commit credentials, generated local secret bundles, real traffic contents, or unreviewed screenshots. Fixtures must be synthetic and meet the data-minimization contract. Do not introduce dependencies or migrate shared schemas merely to make the directory layout resemble a planned architecture.

## Submit evidence

A pull request should explain the problem and resulting behavior, list verification commands and results, identify remaining limitations, and link the affected requirement/task IDs. Do not mark a task complete on code presence or agent status alone. Preserve architecture history when superseding a decision.

Release publication is owned by the repository maintainer. The experimental research prerelease does not bypass the full v0.1 release criteria. Contributions remain subject to the existing [MIT License](./LICENSE); do not submit material you lack authority to contribute.
