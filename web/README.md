# SentinelFlow frontend foundation

This directory is the independent frontend/UI boundary for SentinelFlow. The
frontend validates checked-in root JSON Schemas plus versioned management API
DTOs through fail-closed decoders. Live routes use the same-origin REST/SSE
management plane by default; `/fixtures/**` and `/states/**` remain explicit,
inert presentation environments. This package does not implement backend,
domain, AI, policy-validation, dispatcher, or executor authority.

## Commands

```bash
npm ci
npm run verify
```

Individual gates are available through `format:check`, `lint`, `typecheck`,
`test`, `build`, and `test:browser`. Install the pinned Playwright Chromium
runtime once with `npm run test:browser:install` when the host does not already
have it.

Linux visual baselines are compared only in the pinned Playwright 1.61.1
Noble image, whose immutable image digest also freezes the browser and system
font packages used for screenshot layout. This is intentionally separate from
the Node 24.13 functional/a11y run because a different Linux distribution's
`system-ui` font metrics can change line wrapping without an application
change:

```bash
npm run test:browser:functional:linux
npm run test:browser:visual:linux
```

The command copies only the required `web/` files and checked-in contract files
into a mode-restricted temporary tree outside the repository. The networked
container receives that sanitized tree as its only read-only bind mount, so the
repository root, `.env*`, `secrets/`, dependencies, build output, and test
reports are not reachable inside it. The runner removes exactly the temporary
tree it created, installs the exact lockfile, builds the application, and
compares all four desktop/narrow Linux snapshots. It never uses Playwright's
snapshot-update mode.

## Contract boundary

- `src/contracts/registry.ts` registers root contracts and frontend DTOs by
  exact schema version and rejects unknown versions, enums, fields, and shapes.
- `src/contracts/apiDtos.ts` defines incident, HIL review, lifecycle, audit, and
  typed API error views without calculating server decisions.
- `src/mocks/contractFixtures.ts` contains deeply frozen deterministic records
  covering Gateway/source health through add, inspect, revoke, and audit.
- `src/mocks/presentationStates.ts` adapts typed resource states to UI-only
  presentation copy.
- `src/live/apiClient.ts` bounds response bodies, requires exact media types,
  decodes strict server DTOs, and sends same-origin credentials without
  retaining bearer or CSRF values in UI state.
- `src/live/SessionProvider.tsx` restores the opaque administrator session,
  keeps CSRF only in memory, handles password step-up, and accepts server
  session rotation after a fresh exact HIL decision. An exact idempotent replay
  is shown as an already-recorded result, never accepted as new authority, and
  clears local session capability before requiring a new sign-in.
- `src/live/PolicyDecisionPanel.tsx` enables approve/reject only for the exact
  server-provided policy, current validation snapshot, complete source health,
  and all six ordered passing gates. It consumes a single-use challenge and
  never synthesizes validation, digests, command bytes, or enforcement
  authority.
- `src/live/sseClient.ts` implements bounded canonical `s1` replay,
  reconnect/deduplication, and REST invalidation after a replay gap.
- `tests/mock-management-server.mjs` is a synthetic browser-test boundary. Its
  data and success responses are not evidence that the Go API, database, or
  executor has completed an integrated lifecycle. Every replacement scenario
  regenerates its validation, challenge, nonce/session binding, and authority
  lineage with digest-consistent synthetic values. Its in-memory single-use
  ledger permits one fresh authority per exact challenge across all
  idempotency keys; an exact winner replay returns the persisted identifiers,
  while every competing key fails with a deterministic conflict.
