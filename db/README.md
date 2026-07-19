# SentinelFlow database foundation

This directory contains the PostgreSQL 17 storage and least-privilege role
baseline for SentinelFlow v0.1. It is intentionally independent of the Go and
frontend builds.

## Layout

- `migrations/*.up.sql` — repeatable role, schema, function, and grant setup.
- `queries/*.sql` — sqlc query contracts for event ingestion and durable work.
- `sqlc.yaml` — sqlc parser/generation configuration. Generated code is not
  committed by this foundation package.
- `sqlc_schema_prelude.sql` — analyzer-only schema/domain declarations needed
  because sqlc does not infer objects created inside guarded `DO` blocks.
- `test/verify.sh` — disposable PostgreSQL 17 migration, invariant, and role
  verification.

The checked-in roles are `NOLOGIN` capability roles. Deployment-specific login
roles and passwords must be created outside the repository and granted exactly
one capability role. SentinelFlow intentionally creates no Gateway or executor
database role.

## Verify

```bash
./db/test/verify.sh
```

The verification harness uses synthetic credentials, exposes PostgreSQL only
on a random loopback port for the duration of the test, runs migrations twice
in one database and once in a second empty database, compiles every sqlc query
against the migrated schema, exercises privacy/foreign-key/idempotency
constraints, append-only audit, immutable validation gates, exact single-use
HIL binding, sender/endpoint-scoped five-minute replay protection, atomic
batch/checkpoint/sequence-gap health, optimistic policy-state revisions and
terminal-state rejection, restricted dispatcher leasing, and role-denial
cases, then removes its container on exit.

To compile or generate separately, point sqlc at an already migrated test
database; never use production credentials for code generation:

```bash
SENTINELFLOW_SQLC_DATABASE_URI='postgresql://postgres:test-only@127.0.0.1:5432/sentinelflow?sslmode=disable' \
  sqlc -f db/sqlc.yaml compile
```

These migrations establish storage and permission prerequisites. Stateful
repository methods, retention execution, outbox workers, backup/restore, and
application transaction orchestration remain separate implementation work.
