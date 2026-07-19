package hilstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgreSQL17RevocationMigrationRejectsEveryLegacyEvidenceClass(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-revocation-migration-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"-e", "POSTGRES_PASSWORD=sentinelflow-test-only", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", container).Run()
	})
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	adminURL := revocationDatabaseURL(port, "postgres")
	admin := connectIntegrationPostgreSQL(t, ctx, adminURL)
	defer admin.Close(context.Background())
	if _, err := admin.Exec(ctx, `CREATE DATABASE revocation_base26`); err != nil {
		t.Fatal(err)
	}
	base := connectIntegrationPostgreSQL(t, ctx, revocationDatabaseURL(port, "revocation_base26"))
	applyRevocationMigrationsThrough26(t, ctx, base)
	base.Close(ctx)

	up := readRevocationMigration(t, "000027_revocation_hil.up.sql")
	digest := "sha256:" + strings.Repeat("1", 64)
	legacyCases := []struct {
		name       string
		seed       string
		countQuery string
	}{
		{
			name: "revocation_operation",
			seed: `INSERT INTO sentinelflow.revocation_operations (
                revocation_id, schema_version, action_id, authorization_id,
                approval_decision_id, actor_id, reason_id, reason_digest,
                target_ipv4, original_add_digest, artifact, artifact_digest, state
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'nft-revoke-v1',
                '00000000-0000-4000-8000-000000000002',
                '00000000-0000-4000-8000-000000000003',
                '00000000-0000-4000-8000-000000000004', 'legacy-admin',
                '00000000-0000-4000-8000-000000000005', $1,
                '203.0.113.10', $1, convert_to('legacy', 'UTF8'), $1, 'authorized'
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.revocation_operations`,
		},
		{
			name: "decision_challenge",
			seed: `INSERT INTO sentinelflow.decision_challenges (
                challenge_id, schema_version, nonce_digest, session_id,
                session_digest, actor_id, operation, resource_type, resource_id,
                resource_version, policy_id, policy_version, action_id, target_ipv4,
                policy_digest, evidence_snapshot_digest, generated_artifact_digest,
                canonical_artifact_digest, original_add_digest,
                validation_snapshot_digest, validation_valid_until,
                idempotency_key_digest, authenticated_at, issued_at, expires_at,
                challenge_jcs, challenge_digest
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'hil-challenge-v1', $1,
                '00000000-0000-4000-8000-000000000002', $1, 'legacy-admin',
                'revoke', 'enforcement_action',
                '00000000-0000-4000-8000-000000000003', 1,
                '00000000-0000-4000-8000-000000000004', 1,
                '00000000-0000-4000-8000-000000000003', '203.0.113.10',
                $1, $1, $1, $1, $1, $1, clock_timestamp() + interval '5 minutes',
                $1, clock_timestamp() - interval '1 minute', clock_timestamp(),
				clock_timestamp() + interval '4 minutes', convert_to('{}', 'UTF8'),
				('sha256:' || encode(sha256(convert_to('{}', 'UTF8')), 'hex'))::sentinelflow.sha256_digest
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.decision_challenges WHERE operation = 'revoke'`,
		},
		{
			name: "hil_reason",
			seed: `INSERT INTO sentinelflow.hil_reasons (
                reason_id, schema_version, actor_id, operation, reason_code,
                normalized_reason, reason_jcs, reason_digest
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'hil-reason-v1',
				'legacy-admin', 'revoke', 'emergency_revoke',
				'Legacy revoke reason' || substring($1 from 1 for 0),
				convert_to('{}', 'UTF8'),
				('sha256:' || encode(sha256(convert_to('{}', 'UTF8')), 'hex'))::sentinelflow.sha256_digest
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.hil_reasons WHERE operation = 'revoke'`,
		},
		{
			name: "approval_decision",
			seed: `INSERT INTO sentinelflow.approval_decisions (
                decision_id, schema_version, challenge_id, session_digest, operation,
                decision, resource_type, resource_id, resource_version, policy_id,
                policy_version, action_id, target_ipv4, validation_snapshot_id,
                policy_digest, evidence_snapshot_digest, generated_artifact_digest,
                canonical_artifact_digest, original_add_digest,
                validation_snapshot_digest, actor_id, reason_id, reason_digest,
                challenge_nonce_digest, idempotency_key_digest, decided_at,
                decision_valid_until, decision_jcs, decision_digest
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'hil-decision-v1',
                '00000000-0000-4000-8000-000000000002', $1, 'revoke', 'revoked',
                'enforcement_action', '00000000-0000-4000-8000-000000000003', 1,
                '00000000-0000-4000-8000-000000000004', 1,
                '00000000-0000-4000-8000-000000000003', '203.0.113.10',
                '00000000-0000-4000-8000-000000000005', $1, $1, $1, $1, $1, $1,
                'legacy-admin', '00000000-0000-4000-8000-000000000006', $1, $1, $1,
                clock_timestamp(), clock_timestamp() + interval '4 minutes',
				convert_to('{}', 'UTF8'),
				('sha256:' || encode(sha256(convert_to('{}', 'UTF8')), 'hex'))::sentinelflow.sha256_digest
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.approval_decisions WHERE operation = 'revoke'`,
		},
		{
			name: "enforcement_authorization",
			seed: `INSERT INTO sentinelflow.enforcement_authorizations (
                authorization_id, schema_version, authorization_kind, action_id,
                policy_id, policy_version, approval_decision_id, decision, target_ipv4,
                policy_digest, generated_artifact_digest, canonical_artifact_digest,
                original_add_digest, evidence_snapshot_digest,
                validation_snapshot_digest, actor_id, hil_reason_digest,
                decision_nonce_digest, idempotency_key_digest, authorization_digest,
                decided_at, valid_until, authorization_jcs
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'enforcement-authorization-v1',
                'revoke', '00000000-0000-4000-8000-000000000002',
                '00000000-0000-4000-8000-000000000003', 1,
                '00000000-0000-4000-8000-000000000004', 'revoke', '203.0.113.10',
				$1, $1, $1, $1, $1, $1, 'legacy-admin', $1, $1, $1,
				('sha256:' || encode(sha256(convert_to('{}', 'UTF8')), 'hex'))::sentinelflow.sha256_digest,
                clock_timestamp(), clock_timestamp() + interval '4 minutes',
                convert_to('{}', 'UTF8')
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.enforcement_authorizations WHERE authorization_kind = 'revoke'`,
		},
		{
			name: "outbox_job",
			seed: `INSERT INTO sentinelflow.outbox_jobs (
                job_id, kind, aggregate_type, aggregate_id, aggregate_version,
                operation, idempotency_key, state
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'dispatch_revoke',
                'enforcement_action', '00000000-0000-4000-8000-000000000002',
                1, 'revoke', $1, 'pending'
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.outbox_jobs WHERE operation = 'revoke'`,
		},
		{
			name: "dispatch_operation",
			seed: `INSERT INTO sentinelflow.dispatch_operations (
                job_id, operation, action_id, policy_id, policy_version, target_ipv4,
                artifact, artifact_digest, original_add_digest,
                evidence_snapshot_digest, validation_snapshot_id,
                validation_snapshot_digest, enforcement_authorization_id,
                authorization_digest, actor_id, reason_digest, owned_schema_digest,
                not_before, valid_until
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'revoke',
                '00000000-0000-4000-8000-000000000002',
                '00000000-0000-4000-8000-000000000003', 1, '203.0.113.10',
                convert_to('legacy', 'UTF8'), $1, $1, $1,
                '00000000-0000-4000-8000-000000000004', $1,
                '00000000-0000-4000-8000-000000000005', $1, 'legacy-admin',
                $1, $1, clock_timestamp(), clock_timestamp() + interval '4 minutes'
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.dispatch_operations WHERE operation = 'revoke'`,
		},
		{
			name: "execution_capability",
			seed: `INSERT INTO sentinelflow.execution_capabilities (
                capability_id, schema_version, job_id, operation, action_id, policy_id,
                policy_version, target_ipv4, artifact, artifact_digest,
                original_add_digest, evidence_snapshot_digest,
                validation_snapshot_digest, authorization_digest, actor_id,
                reason_digest, owned_schema_digest, capability_jcs,
                capability_digest, capability_signature, nonce_digest, issued_at,
                not_before, expires_at
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'execution-capability-v1',
                '00000000-0000-4000-8000-000000000002', 'revoke',
                '00000000-0000-4000-8000-000000000003',
                '00000000-0000-4000-8000-000000000004', 1, '203.0.113.10',
                convert_to('legacy', 'UTF8'), $1, $1, $1, $1, $1, 'legacy-admin',
                $1, $1, convert_to('{}', 'UTF8'), $1,
                decode(repeat('00', 64), 'hex'), $1, clock_timestamp(),
                clock_timestamp(), clock_timestamp() + interval '30 seconds'
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.execution_capabilities WHERE operation = 'revoke'`,
		},
		{
			name: "execution_result",
			seed: `INSERT INTO sentinelflow.execution_results (
                result_id, schema_version, capability_id, capability_digest, operation,
                action_id, artifact_digest, target_ipv4, classification,
                nft_exit_class, readback_state, owned_schema_digest, started_at,
                completed_at, journal_sequence, error_code, result_jcs,
                result_digest, result_signature
            ) VALUES (
                '00000000-0000-4000-8000-000000000001', 'execution-result-v1',
                '00000000-0000-4000-8000-000000000002', $1, 'revoke',
                '00000000-0000-4000-8000-000000000003', $1, '203.0.113.10',
                'revoked', 'success', 'absent', $1, clock_timestamp(),
                clock_timestamp(), 1, 'none', convert_to('{}', 'UTF8'), $1,
                decode(repeat('00', 64), 'hex')
            )`,
			countQuery: `SELECT count(*) FROM sentinelflow.execution_results WHERE operation = 'revoke'`,
		},
		{
			name:       "audit_event",
			seed:       revocationLegacyAuditInsert,
			countQuery: `SELECT count(*) FROM sentinelflow.audit_events WHERE action LIKE 'enforcement_revoke%'`,
		},
	}

	for index, testCase := range legacyCases {
		t.Run(testCase.name, func(t *testing.T) {
			database := fmt.Sprintf("revocation_legacy_%02d", index)
			if _, err := admin.Exec(ctx, `CREATE DATABASE `+database+` TEMPLATE revocation_base26`); err != nil {
				t.Fatal(err)
			}
			connection := connectIntegrationPostgreSQL(t, ctx, revocationDatabaseURL(port, database))
			defer connection.Close(context.Background())
			if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, testCase.seed, digest); err != nil {
				t.Fatalf("seed legacy evidence: %v", err)
			}
			if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
				t.Fatal(err)
			}
			_, err := connection.Exec(ctx, up)
			if revocationPGCode(err) != "55000" {
				t.Fatalf("migration error=%v code=%s", err, revocationPGCode(err))
			}
			if _, rollbackErr := connection.Exec(ctx, `ROLLBACK`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			assertRevocationMigrationRolledBack(t, ctx, connection, testCase.countQuery)
		})
	}
}

func TestPostgreSQL17RevocationMigrationPrivilegeAndAuditDowngradeFences(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-revocation-down-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"-e", "POSTGRES_PASSWORD=sentinelflow-test-only", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", container).Run()
	})
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	connection := connectIntegrationPostgreSQL(t, ctx, revocationDatabaseURL(port, "postgres"))
	defer connection.Close(context.Background())
	applyRevocationMigrationsThrough26(t, ctx, connection)
	up := readRevocationMigration(t, "000027_revocation_hil.up.sql")
	down := readRevocationMigration(t, "000027_revocation_hil.down.sql")
	if _, err := connection.Exec(ctx, up); err != nil {
		t.Fatalf("first up: %v", err)
	}
	assertRevocationDMLDenied(t, ctx, connection, "after up")
	assertRevocationFunctionACLs(t, ctx, connection, "after up")
	assertLifecycleFormatterParity(t, ctx, connection)

	digest := "sha256:" + strings.Repeat("1", 64)
	if _, err := connection.Exec(ctx, revocationLegacyAuditInsert, digest); err != nil {
		t.Fatalf("seed audit-only downgrade evidence: %v", err)
	}
	_, err := connection.Exec(ctx, down)
	if revocationPGCode(err) != "55000" {
		t.Fatalf("audit-only down error=%v code=%s", err, revocationPGCode(err))
	}
	if _, err := connection.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	var version27 int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 27`).Scan(&version27); err != nil || version27 != 1 {
		t.Fatalf("audit-only down was not atomic: version=%d err=%v", version27, err)
	}
	if _, err := connection.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM sentinelflow.audit_events WHERE action LIKE 'enforcement_revoke%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, down); err != nil {
		t.Fatalf("evidence-free down: %v", err)
	}
	assertRevocationDMLDenied(t, ctx, connection, "after down")
	if _, err := connection.Exec(ctx, up); err != nil {
		t.Fatalf("second up: %v", err)
	}
	assertRevocationDMLDenied(t, ctx, connection, "after down/up")
	assertRevocationFunctionACLs(t, ctx, connection, "after down/up")
}

const revocationLegacyAuditInsert = `INSERT INTO sentinelflow.audit_events (
    event_id, actor_type, actor_id, action, object_type, object_id,
    primary_digest, secondary_digest, outcome, occurred_at
) VALUES (
    '00000000-0000-4000-8000-000000000001', 'administrator', 'legacy-admin',
    'enforcement_revoke_authorized', 'revocation',
    '00000000-0000-4000-8000-000000000002', $1, $1, 'accepted', clock_timestamp()
)`

func revocationDatabaseURL(port, database string) string {
	return "postgresql://postgres:sentinelflow-test-only@127.0.0.1:" + port + "/" + database + "?sslmode=disable"
}

func applyRevocationMigrationsThrough26(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate revocation migration test")
	}
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(migrations)
	for _, migration := range migrations {
		if filepath.Base(migration) >= "000027_" {
			break
		}
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read %s: %v", filepath.Base(migration), readErr)
		}
		if _, applyErr := connection.Exec(ctx, string(contents)); applyErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(migration), applyErr)
		}
	}
}

func readRevocationMigration(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate revocation migration test")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func assertRevocationMigrationRolledBack(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	countQuery string,
) {
	t.Helper()
	var actionVersionExists bool
	if err := connection.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'sentinelflow'
      AND table_name = 'revocation_operations'
      AND column_name = 'action_version'
)`).Scan(&actionVersionExists); err != nil || actionVersionExists {
		t.Fatalf("action_version rollback=%v err=%v", actionVersionExists, err)
	}
	var migrationCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 27`).Scan(&migrationCount); err != nil || migrationCount != 0 {
		t.Fatalf("schema migration rollback count=%d err=%v", migrationCount, err)
	}
	var evidenceCount int
	if err := connection.QueryRow(ctx, countQuery).Scan(&evidenceCount); err != nil || evidenceCount != 1 {
		t.Fatalf("legacy evidence was not retained count=%d err=%v", evidenceCount, err)
	}
}

func assertRevocationDMLDenied(t *testing.T, ctx context.Context, connection *pgx.Conn, stage string) {
	t.Helper()
	roles := []string{
		"sentinelflow_api", "sentinelflow_worker", "sentinelflow_read",
		"sentinelflow_dispatcher", "sentinelflow_lifecycle", "sentinelflow_retention",
		"sentinelflow_metrics",
	}
	for _, role := range roles {
		for _, privilege := range []string{"INSERT", "UPDATE", "DELETE"} {
			var allowed bool
			if err := connection.QueryRow(ctx,
				`SELECT has_table_privilege($1, 'sentinelflow.revocation_operations', $2)`,
				role, privilege,
			).Scan(&allowed); err != nil || allowed {
				t.Fatalf("%s role=%s privilege=%s allowed=%v err=%v", stage, role, privilege, allowed, err)
			}
		}
		var updateColumns int
		if err := connection.QueryRow(ctx, `
SELECT count(*)
FROM information_schema.columns column_info
WHERE column_info.table_schema = 'sentinelflow'
  AND column_info.table_name = 'revocation_operations'
  AND has_column_privilege($1, 'sentinelflow.revocation_operations', column_info.column_name, 'UPDATE')`, role).Scan(&updateColumns); err != nil || updateColumns != 0 {
			t.Fatalf("%s role=%s writable_columns=%d err=%v", stage, role, updateColumns, err)
		}
	}
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO sentinelflow.revocation_operations DEFAULT VALUES`); revocationPGCode(err) != "42501" {
		t.Fatalf("%s direct API insert code=%s err=%v", stage, revocationPGCode(err), err)
	}
	if _, err := connection.Exec(ctx, `UPDATE sentinelflow.revocation_operations SET state = state, completed_at = completed_at WHERE false`); revocationPGCode(err) != "42501" {
		t.Fatalf("%s direct API update code=%s err=%v", stage, revocationPGCode(err), err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
}

func assertRevocationFunctionACLs(t *testing.T, ctx context.Context, connection *pgx.Conn, stage string) {
	t.Helper()
	functionNames := []string{
		"revocation_artifact_000027",
		"lifecycle_rfc3339_000027",
		"revocation_challenge_jcs_000027",
		"revocation_decision_jcs_000027",
		"revocation_authorization_jcs_000027",
		"require_revocation_operation_match_000027",
		"issue_hil_revocation_challenge_000027",
		"commit_hil_revocation_with_session_rotation_000027",
		"record_execution_capability",
		"record_execution_result",
	}
	rows, err := connection.Query(ctx, `
SELECT procedure.proname, procedure.oid
FROM pg_proc procedure
JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'sentinelflow'
  AND procedure.proname = ANY($1::text[])
ORDER BY procedure.proname`, functionNames)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type functionIdentity struct {
		name string
		oid  uint32
	}
	functions := make([]functionIdentity, 0, len(functionNames))
	for rows.Next() {
		var identity functionIdentity
		if err := rows.Scan(&identity.name, &identity.oid); err != nil {
			t.Fatal(err)
		}
		functions = append(functions, identity)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(functions) != len(functionNames) {
		t.Fatalf("%s enumerated 000027 functions=%d want=%d", stage, len(functions), len(functionNames))
	}

	roles := []string{
		"sentinelflow_api", "sentinelflow_worker", "sentinelflow_read",
		"sentinelflow_dispatcher", "sentinelflow_lifecycle", "sentinelflow_retention",
		"sentinelflow_metrics",
	}
	for _, function := range functions {
		var publicExecute int
		if err := connection.QueryRow(ctx, `
SELECT count(*)
FROM aclexplode(COALESCE(
    (SELECT proacl FROM pg_proc WHERE oid = $1),
    acldefault('f', (SELECT proowner FROM pg_proc WHERE oid = $1))
)) privilege
WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'`, function.oid).Scan(&publicExecute); err != nil || publicExecute != 0 {
			t.Fatalf("%s PUBLIC execute function=%s count=%d err=%v", stage, function.name, publicExecute, err)
		}
		for _, role := range roles {
			var allowed bool
			if err := connection.QueryRow(ctx, `SELECT has_function_privilege($1, $2::oid, 'EXECUTE')`, role, function.oid).Scan(&allowed); err != nil {
				t.Fatal(err)
			}
			expected := role == "sentinelflow_api" &&
				(function.name == "issue_hil_revocation_challenge_000027" ||
					function.name == "commit_hil_revocation_with_session_rotation_000027")
			expected = expected || role == "sentinelflow_dispatcher" &&
				(function.name == "record_execution_capability" || function.name == "record_execution_result")
			if allowed != expected {
				t.Fatalf("%s function=%s role=%s execute=%v want=%v", stage, function.name, role, allowed, expected)
			}
		}
	}

	if _, err := connection.Exec(ctx, `
DO $probe$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinelflow_public_probe') THEN
        CREATE ROLE sentinelflow_public_probe NOLOGIN;
    END IF;
END
$probe$`); err != nil {
		t.Fatal(err)
	}
	actualRoles := append([]string{"sentinelflow_public_probe"}, roles...)
	for _, role := range actualRoles {
		if role == "sentinelflow_dispatcher" {
			// The positive dispatcher grant is asserted through the exact function
			// OIDs above; the predecessor deliberately reuses SQLSTATE 42501 for a
			// non-live lease, so a NULL invocation cannot distinguish that domain
			// rejection from an ACL rejection.
			continue
		}
		if _, err := connection.Exec(ctx, `SET ROLE `+role); err != nil {
			t.Fatal(err)
		}
		_, capabilityErr := connection.Exec(ctx, revocationNullCapabilityCall)
		_, resultErr := connection.Exec(ctx, revocationNullResultCall)
		if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if revocationPGCode(capabilityErr) != "42501" || revocationPGCode(resultErr) != "42501" {
			t.Fatalf("%s role=%s wrapper ACL capability=%v result=%v", stage, role, capabilityErr, resultErr)
		}
	}
}

const revocationNullCapabilityCall = `SELECT sentinelflow.record_execution_capability(
    NULL::uuid, NULL::uuid, NULL::uuid, NULL::text, NULL::uuid, NULL::uuid,
    NULL::integer, NULL::sentinelflow.canonical_ipv4, NULL::bytea,
    NULL::sentinelflow.sha256_digest, NULL::sentinelflow.sha256_digest,
    NULL::sentinelflow.sha256_digest, NULL::sentinelflow.sha256_digest,
    NULL::sentinelflow.sha256_digest, NULL::sentinelflow.ascii_id,
    NULL::sentinelflow.sha256_digest, NULL::sentinelflow.sha256_digest,
    NULL::bytea, NULL::sentinelflow.sha256_digest, NULL::bytea,
    NULL::sentinelflow.sha256_digest, NULL::timestamptz, NULL::timestamptz,
    NULL::timestamptz
)`

const revocationNullResultCall = `SELECT sentinelflow.record_execution_result(
    NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid,
    NULL::sentinelflow.sha256_digest, NULL::text, NULL::uuid,
    NULL::sentinelflow.sha256_digest, NULL::sentinelflow.canonical_ipv4,
    NULL::text, NULL::text, NULL::text, NULL::bigint, NULL::integer,
    NULL::sentinelflow.sha256_digest, NULL::timestamptz, NULL::timestamptz,
    NULL::bigint, NULL::text, NULL::bytea, NULL::sentinelflow.sha256_digest,
    NULL::bytea
)`

func assertLifecycleFormatterParity(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	inspect, err := lifecycleartifact.CheckInspectArtifact(lifecycleartifact.InspectInput{
		ActionID: "019b0000-0000-4000-8000-000000000301", TargetIPv4: "203.0.113.20",
		OriginalAddDigest: testDigest('a'), OwnedSchemaDigest: testDigest('b'),
		Purpose: lifecycleartifact.PurposeReconciliation,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, requestedAt := range []time.Time{
		time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC),
		time.Date(2026, 7, 19, 1, 2, 3, 123_400_000, time.UTC),
	} {
		validUntil := requestedAt.Add(time.Minute)
		authorization, checkErr := lifecycleartifact.CheckInspectionAuthorization(
			lifecycleartifact.InspectionAuthorizationInput{
				AuthorizationID: "019b0000-0000-4000-8000-000000000302",
				PolicyID:        "019b0000-0000-4000-8000-000000000303", PolicyVersion: 7,
				OriginalAuthorizationDigest: testDigest('c'),
				EvidenceSnapshotDigest:      testDigest('d'), ValidationSnapshotDigest: testDigest('e'),
				SchedulerID: "reconciler", RequestedAt: requestedAt, ValidUntil: validUntil,
				IdempotencyKeyDigest: testDigest('f'), Inspect: inspect,
			},
		)
		if checkErr != nil {
			t.Fatal(checkErr)
		}
		var databaseJCS []byte
		var databaseDigest string
		if err := connection.QueryRow(ctx, `
WITH canonical AS (
    SELECT sentinelflow.lifecycle_inspection_authorization_jcs_000026(
        $1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8,
        $9::uuid, $10, $11, $12::timestamptz, $13, $14,
        $15::timestamptz, $16
    ) AS value
)
SELECT value, sentinelflow.hil_sha256(value)::text FROM canonical`,
			inspect.Value().ActionID, inspect.Digest(), authorization.Value().AuthorizationID,
			authorization.Value().EvidenceSnapshotDigest,
			authorization.Value().IdempotencyKeyDigest, inspect.Value().OriginalAddDigest,
			authorization.Value().OriginalAuthorizationDigest, inspect.Value().OwnedSchemaDigest,
			authorization.Value().PolicyID, authorization.Value().PolicyVersion,
			string(inspect.Value().Purpose), requestedAt, authorization.Value().SchedulerID,
			inspect.Value().TargetIPv4, validUntil, authorization.Value().ValidationSnapshotDigest,
		).Scan(&databaseJCS, &databaseDigest); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(databaseJCS, authorization.CanonicalBytes()) || databaseDigest != authorization.Digest() {
			t.Fatalf("lifecycle formatter parity requested_at=%s\nDB: %s\nGo: %s\nDB digest=%s Go digest=%s",
				requestedAt.Format(time.RFC3339Nano), databaseJCS, authorization.CanonicalBytes(),
				databaseDigest, authorization.Digest())
		}
	}
}

func revocationPGCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
