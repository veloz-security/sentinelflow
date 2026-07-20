package recoverybundle

import (
	"strings"
	"testing"
)

func TestPostgreSQLRecoveryLockSQLIsStaticAndComplete(t *testing.T) {
	backup, err := PostgreSQLRecoveryLockSQL(PostgreSQLBackupLocks)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := PostgreSQLRecoveryLockSQL(PostgreSQLRestoreLocks)
	if err != nil {
		t.Fatal(err)
	}
	for name, sql := range map[string]string{"backup": backup, "restore": restore} {
		if !strings.HasPrefix(sql, "LOCK TABLE sentinelflow.admin_sessions") {
			t.Fatalf("%s lock preamble is not a direct static application-table lock", name)
		}
		firstTerminator := strings.IndexByte(sql, ';')
		if firstTerminator < 0 || strings.Contains(sql[:firstTerminator], "pg_catalog") ||
			strings.Contains(strings.ToUpper(sql[:firstTerminator]), "SELECT") {
			t.Fatalf("%s first statement is catalog-derived: %q", name, sql[:firstTerminator+1])
		}
		for _, catalog := range []string{
			"pg_catalog.pg_class", "pg_catalog.pg_namespace", "pg_catalog.pg_proc",
			"pg_catalog.pg_type", "pg_catalog.pg_enum", "pg_catalog.pg_ts_config",
		} {
			if !strings.Contains(sql, catalog) {
				t.Fatalf("%s lock preamble lacks DDL fence %s", name, catalog)
			}
		}
		if strings.Contains(sql, "ALTER SCHEMA") {
			t.Fatalf("%s retained ineffective same-owner schema alteration", name)
		}
	}
	if !strings.Contains(backup, "ALTER SEQUENCE sentinelflow.audit_events_sequence_seq AS bigint;") ||
		!strings.Contains(backup, "ALTER SEQUENCE sentinelflow.sse_notification_cursor_seq AS bigint;") {
		t.Fatal("backup lacks all sequence writer fences")
	}
	if !strings.Contains(restore, "ALTER SEQUENCE sentinelflow.audit_events_sequence_seq OWNER TO sentinelflow_migration;") ||
		!strings.Contains(restore, "ALTER SEQUENCE sentinelflow.sse_notification_cursor_seq OWNER TO sentinelflow_migration;") {
		t.Fatal("restore lacks all sequence mutation locks")
	}
}

func TestPostgreSQLContractsCoverCacheAndMissingOperations(t *testing.T) {
	rows := PostgreSQLRelationContractRows()
	for _, relation := range []string{
		"sentinelflow.demo_history_runtime_activations",
		"sentinelflow.demo_history_runtime_capability_expectation",
		"sentinelflow.demo_history_runtime_uses",
		"sentinelflow.enforcement_expiry_bounds_000034",
		"sentinelflow.execution_result_readback_bounds_000034",
	} {
		if !strings.Contains(rows, relation+"\tr\tp\tfalse\t-") {
			t.Fatalf("trusted relation contract omits %s", relation)
		}
	}
	if strings.Count(rows, "bigint:1:1:9223372036854775807:1:false:1:sentinelflow_migration:") != 2 {
		t.Fatal("trusted sequence contract does not bind cache size")
	}
	if !strings.Contains(PostgreSQLRelationContractCopySQL(), "sequence.seqcache") {
		t.Fatal("live relation query omits sequence cache size")
	}
	artifactSQL := PostgreSQLExecutionArtifactCopySQL()
	for _, join := range []string{
		"LEFT JOIN sentinelflow.execution_results",
		"LEFT JOIN sentinelflow.lifecycle_result_applications_000026",
		"LEFT JOIN sentinelflow.outbox_jobs",
		"LEFT JOIN sentinelflow.dispatch_operations",
	} {
		if !strings.Contains(artifactSQL, join) {
			t.Fatalf("artifact stream can omit corrupt rows: missing %q", join)
		}
	}
	for _, lifecycleField := range []string{
		"'schema_version', 'sentinelflow-execution-artifact-row-v2'",
		"'lifecycle_application'",
		"'schema_version', 'lifecycle-result-application-v1'",
		"'resulting_action_version', application.resulting_action_version",
	} {
		if !strings.Contains(artifactSQL, lifecycleField) {
			t.Fatalf("artifact stream omits lifecycle application binding: missing %q", lifecycleField)
		}
	}
	if strings.Contains(artifactSQL, "'action_state'") ||
		strings.Contains(artifactSQL, "'action_version'") {
		t.Fatal("artifact stream binds immutable lifecycle history to mutable current action state")
	}
	for _, canonicalIPv4 := range []string{
		"'target_ipv4', host(operation.target_ipv4)",
		"'target_ipv4', host(capability.target_ipv4)",
		"'target_ipv4', host(result.target_ipv4)",
	} {
		if !strings.Contains(artifactSQL, canonicalIPv4) {
			t.Fatalf("artifact stream does not export canonical host-only IPv4: missing %q", canonicalIPv4)
		}
	}
	if strings.Contains(artifactSQL, "target_ipv4::text") {
		t.Fatal("artifact stream exports PostgreSQL CIDR-form IPv4")
	}
}
