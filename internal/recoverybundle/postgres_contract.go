package recoverybundle

import (
	"errors"
	"strings"
)

// PostgreSQLRelationLockMode selects the only two lock profiles used by the
// recovery scripts. The relation names are a checked-in contract, never a
// catalog-derived list: a catalog lookup before these locks would establish a
// repeatable-read snapshot before an already-running TRUNCATE commits.
type PostgreSQLRelationLockMode string

const (
	PostgreSQLBackupLocks  PostgreSQLRelationLockMode = "backup"
	PostgreSQLRestoreLocks PostgreSQLRelationLockMode = "restore"
)

type postgresRelationContract struct {
	name            string
	kind            byte
	persistence     byte
	partition       bool
	sequenceOwner   string
	sequenceOwnedBy string
}

// Keep this list sorted by qualified name. Adding or removing a base,
// partitioned, or sequence relation requires changing this contract before a
// recovery binary will accept that database schema.
var postgresRelations = []postgresRelationContract{
	{name: "sentinelflow.admin_sessions", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ai_analyses", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ai_budget_ledger", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ai_budget_reservations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.analysis_attempt_claims", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.analysis_attempt_results", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.analysis_evidence", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.analysis_false_positive_factors", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.analysis_output_staging", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.approval_decisions", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.audit_events", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.audit_events_sequence_seq", kind: 'S', persistence: 'p', sequenceOwner: "sentinelflow_migration", sequenceOwnedBy: "sentinelflow.audit_events.sequence"},
	{name: "sentinelflow.auth_events", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.command_candidates", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.dead_letter_jobs", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.decision_challenges", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_import_batches", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_imports", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_runtime_activations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_runtime_capability_expectation", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_runtime_uses", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.demo_history_source_coverage", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.detector_run_signals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.detector_runs", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.dispatch_operations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.enforcement_actions", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.enforcement_authorizations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.evidence_snapshot_artifacts", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.evidence_snapshot_events", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.evidence_snapshot_signals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.evidence_snapshots", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.execution_capabilities", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.execution_results", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.expected_source_binding_retirements", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.expected_source_bindings", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.gateway_events", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.hil_exact_artifacts", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.hil_reasons", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.incident_events", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.incident_signals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.incident_version_history", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.incident_version_signals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.incidents", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ingest_batches", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ingest_gap_lifecycle", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ingest_replay_nonces", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ingest_sequence_gap_resolutions", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.ingest_sequence_gaps", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.inspection_authorizations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.lifecycle_capability_applications_000026", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.lifecycle_inspection_artifacts_000026", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.lifecycle_inspection_schedules_000026", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.lifecycle_result_applications_000026", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.outbox_jobs", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.policy_proposals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.retention_runs", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.revocation_operations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.schema_migrations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.sender_checkpoints", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.signal_evidence", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.signals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.source_coverage_attestations", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.source_health_intervals", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.sse_client_leases", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.sse_notification_cursor_seq", kind: 'S', persistence: 'p', sequenceOwner: "sentinelflow_migration", sequenceOwnedBy: "none"},
	{name: "sentinelflow.sse_notification_ledger", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.sse_notification_replay_state", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.validation_attempt_claims", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.validation_attempt_gates", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.validation_attempt_results", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.validation_gates", kind: 'r', persistence: 'p'},
	{name: "sentinelflow.validation_snapshots", kind: 'r', persistence: 'p'},
}

// PostgreSQLRecoveryLockSQL returns a complete, static lock preamble. The first
// statement is always one direct multi-relation LOCK; it contains no catalog
// query or PL/pgSQL loop. Sequence ALTER statements use the same bigint type
// in backup mode to obtain ShareRowExclusiveLock without changing the intended
// schema, and the same owner in restore mode to obtain AccessExclusiveLock.
func PostgreSQLRecoveryLockSQL(mode PostgreSQLRelationLockMode) (string, error) {
	if mode != PostgreSQLBackupLocks && mode != PostgreSQLRestoreLocks {
		return "", errors.New("invalid PostgreSQL recovery lock mode")
	}
	lockMode := "SHARE"
	if mode == PostgreSQLRestoreLocks {
		lockMode = "ACCESS EXCLUSIVE"
	}
	var tables []string
	var sequences []postgresRelationContract
	for _, relation := range postgresRelations {
		switch relation.kind {
		case 'r', 'p':
			tables = append(tables, relation.name)
		case 'S':
			sequences = append(sequences, relation)
		}
	}
	var result strings.Builder
	result.WriteString("LOCK TABLE ")
	result.WriteString(strings.Join(tables, ", "))
	result.WriteString(" IN ")
	result.WriteString(lockMode)
	result.WriteString(" MODE;\n")
	// These catalogs cover every schema-scoped object included by the canonical
	// pg_dump options: relations/namespaces, routines, types, collations,
	// conversions, operators/opclasses, and text-search objects. Their SRX
	// locks block uncooperative DDL (including CREATE FUNCTION/TYPE) while
	// remaining compatible with pg_dump's AccessShare reads. This static lock
	// follows the application-table lock so that the trusted direct multi-table
	// lock remains the first snapshot-affecting statement.
	result.WriteString("LOCK TABLE pg_catalog.pg_aggregate, pg_catalog.pg_amop, pg_catalog.pg_amproc, pg_catalog.pg_attrdef, pg_catalog.pg_attribute, pg_catalog.pg_cast, pg_catalog.pg_class, pg_catalog.pg_collation, pg_catalog.pg_constraint, pg_catalog.pg_conversion, pg_catalog.pg_depend, pg_catalog.pg_enum, pg_catalog.pg_extension, pg_catalog.pg_foreign_data_wrapper, pg_catalog.pg_foreign_server, pg_catalog.pg_foreign_table, pg_catalog.pg_index, pg_catalog.pg_inherits, pg_catalog.pg_language, pg_catalog.pg_namespace, pg_catalog.pg_opclass, pg_catalog.pg_operator, pg_catalog.pg_opfamily, pg_catalog.pg_partitioned_table, pg_catalog.pg_policy, pg_catalog.pg_proc, pg_catalog.pg_publication, pg_catalog.pg_publication_namespace, pg_catalog.pg_publication_rel, pg_catalog.pg_range, pg_catalog.pg_rewrite, pg_catalog.pg_sequence, pg_catalog.pg_statistic_ext, pg_catalog.pg_statistic_ext_data, pg_catalog.pg_transform, pg_catalog.pg_trigger, pg_catalog.pg_ts_config, pg_catalog.pg_ts_config_map, pg_catalog.pg_ts_dict, pg_catalog.pg_ts_parser, pg_catalog.pg_ts_template, pg_catalog.pg_type IN SHARE ROW EXCLUSIVE MODE;\n")
	for _, sequence := range sequences {
		result.WriteString("ALTER SEQUENCE ")
		result.WriteString(sequence.name)
		if mode == PostgreSQLBackupLocks {
			result.WriteString(" AS bigint;\n")
		} else {
			result.WriteString(" OWNER TO ")
			result.WriteString(sequence.sequenceOwner)
			result.WriteString(";\n")
		}
	}
	return result.String(), nil
}

// PostgreSQLRelationContractRows is the trusted COPY-compatible relation set.
// It intentionally excludes OIDs because a fresh restored database assigns
// different OIDs; schema/name/kind/persistence/partition and exact sequence
// definition/ownership are compared instead.
func PostgreSQLRelationContractRows() string {
	var result strings.Builder
	for _, relation := range postgresRelations {
		result.WriteString(relation.name)
		result.WriteByte('\t')
		result.WriteByte(relation.kind)
		result.WriteByte('\t')
		result.WriteByte(relation.persistence)
		result.WriteByte('\t')
		if relation.partition {
			result.WriteString("true")
		} else {
			result.WriteString("false")
		}
		result.WriteByte('\t')
		if relation.kind == 'S' {
			result.WriteString("bigint:1:1:9223372036854775807:1:false:1:")
			result.WriteString(relation.sequenceOwner)
			result.WriteByte(':')
			result.WriteString(relation.sequenceOwnedBy)
		} else {
			result.WriteByte('-')
		}
		result.WriteByte('\n')
	}
	return result.String()
}

func PostgreSQLSequenceNames() []string {
	result := make([]string, 0, 2)
	for _, relation := range postgresRelations {
		if relation.kind == 'S' {
			result = append(result, relation.name)
		}
	}
	return result
}

// PostgreSQLExecutionArtifactCopySQL emits one bounded NDJSON row for every
// persisted capability/result pair. Exact signed bytes are hex encoded; they
// are never cast to json/jsonb in PostgreSQL.
func PostgreSQLExecutionArtifactCopySQL() string {
	return `COPY (
SELECT json_build_object(
  'schema_version', 'sentinelflow-execution-artifact-row-v2',
  'job', json_build_object(
    'job_id', job.job_id::text, 'kind', job.kind,
    'operation', job.operation, 'state', job.state,
    'aggregate_type', job.aggregate_type::text,
    'aggregate_id', job.aggregate_id::text,
    'aggregate_version', job.aggregate_version,
    'available_at', to_char(job.available_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'attempts', job.attempts, 'max_attempts', job.max_attempts,
    'last_error_code', job.last_error_code,
    'last_error_digest', job.last_error_digest::text,
    'dead_letter_state', dead_letter.resolution_state,
    'dead_letter_job_id', dead_letter.job_id::text,
    'dead_letter_kind', dead_letter.kind,
    'dead_letter_aggregate_type', dead_letter.aggregate_type::text,
    'dead_letter_aggregate_id', dead_letter.aggregate_id::text,
    'dead_letter_aggregate_version', dead_letter.aggregate_version,
    'dead_letter_attempts', dead_letter.attempts,
    'dead_letter_failure_code', dead_letter.failure_code::text,
    'dead_letter_failure_digest', dead_letter.failure_digest::text,
    'dead_letter_dead_at', to_char(dead_letter.dead_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'dead_letter_resolved_at', to_char(dead_letter.resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'dead_letter_resolution_actor', dead_letter.resolution_actor::text,
    'dead_letter_resolution_digest', dead_letter.resolution_digest::text,
    'updated_at', to_char(job.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ),
  'operation', json_build_object(
    'job_id', operation.job_id::text, 'operation', operation.operation,
    'action_id', operation.action_id::text, 'policy_id', operation.policy_id::text,
    'policy_version', operation.policy_version, 'target_ipv4', host(operation.target_ipv4),
    'artifact_hex', encode(operation.artifact, 'hex'),
    'artifact_digest', operation.artifact_digest::text,
    'original_add_digest', operation.original_add_digest::text,
    'evidence_snapshot_digest', operation.evidence_snapshot_digest::text,
    'validation_snapshot_digest', operation.validation_snapshot_digest::text,
    'authorization_digest', operation.authorization_digest::text,
    'actor_id', operation.actor_id::text, 'reason_digest', operation.reason_digest::text,
    'owned_schema_digest', operation.owned_schema_digest::text,
    'not_before', to_char(operation.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'valid_until', to_char(operation.valid_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ),
  'capability', json_build_object(
    'capability_id', capability.capability_id::text,
    'schema_version', capability.schema_version, 'job_id', capability.job_id::text,
    'operation', capability.operation, 'action_id', capability.action_id::text,
    'policy_id', capability.policy_id::text, 'policy_version', capability.policy_version,
    'target_ipv4', host(capability.target_ipv4),
    'artifact_hex', encode(capability.artifact, 'hex'),
    'artifact_digest', capability.artifact_digest::text,
    'original_add_digest', capability.original_add_digest::text,
    'evidence_snapshot_digest', capability.evidence_snapshot_digest::text,
    'validation_snapshot_digest', capability.validation_snapshot_digest::text,
    'authorization_digest', capability.authorization_digest::text,
    'actor_id', capability.actor_id::text, 'reason_digest', capability.reason_digest::text,
    'owned_schema_digest', capability.owned_schema_digest::text,
    'capability_jcs_hex', encode(capability.capability_jcs, 'hex'),
    'capability_digest', capability.capability_digest::text,
    'capability_signature_hex', encode(capability.capability_signature, 'hex'),
    'nonce_digest', capability.nonce_digest::text,
    'issued_at', to_char(capability.issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'not_before', to_char(capability.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'expires_at', to_char(capability.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'consumed_at', to_char(capability.consumed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ),
  'result', CASE WHEN result.result_id IS NULL THEN NULL ELSE json_build_object(
    'result_id', result.result_id::text, 'schema_version', result.schema_version,
    'capability_id', result.capability_id::text,
    'capability_digest', result.capability_digest::text,
    'operation', result.operation, 'action_id', result.action_id::text,
    'artifact_digest', result.artifact_digest::text, 'target_ipv4', host(result.target_ipv4),
    'classification', result.classification, 'nft_exit_class', result.nft_exit_class,
    'readback_state', result.readback_state, 'element_handle', result.element_handle,
    'remaining_ttl_seconds', result.remaining_ttl_seconds,
    'owned_schema_digest', result.owned_schema_digest::text,
    'started_at', to_char(result.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'completed_at', to_char(result.completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'journal_sequence', result.journal_sequence, 'error_code', result.error_code,
    'result_jcs_hex', encode(result.result_jcs, 'hex'),
    'result_digest', result.result_digest::text,
    'result_signature_hex', encode(result.result_signature, 'hex'),
    'persisted_at', to_char(result.persisted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ) END,
  'lifecycle_application', CASE WHEN application.result_id IS NULL THEN NULL ELSE json_build_object(
    'schema_version', 'lifecycle-result-application-v1',
    'job_id', capability.job_id::text,
    'capability_id', capability.capability_id::text,
    'result_id', application.result_id::text,
    'result_digest', application.result_digest::text,
    'action_id', application.action_id::text,
    'operation', application.operation,
    'classification', application.classification,
    'resulting_state', application.resulting_state,
    'resulting_action_version', application.resulting_action_version,
    'processed_at', to_char(application.processed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ) END
)::text
FROM sentinelflow.execution_capabilities capability
LEFT JOIN sentinelflow.execution_results result USING (capability_id)
LEFT JOIN sentinelflow.lifecycle_result_applications_000026 application
  ON application.result_id = result.result_id
LEFT JOIN sentinelflow.outbox_jobs job ON job.job_id = capability.job_id
LEFT JOIN sentinelflow.dispatch_operations operation ON operation.job_id = capability.job_id
LEFT JOIN sentinelflow.dead_letter_jobs dead_letter ON dead_letter.job_id = capability.job_id
ORDER BY capability.capability_id
) TO STDOUT;
`
}

func PostgreSQLRelationContractCopySQL() string {
	return `COPY (
WITH sequence_dependency AS (
  SELECT dependency.objid AS sequence_oid,
         string_agg(format('%I.%I.%I', owner_namespace.nspname, owner_relation.relname, owner_attribute.attname), ',' ORDER BY dependency.refobjid, dependency.refobjsubid) AS owned_by
  FROM pg_catalog.pg_depend dependency
  JOIN pg_catalog.pg_class owner_relation ON owner_relation.oid = dependency.refobjid
  JOIN pg_catalog.pg_namespace owner_namespace ON owner_namespace.oid = owner_relation.relnamespace
  JOIN pg_catalog.pg_attribute owner_attribute ON owner_attribute.attrelid = dependency.refobjid AND owner_attribute.attnum = dependency.refobjsubid
  WHERE dependency.classid = 'pg_catalog.pg_class'::regclass
    AND dependency.refclassid = 'pg_catalog.pg_class'::regclass
    AND dependency.deptype IN ('a','i')
  GROUP BY dependency.objid
)
SELECT format('%I.%I', namespace.nspname, relation.relname),
       relation.relkind, relation.relpersistence, relation.relispartition::text,
       CASE WHEN relation.relkind = 'S' THEN format(
         '%s:%s:%s:%s:%s:%s:%s:%s:%s', sequence.seqtypid::regtype::text,
         sequence.seqstart, sequence.seqincrement, sequence.seqmax,
         sequence.seqmin, sequence.seqcycle::text, sequence.seqcache,
         pg_catalog.pg_get_userbyid(relation.relowner),
         coalesce(sequence_dependency.owned_by, 'none')
       ) ELSE '-' END
FROM pg_catalog.pg_class relation
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
LEFT JOIN pg_catalog.pg_sequence sequence ON sequence.seqrelid = relation.oid
LEFT JOIN sequence_dependency ON sequence_dependency.sequence_oid = relation.oid
WHERE namespace.nspname = 'sentinelflow'
  AND relation.relkind IN ('r','p','S')
ORDER BY namespace.nspname, relation.relname, relation.oid
) TO STDOUT;
`
}

func PostgreSQLSequenceStateCopySQL() string {
	return `COPY (
SELECT 'sentinelflow.audit_events_sequence_seq', last_value::text, is_called::text
FROM sentinelflow.audit_events_sequence_seq
UNION ALL
SELECT 'sentinelflow.sse_notification_cursor_seq', last_value::text, is_called::text
FROM sentinelflow.sse_notification_cursor_seq
ORDER BY 1
) TO STDOUT;
`
}
