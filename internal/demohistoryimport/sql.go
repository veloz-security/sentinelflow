package demohistoryimport

const (
	lockImportSQL = `SELECT pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('sentinelflow:demo-history-dataset-v1', 0)
)`

	beginImportSQL = `SELECT sentinelflow.begin_demo_history_import_leased_000030(
    $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::bigint,
    $7::text, $8::text, $9::text, $10::text, $11::text,
    $12::timestamptz, $13::timestamptz, $14::timestamptz, $15::timestamptz
)`

	appendGatewaySQL = `SELECT sentinelflow.append_demo_history_gateway_leased_000030(
    $1::uuid, $2::text, $3::bigint, $4::uuid, $5::text, $6::integer,
    $7::uuid, $8::text, $9::uuid, $10::uuid,
    $11::timestamptz, $12::timestamptz, $13::text,
    $14::text, $15::text, $16::text, $17::text, $18::text, $19::text,
    $20::text, $21::integer, $22::bigint, $23::bigint, $24::integer
)`

	appendAuthSQL = `SELECT sentinelflow.append_demo_history_auth_leased_000030(
    $1::uuid, $2::text, $3::bigint, $4::uuid, $5::text, $6::integer,
    $7::uuid, $8::text, $9::uuid, $10::uuid, $11::timestamptz,
    $12::text, $13::text, $14::text, $15::text, $16::text
)`

	appendCoverageSQL = `SELECT sentinelflow.append_demo_history_source_coverage_leased_000030(
    $1::uuid, $2::text, $3::text, $4::text,
    $5::timestamptz, $6::timestamptz, $7::bigint, $8::bigint
)`

	completeImportSQL   = `SELECT sentinelflow.complete_demo_history_import_leased_000030($1::uuid)`
	forceConstraintsSQL = `SET CONSTRAINTS ALL IMMEDIATE`

	readImportSQL = `SELECT import_id::text, manifest_id::text, dataset_id::text,
    raw_file_byte_sha256, manifest_dataset_jcs_digest,
    imported_rows_jcs_digest, imported_record_count,
    source_health_jcs_digest, manifest_digest,
    run_scope_digest, public_key_digest, signature_verification_digest,
    clock_at, issued_at, coverage_start, coverage_end,
    status, coalesce(failure_code, ''), attempt_count,
    gateway_record_count, auth_record_count, source_coverage_count, completed_at
FROM sentinelflow.read_demo_history_import_leased_000030($1::uuid)`

	readRecoveryImportSQL = `SELECT import_id::text, manifest_id::text,
    schema_version, profile, dataset_id::text, dataset_schema_version,
    dataset_locator, path_catalog_version, raw_file_byte_sha256,
    manifest_dataset_jcs_digest, imported_rows_jcs_digest,
    imported_record_count, source_health_jcs_digest, manifest_digest,
    run_scope_digest, public_key_digest, signature_verification_digest,
    clock_at, issued_at, coverage_start, coverage_end, status,
    coalesce(failure_code, ''), attempt_count, gateway_record_count,
    auth_record_count, source_coverage_count, completed_at, rows_valid,
    mapped_gateway_count, mapped_auth_count, coverage_row_count
FROM sentinelflow.read_demo_history_import_recovery_leased_000030($1::uuid)`

	recordFailureSQL = `SELECT sentinelflow.record_demo_history_import_failure_leased_000030(
    $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::bigint,
    $7::text, $8::text, $9::text, $10::text, $11::text,
    $12::timestamptz, $13::timestamptz, $14::timestamptz, $15::timestamptz,
    $16::text
)`
)
