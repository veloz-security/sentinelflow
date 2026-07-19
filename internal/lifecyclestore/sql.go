package lifecyclestore

const (
	claimScheduleSQL = `
SELECT schedule_identity, lease_identity, authorization_id, action_id,
    action_version, policy_id, policy_version, target_ipv4,
    original_add_digest, original_authorization_digest,
    evidence_snapshot_digest, validation_snapshot_digest,
    owned_schema_digest, purpose, requested_at, valid_until
FROM sentinelflow.claim_lifecycle_inspection_schedule_000026($1, $2, $3)`

	commitInspectionSQL = `
SELECT sentinelflow.commit_lifecycle_inspection_000026(
    $1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, $9
)`

	finishFailureSQL = `
SELECT sentinelflow.finish_lifecycle_inspection_failure_000026(
    $1::uuid, $2::uuid, $3, $4, $5, $6
)`
)
