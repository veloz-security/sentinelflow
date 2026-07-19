package investigationstore

const listIncidentsSQL = `
SELECT incident_id::text, kind, state, host(source_ip), service_label,
       first_seen, last_seen, closed_at, deterministic_score::text, version,
       analysis_failure_reason, created_at, updated_at
FROM sentinelflow.incidents
WHERE ($1::text = '' OR state = $1)
  AND ($2::text = '' OR kind = $2)
  AND (NULLIF($3::text, '') IS NULL OR source_ip = NULLIF($3::text, '')::inet)
  AND ($4::text = '' OR service_label = $4)
  AND ($5::timestamptz IS NULL OR last_seen >= $5)
  AND ($6::timestamptz IS NULL OR last_seen <= $6)
  AND ($7::timestamptz IS NULL OR (last_seen, incident_id) < ($7, $8::uuid))
ORDER BY last_seen DESC, incident_id DESC
LIMIT $9`

const getIncidentSQL = `
SELECT incident_id::text, kind, state, host(source_ip), service_label,
       first_seen, last_seen, closed_at, deterministic_score::text, version,
       analysis_failure_reason, created_at, updated_at, evidence_version
FROM sentinelflow.incidents
WHERE incident_id = $1::uuid`

const listIncidentSignalsSQL = `
SELECT signal.signal_id::text, signal.rule_id, signal.rule_version, signal.kind,
       signal.window_start, signal.window_end, signal.observed_count,
       signal.distinct_count, signal.threshold_count, signal.threshold_distinct,
       signal.source_health_status, signal.evidence_digest
FROM sentinelflow.incident_signals link
JOIN sentinelflow.signals signal USING (signal_id)
WHERE link.incident_id = $1::uuid
ORDER BY signal.window_end DESC, signal.signal_id DESC
LIMIT $2`

const latestIncidentAnalysisSQL = `
SELECT analysis_id::text, incident_version, provider_kind, adapter_id, model,
       reasoning_effort, rate_card_version, result_state, failure_reason,
       output_digest, incident_summary, classification, confidence::text,
       uncertainty, started_at, completed_at
FROM sentinelflow.ai_analyses analysis
WHERE analysis.incident_id = $1::uuid
  AND analysis.incident_version = $2::integer
ORDER BY analysis.attempt DESC, analysis.analysis_id DESC
LIMIT 1`

const analysisFalsePositivesSQL = `
SELECT factor
FROM sentinelflow.analysis_false_positive_factors
WHERE analysis_id = $1::uuid
ORDER BY ordinal ASC`

const incidentPoliciesSQL = `
SELECT policy_id::text, version, incident_version, state, state_revision,
       host(target_ipv4), ttl_seconds, policy_digest,
       evidence_snapshot_digest, updated_at
FROM sentinelflow.policy_proposals
WHERE incident_id = $1::uuid
ORDER BY incident_version DESC, version DESC, policy_id DESC
LIMIT $2`

const listIncidentEventsSQL = `
WITH minimized AS (
    SELECT link.incident_event_id, link.incident_version, link.event_kind,
           COALESCE(gateway.event_id, auth.event_id, health.event_id) AS event_id,
           CASE link.event_kind
               WHEN 'gateway' THEN gateway.started_at
               WHEN 'auth' THEN auth.occurred_at
               ELSE health.occurred_at
           END AS occurred_at,
           COALESCE(gateway.trace_id, auth.trace_id) AS trace_id,
           COALESCE(gateway.source_ip, auth.source_ip) AS source_ip,
           COALESCE(gateway.service_label, auth.service_label) AS service_label,
           COALESCE(gateway.route_label, auth.route_label) AS route_label,
           gateway.method, gateway.status_code, gateway.suspicious_path_id,
           auth.outcome AS auth_outcome, auth.binding_state,
           health.state AS health_state, health.cause AS health_cause,
           health.dropped_count,
           COALESCE(gateway.trust_state, auth.trust_state, health.trust_state) AS trust_state,
           COALESCE(gateway.trust_reason, auth.trust_reason, health.trust_reason) AS trust_reason,
           link.relation_reason
    FROM sentinelflow.incident_events link
    LEFT JOIN sentinelflow.gateway_events gateway
      ON link.event_kind = 'gateway' AND gateway.event_id = link.gateway_event_id
    LEFT JOIN sentinelflow.auth_events auth
      ON link.event_kind = 'auth' AND auth.event_id = link.auth_event_id
    LEFT JOIN sentinelflow.source_health_intervals health
      ON link.event_kind = 'source_health' AND health.event_id = link.source_health_event_id
    WHERE link.incident_id = $1::uuid
)
SELECT incident_event_id::text, event_id::text, incident_version, event_kind,
       occurred_at, trace_id::text, host(source_ip), service_label, route_label,
       method, status_code, suspicious_path_id, auth_outcome, binding_state,
       health_state, health_cause, dropped_count, trust_state, trust_reason,
       relation_reason
FROM minimized
WHERE ($2::timestamptz IS NULL OR (occurred_at, incident_event_id) < ($2, $3::uuid))
ORDER BY occurred_at DESC, incident_event_id DESC
LIMIT $4`

const getPolicySQL = `
SELECT policy.policy_id::text, policy.version, policy.incident_id::text,
       policy.incident_version, policy.analysis_id::text,
       policy.command_candidate_id::text, policy.state, policy.state_revision,
       host(policy.target_ipv4), policy.action, policy.ttl_seconds,
       candidate.timeout_token, policy.rationale, policy.policy_digest,
       policy.evidence_snapshot_digest, candidate.generated_command,
       policy.generated_artifact_digest,
       convert_from(candidate.canonical_artifact, 'UTF8'),
       policy.canonical_artifact_digest, candidate.parse_state,
       candidate.parse_error_code, policy.created_at, policy.updated_at
FROM sentinelflow.policy_proposals policy
JOIN sentinelflow.command_candidates candidate USING (command_candidate_id)
WHERE policy.policy_id = $1::uuid
ORDER BY policy.version DESC
LIMIT 1`

const latestValidationSQL = `
SELECT validation_snapshot_id::text, snapshot_digest, state, failure_code,
       source_health_status, base_chain_contract_raw_digest,
       live_owned_schema_digest, protected_ipv4_static_digest,
       protected_ipv4_effective_config_digest, historical_impact_digest,
       history_dataset_digest, history_manifest_digest, created_at, valid_until
FROM sentinelflow.validation_snapshots
WHERE policy_id = $1::uuid AND policy_version = $2
ORDER BY created_at DESC, validation_snapshot_id DESC
LIMIT 1`

const validationGatesSQL = `
SELECT gate_order, gate_name, passed, result_code, input_digest,
       result_digest, checked_at
FROM sentinelflow.validation_gates
WHERE validation_snapshot_id = $1::uuid
ORDER BY gate_order ASC`

const latestValidationAttemptSQL = `
SELECT validation_attempt_id::text, policy_id::text, analysis_id::text,
       incident_id::text, incident_version, state, failure_code, failed_gate,
       prepared_snapshot_digest, terminal_mutation_digest, completed_at,
       gate_order, gate_name, gate_state, gate_result_code,
       gate_artifact_digest
FROM sentinelflow.read_policy_validation_attempt_000032($1::uuid)`

const policyDecisionSQL = `
SELECT decision_id::text, decision, actor_id, reason_digest, decided_at
FROM sentinelflow.approval_decisions
WHERE policy_id = $1::uuid AND policy_version = $2
  AND operation IN ('approve', 'reject')
ORDER BY decided_at DESC, decision_id DESC
LIMIT 1`

const getActionSQL = `
SELECT action.action_id::text, action.policy_id::text, action.policy_version,
       action.validation_snapshot_id::text, action.evidence_snapshot_digest,
       host(action.target_ipv4), action.canonical_artifact_digest,
       action.ttl_seconds, action.state, action.approved_at, action.queued_at,
       action.applied_at, action.expected_expires_at, action.finished_at,
       action.version, action.created_at, action.updated_at,
       result.result_id::text, result.operation, result.classification,
       result.readback_state, result.remaining_ttl_seconds,
       result.journal_sequence, result.error_code, result.result_digest,
       result.persisted_at
FROM sentinelflow.enforcement_actions action
LEFT JOIN LATERAL (
    SELECT result_id, operation, classification, readback_state,
           remaining_ttl_seconds, journal_sequence, error_code,
           result_digest, persisted_at
    FROM sentinelflow.execution_results
    WHERE action_id = action.action_id
    ORDER BY persisted_at DESC, result_id DESC
    LIMIT 1
) result ON true
WHERE action.action_id = $1::uuid`

const listAuditSQL = `
SELECT sequence, event_id::text, actor_type, actor_id, action, object_type,
       object_id::text, incident_id::text, policy_id::text, policy_version,
       enforcement_action_id::text, trace_id::text, primary_digest,
       secondary_digest, outcome, occurred_at, recorded_at
FROM sentinelflow.audit_events
WHERE (NULLIF($1::text, '') IS NULL OR incident_id = NULLIF($1::text, '')::uuid)
  AND (NULLIF($2::text, '') IS NULL OR policy_id = NULLIF($2::text, '')::uuid)
  AND (NULLIF($3::text, '') IS NULL OR enforcement_action_id = NULLIF($3::text, '')::uuid)
  AND ($4::text = '' OR actor_type = $4)
  AND ($5::text = '' OR actor_id = $5)
  AND ($6::text = '' OR object_type = $6)
  AND (NULLIF($7::text, '') IS NULL OR object_id = NULLIF($7::text, '')::uuid)
  AND (NULLIF($8::text, '') IS NULL OR trace_id = NULLIF($8::text, '')::uuid)
  AND ($9::timestamptz IS NULL OR occurred_at >= $9)
  AND ($10::timestamptz IS NULL OR occurred_at <= $10)
  AND ($11::bigint IS NULL OR sequence < $11)
ORDER BY sequence DESC
LIMIT $12`
