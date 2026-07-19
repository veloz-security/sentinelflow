package detectionworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func classifyPersistenceError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) &&
		(postgresError.Code == "40001" || postgresError.Code == "40P01") {
		return ErrRetryablePersistence
	}
	return ErrPersistence
}

const (
	lockDetectionJobSQL = `
SELECT kind, aggregate_type, aggregate_id::text, aggregate_version, state,
       lease_token::text, lease_owner, lease_expires_at, attempts, max_attempts,
       created_at
FROM sentinelflow.outbox_jobs
WHERE job_id = $1::uuid`
	coverageStartSQL = `
SELECT sentinelflow.detection_coverage_start($1, $2, $3)`
	findSignalSQL = `
SELECT signal_id::text, rule_id::text, kind, host(source_ip), service_label::text,
       window_start, window_end, observed_count, distinct_count,
       threshold_count, threshold_distinct, source_health_status,
       evidence_digest::text, configuration_version::text,
       configuration_digest::text, signal_digest::text
FROM sentinelflow.signals
WHERE signal_id = $1::uuid OR signal_digest = $2`
	insertSignalSQL = `
INSERT INTO sentinelflow.signals (
    signal_id, schema_version, rule_id, rule_version, kind, source_ip,
    service_label, window_start, window_end, observed_count, distinct_count,
    threshold_count, threshold_distinct, source_health_status, evidence_digest,
    configuration_version, configuration_digest, signal_digest
) VALUES (
    $1::uuid, 'signal-v1', $2, 1, $3, $4::inet, $5, $6, $7, $8, $9,
    $10, $11, 'complete', $12, $13, $14, $15
)`
	insertSignalGatewayEvidenceSQL = `
INSERT INTO sentinelflow.signal_evidence (
    evidence_link_id, signal_id, event_kind, gateway_event_id,
    event_time, relation_reason
) VALUES ($1::uuid, $2::uuid, 'gateway', $3::uuid, $4, 'threshold_member')`
	insertSignalAuthEvidenceSQL = `
INSERT INTO sentinelflow.signal_evidence (
    evidence_link_id, signal_id, event_kind, auth_event_id,
    event_time, relation_reason
) VALUES ($1::uuid, $2::uuid, 'auth', $3::uuid, $4, 'threshold_member')`
	finishDetectionSQL = `
SELECT job_id::text, state
FROM sentinelflow.finish_detection_job(
    $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9
)`
)

type lockedJob struct {
	kind, aggregateType, aggregateID, state, leaseToken, leaseOwner string
	aggregateVersion, attempts, maxAttempts                         int32
	leaseExpiresAt, createdAt                                       time.Time
}

func (s *PostgreSQLStore) Finalize(ctx context.Context, request FinalizeRequest) (FinalizeResult, bool, error) {
	if ctx == nil || !validFinalizeRequest(request) {
		return FinalizeResult{}, false, ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return FinalizeResult{}, false, classifyPersistenceError(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	job, found, err := lockJob(ctx, tx, request.Job.JobID)
	if err != nil {
		return FinalizeResult{}, false, classifyPersistenceError(err)
	}
	if !found || !job.matches(request.Job) || !job.leaseExpiresAt.After(request.FinishedAt) {
		return FinalizeResult{}, false, nil
	}

	result := FinalizeResult{Effects: make([]SignalEffect, 0, len(request.Mutation.Signals))}
	affected := make(map[string]struct{})
	for _, signal := range request.Mutation.Signals {
		effect, mutated, err := persistSignalAndRoute(ctx, tx, request, job, signal)
		if err != nil {
			if errors.Is(err, ErrInvalidSnapshot) {
				return FinalizeResult{}, false, ErrInvalidSnapshot
			}
			return FinalizeResult{}, false, classifyPersistenceError(err)
		}
		result.Effects = append(result.Effects, effect)
		if mutated {
			result.IncidentMutations++
			affected[effect.IncidentID] = struct{}{}
		}
	}

	// Build the exact downstream artifact only after all signal mutations from
	// this deterministic run are visible in the same transaction. Cross-service
	// incidents remain detected but deliberately get no AI work until the
	// canonical single-service analysis contract is superseded.
	for incidentID := range affected {
		if err = publishCurrentEvidence(ctx, tx, incidentID, request.Mutation.InputDigest, job.createdAt); err != nil {
			if errors.Is(err, ErrInvalidSnapshot) {
				return FinalizeResult{}, false, ErrInvalidSnapshot
			}
			return FinalizeResult{}, false, classifyPersistenceError(err)
		}
	}

	var returnedJob, returnedState string
	err = tx.QueryRow(ctx, finishDetectionSQL,
		request.Job.JobID, request.Job.LeaseToken,
		request.Mutation.ConfigurationVersion, request.Mutation.ConfigurationDigest,
		request.Mutation.EvaluatedAt.UTC(), request.Mutation.InputDigest,
		string(request.Mutation.Outcome), len(result.Effects), result.IncidentMutations,
	).Scan(&returnedJob, &returnedState)
	if errors.Is(err, pgx.ErrNoRows) {
		return FinalizeResult{}, false, nil
	}
	if err != nil || returnedJob != request.Job.JobID || returnedState != "completed" {
		if err != nil {
			return FinalizeResult{}, false, classifyPersistenceError(err)
		}
		return FinalizeResult{}, false, ErrPersistence
	}
	for _, effect := range result.Effects {
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.detector_run_signals (
    job_id, signal_id, disposition, incident_id, incident_version
) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)`,
			request.Job.JobID, effect.SignalID, string(effect.Disposition),
			effect.IncidentID, effect.IncidentVersion); err != nil {
			return FinalizeResult{}, false, classifyPersistenceError(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return FinalizeResult{}, false, classifyPersistenceError(err)
	}
	return result, true, nil
}

func validFinalizeRequest(request FinalizeRequest) bool {
	if request.Job.Kind != worker.JobDetect || !uuidPattern.MatchString(request.Job.JobID) ||
		!uuidPattern.MatchString(request.Job.LeaseToken) || request.FinishedAt.IsZero() ||
		request.Snapshot.JobID != request.Job.JobID ||
		request.Snapshot.AggregateID != request.Job.AggregateID ||
		request.Mutation.EvaluatedAt.IsZero() ||
		!request.Mutation.EvaluatedAt.Equal(request.Snapshot.EvaluatedAt) ||
		!identifierPattern.MatchString(request.Mutation.ConfigurationVersion) ||
		!digestPattern.MatchString(request.Mutation.ConfigurationDigest) ||
		!digestPattern.MatchString(request.Mutation.InputDigest) ||
		(request.Mutation.Outcome != RunComplete && request.Mutation.Outcome != RunIncomplete &&
			request.Mutation.Outcome != RunNoCandidates) || len(request.Mutation.Signals) > 10000 {
		return false
	}
	if request.Mutation.Outcome != RunComplete && len(request.Mutation.Signals) != 0 {
		return false
	}
	previous := ""
	for _, signal := range request.Mutation.Signals {
		if !uuidPattern.MatchString(signal.SignalID) || signal.SignalID <= previous ||
			signal.ConfigurationVersion != request.Mutation.ConfigurationVersion ||
			signal.ConfigurationDigest != request.Mutation.ConfigurationDigest {
			return false
		}
		previous = signal.SignalID
	}
	return true
}

func lockJob(ctx context.Context, tx pgx.Tx, jobID string) (lockedJob, bool, error) {
	var value lockedJob
	err := tx.QueryRow(ctx, lockDetectionJobSQL, jobID).Scan(
		&value.kind, &value.aggregateType, &value.aggregateID, &value.aggregateVersion,
		&value.state, &value.leaseToken, &value.leaseOwner, &value.leaseExpiresAt,
		&value.attempts, &value.maxAttempts, &value.createdAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedJob{}, false, nil
	}
	return value, err == nil, err
}

func (j lockedJob) matches(job worker.LeasedJob) bool {
	return j.kind == string(worker.JobDetect) && j.aggregateType == job.AggregateType &&
		j.aggregateID == job.AggregateID && j.aggregateVersion == job.AggregateVersion &&
		j.state == "leased" && j.leaseToken == job.LeaseToken &&
		j.leaseOwner == job.LeaseOwner && j.attempts == job.Attempt &&
		j.maxAttempts == job.MaxAttempts
}

func persistSignalAndRoute(
	ctx context.Context,
	tx pgx.Tx,
	request FinalizeRequest,
	job lockedJob,
	signal detection.Signal,
) (SignalEffect, bool, error) {
	if err := reproduceSignal(ctx, tx, signal); err != nil {
		return SignalEffect{}, false, err
	}
	stored, found, err := loadStoredSignal(ctx, tx, signal)
	if err != nil {
		return SignalEffect{}, false, err
	}
	if found {
		if !signalsEqual(stored, signal) {
			return SignalEffect{}, false, ErrInvalidSnapshot
		}
		var incidentID string
		var version int32
		err = tx.QueryRow(ctx, `
SELECT incident.incident_id::text, incident.version
FROM sentinelflow.incident_signals link
JOIN sentinelflow.incidents incident USING (incident_id)
WHERE link.signal_id = $1::uuid`, signal.SignalID).Scan(&incidentID, &version)
		if err != nil {
			return SignalEffect{}, false, err
		}
		return SignalEffect{signal.SignalID, SignalDuplicate, incidentID, version}, false, nil
	}

	if err = insertSignal(ctx, tx, signal); err != nil {
		return SignalEffect{}, false, err
	}
	incidentID, version, err := routeSignal(ctx, tx, signal, job.createdAt, request.Job.JobID)
	if err != nil {
		return SignalEffect{}, false, err
	}
	return SignalEffect{signal.SignalID, SignalCreated, incidentID, version}, true, nil
}

func reproduceSignal(ctx context.Context, tx pgx.Tx, expected detection.Signal) error {
	if expected.SourceHealthStatus != detection.SourceHealthStatusComplete || len(expected.EvidenceIDs) == 0 {
		return ErrInvalidSnapshot
	}
	input := detection.EvaluationInput{Now: expected.WindowEnd.UTC()}
	input.GatewayHealth = detection.SourceHealth{
		Source: detection.SourceGateway, Complete: true,
		CoverageStart: expected.WindowStart.UTC(), CoverageEnd: expected.WindowEnd.UTC(),
	}
	input.AuthHealth = detection.SourceHealth{
		Source: detection.SourceAuth, Complete: true,
		CoverageStart: expected.WindowStart.UTC(), CoverageEnd: expected.WindowEnd.UTC(),
	}

	needGateway := expected.RuleID != detection.RuleCredentialStuffing
	needAuth := expected.RuleID == detection.RuleCredentialStuffing || expected.RuleID == detection.RuleLoginBruteForce
	if needGateway {
		complete, err := coverageIncludes(ctx, tx, "gateway", expected.ServiceLabel,
			expected.WindowStart, expected.WindowEnd)
		if err != nil || !complete {
			return ErrInvalidSnapshot
		}
		input.GatewayEvents, err = loadGatewayEvidence(ctx, tx, expected.EvidenceIDs)
		if err != nil {
			return err
		}
	}
	if needAuth {
		complete, err := coverageIncludes(ctx, tx, "auth", expected.ServiceLabel,
			expected.WindowStart, expected.WindowEnd)
		if err != nil || !complete {
			return ErrInvalidSnapshot
		}
		if expected.RuleID == detection.RuleCredentialStuffing {
			input.AuthEvents, err = loadAuthEvidence(ctx, tx, expected.EvidenceIDs)
			if err != nil {
				return err
			}
		}
	}
	detector := detection.NewDefault()
	output, err := detector.Evaluate(input)
	if err != nil {
		return err
	}
	actual, _ := collectSignals(output)
	for _, candidate := range actual {
		if candidate.SignalID == expected.SignalID && signalsEqual(candidate, expected) {
			return nil
		}
	}
	return ErrInvalidSnapshot
}

func coverageIncludes(
	ctx context.Context,
	tx pgx.Tx,
	endpoint, service string,
	start, end time.Time,
) (bool, error) {
	var coverageStart *time.Time
	if err := tx.QueryRow(ctx, coverageStartSQL, endpoint, service, end.UTC()).Scan(&coverageStart); err != nil {
		return false, err
	}
	return coverageStart != nil && !coverageStart.After(start.UTC()), nil
}

func loadGatewayEvidence(ctx context.Context, tx pgx.Tx, ids []string) ([]detection.GatewayEvent, error) {
	rows, err := tx.Query(ctx, `
SELECT event.event_id::text, event.completed_at, host(event.source_ip),
       event.service_label::text, event.route_label::text,
       event.path_catalog_version, event.suspicious_path_id,
       event.status_code, event.trust_state,
       CASE
         WHEN event.route_label <> 'login' THEN 'not_applicable'
         WHEN EXISTS (
             SELECT 1 FROM sentinelflow.auth_events auth
             WHERE auth.bound_gateway_event_id = event.event_id
               AND auth.binding_state = 'verified' AND auth.trust_state = 'trusted'
               AND auth.outcome = 'failed'
         ) THEN 'verified'
         WHEN EXISTS (
             SELECT 1 FROM sentinelflow.auth_events auth
             WHERE auth.gateway_request_id = event.request_id
               AND auth.binding_state = 'untrusted'
         ) THEN 'untrusted'
         ELSE 'pending'
       END
FROM sentinelflow.gateway_events event
WHERE event.event_id = ANY($1::uuid[])
ORDER BY event.completed_at, event.event_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]detection.GatewayEvent, 0, len(ids))
	for rows.Next() {
		var value detection.GatewayEvent
		var suspicious, trust, binding string
		if err = rows.Scan(&value.EventID, &value.OccurredAt, &value.SourceIP,
			&value.ServiceLabel, &value.RouteLabel, &value.PathCatalogVersion,
			&suspicious, &value.StatusCode, &trust, &binding); err != nil {
			return nil, err
		}
		value.SuspiciousPathID = detection.SuspiciousPathID(suspicious)
		value.TimestampTrust = detection.TimestampTrust(trust)
		value.AuthenticationMatch = detection.BindingState(binding)
		result = append(result, value)
	}
	if err = rows.Err(); err != nil || len(result) != len(ids) {
		return nil, ErrInvalidSnapshot
	}
	return result, nil
}

func loadAuthEvidence(ctx context.Context, tx pgx.Tx, ids []string) ([]detection.AuthEvent, error) {
	rows, err := tx.Query(ctx, `
SELECT event.event_id::text, event.occurred_at, host(event.source_ip),
       event.service_label::text, event.route_label::text,
       event.account_hash::text, event.outcome, event.trust_state, event.binding_state
FROM sentinelflow.auth_events event
WHERE event.event_id = ANY($1::uuid[])
ORDER BY event.occurred_at, event.event_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]detection.AuthEvent, 0, len(ids))
	for rows.Next() {
		var value detection.AuthEvent
		var outcome, trust, binding string
		if err = rows.Scan(&value.EventID, &value.OccurredAt, &value.SourceIP,
			&value.ServiceLabel, &value.RouteLabel, &value.AccountHash,
			&outcome, &trust, &binding); err != nil {
			return nil, err
		}
		value.Outcome = detection.AuthOutcome(outcome)
		value.TimestampTrust = detection.TimestampTrust(trust)
		value.GatewayBinding = detection.BindingState(binding)
		result = append(result, value)
	}
	if err = rows.Err(); err != nil || len(result) != len(ids) {
		return nil, ErrInvalidSnapshot
	}
	return result, nil
}

func insertSignal(ctx context.Context, tx pgx.Tx, signal detection.Signal) error {
	distinct, thresholdDistinct := signalDistincts(signal)
	if _, err := tx.Exec(ctx, insertSignalSQL,
		signal.SignalID, string(signal.RuleID), string(signal.Classification),
		signal.SourceIP, signal.ServiceLabel, signal.WindowStart.UTC(), signal.WindowEnd.UTC(),
		signal.Metrics.EventCount, distinct, thresholdCount(signal.RuleID), thresholdDistinct,
		signal.EvidenceDigest, signal.ConfigurationVersion, signal.ConfigurationDigest, signal.Digest,
	); err != nil {
		return err
	}
	eventKind := "gateway"
	if signal.RuleID == detection.RuleCredentialStuffing {
		eventKind = "auth"
	}
	for _, eventID := range signal.EvidenceIDs {
		linkID := deterministicUUID("signal-evidence-v1", signal.SignalID, eventKind, eventID)
		var eventTime time.Time
		if eventKind == "gateway" {
			if err := tx.QueryRow(ctx, `SELECT completed_at FROM sentinelflow.gateway_events WHERE event_id = $1::uuid`, eventID).Scan(&eventTime); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, insertSignalGatewayEvidenceSQL,
				linkID, signal.SignalID, eventID, eventTime.UTC()); err != nil {
				return err
			}
		} else {
			if err := tx.QueryRow(ctx, `SELECT occurred_at FROM sentinelflow.auth_events WHERE event_id = $1::uuid`, eventID).Scan(&eventTime); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, insertSignalAuthEvidenceSQL,
				linkID, signal.SignalID, eventID, eventTime.UTC()); err != nil {
				return err
			}
		}
	}
	return nil
}

func signalDistincts(signal detection.Signal) (any, any) {
	switch signal.RuleID {
	case detection.RulePathScan:
		return signal.Metrics.DistinctSuspiciousPathCount, detection.PathScanThreshold
	case detection.RuleCredentialStuffing:
		return signal.Metrics.DistinctAccountCount, detection.CredentialStuffingAccountThreshold
	default:
		return nil, nil
	}
}

func thresholdCount(rule detection.RuleID) int {
	switch rule {
	case detection.RulePathScan:
		return detection.PathScanThreshold
	case detection.RuleRequestBurst:
		return detection.RequestBurstThreshold
	case detection.RuleLoginBruteForce:
		return detection.LoginBruteForceThreshold
	case detection.RuleCredentialStuffing:
		return detection.CredentialStuffingEventThreshold
	default:
		return 0
	}
}

func loadStoredSignal(ctx context.Context, tx pgx.Tx, expected detection.Signal) (detection.Signal, bool, error) {
	var stored detection.Signal
	var rule, kind, health, configurationVersion, configurationDigest, signalDigest string
	var distinct, thresholdDistinct *int
	var threshold int
	err := tx.QueryRow(ctx, findSignalSQL, expected.SignalID, expected.Digest).Scan(
		&stored.SignalID, &rule, &kind, &stored.SourceIP, &stored.ServiceLabel,
		&stored.WindowStart, &stored.WindowEnd, &stored.Metrics.EventCount, &distinct,
		&threshold, &thresholdDistinct, &health, &stored.EvidenceDigest,
		&configurationVersion, &configurationDigest, &signalDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return detection.Signal{}, false, nil
	}
	if err != nil {
		return detection.Signal{}, false, err
	}
	stored.RuleID = detection.RuleID(rule)
	stored.Classification = detection.Classification(kind)
	stored.ConfigurationVersion = configurationVersion
	stored.ConfigurationDigest = configurationDigest
	stored.Digest = signalDigest
	stored.SourceHealthStatus = detection.SourceHealthStatus(health)
	expectedDistinct, expectedThresholdDistinct := signalDistincts(expected)
	if threshold != thresholdCount(expected.RuleID) ||
		!nullableIntEqual(distinct, expectedDistinct) ||
		!nullableIntEqual(thresholdDistinct, expectedThresholdDistinct) {
		return detection.Signal{}, false, ErrInvalidSnapshot
	}
	if distinct != nil {
		if stored.RuleID == detection.RulePathScan {
			stored.Metrics.DistinctSuspiciousPathCount = *distinct
		} else {
			stored.Metrics.DistinctAccountCount = *distinct
		}
	}
	rows, err := tx.Query(ctx, `
SELECT CASE event_kind WHEN 'gateway' THEN gateway_event_id::text ELSE auth_event_id::text END
FROM sentinelflow.signal_evidence WHERE signal_id = $1::uuid
ORDER BY 1`, stored.SignalID)
	if err != nil {
		return detection.Signal{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return detection.Signal{}, false, err
		}
		stored.EvidenceIDs = append(stored.EvidenceIDs, id)
	}
	return stored, true, rows.Err()
}

func nullableIntEqual(actual *int, expected any) bool {
	if expected == nil {
		return actual == nil
	}
	value, ok := expected.(int)
	return ok && actual != nil && *actual == value
}

func signalsEqual(left, right detection.Signal) bool {
	if left.SignalID != right.SignalID || left.RuleID != right.RuleID ||
		left.Classification != right.Classification ||
		left.ConfigurationVersion != right.ConfigurationVersion ||
		left.ConfigurationDigest != right.ConfigurationDigest ||
		left.SourceIP != right.SourceIP || left.ServiceLabel != right.ServiceLabel ||
		!left.WindowStart.Equal(right.WindowStart) || !left.WindowEnd.Equal(right.WindowEnd) ||
		left.Metrics != right.Metrics || left.EvidenceDigest != right.EvidenceDigest ||
		left.Digest != right.Digest || left.SourceHealthStatus != right.SourceHealthStatus ||
		len(left.EvidenceIDs) != len(right.EvidenceIDs) {
		return false
	}
	for index := range left.EvidenceIDs {
		if left.EvidenceIDs[index] != right.EvidenceIDs[index] {
			return false
		}
	}
	return true
}

func deterministicUUID(domain string, values ...string) string {
	var builder strings.Builder
	builder.WriteString(domain)
	builder.WriteByte('\n')
	for _, value := range values {
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(builder.String()))
	bytes := [16]byte{}
	copy(bytes[:], sum[:16])
	bytes[6] = (bytes[6] & 0x0f) | 0x80
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

func mutationDigest(domain string, values ...string) string {
	var builder strings.Builder
	builder.WriteString(domain)
	builder.WriteByte('\n')
	for _, value := range values {
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	return digestBytes([]byte(builder.String()))
}

// qualifiedSentinelScore is intentionally not a severity formula. The
// canonical documents have not frozen one. 1.00000 means only that at least
// one complete deterministic threshold was reproduced; exact metrics remain
// on the immutable signal rows.
const qualifiedSentinelScore = 1.00000

func classifySignals(kinds []string) string {
	if len(kinds) == 0 {
		return "unknown"
	}
	first := kinds[0]
	for _, kind := range kinds[1:] {
		if kind != first {
			return "mixed"
		}
	}
	return first
}

func sortedUniqueStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write > 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func lowerHexDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:%s\n", len(value), value)))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
