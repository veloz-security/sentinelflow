package detectionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	leaseSQL = `
SELECT job_id::text, kind, aggregate_type, aggregate_id::text,
    aggregate_version, state, available_at, lease_token::text,
    lease_owner, updated_at, lease_expires_at, attempts, max_attempts
FROM sentinelflow.lease_detection_outbox_job($1, $2::uuid, $3, $4)`
	prepareSQL = `
SELECT status, snapshot
FROM sentinelflow.prepare_detection_job($1::uuid, $2::uuid)`
	gatewayEventsSQL = `
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
       END AS authentication_match
FROM sentinelflow.gateway_events event
WHERE event.service_label = $1
  AND event.completed_at >= $2::timestamptz - interval '5 minutes'
  AND event.completed_at <= $2::timestamptz
  AND host(event.source_ip) = ANY($3::text[])
ORDER BY event.completed_at, event.event_id`
	authEventsSQL = `
SELECT event.event_id::text, event.occurred_at, host(event.source_ip),
       event.service_label::text, event.route_label::text,
       event.account_hash::text, event.outcome, event.trust_state,
       event.binding_state
FROM sentinelflow.auth_events event
WHERE event.service_label = $1
  AND event.occurred_at >= $2::timestamptz - interval '5 minutes'
  AND event.occurred_at <= $2::timestamptz
  AND host(event.source_ip) = ANY($3::text[])
ORDER BY event.occurred_at, event.event_id`
	finishFailureSQL = `
SELECT job_id::text, state
FROM sentinelflow.finish_worker_outbox_job(
    $1, $2, $3, $4, $5, $6::uuid, $7::uuid
)`
)

type postgresDB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgreSQLStore struct{ db postgresDB }

func NewPostgreSQLStore(db postgresDB) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgreSQLStore{db: db}, nil
}

func (s *PostgreSQLStore) Lease(ctx context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	if ctx == nil || request.Now.IsZero() || request.LeaseExpiresAt.IsZero() ||
		!request.LeaseExpiresAt.After(request.Now) || !uuidPattern.MatchString(request.LeaseToken) ||
		!identifierPattern.MatchString(request.LeaseOwner) {
		return worker.LeasedJob{}, false, ErrInvalidRequest
	}
	var job worker.LeasedJob
	var kind, token string
	err := s.db.QueryRow(ctx, leaseSQL, request.Now.UTC(), request.LeaseToken,
		request.LeaseOwner, request.LeaseExpiresAt.UTC()).Scan(
		&job.JobID, &kind, &job.AggregateType, &job.AggregateID,
		&job.AggregateVersion, &job.State, &job.AvailableAt, &token,
		&job.LeaseOwner, &job.LeaseGrantedAt, &job.LeaseExpiresAt,
		&job.Attempt, &job.MaxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.LeasedJob{}, false, nil
	}
	if err != nil {
		return worker.LeasedJob{}, false, classifyPersistenceError(err)
	}
	job.Kind = worker.JobKind(kind)
	job.LeaseToken = token
	if !validLease(job, request) {
		return worker.LeasedJob{}, false, ErrInvalidSnapshot
	}
	return job, true, nil
}

type prepareDocument struct {
	JobID                string     `json:"job_id"`
	AggregateType        string     `json:"aggregate_type"`
	AggregateID          string     `json:"aggregate_id"`
	AggregateVersion     int32      `json:"aggregate_version"`
	BatchID              string     `json:"batch_id"`
	EndpointKind         string     `json:"endpoint_kind"`
	ServiceLabel         string     `json:"service_label"`
	EvaluatedAt          time.Time  `json:"evaluated_at"`
	GatewayCoverageStart *time.Time `json:"gateway_coverage_start"`
	AuthCoverageStart    *time.Time `json:"auth_coverage_start"`
	CandidateSourceIPs   []string   `json:"candidate_source_ips"`
}

func (s *PostgreSQLStore) Prepare(ctx context.Context, job worker.LeasedJob) (Snapshot, bool, error) {
	if ctx == nil || job.Kind != worker.JobDetect || !uuidPattern.MatchString(job.JobID) ||
		!uuidPattern.MatchString(job.LeaseToken) {
		return Snapshot{}, false, ErrInvalidRequest
	}
	// prepare_detection_job fences the leased row and may terminalize a replayed
	// job. Keep this repeatable-read transaction writable even though ordinary
	// preparation only reads evidence.
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return Snapshot{}, false, classifyPersistenceError(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var status string
	var raw []byte
	err = tx.QueryRow(ctx, prepareSQL, job.JobID, job.LeaseToken).Scan(&status, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, classifyPersistenceError(err)
	}
	if status != "prepared" || len(raw) < 2 || len(raw) > 1<<20 {
		return Snapshot{}, false, ErrPersistence
	}
	var document prepareDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&document); err != nil || decoderHasTrailing(decoder) {
		return Snapshot{}, false, ErrInvalidSnapshot
	}
	// Detector windows and source-coverage attestations use the frozen
	// millisecond event-time contract. Reject a drifting database function
	// instead of silently normalizing a different snapshot in the worker.
	if document.EvaluatedAt.IsZero() ||
		!document.EvaluatedAt.Equal(time.UnixMilli(document.EvaluatedAt.UnixMilli())) {
		return Snapshot{}, false, ErrInvalidSnapshot
	}
	input := detection.EvaluationInput{Now: document.EvaluatedAt.UTC()}
	input.GatewayHealth = sourceHealth(detection.SourceGateway,
		document.GatewayCoverageStart, document.EvaluatedAt)
	input.AuthHealth = sourceHealth(detection.SourceAuth,
		document.AuthCoverageStart, document.EvaluatedAt)
	if len(document.CandidateSourceIPs) > 0 {
		input.GatewayEvents, err = loadGatewayEvents(ctx, tx, document)
		if err != nil {
			if errors.Is(err, ErrInvalidSnapshot) {
				return Snapshot{}, false, err
			}
			return Snapshot{}, false, classifyPersistenceError(err)
		}
		input.AuthEvents, err = loadAuthEvents(ctx, tx, document)
		if err != nil {
			if errors.Is(err, ErrInvalidSnapshot) {
				return Snapshot{}, false, err
			}
			return Snapshot{}, false, classifyPersistenceError(err)
		}
		if len(input.GatewayEvents)+len(input.AuthEvents) > maximumPreparedEvents {
			return Snapshot{}, false, ErrInvalidSnapshot
		}
	}
	snapshot := Snapshot{
		JobID: document.JobID, AggregateType: document.AggregateType,
		AggregateID: document.AggregateID, AggregateVersion: document.AggregateVersion,
		BatchID: document.BatchID, EndpointKind: document.EndpointKind,
		ServiceLabel: document.ServiceLabel, EvaluatedAt: document.EvaluatedAt.UTC(),
		CandidateSourceIPs: append([]string(nil), document.CandidateSourceIPs...), Input: input,
	}
	if !validSnapshot(snapshot, job) {
		return Snapshot{}, false, ErrInvalidSnapshot
	}
	if err = tx.Commit(ctx); err != nil {
		return Snapshot{}, false, classifyPersistenceError(err)
	}
	return snapshot, true, nil
}

func sourceHealth(source detection.SourceKind, start *time.Time, end time.Time) detection.SourceHealth {
	result := detection.SourceHealth{Source: source, CoverageStart: end.UTC(), CoverageEnd: end.UTC()}
	if start != nil {
		result.Complete = true
		result.CoverageStart = start.UTC()
	}
	return result
}

const maximumPreparedEvents = 1_000_000

func loadGatewayEvents(ctx context.Context, tx pgx.Tx, document prepareDocument) ([]detection.GatewayEvent, error) {
	rows, err := tx.Query(ctx, gatewayEventsSQL, document.ServiceLabel,
		document.EvaluatedAt.UTC(), document.CandidateSourceIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]detection.GatewayEvent, 0)
	for rows.Next() {
		if len(result) >= maximumPreparedEvents {
			return nil, ErrInvalidSnapshot
		}
		var value detection.GatewayEvent
		var suspicious, trust, binding string
		if err = rows.Scan(
			&value.EventID, &value.OccurredAt, &value.SourceIP, &value.ServiceLabel,
			&value.RouteLabel, &value.PathCatalogVersion, &suspicious, &value.StatusCode,
			&trust, &binding,
		); err != nil {
			return nil, err
		}
		value.SuspiciousPathID = detection.SuspiciousPathID(suspicious)
		value.TimestampTrust = detection.TimestampTrust(trust)
		value.AuthenticationMatch = detection.BindingState(binding)
		result = append(result, value)
	}
	return result, rows.Err()
}

func loadAuthEvents(ctx context.Context, tx pgx.Tx, document prepareDocument) ([]detection.AuthEvent, error) {
	rows, err := tx.Query(ctx, authEventsSQL, document.ServiceLabel,
		document.EvaluatedAt.UTC(), document.CandidateSourceIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]detection.AuthEvent, 0)
	for rows.Next() {
		if len(result) >= maximumPreparedEvents {
			return nil, ErrInvalidSnapshot
		}
		var value detection.AuthEvent
		var outcome, trust, binding string
		if err = rows.Scan(
			&value.EventID, &value.OccurredAt, &value.SourceIP, &value.ServiceLabel,
			&value.RouteLabel, &value.AccountHash, &outcome, &trust, &binding,
		); err != nil {
			return nil, err
		}
		value.Outcome = detection.AuthOutcome(outcome)
		value.TimestampTrust = detection.TimestampTrust(trust)
		value.GatewayBinding = detection.BindingState(binding)
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *PostgreSQLStore) FinishFailure(ctx context.Context, request worker.FinishRequest) (bool, error) {
	if ctx == nil || (request.State != worker.FinishRetry && request.State != worker.FinishDead) ||
		!uuidPattern.MatchString(request.JobID) || !uuidPattern.MatchString(request.LeaseToken) ||
		!identifierPattern.MatchString(request.ErrorCode) || !digestPattern.MatchString(request.ErrorDigest) ||
		request.Now.IsZero() || (request.State == worker.FinishRetry) != (request.RetryAt != nil) {
		return false, ErrInvalidRequest
	}
	var retryAt any
	if request.RetryAt != nil {
		retryAt = request.RetryAt.UTC()
	}
	var jobID, state string
	err := s.db.QueryRow(ctx, finishFailureSQL, string(request.State), retryAt,
		request.ErrorCode, request.ErrorDigest, request.Now.UTC(), request.JobID,
		request.LeaseToken).Scan(&jobID, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, classifyPersistenceError(err)
	}
	return jobID == request.JobID && state == string(request.State), nil
}

func decoderHasTrailing(decoder *json.Decoder) bool {
	var extra any
	return !errors.Is(decoder.Decode(&extra), io.EOF)
}
