package detectionworker

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/correlation"
	"github.com/devwooops/sentinelflow/internal/detection"
)

type incidentProjection struct {
	ID, Kind, State, SourceIP, ServiceLabel   string
	Version                                   int32
	FirstSeen, LastSeen, CreatedAt, UpdatedAt time.Time
	ClosedAt, ReopenUntil                     *time.Time
}

func routeSignal(
	ctx context.Context,
	tx pgx.Tx,
	signal detection.Signal,
	jobCreatedAt time.Time,
	jobID string,
) (string, int32, error) {
	mutationAt := databaseTime(jobCreatedAt)
	if mutationAt.Before(signal.WindowEnd) {
		mutationAt = databaseTime(signal.WindowEnd)
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"incident-route-v1\n"+signal.SourceIP); err != nil {
		return "", 0, err
	}

	current, found, err := findRelatedIncident(ctx, tx, signal, mutationAt)
	if err != nil {
		return "", 0, err
	}
	if !found {
		return createIncident(ctx, tx, signal, mutationAt, jobID)
	}
	return appendIncidentSignal(ctx, tx, current, signal, mutationAt, jobID)
}

func findRelatedIncident(
	ctx context.Context,
	tx pgx.Tx,
	signal detection.Signal,
	mutationAt time.Time,
) (incidentProjection, bool, error) {
	const relatedSQL = `
SELECT incident_id::text, kind, state, host(source_ip), service_label::text,
       version, first_seen, last_seen, closed_at, reopen_until, created_at, updated_at
FROM sentinelflow.incidents incident
WHERE incident.source_ip = $1::inet AND incident.state <> 'closed'
  AND EXISTS (
      SELECT 1
      FROM sentinelflow.incident_signals link
      JOIN sentinelflow.signals signal USING (signal_id)
      WHERE link.incident_id = incident.incident_id
        AND signal.window_start <= $3::timestamptz + interval '5 minutes'
        AND $2::timestamptz <= signal.window_end + interval '5 minutes'
  )
ORDER BY incident.last_seen DESC, incident.created_at, incident.incident_id
LIMIT 1`
	value, found, err := scanIncident(tx.QueryRow(ctx, relatedSQL,
		signal.SourceIP, signal.WindowStart.UTC(), signal.WindowEnd.UTC()))
	if err != nil || found {
		return value, found, err
	}

	// Closed incidents use the durable observation-arrival time, not wall-clock
	// retry time. A queue restart therefore cannot turn an eligible reopen into
	// a fresh incident (or extend the fixed thirty-minute reopen boundary).
	const reopenSQL = `
SELECT incident_id::text, kind, state, host(source_ip), service_label::text,
       version, first_seen, last_seen, closed_at, reopen_until, created_at, updated_at
FROM sentinelflow.incidents incident
WHERE incident.source_ip = $1::inet AND incident.state = 'closed'
  AND $2::timestamptz >= incident.closed_at
  AND $2::timestamptz <= incident.reopen_until
ORDER BY incident.closed_at DESC, incident.created_at, incident.incident_id
LIMIT 1`
	return scanIncident(tx.QueryRow(ctx, reopenSQL, signal.SourceIP, mutationAt.UTC()))
}

func scanIncident(row pgx.Row) (incidentProjection, bool, error) {
	var value incidentProjection
	err := row.Scan(
		&value.ID, &value.Kind, &value.State, &value.SourceIP, &value.ServiceLabel,
		&value.Version, &value.FirstSeen, &value.LastSeen, &value.ClosedAt,
		&value.ReopenUntil, &value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return incidentProjection{}, false, nil
	}
	return value, err == nil, err
}

func createIncident(
	ctx context.Context,
	tx pgx.Tx,
	signal detection.Signal,
	mutationAt time.Time,
	jobID string,
) (string, int32, error) {
	groups, err := correlation.Correlate([]detection.Signal{signal})
	if err != nil || len(groups) != 1 {
		return "", 0, ErrInvalidSnapshot
	}
	incident, err := correlation.NewIncident(groups[0], mutationAt)
	if err != nil || incident.Version() != 1 {
		return "", 0, ErrInvalidSnapshot
	}
	incidentID := incident.ID()
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incidents (
    incident_id, kind, state, source_ip, service_label, first_seen, last_seen,
    deterministic_score, version, evidence_version, created_at, updated_at
) VALUES (
    $1::uuid, $2, 'open', $3::inet, $4, $5, $6, $7, 1, 1, $8, $8
)`, incidentID, string(signal.Classification), signal.SourceIP, signal.ServiceLabel,
		signal.WindowStart.UTC(), signal.WindowEnd.UTC(), qualifiedSentinelScore,
		mutationAt.UTC()); err != nil {
		return "", 0, err
	}
	if err = linkSignalToIncident(ctx, tx, incidentID, 1, signal, "same_source_overlap", mutationAt); err != nil {
		return "", 0, err
	}
	if err = recordIncidentVersion(ctx, tx, incidentID, 1, "created",
		mutationDigest("incident-created-v1", jobID, signal.SignalID, signal.Digest), mutationAt); err != nil {
		return "", 0, err
	}
	return incidentID, 1, nil
}

func appendIncidentSignal(
	ctx context.Context,
	tx pgx.Tx,
	current incidentProjection,
	signal detection.Signal,
	mutationAt time.Time,
	jobID string,
) (string, int32, error) {
	if current.State == "analyzing" {
		interrupted, found, err := interruptAnalysisForNewEvidence(ctx, tx, current)
		if err != nil {
			return "", 0, err
		}
		if !found || interrupted.Version != current.Version+1 ||
			interrupted.State != "analysis_failed" {
			return "", 0, ErrInvalidSnapshot
		}
		current = interrupted
	}
	nextVersion := current.Version + 1
	kinds, err := currentSignalKinds(ctx, tx, current.ID)
	if err != nil {
		return "", 0, err
	}
	kinds = append(kinds, string(signal.Classification))
	nextKind := classifySignals(kinds)
	firstSeen := current.FirstSeen
	if signal.WindowStart.Before(firstSeen) {
		firstSeen = signal.WindowStart
	}
	lastSeen := current.LastSeen
	if signal.WindowEnd.After(lastSeen) {
		lastSeen = signal.WindowEnd
	}
	updatedAt := mutationAt
	if updatedAt.Before(current.UpdatedAt) {
		updatedAt = current.UpdatedAt
	}
	mutationKind := "signal_added"
	relation := "same_source_overlap"
	if current.State == "closed" {
		mutationKind = "reopened"
		relation = "same_source_reopen"
	}
	commandDigest := mutationDigest("incident-signal-v1", current.ID,
		strconv.Itoa(int(nextVersion)), jobID, signal.SignalID, signal.Digest, mutationKind)
	commandTag, err := tx.Exec(ctx, `
UPDATE sentinelflow.incidents
SET kind = $2, state = 'open', first_seen = $3, last_seen = $4,
    closed_at = NULL, reopen_until = NULL, deterministic_score = $5,
    version = $6, evidence_version = $6,
    analysis_failure_reason = NULL, updated_at = $7
WHERE incident_id = $1::uuid AND version = $8`,
		current.ID, nextKind, firstSeen.UTC(), lastSeen.UTC(), qualifiedSentinelScore,
		nextVersion, updatedAt.UTC(), current.Version)
	if err != nil || commandTag.RowsAffected() != 1 {
		if err == nil {
			err = ErrInvalidSnapshot
		}
		return "", 0, err
	}
	if _, err = tx.Exec(ctx,
		`UPDATE sentinelflow.incident_signals SET incident_version = $2 WHERE incident_id = $1::uuid`,
		current.ID, nextVersion); err != nil {
		return "", 0, err
	}
	if _, err = tx.Exec(ctx,
		`UPDATE sentinelflow.incident_events SET incident_version = $2 WHERE incident_id = $1::uuid`,
		current.ID, nextVersion); err != nil {
		return "", 0, err
	}
	if err = linkSignalToIncident(ctx, tx, current.ID, nextVersion, signal, relation, mutationAt); err != nil {
		return "", 0, err
	}
	if err = recordIncidentVersion(ctx, tx, current.ID, nextVersion, mutationKind,
		commandDigest, updatedAt); err != nil {
		return "", 0, err
	}
	return current.ID, nextVersion, nil
}

func interruptAnalysisForNewEvidence(
	ctx context.Context,
	tx pgx.Tx,
	current incidentProjection,
) (incidentProjection, bool, error) {
	var terminalVersion int32
	if err := tx.QueryRow(ctx, `
SELECT sentinelflow.interrupt_analysis_for_new_evidence_000017($1::uuid, $2)`,
		current.ID, current.Version).Scan(&terminalVersion); err != nil {
		return incidentProjection{}, false, err
	}
	const projectionSQL = `
SELECT incident.incident_id::text, incident.kind, incident.state,
       host(incident.source_ip), incident.service_label::text,
       incident.version, incident.first_seen, incident.last_seen,
       incident.closed_at, incident.reopen_until, incident.created_at,
       incident.updated_at
FROM sentinelflow.incidents incident
WHERE incident.incident_id = $1::uuid AND incident.version = $2`
	return scanIncident(tx.QueryRow(ctx, projectionSQL, current.ID, terminalVersion))
}

func currentSignalKinds(ctx context.Context, tx pgx.Tx, incidentID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
SELECT signal.kind
FROM sentinelflow.incident_signals link
JOIN sentinelflow.signals signal USING (signal_id)
WHERE link.incident_id = $1::uuid
ORDER BY signal.signal_id`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var kind string
		if err = rows.Scan(&kind); err != nil {
			return nil, err
		}
		result = append(result, kind)
	}
	return result, rows.Err()
}

func linkSignalToIncident(
	ctx context.Context,
	tx pgx.Tx,
	incidentID string,
	version int32,
	signal detection.Signal,
	relation string,
	linkedAt time.Time,
) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_signals (
    incident_id, signal_id, incident_version, relation_reason, linked_at
) VALUES ($1::uuid, $2::uuid, $3, $4, $5)`,
		incidentID, signal.SignalID, version, relation, linkedAt.UTC()); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
SELECT event_kind,
       CASE event_kind
           WHEN 'gateway' THEN gateway_event_id::text
           WHEN 'auth' THEN auth_event_id::text
           ELSE source_health_event_id::text
       END
FROM sentinelflow.signal_evidence
WHERE signal_id = $1::uuid
ORDER BY event_kind, 2`, signal.SignalID)
	if err != nil {
		return err
	}
	type eventLink struct{ kind, eventID string }
	links := make([]eventLink, 0, len(signal.EvidenceIDs))
	for rows.Next() {
		var value eventLink
		if err = rows.Scan(&value.kind, &value.eventID); err != nil {
			rows.Close()
			return err
		}
		links = append(links, value)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(links) != len(signal.EvidenceIDs) {
		return ErrInvalidSnapshot
	}
	for _, link := range links {
		kind, eventID := link.kind, link.eventID
		rowID := deterministicUUID("incident-event-v1", incidentID, kind, eventID)
		switch kind {
		case "gateway":
			_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_events (
    incident_event_id, incident_id, incident_version, event_kind,
    gateway_event_id, relation_reason, linked_at
) VALUES ($1::uuid, $2::uuid, $3, 'gateway', $4::uuid, 'threshold_member', $5)
ON CONFLICT (incident_id, gateway_event_id) WHERE gateway_event_id IS NOT NULL DO NOTHING`,
				rowID, incidentID, version, eventID, linkedAt.UTC())
		case "auth":
			_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_events (
    incident_event_id, incident_id, incident_version, event_kind,
    auth_event_id, relation_reason, linked_at
) VALUES ($1::uuid, $2::uuid, $3, 'auth', $4::uuid, 'threshold_member', $5)
ON CONFLICT (incident_id, auth_event_id) WHERE auth_event_id IS NOT NULL DO NOTHING`,
				rowID, incidentID, version, eventID, linkedAt.UTC())
		case "source_health":
			_, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_events (
    incident_event_id, incident_id, incident_version, event_kind,
    source_health_event_id, relation_reason, linked_at
) VALUES ($1::uuid, $2::uuid, $3, 'source_health', $4::uuid, 'threshold_member', $5)
ON CONFLICT (incident_id, source_health_event_id) WHERE source_health_event_id IS NOT NULL DO NOTHING`,
				rowID, incidentID, version, eventID, linkedAt.UTC())
		default:
			return ErrInvalidSnapshot
		}
		if err != nil {
			return err
		}
		// A shared event may already belong to another signal in this incident.
	}
	return nil
}

func recordIncidentVersion(
	ctx context.Context,
	tx pgx.Tx,
	incidentID string,
	version int32,
	mutationKind, mutationDigestValue string,
	recordedAt time.Time,
) error {
	var current incidentProjection
	var deterministicScore string
	err := tx.QueryRow(ctx, `
SELECT incident_id::text, kind, state, host(source_ip), service_label::text,
       version, first_seen, last_seen, closed_at, reopen_until, created_at,
       updated_at, deterministic_score::text
FROM sentinelflow.incidents
WHERE incident_id = $1::uuid AND version = $2`, incidentID, version).Scan(
		&current.ID, &current.Kind, &current.State, &current.SourceIP,
		&current.ServiceLabel, &current.Version, &current.FirstSeen, &current.LastSeen,
		&current.ClosedAt, &current.ReopenUntil, &current.CreatedAt, &current.UpdatedAt,
		&deterministicScore,
	)
	if err != nil || current.ID != incidentID || current.Version != version ||
		deterministicScore != fmt.Sprintf("%.5f", qualifiedSentinelScore) {
		if err == nil {
			err = ErrInvalidSnapshot
		}
		return err
	}

	type signalVersion struct{ ID, Digest string }
	rows, err := tx.Query(ctx, `
SELECT signal.signal_id::text, signal.signal_digest::text
FROM sentinelflow.incident_signals link
JOIN sentinelflow.signals signal USING (signal_id)
WHERE link.incident_id = $1::uuid
ORDER BY signal.signal_id`, incidentID)
	if err != nil {
		return err
	}
	values := make([]signalVersion, 0)
	for rows.Next() {
		var value signalVersion
		if err = rows.Scan(&value.ID, &value.Digest); err != nil {
			rows.Close()
			return err
		}
		values = append(values, value)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(values) == 0 || len(values) > 10000 {
		return ErrInvalidSnapshot
	}
	digestValues := []string{"incident-evidence-v1", incidentID, strconv.Itoa(int(version))}
	for _, value := range values {
		digestValues = append(digestValues, value.ID, value.Digest)
	}
	evidenceDigest := lowerHexDigest(digestValues...)
	if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_version_history (
    incident_id, incident_version, state, kind, source_ip, service_label,
    first_seen, last_seen, closed_at, reopen_until, deterministic_score,
    mutation_kind, mutation_digest, evidence_digest, signal_count, recorded_at
) VALUES (
    $1::uuid, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16
)`, current.ID, current.Version, current.State, current.Kind, current.SourceIP,
		current.ServiceLabel, current.FirstSeen.UTC(), current.LastSeen.UTC(),
		current.ClosedAt, current.ReopenUntil, qualifiedSentinelScore, mutationKind,
		mutationDigestValue, evidenceDigest, len(values), recordedAt.UTC()); err != nil {
		return err
	}
	for ordinal, value := range values {
		if _, err = tx.Exec(ctx, `
INSERT INTO sentinelflow.incident_version_signals (
    incident_id, incident_version, signal_id, ordinal
) VALUES ($1::uuid, $2, $3::uuid, $4)`,
			incidentID, version, value.ID, ordinal+1); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgreSQLStore) CloseIdle(ctx context.Context, limit int) (int, error) {
	if ctx == nil || limit < 1 || limit > 1000 {
		return 0, ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return 0, classifyPersistenceError(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('incident-close-idle-v1', 0))`); err != nil {
		return 0, classifyPersistenceError(err)
	}
	rows, err := tx.Query(ctx, `
SELECT incident_id::text, kind, state, host(source_ip), service_label::text,
       version, first_seen, last_seen, closed_at, reopen_until, created_at, updated_at
FROM sentinelflow.incidents
WHERE state IN ('open', 'review_ready', 'analysis_failed')
  AND last_seen + interval '15 minutes' <= clock_timestamp()
ORDER BY last_seen, incident_id
LIMIT $1`, limit)
	if err != nil {
		return 0, classifyPersistenceError(err)
	}
	candidates := make([]incidentProjection, 0)
	for rows.Next() {
		value, found, scanErr := scanIncident(rows)
		if scanErr != nil || !found {
			rows.Close()
			if scanErr != nil {
				return 0, classifyPersistenceError(scanErr)
			}
			return 0, ErrPersistence
		}
		candidates = append(candidates, value)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, classifyPersistenceError(err)
	}
	rows.Close()
	for _, current := range candidates {
		nextVersion := current.Version + 1
		closedAt := databaseTime(current.LastSeen.Add(correlation.IncidentIdleTimeout))
		reopenUntil := databaseTime(closedAt.Add(correlation.IncidentReopenWindow))
		var updatedAt time.Time
		if err = tx.QueryRow(ctx, `
UPDATE sentinelflow.incidents
SET state = 'closed', closed_at = $2, reopen_until = $3, version = $4,
    analysis_failure_reason = NULL, updated_at = GREATEST(updated_at, clock_timestamp())
		WHERE incident_id = $1::uuid AND version = $5
		RETURNING updated_at`, current.ID, closedAt, reopenUntil, nextVersion, current.Version).Scan(&updatedAt); err != nil {
			return 0, classifyPersistenceError(err)
		}
		if _, err = tx.Exec(ctx,
			`UPDATE sentinelflow.incident_signals SET incident_version = $2 WHERE incident_id = $1::uuid`,
			current.ID, nextVersion); err != nil {
			return 0, classifyPersistenceError(err)
		}
		if _, err = tx.Exec(ctx,
			`UPDATE sentinelflow.incident_events SET incident_version = $2 WHERE incident_id = $1::uuid`,
			current.ID, nextVersion); err != nil {
			return 0, classifyPersistenceError(err)
		}
		digest := mutationDigest("incident-close-v1", current.ID,
			strconv.Itoa(int(nextVersion)), closedAt.Format(time.RFC3339Nano))
		if err = recordIncidentVersion(ctx, tx, current.ID, nextVersion, "closed", digest, updatedAt); err != nil {
			return 0, classifyPersistenceError(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, classifyPersistenceError(err)
	}
	return len(candidates), nil
}
