package detectionworker

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/evidenceartifactstore"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const evidenceRetention = 7 * 24 * time.Hour

type evidenceIncident struct {
	ID, State, SourceIP, ServiceLabel string
	Version                           int32
	FirstSeen, LastSeen               time.Time
}

type evidenceSignal struct {
	ID, EvidenceDigest, SignalDigest, ServiceLabel string
	ExpandedEventCount                             int
}

func publishCurrentEvidence(
	ctx context.Context,
	tx pgx.Tx,
	incidentID, inputDigest string,
	jobCreatedAt time.Time,
) error {
	var incident evidenceIncident
	err := tx.QueryRow(ctx, `
SELECT incident_id::text, state, host(source_ip), service_label::text,
       version, first_seen, last_seen
FROM sentinelflow.incidents
WHERE incident_id = $1::uuid`, incidentID).Scan(
		&incident.ID, &incident.State, &incident.SourceIP, &incident.ServiceLabel,
		&incident.Version, &incident.FirstSeen, &incident.LastSeen,
	)
	if err != nil {
		return err
	}
	if incident.State != "open" {
		return nil
	}

	signals, err := loadEvidenceSignals(ctx, tx, incident)
	if err != nil {
		return err
	}
	if len(signals) == 0 {
		return ErrInvalidSnapshot
	}
	// The frozen AI contract is single-service. Same-source correlation may
	// legitimately span services, but that supporting context must not be
	// coerced into a false service identity for analysis or enforcement.
	for _, signal := range signals {
		if signal.ServiceLabel != incident.ServiceLabel {
			return nil
		}
	}
	if len(signals) > validation.MaxEvidenceSignalIDs {
		return enqueueAnalysis(ctx, tx, incident, "over-signal-limit", jobCreatedAt)
	}

	digestValues := []string{"source-health-evidence-v1", inputDigest, incident.ID,
		strconv.Itoa(int(incident.Version))}
	signalIDs := make([]string, len(signals))
	signalRows := make([]evidenceartifactstore.SignalRow, len(signals))
	for index, signal := range signals {
		digestValues = append(digestValues, signal.ID, signal.SignalDigest)
		signalIDs[index] = signal.ID
		signalRows[index] = evidenceartifactstore.SignalRow{
			SignalID: signal.ID, EvidenceDigest: signal.EvidenceDigest,
			ExpandedEventCount: signal.ExpandedEventCount,
		}
	}
	sourceHealthDigest := lowerHexDigest(digestValues...)
	snapshotID := deterministicUUID("evidence-snapshot-v1", incident.ID,
		strconv.Itoa(int(incident.Version)), sourceHealthDigest)
	totalExpandedEvents := 0
	for _, signal := range signals {
		totalExpandedEvents += signal.ExpandedEventCount
		if totalExpandedEvents > validation.MaxEvidenceEventIDs {
			return enqueueAnalysis(ctx, tx, incident, "over-event-limit", jobCreatedAt)
		}
	}
	eventRows, eventIDs, err := loadEvidenceEvents(ctx, tx, incident, snapshotID)
	if err != nil {
		return err
	}
	if len(eventRows) == 0 || len(eventRows) > validation.MaxEvidenceEventIDs {
		return enqueueAnalysis(ctx, tx, incident, "over-event-limit", jobCreatedAt)
	}

	createdAt := databaseTime(jobCreatedAt)
	var serverNow time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&serverNow); err != nil {
		return err
	}
	serverNow = databaseTime(serverNow)
	if createdAt.Before(serverNow) {
		createdAt = serverNow
	}
	if createdAt.Before(incident.LastSeen) {
		createdAt = databaseTime(incident.LastSeen)
	}
	checked, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    snapshotID, IncidentID: incident.ID,
		IncidentVersion: uint32(incident.Version), SourceIPv4: incident.SourceIP,
		ServiceLabel: incident.ServiceLabel, WindowStart: incident.FirstSeen.UTC(),
		WindowEnd: incident.LastSeen.UTC(), SourceHealthDigest: sourceHealthDigest,
		EventIDs: eventIDs, SignalIDs: signalIDs, CreatedAt: createdAt,
	})
	if err != nil {
		return ErrInvalidSnapshot
	}
	store, err := evidenceartifactstore.NewPostgreSQLStore(tx)
	if err != nil {
		return err
	}
	if _, err = store.Insert(ctx, evidenceartifactstore.InsertRequest{
		Evidence: checked, SourceHealthStatus: validation.SourceHealthComplete,
		ExpiresAt: createdAt.Add(evidenceRetention), Signals: signalRows, Events: eventRows,
	}); err != nil {
		return err
	}
	return enqueueAnalysis(ctx, tx, incident, checked.Digest(), createdAt)
}

func loadEvidenceSignals(
	ctx context.Context,
	tx pgx.Tx,
	incident evidenceIncident,
) ([]evidenceSignal, error) {
	rows, err := tx.Query(ctx, `
SELECT signal.signal_id::text, signal.evidence_digest::text,
       signal.signal_digest::text, signal.service_label::text, count(evidence.evidence_link_id)::integer
FROM sentinelflow.incident_signals link
JOIN sentinelflow.signals signal USING (signal_id)
JOIN sentinelflow.signal_evidence evidence USING (signal_id)
WHERE link.incident_id = $1::uuid AND link.incident_version = $2
  AND signal.source_health_status = 'complete'
GROUP BY signal.signal_id, signal.evidence_digest, signal.signal_digest, signal.service_label
ORDER BY signal.signal_id`, incident.ID, incident.Version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]evidenceSignal, 0)
	for rows.Next() {
		var value evidenceSignal
		if err = rows.Scan(&value.ID, &value.EvidenceDigest, &value.SignalDigest,
			&value.ServiceLabel, &value.ExpandedEventCount); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func loadEvidenceEvents(
	ctx context.Context,
	tx pgx.Tx,
	incident evidenceIncident,
	snapshotID string,
) ([]evidenceartifactstore.EventRow, []string, error) {
	rows, err := tx.Query(ctx, `
SELECT evidence.signal_id::text, evidence.event_kind,
       CASE evidence.event_kind
           WHEN 'gateway' THEN evidence.gateway_event_id::text
           WHEN 'auth' THEN evidence.auth_event_id::text
           ELSE evidence.source_health_event_id::text
       END AS event_id,
       evidence.event_time
FROM sentinelflow.incident_signals incident_signal
JOIN sentinelflow.signal_evidence evidence USING (signal_id)
WHERE incident_signal.incident_id = $1::uuid
  AND incident_signal.incident_version = $2
ORDER BY evidence.signal_id, evidence.event_kind, event_id`, incident.ID, incident.Version)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	result := make([]evidenceartifactstore.EventRow, 0)
	eventIDs := make([]string, 0)
	for rows.Next() {
		var signalID, kind, eventID string
		var eventTime time.Time
		if err = rows.Scan(&signalID, &kind, &eventID, &eventTime); err != nil {
			return nil, nil, err
		}
		var eventKind evidenceartifactstore.EventKind
		switch kind {
		case "gateway":
			eventKind = evidenceartifactstore.EventGateway
		case "auth":
			eventKind = evidenceartifactstore.EventAuth
		case "source_health":
			eventKind = evidenceartifactstore.EventSourceHealth
		default:
			return nil, nil, ErrInvalidSnapshot
		}
		result = append(result, evidenceartifactstore.EventRow{
			EventRowID: deterministicUUID("evidence-event-row-v1", snapshotID,
				signalID, kind, eventID),
			SignalID: signalID, Kind: eventKind, EventID: eventID,
			EventTime: eventTime.UTC(),
		})
		eventIDs = append(eventIDs, eventID)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}
	return result, sortedUniqueStrings(eventIDs), nil
}

func enqueueAnalysis(
	ctx context.Context,
	tx pgx.Tx,
	incident evidenceIncident,
	binding string,
	createdAt time.Time,
) error {
	canonical := "sentinelflow analysis outbox v1\n" + incident.ID + "\n" +
		strconv.Itoa(int(incident.Version)) + "\n" + binding + "\n"
	idempotency := digestBytes([]byte(canonical))
	jobID := deterministicUUID("analysis-outbox-v1", canonical)
	createdAt = databaseTime(createdAt)
	commandTag, err := tx.Exec(ctx, `
INSERT INTO sentinelflow.outbox_jobs (
    job_id, kind, aggregate_type, aggregate_id, aggregate_version,
    idempotency_key, state, available_at, max_attempts, created_at, updated_at
) VALUES (
    $1::uuid, 'analyze', 'incident', $2::uuid, $3, $4,
    'pending', $5, 8, $5, $5
)
ON CONFLICT DO NOTHING`, jobID, incident.ID, incident.Version, idempotency, createdAt.UTC())
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 1 {
		return nil
	}
	var existingID, kind, aggregateType, aggregateID, existingDigest string
	var aggregateVersion int32
	err = tx.QueryRow(ctx, `
SELECT job_id::text, kind, aggregate_type, aggregate_id::text,
       aggregate_version, idempotency_key::text
FROM sentinelflow.outbox_jobs
WHERE job_id = $1::uuid OR idempotency_key = $2 OR
      (kind = 'analyze' AND aggregate_type = 'incident' AND
       aggregate_id = $3::uuid AND aggregate_version = $4)`,
		jobID, idempotency, incident.ID, incident.Version).Scan(
		&existingID, &kind, &aggregateType, &aggregateID, &aggregateVersion, &existingDigest)
	if err != nil || existingID != jobID || kind != "analyze" || aggregateType != "incident" ||
		aggregateID != incident.ID || aggregateVersion != incident.Version ||
		existingDigest != idempotency {
		if err == nil {
			err = ErrInvalidSnapshot
		}
		return err
	}
	return nil
}
