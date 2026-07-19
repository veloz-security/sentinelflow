// Package investigationstore implements the read-only PostgreSQL boundary for
// the authenticated administrator investigation API.
package investigationstore

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type rowScanner interface {
	Scan(...any) error
}

// PostgreSQLStore uses direct SELECT statements only against tables granted to
// sentinelflow_api by the checked-in migrations. It has no mutation method.
type PostgreSQLStore struct {
	db queryer
}

func NewPostgreSQLStore(db queryer) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrInvalidArgument
	}
	return &PostgreSQLStore{db: db}, nil
}

func (store *PostgreSQLStore) ListIncidents(ctx context.Context, query IncidentQuery) (IncidentPage, error) {
	if ctx == nil || store == nil || store.db == nil || !validIncidentQuery(query) {
		return IncidentPage{}, ErrInvalidArgument
	}
	limit, _ := normalizeLimit(query.Limit)
	var cursorTime, cursorID any
	if query.Cursor.set {
		cursorTime, cursorID = query.Cursor.time.UTC(), query.Cursor.id
	}
	rows, err := store.db.Query(ctx, listIncidentsSQL,
		query.State, query.Kind, query.SourceIP, query.ServiceLabel,
		timeArgument(query.From), timeArgument(query.Until), cursorTime, cursorID, limit+1,
	)
	if err != nil {
		return IncidentPage{}, ErrUnavailable
	}
	defer rows.Close()
	items := make([]IncidentSummary, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanIncident(rows)
		if scanErr != nil {
			return IncidentPage{}, scanErr
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return IncidentPage{}, ErrUnavailable
	}
	page := IncidentPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = newIncidentCursor(last.LastSeen, last.IncidentID).String()
	}
	return page, nil
}

func (store *PostgreSQLStore) GetIncident(ctx context.Context, incidentID string) (IncidentDetail, error) {
	if ctx == nil || store == nil || store.db == nil || !validUUID(incidentID) {
		return IncidentDetail{}, ErrInvalidArgument
	}
	incident, evidenceVersion, err := scanIncidentDetailBase(store.db.QueryRow(ctx, getIncidentSQL, incidentID))
	if err != nil {
		return IncidentDetail{}, err
	}
	detail := IncidentDetail{Incident: incident, Signals: []SignalSummary{}, Policies: []PolicySummary{}}

	rows, err := store.db.Query(ctx, listIncidentSignalsSQL, incidentID, DetailItemLimit+1)
	if err != nil {
		return IncidentDetail{}, ErrUnavailable
	}
	for rows.Next() {
		var signal SignalSummary
		if err = rows.Scan(
			&signal.SignalID, &signal.RuleID, &signal.RuleVersion, &signal.Kind,
			&signal.WindowStart, &signal.WindowEnd, &signal.ObservedCount,
			&signal.DistinctCount, &signal.ThresholdCount, &signal.ThresholdDistinct,
			&signal.SourceHealth, &signal.EvidenceDigest,
		); err != nil || !validSignal(signal) {
			rows.Close()
			return IncidentDetail{}, invalidRow(err)
		}
		normalizeSignalTimes(&signal)
		detail.Signals = append(detail.Signals, signal)
	}
	if rows.Err() != nil {
		rows.Close()
		return IncidentDetail{}, ErrUnavailable
	}
	rows.Close()
	if len(detail.Signals) > DetailItemLimit {
		detail.Signals = detail.Signals[:DetailItemLimit]
		detail.SignalsTruncated = true
	}

	var analysisVersion any
	if evidenceVersion != nil {
		analysisVersion = *evidenceVersion
	}
	analysis, err := scanAnalysis(store.db.QueryRow(ctx, latestIncidentAnalysisSQL, incidentID, analysisVersion))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return IncidentDetail{}, err
	}
	if err == nil {
		factors, factorErr := store.listFalsePositives(ctx, analysis.AnalysisID)
		if factorErr != nil {
			return IncidentDetail{}, factorErr
		}
		analysis.FalsePositives = factors
		if !validAnalysis(analysis) {
			return IncidentDetail{}, ErrInvalidRow
		}
		detail.Analysis = &analysis
	}

	rows, err = store.db.Query(ctx, incidentPoliciesSQL, incidentID, DetailItemLimit+1)
	if err != nil {
		return IncidentDetail{}, ErrUnavailable
	}
	for rows.Next() {
		var policy PolicySummary
		if err = rows.Scan(
			&policy.PolicyID, &policy.Version, &policy.IncidentVersion, &policy.State,
			&policy.StateRevision, &policy.TargetIPv4, &policy.TTLSeconds,
			&policy.PolicyDigest, &policy.EvidenceSnapshotDigest, &policy.UpdatedAt,
		); err != nil || !validPolicySummary(policy) {
			rows.Close()
			return IncidentDetail{}, invalidRow(err)
		}
		policy.UpdatedAt = policy.UpdatedAt.UTC()
		detail.Policies = append(detail.Policies, policy)
	}
	if rows.Err() != nil {
		rows.Close()
		return IncidentDetail{}, ErrUnavailable
	}
	rows.Close()
	if len(detail.Policies) > DetailItemLimit {
		detail.Policies = detail.Policies[:DetailItemLimit]
		detail.PoliciesTruncated = true
	}
	return detail, nil
}

func (store *PostgreSQLStore) ListIncidentEvents(ctx context.Context, query IncidentEventQuery) (IncidentEventPage, error) {
	if ctx == nil || store == nil || store.db == nil || !validUUID(query.IncidentID) ||
		(query.Cursor.set && (!validFiniteTime(query.Cursor.time) || !validUUID(query.Cursor.id))) {
		return IncidentEventPage{}, ErrInvalidArgument
	}
	limit, ok := normalizeLimit(query.Limit)
	if !ok {
		return IncidentEventPage{}, ErrInvalidArgument
	}
	var cursorTime, cursorID any
	if query.Cursor.set {
		cursorTime, cursorID = query.Cursor.time.UTC(), query.Cursor.id
	}
	rows, err := store.db.Query(ctx, listIncidentEventsSQL, query.IncidentID, cursorTime, cursorID, limit+1)
	if err != nil {
		return IncidentEventPage{}, ErrUnavailable
	}
	defer rows.Close()
	items := make([]IncidentEvent, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanIncidentEvent(rows)
		if scanErr != nil {
			return IncidentEventPage{}, scanErr
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return IncidentEventPage{}, ErrUnavailable
	}
	page := IncidentEventPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = newEventCursor(last.OccurredAt, last.IncidentEventID).String()
	}
	return page, nil
}

func (store *PostgreSQLStore) GetPolicy(ctx context.Context, policyID string) (PolicyDetail, error) {
	if ctx == nil || store == nil || store.db == nil || !validUUID(policyID) {
		return PolicyDetail{}, ErrInvalidArgument
	}
	var policy PolicyDetail
	var canonical *string
	err := store.db.QueryRow(ctx, getPolicySQL, policyID).Scan(
		&policy.PolicyID, &policy.Version, &policy.IncidentID, &policy.IncidentVersion,
		&policy.AnalysisID, &policy.CommandCandidateID, &policy.State, &policy.StateRevision,
		&policy.TargetIPv4, &policy.Action, &policy.TTLSeconds, &policy.TimeoutToken,
		&policy.Rationale, &policy.PolicyDigest, &policy.EvidenceSnapshotDigest,
		&policy.GeneratedCommand, &policy.GeneratedDigest, &canonical,
		&policy.CanonicalDigest, &policy.ParseState, &policy.ParseErrorCode,
		&policy.CreatedAt, &policy.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyDetail{}, ErrNotFound
	}
	if err != nil {
		return PolicyDetail{}, ErrUnavailable
	}
	if canonical == nil {
		return PolicyDetail{}, ErrInvalidRow
	}
	policy.CanonicalCommand = *canonical
	policy.CreatedAt, policy.UpdatedAt = policy.CreatedAt.UTC(), policy.UpdatedAt.UTC()
	if !validPolicy(policy) {
		return PolicyDetail{}, ErrInvalidRow
	}

	validation, err := store.latestValidation(ctx, policy.PolicyID, policy.Version)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return PolicyDetail{}, err
	}
	if err == nil {
		policy.Validation = &validation
	}
	attempt, err := store.latestValidationAttempt(ctx, policy.PolicyID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return PolicyDetail{}, err
	}
	if err == nil {
		policy.ValidationAttempt = &attempt
	}
	decision, err := scanDecision(store.db.QueryRow(ctx, policyDecisionSQL, policy.PolicyID, policy.Version))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return PolicyDetail{}, err
	}
	if err == nil {
		policy.Decision = &decision
	}
	if !validPolicyTerminalBinding(policy) {
		return PolicyDetail{}, ErrInvalidRow
	}
	return policy, nil
}

func (store *PostgreSQLStore) latestValidationAttempt(ctx context.Context, policyID string) (ValidationAttemptSummary, error) {
	rows, err := store.db.Query(ctx, latestValidationAttemptSQL, policyID)
	if err != nil {
		return ValidationAttemptSummary{}, ErrUnavailable
	}
	defer rows.Close()
	var value ValidationAttemptSummary
	value.Gates = []ValidationAttemptGate{}
	for rows.Next() {
		var row ValidationAttemptSummary
		var gateOrder *int16
		var gateName, gateState, gateResultCode, gateArtifactDigest *string
		if err = rows.Scan(
			&row.ValidationAttemptID, &row.PolicyID, &row.AnalysisID,
			&row.IncidentID, &row.IncidentVersion, &row.State, &row.FailureCode,
			&row.FailedGate, &row.PreparedSnapshotDigest, &row.TerminalMutationDigest,
			&row.CompletedAt, &gateOrder, &gateName, &gateState, &gateResultCode,
			&gateArtifactDigest,
		); err != nil {
			return ValidationAttemptSummary{}, ErrUnavailable
		}
		row.CompletedAt = row.CompletedAt.UTC()
		if value.ValidationAttemptID == "" {
			value = row
			value.Gates = []ValidationAttemptGate{}
		} else if !sameValidationAttemptRow(value, row) {
			return ValidationAttemptSummary{}, ErrInvalidRow
		}
		if gateOrder == nil || gateName == nil || gateState == nil || gateResultCode == nil || gateArtifactDigest == nil {
			if gateOrder != nil || gateName != nil || gateState != nil || gateResultCode != nil || gateArtifactDigest != nil {
				return ValidationAttemptSummary{}, ErrInvalidRow
			}
			continue
		}
		value.Gates = append(value.Gates, ValidationAttemptGate{
			Order: *gateOrder, Name: *gateName, State: *gateState,
			ResultCode: *gateResultCode, ArtifactDigest: *gateArtifactDigest,
		})
	}
	if rows.Err() != nil {
		return ValidationAttemptSummary{}, ErrUnavailable
	}
	if value.ValidationAttemptID == "" {
		return ValidationAttemptSummary{}, ErrNotFound
	}
	if !validValidationAttempt(value) {
		return ValidationAttemptSummary{}, ErrInvalidRow
	}
	return value, nil
}

func sameValidationAttemptRow(left, right ValidationAttemptSummary) bool {
	return left.ValidationAttemptID == right.ValidationAttemptID && left.PolicyID == right.PolicyID &&
		left.AnalysisID == right.AnalysisID && left.IncidentID == right.IncidentID &&
		left.IncidentVersion == right.IncidentVersion && left.State == right.State &&
		equalOptionalString(left.FailureCode, right.FailureCode) &&
		equalOptionalString(left.FailedGate, right.FailedGate) &&
		left.PreparedSnapshotDigest == right.PreparedSnapshotDigest &&
		equalOptionalString(left.TerminalMutationDigest, right.TerminalMutationDigest) &&
		left.CompletedAt.Equal(right.CompletedAt)
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (store *PostgreSQLStore) GetEnforcementAction(ctx context.Context, actionID string) (EnforcementActionDetail, error) {
	if ctx == nil || store == nil || store.db == nil || !validUUID(actionID) {
		return EnforcementActionDetail{}, ErrInvalidArgument
	}
	var action EnforcementActionDetail
	var resultID, operation, classification, readbackState, errorCode, resultDigest *string
	var remainingTTL *int32
	var journalSequence *int64
	var persistedAt *time.Time
	err := store.db.QueryRow(ctx, getActionSQL, actionID).Scan(
		&action.ActionID, &action.PolicyID, &action.PolicyVersion,
		&action.ValidationSnapshotID, &action.EvidenceSnapshotDigest,
		&action.TargetIPv4, &action.CanonicalDigest, &action.TTLSeconds,
		&action.State, &action.ApprovedAt, &action.QueuedAt, &action.AppliedAt,
		&action.ExpectedExpiresAt, &action.FinishedAt, &action.Version,
		&action.CreatedAt, &action.UpdatedAt, &resultID, &operation,
		&classification, &readbackState, &remainingTTL, &journalSequence,
		&errorCode, &resultDigest, &persistedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnforcementActionDetail{}, ErrNotFound
	}
	if err != nil {
		return EnforcementActionDetail{}, ErrUnavailable
	}
	normalizeActionTimes(&action)
	if !validAction(action) {
		return EnforcementActionDetail{}, ErrInvalidRow
	}
	if resultID != nil {
		if operation == nil || classification == nil || readbackState == nil || journalSequence == nil ||
			errorCode == nil || resultDigest == nil || persistedAt == nil {
			return EnforcementActionDetail{}, ErrInvalidRow
		}
		result := ExecutionResultSummary{
			ResultID: *resultID, Operation: *operation, Classification: *classification,
			ReadbackState: *readbackState, RemainingTTLSeconds: remainingTTL,
			JournalSequence: *journalSequence, ErrorCode: *errorCode,
			ResultDigest: *resultDigest, PersistedAt: persistedAt.UTC(),
		}
		if !validExecutionResult(result) ||
			result.RemainingTTLSeconds != nil && *result.RemainingTTLSeconds > action.TTLSeconds {
			return EnforcementActionDetail{}, ErrInvalidRow
		}
		action.LatestResult = &result
	} else if operation != nil || classification != nil || readbackState != nil || remainingTTL != nil ||
		journalSequence != nil || errorCode != nil || resultDigest != nil || persistedAt != nil {
		return EnforcementActionDetail{}, ErrInvalidRow
	}
	return action, nil
}

func (store *PostgreSQLStore) ListAuditEvents(ctx context.Context, query AuditQuery) (AuditPage, error) {
	if ctx == nil || store == nil || store.db == nil || !validAuditQuery(query) {
		return AuditPage{}, ErrInvalidArgument
	}
	limit, _ := normalizeLimit(query.Limit)
	var cursor any
	if query.Cursor.set {
		cursor = query.Cursor.sequence
	}
	rows, err := store.db.Query(ctx, listAuditSQL,
		query.IncidentID, query.PolicyID, query.ActionID,
		query.ActorType, query.ActorID, query.ObjectType, query.ObjectID, query.TraceID,
		timeArgument(query.From), timeArgument(query.Until), cursor, limit+1,
	)
	if err != nil {
		return AuditPage{}, ErrUnavailable
	}
	defer rows.Close()
	items := make([]AuditEvent, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanAuditEvent(rows)
		if scanErr != nil {
			return AuditPage{}, scanErr
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return AuditPage{}, ErrUnavailable
	}
	page := AuditPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor = newAuditCursor(last.Sequence).String()
	}
	return page, nil
}

func (store *PostgreSQLStore) listFalsePositives(ctx context.Context, analysisID string) ([]string, error) {
	rows, err := store.db.Query(ctx, analysisFalsePositivesSQL, analysisID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	values := make([]string, 0, 5)
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil || value == "" || !utf8.ValidString(value) ||
			utf8.RuneCountInString(value) > 240 {
			return nil, invalidRow(err)
		}
		values = append(values, value)
		if len(values) > 5 {
			return nil, ErrInvalidRow
		}
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return values, nil
}

func (store *PostgreSQLStore) latestValidation(ctx context.Context, policyID string, version int32) (ValidationSummary, error) {
	var value ValidationSummary
	err := store.db.QueryRow(ctx, latestValidationSQL, policyID, version).Scan(
		&value.ValidationSnapshotID, &value.SnapshotDigest, &value.State,
		&value.FailureCode, &value.SourceHealthStatus, &value.BaseChainRawDigest,
		&value.LiveOwnedSchemaDigest, &value.ProtectedStaticDigest,
		&value.ProtectedEffectiveDigest, &value.HistoricalImpactDigest,
		&value.HistoryDatasetDigest, &value.HistoryManifestDigest,
		&value.CreatedAt, &value.ValidUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ValidationSummary{}, ErrNotFound
	}
	if err != nil {
		return ValidationSummary{}, ErrUnavailable
	}
	value.CreatedAt, value.ValidUntil = value.CreatedAt.UTC(), value.ValidUntil.UTC()
	rows, err := store.db.Query(ctx, validationGatesSQL, value.ValidationSnapshotID)
	if err != nil {
		return ValidationSummary{}, ErrUnavailable
	}
	defer rows.Close()
	value.Gates = []ValidationGate{}
	for rows.Next() {
		var gate ValidationGate
		if err = rows.Scan(&gate.Order, &gate.Name, &gate.Passed, &gate.ResultCode,
			&gate.InputDigest, &gate.ResultDigest, &gate.CheckedAt); err != nil {
			return ValidationSummary{}, ErrUnavailable
		}
		gate.CheckedAt = gate.CheckedAt.UTC()
		value.Gates = append(value.Gates, gate)
	}
	if rows.Err() != nil {
		return ValidationSummary{}, ErrUnavailable
	}
	if !validValidation(value) {
		return ValidationSummary{}, ErrInvalidRow
	}
	return value, nil
}

func scanIncident(row rowScanner) (IncidentSummary, error) {
	var value IncidentSummary
	err := row.Scan(
		&value.IncidentID, &value.Kind, &value.State, &value.SourceIP,
		&value.ServiceLabel, &value.FirstSeen, &value.LastSeen, &value.ClosedAt,
		&value.DeterministicScore, &value.Version, &value.AnalysisFailureCode,
		&value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IncidentSummary{}, ErrNotFound
	}
	if err != nil {
		return IncidentSummary{}, ErrUnavailable
	}
	normalizeIncidentTimes(&value)
	if !validIncident(value) {
		return IncidentSummary{}, ErrInvalidRow
	}
	return value, nil
}

func scanIncidentDetailBase(row rowScanner) (IncidentSummary, *int32, error) {
	var value IncidentSummary
	var evidenceVersion *int32
	err := row.Scan(
		&value.IncidentID, &value.Kind, &value.State, &value.SourceIP,
		&value.ServiceLabel, &value.FirstSeen, &value.LastSeen, &value.ClosedAt,
		&value.DeterministicScore, &value.Version, &value.AnalysisFailureCode,
		&value.CreatedAt, &value.UpdatedAt, &evidenceVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IncidentSummary{}, nil, ErrNotFound
	}
	if err != nil {
		return IncidentSummary{}, nil, ErrUnavailable
	}
	normalizeIncidentTimes(&value)
	if !validIncident(value) || (evidenceVersion != nil && (*evidenceVersion < 1 || *evidenceVersion > value.Version)) {
		return IncidentSummary{}, nil, ErrInvalidRow
	}
	return value, evidenceVersion, nil
}

func scanAnalysis(row rowScanner) (AnalysisSummary, error) {
	var value AnalysisSummary
	err := row.Scan(
		&value.AnalysisID, &value.IncidentVersion, &value.ProviderKind, &value.AdapterID,
		&value.Model, &value.ReasoningEffort, &value.RateCardVersion, &value.ResultState,
		&value.FailureCode, &value.OutputDigest, &value.Summary, &value.Classification,
		&value.Confidence, &value.Uncertainty, &value.StartedAt, &value.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AnalysisSummary{}, ErrNotFound
	}
	if err != nil {
		return AnalysisSummary{}, ErrUnavailable
	}
	value.StartedAt = value.StartedAt.UTC()
	value.CompletedAt = utcPointer(value.CompletedAt)
	value.FalsePositives = []string{}
	if !validAnalysis(value) {
		return AnalysisSummary{}, ErrInvalidRow
	}
	return value, nil
}

func scanIncidentEvent(row rowScanner) (IncidentEvent, error) {
	var value IncidentEvent
	err := row.Scan(
		&value.IncidentEventID, &value.EventID, &value.IncidentVersion, &value.Kind,
		&value.OccurredAt, &value.TraceID, &value.SourceIP, &value.ServiceLabel,
		&value.RouteLabel, &value.Method, &value.StatusCode, &value.SuspiciousPathID,
		&value.AuthOutcome, &value.BindingState, &value.HealthState, &value.HealthCause,
		&value.DroppedCount, &value.TrustState, &value.TrustReason, &value.RelationReason,
	)
	if err != nil {
		return IncidentEvent{}, ErrUnavailable
	}
	value.OccurredAt = value.OccurredAt.UTC()
	if !validIncidentEvent(value) {
		return IncidentEvent{}, ErrInvalidRow
	}
	return value, nil
}

func scanDecision(row rowScanner) (DecisionSummary, error) {
	var value DecisionSummary
	err := row.Scan(&value.DecisionID, &value.Decision, &value.ActorID, &value.ReasonDigest, &value.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DecisionSummary{}, ErrNotFound
	}
	if err != nil {
		return DecisionSummary{}, ErrUnavailable
	}
	value.DecidedAt = value.DecidedAt.UTC()
	if !validDecision(value) {
		return DecisionSummary{}, ErrInvalidRow
	}
	return value, nil
}

func scanAuditEvent(row rowScanner) (AuditEvent, error) {
	var value AuditEvent
	err := row.Scan(
		&value.Sequence, &value.EventID, &value.ActorType, &value.ActorID,
		&value.Action, &value.ObjectType, &value.ObjectID, &value.IncidentID,
		&value.PolicyID, &value.PolicyVersion, &value.EnforcementActionID,
		&value.TraceID, &value.PrimaryDigest, &value.SecondaryDigest,
		&value.Outcome, &value.OccurredAt, &value.RecordedAt,
	)
	if err != nil {
		return AuditEvent{}, ErrUnavailable
	}
	value.OccurredAt, value.RecordedAt = value.OccurredAt.UTC(), value.RecordedAt.UTC()
	if !validAuditEvent(value) {
		return AuditEvent{}, ErrInvalidRow
	}
	return value, nil
}

func normalizeIncidentTimes(value *IncidentSummary) {
	value.FirstSeen, value.LastSeen = value.FirstSeen.UTC(), value.LastSeen.UTC()
	value.ClosedAt = utcPointer(value.ClosedAt)
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
}

func normalizeSignalTimes(value *SignalSummary) {
	value.WindowStart, value.WindowEnd = value.WindowStart.UTC(), value.WindowEnd.UTC()
}

func normalizeActionTimes(value *EnforcementActionDetail) {
	value.ApprovedAt = value.ApprovedAt.UTC()
	value.QueuedAt, value.AppliedAt = utcPointer(value.QueuedAt), utcPointer(value.AppliedAt)
	value.ExpectedExpiresAt, value.FinishedAt = utcPointer(value.ExpectedExpiresAt), utcPointer(value.FinishedAt)
	value.CreatedAt, value.UpdatedAt = value.CreatedAt.UTC(), value.UpdatedAt.UTC()
}

func utcPointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func timeArgument(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func invalidRow(err error) error {
	if err != nil {
		return ErrUnavailable
	}
	return ErrInvalidRow
}
