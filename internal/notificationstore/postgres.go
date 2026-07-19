// Package notificationstore implements the durable PostgreSQL event source
// used by the authenticated investigation SSE endpoint.
package notificationstore

import (
	"context"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/investigationapi"
	"github.com/jackc/pgx/v5"
)

var (
	actorPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	processPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PostgreSQLStore exposes only bounded SECURITY DEFINER functions. The role
// behind db must be sentinelflow_api; it has no direct notification-ledger or
// client-lease table access.
type PostgreSQLStore struct {
	db queryer
}

var _ investigationapi.EventSource = (*PostgreSQLStore)(nil)
var _ investigationapi.ClientLeaseStore = (*PostgreSQLStore)(nil)

func NewPostgreSQLStore(db queryer) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, investigationapi.ErrSourceUnavailable
	}
	return &PostgreSQLStore{db: db}, nil
}

func (*PostgreSQLStore) ParseCursor(raw string) (investigationapi.StreamCursor, error) {
	cursor, _, err := investigationapi.ParseSequenceCursor(raw)
	return cursor, err
}

func (*PostgreSQLStore) CompareCursor(left, right investigationapi.StreamCursor) (int, error) {
	return investigationapi.CompareSequenceCursor(left, right)
}

func (store *PostgreSQLStore) RegisterLease(ctx context.Context, leaseID, processInstance string) error {
	return store.writeLease(ctx, registerLeaseSQL, leaseID, processInstance)
}

func (store *PostgreSQLStore) TouchLease(ctx context.Context, leaseID, processInstance string) error {
	return store.writeLease(ctx, touchLeaseSQL, leaseID, processInstance)
}

func (store *PostgreSQLStore) UnregisterLease(ctx context.Context, leaseID, processInstance string) error {
	if !store.validLeaseRequest(ctx, leaseID, processInstance) {
		return investigationapi.ErrSourceUnavailable
	}
	var removed bool
	if err := store.db.QueryRow(ctx, unregisterLeaseSQL, leaseID, processInstance).Scan(&removed); err != nil {
		return sourceError(ctx)
	}
	return nil
}

func (store *PostgreSQLStore) writeLease(ctx context.Context, query, leaseID, processInstance string) error {
	if !store.validLeaseRequest(ctx, leaseID, processInstance) {
		return investigationapi.ErrSourceUnavailable
	}
	var expiry time.Time
	if err := store.db.QueryRow(ctx, query, leaseID, processInstance).Scan(&expiry); err != nil {
		return sourceError(ctx)
	}
	if expiry.IsZero() || expiry.Year() < 2000 || expiry.Year() > 9999 {
		return investigationapi.ErrSourceUnavailable
	}
	return nil
}

func (store *PostgreSQLStore) validLeaseRequest(ctx context.Context, leaseID, processInstance string) bool {
	return ctx != nil && store != nil && store.db != nil && ctx.Err() == nil &&
		uuidPattern.MatchString(leaseID) && leaseID != "00000000-0000-0000-0000-000000000000" &&
		processPattern.MatchString(processInstance)
}

func (store *PostgreSQLStore) Tail(
	ctx context.Context,
	principal investigationapi.Principal,
) (investigationapi.ReplayWindow, error) {
	if ctx == nil || store == nil || store.db == nil || !validPrincipal(principal) {
		return investigationapi.ReplayWindow{}, investigationapi.ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return investigationapi.ReplayWindow{}, err
	}
	var floor, watermark int64
	if err := store.db.QueryRow(ctx, readWindowSQL).Scan(&floor, &watermark); err != nil {
		return investigationapi.ReplayWindow{}, sourceError(ctx)
	}
	return replayWindow(floor, watermark)
}

func (store *PostgreSQLStore) Poll(
	ctx context.Context,
	principal investigationapi.Principal,
	after investigationapi.StreamCursor,
	limit int,
) (investigationapi.EventPage, error) {
	if ctx == nil || store == nil || store.db == nil || !validPrincipal(principal) ||
		limit < 1 || limit > investigationapi.MaxStreamPageSize {
		return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return investigationapi.EventPage{}, err
	}
	canonical, afterValue, err := investigationapi.ParseSequenceCursor(string(after))
	if err != nil || canonical != after {
		return investigationapi.EventPage{}, investigationapi.ErrInvalidCursor
	}
	rows, err := store.db.Query(ctx, readPageSQL, afterValue, limit)
	if err != nil {
		return investigationapi.EventPage{}, sourceError(ctx)
	}
	defer rows.Close()

	page := investigationapi.EventPage{Next: after, Events: []investigationapi.StreamEvent{}}
	var initialized bool
	var previous int64 = afterValue
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return investigationapi.EventPage{}, err
		}
		row, scanErr := scanPageRow(rows)
		if scanErr != nil {
			return investigationapi.EventPage{}, sourceError(ctx)
		}
		if !initialized {
			page.ReplayWindow, err = replayWindow(row.floor, row.watermark)
			if err != nil || row.gap && row.future {
				return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
			}
			page.Gap = row.gap
			initialized = true
		} else if row.floor != rowFloor(page.ReplayWindow) || row.watermark != rowWatermark(page.ReplayWindow) ||
			row.gap != page.Gap || row.future {
			return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
		}
		if row.future {
			return investigationapi.EventPage{}, investigationapi.ErrInvalidCursor
		}
		if row.gap {
			if row.hasEvent() {
				return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
			}
			continue
		}
		if !row.hasEvent() {
			continue
		}
		event, cursorValue, mapErr := row.event()
		if mapErr != nil || cursorValue <= previous || cursorValue > row.watermark {
			return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
		}
		previous = cursorValue
		page.Events = append(page.Events, event)
		page.Next = event.ID
		if len(page.Events) > limit {
			return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
		}
	}
	if rows.Err() != nil {
		return investigationapi.EventPage{}, sourceError(ctx)
	}
	if !initialized {
		return investigationapi.EventPage{}, investigationapi.ErrSourceUnavailable
	}
	if page.Gap {
		page.Events = []investigationapi.StreamEvent{}
		page.Next = after
		return page, investigationapi.ErrReplayGap
	}
	return page, nil
}

type pageRow struct {
	floor, watermark int64
	gap, future      bool
	cursor           *int64
	eventType        *string
	resourceType     *string
	resourceID       *string
	resourceVersion  *int64
	state            *string
	summaryCode      *string
	incidentID       *string
	traceID          *string
	occurredAt       *time.Time
}

func scanPageRow(row interface{ Scan(...any) error }) (pageRow, error) {
	var value pageRow
	err := row.Scan(
		&value.floor, &value.watermark, &value.gap, &value.future,
		&value.cursor, &value.eventType, &value.resourceType, &value.resourceID,
		&value.resourceVersion, &value.state, &value.summaryCode,
		&value.incidentID, &value.traceID, &value.occurredAt,
	)
	return value, err
}

func (row pageRow) hasEvent() bool {
	return row.cursor != nil || row.eventType != nil || row.resourceType != nil ||
		row.resourceID != nil || row.resourceVersion != nil || row.state != nil ||
		row.summaryCode != nil || row.incidentID != nil || row.traceID != nil || row.occurredAt != nil
}

func (row pageRow) event() (investigationapi.StreamEvent, int64, error) {
	if row.cursor == nil || row.eventType == nil || row.resourceType == nil ||
		row.resourceID == nil || row.resourceVersion == nil || row.state == nil ||
		row.summaryCode == nil || row.occurredAt == nil || *row.resourceVersion < 1 ||
		!uuidPattern.MatchString(*row.resourceID) || !actorPattern.MatchString(*row.state) ||
		!actorPattern.MatchString(*row.summaryCode) {
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	id, err := investigationapi.FormatSequenceCursor(*row.cursor)
	if err != nil {
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	eventType := investigationapi.EventType(*row.eventType)
	if !validEventShape(eventType, *row.resourceType, *row.state, *row.summaryCode, row.incidentID, *row.resourceID) {
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	if row.traceID != nil && !uuidPattern.MatchString(*row.traceID) {
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	occurredAt := row.occurredAt.UTC()
	if occurredAt.IsZero() || occurredAt.Year() < 2000 || occurredAt.Year() > 9999 {
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	event := investigationapi.StreamEvent{
		ID: id, Type: eventType, ResourceID: *row.resourceID,
		ResourceVersion: *row.resourceVersion, OccurredAt: occurredAt,
		TraceID: row.traceID,
		Summary: investigationapi.EventSummary{Code: *row.summaryCode, Outcome: *row.state},
	}
	switch *row.resourceType {
	case "incident":
		event.IncidentID = copyString(row.resourceID)
	case "analysis":
		event.IncidentID = copyString(row.incidentID)
	case "policy":
		event.IncidentID = copyString(row.incidentID)
		event.PolicyID = copyString(row.resourceID)
	case "enforcement_action":
		event.IncidentID = copyString(row.incidentID)
		event.ActionID = copyString(row.resourceID)
	case "source_health":
	default:
		return investigationapi.StreamEvent{}, 0, investigationapi.ErrSourceUnavailable
	}
	return event, *row.cursor, nil
}

func replayWindow(floor, watermark int64) (investigationapi.ReplayWindow, error) {
	if floor < 0 || watermark < floor {
		return investigationapi.ReplayWindow{}, investigationapi.ErrSourceUnavailable
	}
	floorCursor, err := investigationapi.FormatSequenceCursor(floor)
	if err != nil {
		return investigationapi.ReplayWindow{}, investigationapi.ErrSourceUnavailable
	}
	watermarkCursor, err := investigationapi.FormatSequenceCursor(watermark)
	if err != nil {
		return investigationapi.ReplayWindow{}, investigationapi.ErrSourceUnavailable
	}
	return investigationapi.ReplayWindow{Floor: floorCursor, Watermark: watermarkCursor}, nil
}

func validPrincipal(value investigationapi.Principal) bool {
	now := time.Now()
	return actorPattern.MatchString(value.ActorID) && uuidPattern.MatchString(value.SessionID) &&
		!value.ValidatedAt.IsZero() && value.ValidatedAt.Year() >= 2000 && value.ValidatedAt.Year() <= 9999 &&
		!value.ExpiresAt.IsZero() && value.ExpiresAt.Year() >= 2000 && value.ExpiresAt.Year() <= 9999 &&
		utcOffset(value.ValidatedAt) == 0 && utcOffset(value.ExpiresAt) == 0 &&
		!value.ValidatedAt.After(now) && value.ExpiresAt.After(value.ValidatedAt) && value.ExpiresAt.After(now)
}

func utcOffset(value time.Time) int {
	_, offset := value.Zone()
	return offset
}

func validEventShape(eventType investigationapi.EventType, resourceType, state, summary string, incidentID *string, resourceID string) bool {
	if incidentID != nil && !uuidPattern.MatchString(*incidentID) {
		return false
	}
	switch eventType {
	case investigationapi.EventIncidentCreated:
		return resourceType == "incident" && incidentID != nil && *incidentID == resourceID &&
			validIncidentState(state) && summary == "incident_created"
	case investigationapi.EventIncidentUpdated:
		return resourceType == "incident" && incidentID != nil && *incidentID == resourceID &&
			validIncidentState(state) && summary == "incident_updated"
	case investigationapi.EventAnalysisCompleted:
		return resourceType == "analysis" && incidentID != nil && state == "succeeded" && summary == "analysis_completed"
	case investigationapi.EventAnalysisFailed:
		return resourceType == "analysis" && incidentID != nil && state == "failed" && summary == "analysis_failed"
	case investigationapi.EventPolicyValidationUpdated:
		return resourceType == "policy" && incidentID != nil &&
			oneOf(state, "validating", "valid", "invalid", "stale") && summary == "policy_validation_updated"
	case investigationapi.EventApprovalRecorded:
		return oneOf(resourceType, "policy", "enforcement_action") && incidentID != nil &&
			oneOf(state, "approved", "rejected", "revoked") && summary == "approval_recorded"
	case investigationapi.EventEnforcementUpdated:
		return resourceType == "enforcement_action" && incidentID != nil &&
			oneOf(state, "approved", "queued", "active", "expired", "failed", "revoked", "indeterminate") &&
			summary == "enforcement_updated"
	case investigationapi.EventSourceDegraded:
		return resourceType == "source_health" && incidentID == nil && oneOf(state, "degraded", "lost") && summary == "source_degraded"
	case investigationapi.EventSourceRecovered:
		return resourceType == "source_health" && incidentID == nil && state == "recovered" && summary == "source_recovered"
	default:
		return false
	}
}

func validIncidentState(value string) bool {
	return oneOf(value, "open", "analyzing", "review_ready", "analysis_failed", "closed")
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func rowFloor(window investigationapi.ReplayWindow) int64 {
	_, value, _ := investigationapi.ParseSequenceCursor(string(window.Floor))
	return value
}

func rowWatermark(window investigationapi.ReplayWindow) int64 {
	_, value, _ := investigationapi.ParseSequenceCursor(string(window.Watermark))
	return value
}

func sourceError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return investigationapi.ErrSourceUnavailable
}
