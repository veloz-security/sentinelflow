// Package evidenceartifactstore is the frozen persistence seam between the
// correlation producer and validation/HIL.  It never derives validation
// evidence from correlation-evidence-v1 bytes.
package evidenceartifactstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

const MaxCoordinatorPayloadBytes = 128 * 1024 * 1024

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	ErrInvalidRequest = errors.New("evidence artifact store: invalid request")
	ErrPersistence    = errors.New("evidence artifact store: persistence unavailable")
	ErrInvalidRow     = errors.New("evidence artifact store: invalid persistence result")
)

type EventKind string

const (
	EventGateway      EventKind = "gateway"
	EventAuth         EventKind = "auth"
	EventSourceHealth EventKind = "source_health"
)

type SignalRow struct {
	SignalID           string
	EvidenceDigest     string
	ExpandedEventCount int
}

type EventRow struct {
	EventRowID string
	SignalID   string
	Kind       EventKind
	EventID    string
	EventTime  time.Time
}

// InsertRequest contains both independently checked canonical evidence and
// the normalized rows from which detectors and analysis read.  Insert is
// atomic and exact replay is idempotent; a legacy normalized row cannot be
// upgraded by this API.
type InsertRequest struct {
	Evidence           validation.CheckedEvidenceSnapshot
	SourceHealthStatus string
	ExpiresAt          time.Time
	Signals            []SignalRow
	Events             []EventRow
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgreSQLStore struct{ db queryRower }

func NewPostgreSQLStore(db queryRower) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgreSQLStore{db: db}, nil
}

const insertSQL = `
SELECT evidence_snapshot_id::text, snapshot_digest::text, inserted
FROM sentinelflow.insert_exact_evidence_snapshot($1::json, $2::bytea)`

func (s *PostgreSQLStore) Insert(ctx context.Context, request InsertRequest) (bool, error) {
	if ctx == nil {
		return false, ErrInvalidRequest
	}
	payload, canonical, digest, snapshotID, err := encodeRequest(request)
	if err != nil {
		return false, ErrInvalidRequest
	}
	var returnedID, returnedDigest string
	var inserted bool
	if err := s.db.QueryRow(ctx, insertSQL, payload, canonical).
		Scan(&returnedID, &returnedDigest, &inserted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrInvalidRow
		}
		return false, ErrPersistence
	}
	if returnedID != snapshotID || returnedDigest != digest {
		return false, ErrInvalidRow
	}
	return inserted, nil
}

type snapshotWire struct {
	SnapshotID         string       `json:"snapshot_id"`
	SchemaVersion      string       `json:"schema_version"`
	IncidentID         string       `json:"incident_id"`
	IncidentVersion    uint32       `json:"incident_version"`
	SourceIPv4         string       `json:"source_ipv4"`
	ServiceLabel       string       `json:"service_label"`
	WindowStart        string       `json:"window_start"`
	WindowEnd          string       `json:"window_end"`
	SourceHealthStatus string       `json:"source_health_status"`
	SignalCount        int          `json:"signal_count"`
	ExpandedEventCount int          `json:"expanded_event_count"`
	SnapshotDigest     string       `json:"snapshot_digest"`
	CreatedAt          string       `json:"created_at"`
	ExpiresAt          string       `json:"expires_at"`
	Signals            []signalWire `json:"signals"`
	Events             []eventWire  `json:"events"`
}

type signalWire struct {
	Ordinal            int    `json:"ordinal"`
	SignalID           string `json:"signal_id"`
	EvidenceDigest     string `json:"evidence_digest"`
	ExpandedEventCount int    `json:"expanded_event_count"`
}

type eventWire struct {
	EventRowID string `json:"event_row_id"`
	SignalID   string `json:"signal_id"`
	EventKind  string `json:"event_kind"`
	EventID    string `json:"event_id"`
	EventTime  string `json:"event_time"`
}

func encodeRequest(request InsertRequest) ([]byte, []byte, string, string, error) {
	canonical := request.Evidence.CanonicalBytes()
	checked, err := validation.ParseCanonicalEvidenceSnapshot(canonical)
	if err != nil || checked.Digest() == "" || checked.Digest() != request.Evidence.Digest() ||
		!bytes.Equal(checked.CanonicalBytes(), canonical) {
		return nil, nil, "", "", ErrInvalidRequest
	}
	value := checked.Value()
	if (request.SourceHealthStatus != validation.SourceHealthComplete &&
		request.SourceHealthStatus != "incomplete") || request.ExpiresAt.IsZero() ||
		!request.ExpiresAt.Round(0).UTC().After(value.CreatedAt) ||
		len(request.Signals) != len(value.SignalIDs) || len(request.Events) == 0 ||
		len(request.Events) > validation.MaxEvidenceEventIDs {
		return nil, nil, "", "", ErrInvalidRequest
	}
	if address, parseErr := netip.ParseAddr(value.SourceIPv4); parseErr != nil ||
		!address.Is4() || address.String() != value.SourceIPv4 {
		return nil, nil, "", "", ErrInvalidRequest
	}

	counts := make(map[string]int, len(request.Signals))
	signalSet := make(map[string]struct{}, len(request.Signals))
	signals := make([]signalWire, len(request.Signals))
	for index, signal := range request.Signals {
		if signal.SignalID != value.SignalIDs[index] || !uuidPattern.MatchString(signal.SignalID) ||
			!digestPattern.MatchString(signal.EvidenceDigest) || signal.ExpandedEventCount < 1 {
			return nil, nil, "", "", ErrInvalidRequest
		}
		signalSet[signal.SignalID] = struct{}{}
		signals[index] = signalWire{index + 1, signal.SignalID, signal.EvidenceDigest, signal.ExpandedEventCount}
	}

	events := make([]eventWire, len(request.Events))
	rowIDs := make(map[string]struct{}, len(request.Events))
	eventIDs := make(map[string]struct{}, len(value.EventIDs))
	for index, event := range request.Events {
		if !uuidPattern.MatchString(event.EventRowID) || !uuidPattern.MatchString(event.EventID) ||
			!uuidPattern.MatchString(event.SignalID) || event.EventTime.IsZero() ||
			event.EventTime.Before(value.WindowStart) || event.EventTime.After(value.WindowEnd) ||
			(event.Kind != EventGateway && event.Kind != EventAuth && event.Kind != EventSourceHealth) {
			return nil, nil, "", "", ErrInvalidRequest
		}
		if _, exists := rowIDs[event.EventRowID]; exists {
			return nil, nil, "", "", ErrInvalidRequest
		}
		if _, exists := signalSet[event.SignalID]; !exists {
			return nil, nil, "", "", ErrInvalidRequest
		}
		rowIDs[event.EventRowID] = struct{}{}
		eventIDs[event.EventID] = struct{}{}
		counts[event.SignalID]++
		events[index] = eventWire{
			event.EventRowID, event.SignalID, string(event.Kind), event.EventID,
			event.EventTime.Round(0).UTC().Format(time.RFC3339Nano),
		}
	}
	for _, signal := range request.Signals {
		if counts[signal.SignalID] != signal.ExpandedEventCount {
			return nil, nil, "", "", ErrInvalidRequest
		}
	}
	union := make([]string, 0, len(eventIDs))
	for eventID := range eventIDs {
		union = append(union, eventID)
	}
	sort.Strings(union)
	if !equalStrings(union, value.EventIDs) {
		return nil, nil, "", "", ErrInvalidRequest
	}

	wire := snapshotWire{
		SnapshotID: value.SnapshotID, SchemaVersion: value.SchemaVersion,
		IncidentID: value.IncidentID, IncidentVersion: value.IncidentVersion,
		SourceIPv4: value.SourceIPv4, ServiceLabel: value.ServiceLabel,
		WindowStart:        value.WindowStart.Format(time.RFC3339Nano),
		WindowEnd:          value.WindowEnd.Format(time.RFC3339Nano),
		SourceHealthStatus: request.SourceHealthStatus,
		SignalCount:        len(signals), ExpandedEventCount: len(events),
		SnapshotDigest: checked.Digest(), CreatedAt: value.CreatedAt.Format(time.RFC3339Nano),
		ExpiresAt: request.ExpiresAt.Round(0).UTC().Format(time.RFC3339Nano),
		Signals:   signals, Events: events,
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) < 2 || len(payload) > MaxCoordinatorPayloadBytes {
		return nil, nil, "", "", ErrInvalidRequest
	}
	return payload, canonical, checked.Digest(), value.SnapshotID, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
