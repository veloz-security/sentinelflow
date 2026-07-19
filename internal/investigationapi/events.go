package investigationapi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MaxStreamCursorBytes = 256
	MaxStreamPageSize    = 64
)

var (
	ErrInvalidCursor     = errors.New("investigation event source: invalid cursor")
	ErrReplayGap         = errors.New("investigation event source: replay gap")
	ErrSourceUnavailable = errors.New("investigation event source: unavailable")
)

var sequenceCursorPattern = regexp.MustCompile(`^s1\.[0-9a-f]{16}$`)

type StreamCursor string

// FormatSequenceCursor is the single canonical wire encoding for v0.1 SSE
// event IDs. Zero is the empty-ledger floor; PostgreSQL bigint keeps the
// remaining order within signed 64-bit sequence space.
func FormatSequenceCursor(sequence int64) (StreamCursor, error) {
	if sequence < 0 {
		return "", ErrInvalidCursor
	}
	return StreamCursor(fmt.Sprintf("s1.%016x", uint64(sequence))), nil
}

func ParseSequenceCursor(raw string) (StreamCursor, int64, error) {
	if !sequenceCursorPattern.MatchString(raw) {
		return "", 0, ErrInvalidCursor
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(raw, "s1."), 16, 63)
	if err != nil {
		return "", 0, ErrInvalidCursor
	}
	return StreamCursor(raw), int64(parsed), nil
}

func CompareSequenceCursor(left, right StreamCursor) (int, error) {
	_, leftValue, err := ParseSequenceCursor(string(left))
	if err != nil {
		return 0, err
	}
	_, rightValue, err := ParseSequenceCursor(string(right))
	if err != nil {
		return 0, err
	}
	switch {
	case leftValue < rightValue:
		return -1, nil
	case leftValue > rightValue:
		return 1, nil
	default:
		return 0, nil
	}
}

type EventType string

const (
	EventIncidentCreated         EventType = "incident.created"
	EventIncidentUpdated         EventType = "incident.updated"
	EventAnalysisCompleted       EventType = "analysis.completed"
	EventAnalysisFailed          EventType = "analysis.failed"
	EventPolicyValidationUpdated EventType = "policy.validation_updated"
	EventApprovalRecorded        EventType = "approval.recorded"
	EventEnforcementUpdated      EventType = "enforcement.updated"
	EventSourceDegraded          EventType = "source.degraded"
	EventSourceRecovered         EventType = "source.recovered"
)

type EventSummary struct {
	Code    string `json:"code"`
	Outcome string `json:"outcome"`
}

// StreamEvent is the complete SSE data allowlist. It cannot carry command
// bytes, evidence bodies, signatures, credentials, approval authority, or an
// arbitrary map supplied by a producer.
type StreamEvent struct {
	ID              StreamCursor `json:"-"`
	Type            EventType    `json:"-"`
	ResourceID      string       `json:"resource_id"`
	ResourceVersion int64        `json:"resource_version"`
	IncidentID      *string      `json:"incident_id,omitempty"`
	PolicyID        *string      `json:"policy_id,omitempty"`
	ActionID        *string      `json:"action_id,omitempty"`
	OccurredAt      time.Time    `json:"occurred_at"`
	TraceID         *string      `json:"trace_id,omitempty"`
	Summary         EventSummary `json:"summary"`
}

// ReplayWindow describes the currently retained, authorized event interval.
// Floor and Watermark are opaque cursors in the same total order.
type ReplayWindow struct {
	Floor     StreamCursor
	Watermark StreamCursor
}

type EventPage struct {
	Events       []StreamEvent
	Next         StreamCursor
	ReplayWindow ReplayWindow
	Gap          bool
}

// EventSource is intentionally an adapter boundary rather than an inference
// over mutable domain tables. Implementations MUST:
//   - parse opaque IDs strictly and compare them in one monotonic total order;
//   - authorize/filter every Tail and Poll using the supplied principal;
//   - expose a bounded retained floor and current watermark;
//   - return Gap without events when after predates that principal's floor;
//   - return at most limit events, strictly after after and in ascending order;
//   - bind each event to an immutable resource version; and
//   - treat context cancellation as a hard stop.
//
// Next is either after or the last returned event ID. It must not silently skip
// authorized visible events. SSE is read-only notification; this interface has
// no mutation or approval operation.
type EventSource interface {
	ParseCursor(string) (StreamCursor, error)
	CompareCursor(StreamCursor, StreamCursor) (int, error)
	Tail(context.Context, Principal) (ReplayWindow, error)
	Poll(context.Context, Principal, StreamCursor, int) (EventPage, error)
}

// ClientLeaseStore tracks only live stream capacity. LeaseID is a fresh random
// UUID per connection and processInstance is a bounded random API-process UUID;
// neither value identifies an administrator, session, address, or resource.
// Implementations must use their own trusted clock and expire abandoned leases.
type ClientLeaseStore interface {
	RegisterLease(context.Context, string, string) error
	TouchLease(context.Context, string, string) error
	UnregisterLease(context.Context, string, string) error
}

func allowedEventType(value EventType) bool {
	switch value {
	case EventIncidentCreated, EventIncidentUpdated, EventAnalysisCompleted,
		EventAnalysisFailed, EventPolicyValidationUpdated, EventApprovalRecorded,
		EventEnforcementUpdated, EventSourceDegraded, EventSourceRecovered:
		return true
	default:
		return false
	}
}
