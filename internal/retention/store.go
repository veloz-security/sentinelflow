package retention

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrPersistence    = errors.New("retention persistence failed")
	ErrInvariant      = errors.New("retention result rejected")
	ErrStaleLiveState = errors.New("retention blocked by stale live state")
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Result contains only aggregate deletion counts and the digest-bound run
// identity. It contains no retained event, evidence, administrator, policy,
// command, network, or credential material.
type Result struct {
	RunID                string    `json:"run_id"`
	Replayed             bool      `json:"replayed"`
	Outcome              string    `json:"outcome"`
	FailureCode          string    `json:"failure_code,omitempty"`
	AnomalyCount         int64     `json:"anomaly_count"`
	EventEvidenceDeleted int64     `json:"event_evidence_deleted"`
	ControlPlaneDeleted  int64     `json:"control_plane_deleted"`
	TransientDeleted     int64     `json:"transient_deleted"`
	AuditDeleted         int64     `json:"audit_deleted"`
	RunDigest            string    `json:"run_digest"`
	CompletedAt          time.Time `json:"completed_at"`
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Store is a narrow adapter over the single SECURITY DEFINER function exposed
// to sentinelflow_retention. It issues no direct table statement.
type Store struct{ database queryRower }

func NewStore(database queryRower) (*Store, error) {
	if database == nil {
		return nil, ErrInvariant
	}
	return &Store{database: database}, nil
}

// CurrentTime returns the database clock used to derive every retention
// boundary. Host/container clock skew must never delete data early.
func (s *Store) CurrentTime(ctx context.Context) (time.Time, error) {
	if s == nil || s.database == nil || ctx == nil {
		return time.Time{}, ErrInvariant
	}
	var current time.Time
	if err := s.database.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&current); err != nil {
		return time.Time{}, ErrPersistence
	}
	if current.IsZero() {
		return time.Time{}, ErrInvariant
	}
	return current.UTC(), nil
}

func (s *Store) Run(ctx context.Context, runID string, asOf time.Time, maxRows int) (Result, error) {
	if s == nil || s.database == nil || ctx == nil || !uuidPattern.MatchString(runID) ||
		asOf.IsZero() || maxRows < 1 || maxRows > 10000 {
		return Result{}, ErrInvariant
	}
	var result Result
	err := s.database.QueryRow(ctx, `
SELECT run_id::text, replayed, event_evidence_deleted,
       outcome, failure_code, anomaly_count, control_plane_deleted,
       transient_deleted, audit_deleted, run_digest::text, completed_at
FROM sentinelflow.run_retention_000023($1::uuid, $2::timestamptz, $3::integer)`,
		runID, asOf.UTC(), maxRows,
	).Scan(
		&result.RunID, &result.Replayed, &result.EventEvidenceDeleted,
		&result.Outcome, &result.FailureCode, &result.AnomalyCount,
		&result.ControlPlaneDeleted, &result.TransientDeleted,
		&result.AuditDeleted, &result.RunDigest, &result.CompletedAt,
	)
	if err != nil {
		return Result{}, ErrPersistence
	}
	if result.RunID != runID || !digestPattern.MatchString(result.RunDigest) ||
		result.CompletedAt.IsZero() || result.EventEvidenceDeleted < 0 ||
		result.ControlPlaneDeleted < 0 || result.TransientDeleted < 0 ||
		result.AuditDeleted < 0 {
		return Result{}, ErrInvariant
	}
	limit := int64(maxRows)
	if result.EventEvidenceDeleted > limit || result.ControlPlaneDeleted > limit ||
		result.TransientDeleted > limit || result.AuditDeleted > limit ||
		result.EventEvidenceDeleted+result.ControlPlaneDeleted+
			result.TransientDeleted+result.AuditDeleted > limit {
		return Result{}, ErrInvariant
	}
	switch result.Outcome {
	case "succeeded":
		if result.FailureCode != "" || result.AnomalyCount != 0 {
			return Result{}, ErrInvariant
		}
	case "failed":
		if result.FailureCode != "stale_live_state" || result.AnomalyCount < 1 ||
			result.AnomalyCount > limit || result.EventEvidenceDeleted != 0 ||
			result.ControlPlaneDeleted != 0 || result.TransientDeleted != 0 ||
			result.AuditDeleted != 0 {
			return Result{}, ErrInvariant
		}
		result.CompletedAt = result.CompletedAt.UTC()
		return result, ErrStaleLiveState
	default:
		return Result{}, ErrInvariant
	}
	result.CompletedAt = result.CompletedAt.UTC()
	return result, nil
}
