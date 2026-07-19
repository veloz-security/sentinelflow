// Package hilartifactstore loads the sole durable exact-artifact projection
// and reconstructs the checked HIL handoff from canonical bytes.
package hilartifactstore

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	ErrInvalidRequest = errors.New("HIL artifact store: invalid request")
	ErrNotFound       = errors.New("HIL artifact store: artifact unavailable")
	ErrCorrupt        = errors.New("HIL artifact store: artifact rejected")
	ErrStale          = errors.New("HIL artifact store: validation stale")
	ErrPersistence    = errors.New("HIL artifact store: persistence unavailable")
)

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

const loadSQL = `
SELECT policy_id::text, policy_version, command_candidate_id::text,
    validation_snapshot_id::text, evidence_snapshot_id::text, target_ipv4,
    ttl_seconds, policy_bytes, policy_digest, evidence_bytes, evidence_digest,
    validation_bytes, validation_digest, generated_bytes, generated_digest,
    canonical_bytes, canonical_digest, validation_created_at,
    validation_valid_until
FROM sentinelflow.read_hil_exact_artifact($1::uuid, $2)`

type rowValue struct {
	PolicyID             string
	PolicyVersion        int64
	CommandCandidateID   string
	ValidationSnapshotID string
	EvidenceSnapshotID   string
	TargetIPv4           string
	TTLSeconds           int64
	PolicyBytes          []byte
	PolicyDigest         string
	EvidenceBytes        []byte
	EvidenceDigest       string
	ValidationBytes      []byte
	ValidationDigest     string
	GeneratedBytes       []byte
	GeneratedDigest      string
	CanonicalBytes       []byte
	CanonicalDigest      string
	ValidationCreatedAt  time.Time
	ValidationValidUntil time.Time
}

// Load parses and re-canonicalizes every persisted artifact, validates every
// digest and normalized relation through hil.CheckExactArtifact, and rejects a
// future-created or expired validation snapshot.
func (s *PostgreSQLStore) Load(
	ctx context.Context,
	policyID string,
	policyVersion uint32,
	now time.Time,
) (hil.ExactArtifact, error) {
	if ctx == nil || !uuidPattern.MatchString(policyID) || policyVersion == 0 ||
		policyVersion > 2_147_483_647 || !validTime(now) {
		return hil.ExactArtifact{}, ErrInvalidRequest
	}
	exact, err := s.loadChecked(ctx, policyID, policyVersion)
	if err != nil {
		return hil.ExactArtifact{}, err
	}
	if !exact.FreshAt(now.Round(0).UTC()) {
		return hil.ExactArtifact{}, ErrStale
	}
	return exact, nil
}

// LoadHistorical reconstructs the immutable exact artifact without granting
// it current-validation status. It is intended only for digest-complete,
// read-only lookup of an already committed HIL decision after response loss.
// Mutation and challenge issuance must continue to use Load.
func (s *PostgreSQLStore) LoadHistorical(
	ctx context.Context,
	policyID string,
	policyVersion uint32,
) (hil.ExactArtifact, error) {
	if ctx == nil || !uuidPattern.MatchString(policyID) || policyVersion == 0 ||
		policyVersion > 2_147_483_647 {
		return hil.ExactArtifact{}, ErrInvalidRequest
	}
	return s.loadChecked(ctx, policyID, policyVersion)
}

func (s *PostgreSQLStore) loadChecked(ctx context.Context, policyID string, policyVersion uint32) (hil.ExactArtifact, error) {
	if s == nil || s.db == nil {
		return hil.ExactArtifact{}, ErrPersistence
	}
	var row rowValue
	err := s.db.QueryRow(ctx, loadSQL, policyID, policyVersion).Scan(
		&row.PolicyID, &row.PolicyVersion, &row.CommandCandidateID,
		&row.ValidationSnapshotID, &row.EvidenceSnapshotID, &row.TargetIPv4,
		&row.TTLSeconds, &row.PolicyBytes, &row.PolicyDigest,
		&row.EvidenceBytes, &row.EvidenceDigest, &row.ValidationBytes,
		&row.ValidationDigest, &row.GeneratedBytes, &row.GeneratedDigest,
		&row.CanonicalBytes, &row.CanonicalDigest, &row.ValidationCreatedAt,
		&row.ValidationValidUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return hil.ExactArtifact{}, ErrNotFound
	}
	if err != nil {
		return hil.ExactArtifact{}, ErrPersistence
	}
	exact, err := checkRow(row, policyID, policyVersion)
	if err != nil {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	return exact, nil
}

func checkRow(row rowValue, policyID string, policyVersion uint32) (hil.ExactArtifact, error) {
	if row.PolicyID != policyID || row.PolicyVersion != int64(policyVersion) ||
		!uuidPattern.MatchString(row.CommandCandidateID) ||
		!uuidPattern.MatchString(row.ValidationSnapshotID) ||
		!uuidPattern.MatchString(row.EvidenceSnapshotID) ||
		row.TTLSeconds < int64(policy.MinTTLSeconds) || row.TTLSeconds > int64(policy.MaxTTLSeconds) ||
		len(row.PolicyBytes) < 2 || len(row.PolicyBytes) > 8192 ||
		len(row.EvidenceBytes) < 2 || len(row.EvidenceBytes) > validation.MaxEvidenceSnapshotBytes ||
		len(row.ValidationBytes) < 2 || len(row.ValidationBytes) > validation.MaxValidationSnapshotBytes ||
		len(row.GeneratedBytes) < 1 || len(row.GeneratedBytes) > policy.MaxGeneratedBytes ||
		len(row.CanonicalBytes) < 1 || len(row.CanonicalBytes) > policy.MaxGeneratedBytes ||
		!validTime(row.ValidationCreatedAt) || !validTime(row.ValidationValidUntil) ||
		!row.ValidationValidUntil.Equal(row.ValidationCreatedAt.Add(validation.ValidationSnapshotLifetime)) {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	checkedPolicy, err := policy.ParseCanonicalResponsePolicy(row.PolicyBytes)
	if err != nil || checkedPolicy.Digest() != row.PolicyDigest {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	checkedEvidence, err := validation.ParseCanonicalEvidenceSnapshot(row.EvidenceBytes)
	if err != nil || checkedEvidence.Digest() != row.EvidenceDigest ||
		checkedEvidence.Value().SnapshotID != row.EvidenceSnapshotID {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	checkedValidation, err := validation.ParseCanonicalValidationSnapshot(row.ValidationBytes)
	if err != nil || checkedValidation.Digest() != row.ValidationDigest ||
		checkedValidation.Value().ValidationID != row.ValidationSnapshotID ||
		!checkedValidation.Value().CreatedAt.Equal(row.ValidationCreatedAt) ||
		!checkedValidation.Value().ValidUntil.Equal(row.ValidationValidUntil) {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	command, err := nftvalidate.Canonicalize(row.GeneratedBytes, uint32(row.TTLSeconds))
	if err != nil || command.GeneratedDigest() != row.GeneratedDigest ||
		command.CanonicalDigest() != row.CanonicalDigest ||
		!bytes.Equal(command.CanonicalBytes(), row.CanonicalBytes) {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: checkedEvidence,
		Validation: checkedValidation,
	})
	if err != nil || exact.PolicyID() != row.PolicyID ||
		exact.PolicyVersion() != uint32(row.PolicyVersion) ||
		exact.TargetIPv4() != row.TargetIPv4 || exact.TTLSeconds() != uint32(row.TTLSeconds) ||
		exact.PolicyDigest() != row.PolicyDigest ||
		exact.EvidenceSnapshotDigest() != row.EvidenceDigest ||
		exact.ValidationSnapshotDigest() != row.ValidationDigest ||
		exact.GeneratedArtifactDigest() != row.GeneratedDigest ||
		exact.CanonicalArtifactDigest() != row.CanonicalDigest {
		return hil.ExactArtifact{}, ErrCorrupt
	}
	return exact, nil
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Equal(value.Round(0).UTC())
}
