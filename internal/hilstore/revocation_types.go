package hilstore

import (
	"encoding/base64"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

// RevocationIssueRequest identifies one database-current active action
// version. The exact delete artifact and eligibility horizon are derived under
// lock by PostgreSQL; callers cannot supply either value.
type RevocationIssueRequest struct {
	Browser           BrowserRequest
	ActionID          string
	ActionVersion     uint32
	TargetIPv4        string
	OriginalAddDigest string
}

func (RevocationIssueRequest) String() string {
	return "hilstore.RevocationIssueRequest{session:[REDACTED]}"
}
func (r RevocationIssueRequest) GoString() string { return r.String() }

// IssuedRevocationChallenge owns the only in-process nonce copy. The checked
// challenge is permanently bound to one deterministic nft-revoke-v1 artifact.
type IssuedRevocationChallenge struct {
	challenge     hil.CheckedRevocationChallenge
	policyID      string
	policyVersion uint32
	nonceMu       sync.Mutex
	nonce         []byte
}

func (i *IssuedRevocationChallenge) PolicyID() string {
	if i == nil {
		return ""
	}
	return i.policyID
}

func (i *IssuedRevocationChallenge) PolicyVersion() uint32 {
	if i == nil {
		return 0
	}
	return i.policyVersion
}

func (i *IssuedRevocationChallenge) Challenge() hil.CheckedRevocationChallenge {
	if i == nil {
		return hil.CheckedRevocationChallenge{}
	}
	return i.challenge
}

func (i *IssuedRevocationChallenge) TakeNonce() (string, error) {
	if i == nil {
		return "", ErrNotFound
	}
	i.nonceMu.Lock()
	defer i.nonceMu.Unlock()
	if len(i.nonce) != decisionNonceBytes {
		return "", ErrNotFound
	}
	encoded := base64.RawURLEncoding.EncodeToString(i.nonce)
	clear(i.nonce)
	i.nonce = nil
	return encoded, nil
}

func (*IssuedRevocationChallenge) String() string {
	return "hilstore.IssuedRevocationChallenge{nonce:[REDACTED],artifact:[REDACTED]}"
}
func (i *IssuedRevocationChallenge) GoString() string { return i.String() }

// RevocationLookup contains no raw browser secret and no add authority. It is
// sufficient only to commit or read the exact revoke decision identified by
// its challenge and idempotency digest.
type RevocationLookup struct {
	Browser       BrowserRequest
	Challenge     hil.CheckedRevocationChallenge
	Nonce         DecisionNonce
	Reason        hil.CheckedReason
	policyID      string
	policyVersion uint32
}

func (RevocationLookup) String() string {
	return "hilstore.RevocationLookup{nonce:[REDACTED],reason:[REDACTED],artifact:[REDACTED]}"
}
func (r RevocationLookup) GoString() string { return r.String() }

// RevocationDecisionInput is the stateless HTTP-roundtrippable input to a
// revoke decision. All byte slices are untrusted and reparsed; PolicyID and
// PolicyVersion are explicit context because they are intentionally absent
// from hil-challenge-v1 and are revalidated under the DB action lock.
type RevocationDecisionInput struct {
	Browser                 BrowserRequest
	CanonicalChallenge      []byte
	CanonicalRevokeArtifact []byte
	Nonce                   DecisionNonce
	Reason                  hil.CheckedReason
	PolicyID                string
	PolicyVersion           uint32
}

func (RevocationDecisionInput) String() string {
	return "hilstore.RevocationDecisionInput{challenge:[REDACTED],artifact:[REDACTED],reason:[REDACTED]}"
}
func (i RevocationDecisionInput) GoString() string { return i.String() }

// BindRevocationLookup reparses all browser-returned bytes and deterministically
// reconstructs the revoke binding without issuance-process memory.
func BindRevocationLookup(input RevocationDecisionInput) (RevocationLookup, error) {
	challenge, err := hil.ParseCanonicalChallenge(input.CanonicalChallenge)
	if err != nil {
		return RevocationLookup{}, ErrInvalidInput
	}
	artifact, err := lifecycleartifact.ParseCanonicalRevokeArtifact(input.CanonicalRevokeArtifact)
	if err != nil {
		return RevocationLookup{}, ErrInvalidInput
	}
	value := challenge.Value()
	if value.Operation != hil.OperationRevoke || value.OriginalAddDigest == nil ||
		value.NonceDigest != input.Nonce.digest ||
		value.SessionDigest != input.Browser.session.TokenDigest.String() ||
		!value.AuthenticatedAt.Equal(input.Browser.session.AuthenticatedAt) ||
		artifact.Digest() != value.CanonicalArtifactDigest ||
		value.GeneratedArtifactDigest != value.CanonicalArtifactDigest ||
		!validUUID(input.PolicyID) || input.PolicyVersion == 0 ||
		input.PolicyVersion > 2_147_483_647 {
		return RevocationLookup{}, ErrInvalidInput
	}
	binding, err := hil.CheckRevocationBinding(hil.RevocationBindingInput{
		ActionID: value.ResourceID, ActionVersion: value.ResourceVersion,
		TargetIPv4: value.TargetIPv4, OriginalAddDigest: *value.OriginalAddDigest,
		PolicyDigest:             value.PolicyDigest,
		EvidenceSnapshotDigest:   value.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: value.ValidationSnapshotDigest,
		EligibilityValidUntil:    value.ValidationValidUntil,
		Session: hil.SessionBinding{
			SessionID:       input.Browser.session.ID.String(),
			SessionDigest:   input.Browser.session.TokenDigest.String(),
			ActorID:         input.Browser.session.ActorID,
			AuthenticatedAt: input.Browser.session.AuthenticatedAt,
			ExpiresAt:       input.Browser.session.ExpiresAt,
		},
		IdempotencyKeyDigest: input.Browser.idempotency.digest,
		Artifact:             artifact,
	})
	if err != nil {
		return RevocationLookup{}, ErrInvalidInput
	}
	bound, err := hil.BindRevocationChallenge(binding, challenge)
	if err != nil {
		return RevocationLookup{}, ErrInvalidInput
	}
	lookup := RevocationLookup{
		Browser: input.Browser, Challenge: bound, Nonce: input.Nonce, Reason: input.Reason,
		policyID: input.PolicyID, policyVersion: input.PolicyVersion,
	}
	if !validRevocationLookup(lookup) {
		return RevocationLookup{}, ErrInvalidInput
	}
	return lookup, nil
}

// PrivilegedRevocationCommit binds a fresh revoke decision to the exact
// ordinary privileged session rotation. Its zero value is invalid.
type PrivilegedRevocationCommit struct {
	lookup      RevocationLookup
	expected    adminauth.SessionRecord
	replacement adminauth.SessionRecord
	rotationAt  time.Time
	material    *revocationCommitMaterial
}

// revocationCommitMaterial is shared by value copies of one checked commit.
// It preserves the exact DB-clock time, UUIDs, and canonical artifacts across
// transport retries and serializes concurrent retries of that same decision.
type revocationCommitMaterial struct {
	mu sync.Mutex

	initialized         bool
	decidedAt           time.Time
	validUntil          time.Time
	identities          []string
	decision            hil.CheckedDecision
	authorizationJCS    []byte
	authorizationDigest string
}

func (PrivilegedRevocationCommit) String() string {
	return "hilstore.PrivilegedRevocationCommit{session:[REDACTED],rotation:[REDACTED]}"
}
func (r PrivilegedRevocationCommit) GoString() string { return r.String() }

// BindPrivilegedRevocationCommit rejects historical-only browser projections
// and non-canonical or misbound privileged rotations.
func BindPrivilegedRevocationCommit(
	lookup RevocationLookup,
	expected adminauth.SessionRecord,
	rotation adminauth.SessionRotation,
) (PrivilegedRevocationCommit, error) {
	expected = cloneSession(expected)
	revoked := cloneSession(rotation.Revoked)
	replacement := cloneSession(rotation.Issued.Record)
	if !validRevocationLookup(lookup) || lookup.Browser.historicalOnly ||
		!sameSession(expected, lookup.Browser.session) ||
		!validPrivilegeRotation(expected, revoked, replacement) {
		return PrivilegedRevocationCommit{}, ErrInvalidInput
	}
	return PrivilegedRevocationCommit{
		lookup: lookup, expected: expected, replacement: replacement,
		rotationAt: *revoked.RevokedAt, material: &revocationCommitMaterial{},
	}, nil
}

// StoredRevocation is a checked, redacted persistence result. The decision
// exposes revoke-only authority through hil.CheckedRevocationDecision and can
// never be converted into add authority.
type StoredRevocation struct {
	decision            hil.CheckedRevocationDecision
	revocationID        string
	authorizationID     string
	authorizationDigest string
	outboxJobID         string
	auditEventID        string
	sessionRotated      bool
}

func (r StoredRevocation) Decision() hil.CheckedRevocationDecision { return r.decision }
func (r StoredRevocation) RevocationID() string                    { return r.revocationID }
func (r StoredRevocation) AuthorizationID() string                 { return r.authorizationID }
func (r StoredRevocation) AuthorizationDigest() string             { return r.authorizationDigest }
func (r StoredRevocation) OutboxJobID() string                     { return r.outboxJobID }
func (r StoredRevocation) AuditEventID() string                    { return r.auditEventID }
func (r StoredRevocation) SessionRotated() bool                    { return r.sessionRotated }
func (StoredRevocation) String() string {
	return "hilstore.StoredRevocation{decision:[REDACTED],artifact:[REDACTED]}"
}
func (r StoredRevocation) GoString() string { return r.String() }

func validRevocationIssueRequest(value RevocationIssueRequest) bool {
	return !value.Browser.historicalOnly && validSessionProjection(value.Browser.session) &&
		validDigest(value.Browser.idempotency.digest) && validUUID(value.ActionID) &&
		value.ActionVersion > 0 && value.ActionVersion <= 2_147_483_647 &&
		validIPv4(value.TargetIPv4) && validDigest(value.OriginalAddDigest)
}

func validRevocationLookup(value RevocationLookup) bool {
	challenge := value.Challenge.Value()
	browserValid := validSessionProjection(value.Browser.session)
	if value.Browser.historicalOnly {
		browserValid = validHistoricalSessionProjection(value.Browser.session)
	}
	return browserValid && validDigest(value.Browser.idempotency.digest) &&
		validDigest(value.Nonce.digest) && value.Challenge.Digest() != "" &&
		len(value.Challenge.CanonicalBytes()) > 0 && len(value.Challenge.RevokeArtifactBytes()) > 0 &&
		validDigest(value.Challenge.RevokeArtifactDigest()) &&
		challenge.Operation == hil.OperationRevoke &&
		challenge.ResourceType == hil.ResourceEnforcementAction &&
		challenge.OriginalAddDigest != nil && challenge.NonceDigest == value.Nonce.digest &&
		challenge.SessionDigest == value.Browser.session.TokenDigest.String() &&
		challenge.ResourceVersion > 0 && validUUID(challenge.ResourceID) &&
		validUUID(value.policyID) && value.policyVersion > 0 && value.policyVersion <= 2_147_483_647 &&
		value.Reason.Value().SchemaVersion == hil.ReasonSchemaVersion &&
		validDigest(value.Reason.Digest()) && len(value.Reason.CanonicalBytes()) > 0
}

func validPrivilegedRevocationCommit(value PrivilegedRevocationCommit) bool {
	if !validRevocationLookup(value.lookup) || value.lookup.Browser.historicalOnly ||
		!sameSession(value.expected, value.lookup.Browser.session) || value.rotationAt.IsZero() ||
		value.material == nil {
		return false
	}
	revoked := value.expected
	revoked.LastSeenAt = value.rotationAt
	revokedAt := value.rotationAt
	revoked.RevokedAt = &revokedAt
	return validPrivilegeRotation(value.expected, revoked, value.replacement)
}

func revocationRotationSuffix(commit PrivilegedRevocationCommit) []any {
	expected := commit.expected
	replacement := commit.replacement
	var expectedParent any
	if expected.RotationParentID != nil {
		expectedParent = expected.RotationParentID.String()
	}
	return []any{
		expected.CreatedAt.UTC(), expected.LastSeenAt.UTC(), expectedParent,
		commit.rotationAt.UTC(), replacement.ID.String(), replacement.ActorID,
		replacement.TokenDigest.String(), replacement.CSRFDigest.String(),
		replacement.AuthenticatedAt.UTC(), replacement.CreatedAt.UTC(),
		replacement.LastSeenAt.UTC(), replacement.ExpiresAt.UTC(),
		replacement.RotationParentID.String(),
	}
}
