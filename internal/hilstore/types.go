package hilstore

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
)

const (
	minimumIdempotencyBytes = 16
	maximumIdempotencyBytes = 256
	decisionNonceBytes      = 32
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	actorPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// IdempotencyKey is the checked digest-only projection of an HTTP
// Idempotency-Key. The raw value is neither retained nor exposed.
type IdempotencyKey struct{ digest string }

func (IdempotencyKey) String() string     { return "hilstore.IdempotencyKey{digest:[REDACTED]}" }
func (k IdempotencyKey) GoString() string { return k.String() }

// CheckIdempotencyKey validates and digests a raw header value. The caller
// remains responsible for clearing its own input buffer after this call.
func CheckIdempotencyKey(raw []byte) (IdempotencyKey, error) {
	if len(raw) < minimumIdempotencyBytes || len(raw) > maximumIdempotencyBytes {
		return IdempotencyKey{}, ErrInvalidInput
	}
	return IdempotencyKey{digest: digestBytes(raw)}, nil
}

// DecisionNonce is a canonical, digest-only single-use challenge nonce. Raw
// browser nonce bytes are decoded only long enough to hash and clear them.
type DecisionNonce struct{ digest string }

func (DecisionNonce) String() string     { return "hilstore.DecisionNonce{digest:[REDACTED]}" }
func (n DecisionNonce) GoString() string { return n.String() }

func CheckDecisionNonce(encoded string) (DecisionNonce, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(decisionNonceBytes) {
		return DecisionNonce{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != decisionNonceBytes || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return DecisionNonce{}, ErrInvalidInput
	}
	digest := digestBytes(raw)
	clear(raw)
	return DecisionNonce{digest: digest}, nil
}

// BrowserRequest is an opaque persistence-bound projection of the
// adminauth.Boundary-validated browser request. Origin, raw session, and raw
// CSRF values cannot enter hilstore. The complete digest-only SessionRecord is
// rechecked against PostgreSQL at issuance.
type BrowserRequest struct {
	session        adminauth.SessionRecord
	idempotency    IdempotencyKey
	historicalOnly bool
}

func (BrowserRequest) String() string     { return "hilstore.BrowserRequest{session:[REDACTED]}" }
func (r BrowserRequest) GoString() string { return r.String() }

// BindValidatedBrowserRequest must be called only with the SessionRecord
// returned by adminauth.Boundary.ValidateBrowserRequest and after the decision
// limiter succeeds. It rejects malformed persistence projections but does not
// accept or revalidate raw Origin/session/CSRF inputs.
func BindValidatedBrowserRequest(validated adminauth.SessionRecord, idempotency IdempotencyKey) (BrowserRequest, error) {
	validated = cloneSession(validated)
	if !validSessionProjection(validated) || !validDigest(idempotency.digest) {
		return BrowserRequest{}, ErrInvalidInput
	}
	return BrowserRequest{session: validated, idempotency: idempotency}, nil
}

// BindHistoricalReplayBrowserRequest binds a Boundary-authenticated, recently
// revoked privileged parent to a read-only exact-decision lookup. The marker
// is private so this value can never issue a challenge or enter a mutating HIL
// commit even though it retains the original decision/session digest binding.
func BindHistoricalReplayBrowserRequest(validated adminauth.SessionRecord, idempotency IdempotencyKey) (BrowserRequest, error) {
	validated = cloneSession(validated)
	if !validHistoricalSessionProjection(validated) || !validDigest(idempotency.digest) {
		return BrowserRequest{}, ErrInvalidInput
	}
	return BrowserRequest{session: validated, idempotency: idempotency, historicalOnly: true}, nil
}

// IssueRequest is an exact policy challenge request. ExactArtifact can only
// be constructed by the checked policy/evidence/command/validation pipeline.
type IssueRequest struct {
	Operation hil.Operation
	Browser   BrowserRequest
	Artifact  hil.ExactArtifact
}

func (IssueRequest) String() string     { return "hilstore.IssueRequest{artifact:[REDACTED]}" }
func (r IssueRequest) GoString() string { return r.String() }

// IssuedChallenge owns the only in-process copy of the raw nonce. PostgreSQL
// stores its digest only, and TakeNonce can return the raw value exactly once.
type IssuedChallenge struct {
	artifact hil.CheckedChallenge
	nonceMu  sync.Mutex
	nonce    []byte
}

func (i *IssuedChallenge) Challenge() hil.CheckedChallenge {
	if i == nil {
		return hil.CheckedChallenge{}
	}
	return i.artifact
}

func (i *IssuedChallenge) TakeNonce() (string, error) {
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

func (*IssuedChallenge) String() string     { return "hilstore.IssuedChallenge{nonce:[REDACTED]}" }
func (i *IssuedChallenge) GoString() string { return i.String() }

// DecisionLookup contains only checked, digest-bound values. It is used for
// exact idempotent reads after the database coordinator commits. It cannot
// create a decision or authorize execution.
type DecisionLookup struct {
	Browser   BrowserRequest
	Challenge hil.CheckedChallenge
	Nonce     DecisionNonce
	Artifact  hil.ExactArtifact
	Reason    hil.CheckedReason
}

func (DecisionLookup) String() string {
	return "hilstore.DecisionLookup{nonce:[REDACTED],reason:[REDACTED],artifact:[REDACTED]}"
}
func (r DecisionLookup) GoString() string { return r.String() }

// PrivilegedDecisionCommit is the only input accepted by the mutating HIL
// commit path. It binds an exact historical lookup to the database-current
// session returned by adminauth.Boundary validation and to the persistence-safe
// projection of Boundary.RotateAfterPrivilege. Raw session and CSRF tokens are
// deliberately not retained.
type PrivilegedDecisionCommit struct {
	lookup      DecisionLookup
	expected    adminauth.SessionRecord
	replacement adminauth.SessionRecord
	rotationAt  time.Time
}

func (PrivilegedDecisionCommit) String() string {
	return "hilstore.PrivilegedDecisionCommit{session:[REDACTED],rotation:[REDACTED]}"
}
func (r PrivilegedDecisionCommit) GoString() string { return r.String() }

// BindPrivilegedDecisionCommit creates the checked input for a fresh or exact
// idempotent HIL commit. expected must be the exact database-current record
// used by the browser boundary, and rotation must be the ordinary privileged
// rotation that preserves authenticated_at.
func BindPrivilegedDecisionCommit(
	lookup DecisionLookup,
	expected adminauth.SessionRecord,
	rotation adminauth.SessionRotation,
) (PrivilegedDecisionCommit, error) {
	expected = cloneSession(expected)
	revoked := cloneSession(rotation.Revoked)
	replacement := cloneSession(rotation.Issued.Record)
	if !validDecisionLookup(lookup) || lookup.Browser.historicalOnly ||
		!sameSession(expected, lookup.Browser.session) ||
		!validPrivilegeRotation(expected, revoked, replacement) {
		return PrivilegedDecisionCommit{}, ErrInvalidInput
	}
	return PrivilegedDecisionCommit{
		lookup: lookup, expected: expected, replacement: replacement,
		rotationAt: *revoked.RevokedAt,
	}, nil
}

// StoredDecision is a historical/idempotency result. The CheckedDecision
// intentionally has no attached reason/command bytes and therefore cannot
// authorize execution through hil.CheckedDecision.AuthorizesAt. Only the
// atomically persisted authorization/action/outbox path may reach dispatch.
type StoredDecision struct {
	decision            hil.CheckedDecision
	actionID            string
	authorizationDigest string
	outboxJobID         string
	sessionRotated      bool
}

func (d StoredDecision) Decision() hil.CheckedDecision { return d.decision }
func (d StoredDecision) ActionID() string              { return d.actionID }
func (d StoredDecision) AuthorizationDigest() string   { return d.authorizationDigest }
func (d StoredDecision) OutboxJobID() string           { return d.outboxJobID }

// SessionRotated reports whether this call performed the one permitted session
// rotation. It is false for exact replays and historical read-only lookups.
func (d StoredDecision) SessionRotated() bool { return d.sessionRotated }
func (StoredDecision) String() string {
	return "hilstore.StoredDecision{decision:[REDACTED]}"
}
func (d StoredDecision) GoString() string { return d.String() }

func validSessionProjection(record adminauth.SessionRecord) bool {
	if record.ID.IsZero() || record.ID[6]>>4 != 4 || record.ID[8]>>6 != 2 ||
		!actorPattern.MatchString(record.ActorID) || zeroDigest(record.TokenDigest) ||
		zeroDigest(record.CSRFDigest) || record.RevokedAt != nil {
		return false
	}
	authenticatedAt, authOK := normalizeTime(record.AuthenticatedAt)
	createdAt, createdOK := normalizeTime(record.CreatedAt)
	lastSeenAt, seenOK := normalizeTime(record.LastSeenAt)
	expiresAt, expiryOK := normalizeTime(record.ExpiresAt)
	if !authOK || !createdOK || !seenOK || !expiryOK || authenticatedAt.After(createdAt) ||
		lastSeenAt.Before(createdAt) || !expiresAt.After(createdAt) ||
		expiresAt.After(createdAt.Add(adminauth.SessionAbsoluteLifetime)) {
		return false
	}
	if record.RotationParentID != nil && record.RotationParentID.IsZero() {
		return false
	}
	return true
}

func validHistoricalSessionProjection(record adminauth.SessionRecord) bool {
	if record.RevokedAt == nil || !postgresTime(*record.RevokedAt) ||
		record.RevokedAt.Before(record.CreatedAt) || record.RevokedAt.After(record.ExpiresAt) {
		return false
	}
	activeShape := cloneSession(record)
	activeShape.RevokedAt = nil
	return validSessionProjection(activeShape)
}

func cloneSession(value adminauth.SessionRecord) adminauth.SessionRecord {
	if value.RevokedAt != nil {
		copyValue := value.RevokedAt.Round(0).UTC()
		value.RevokedAt = &copyValue
	}
	if value.RotationParentID != nil {
		copyValue := *value.RotationParentID
		value.RotationParentID = &copyValue
	}
	value.AuthenticatedAt = value.AuthenticatedAt.Round(0).UTC()
	value.CreatedAt = value.CreatedAt.Round(0).UTC()
	value.LastSeenAt = value.LastSeenAt.Round(0).UTC()
	value.ExpiresAt = value.ExpiresAt.Round(0).UTC()
	return value
}

func sameSession(left, right adminauth.SessionRecord) bool {
	if left.ID != right.ID || left.ActorID != right.ActorID ||
		left.TokenDigest != right.TokenDigest || left.CSRFDigest != right.CSRFDigest ||
		!left.AuthenticatedAt.Equal(right.AuthenticatedAt) ||
		!left.CreatedAt.Equal(right.CreatedAt) || !left.LastSeenAt.Equal(right.LastSeenAt) ||
		!left.ExpiresAt.Equal(right.ExpiresAt) || !sameOptionalTime(left.RevokedAt, right.RevokedAt) {
		return false
	}
	if left.RotationParentID == nil || right.RotationParentID == nil {
		return left.RotationParentID == nil && right.RotationParentID == nil
	}
	return *left.RotationParentID == *right.RotationParentID
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func validPrivilegeRotation(expected, revoked, replacement adminauth.SessionRecord) bool {
	if !validSessionProjection(expected) || revoked.RevokedAt == nil || replacement.RevokedAt != nil ||
		expected.TokenDigest == expected.CSRFDigest ||
		revoked.ID != expected.ID || revoked.ActorID != expected.ActorID ||
		revoked.TokenDigest != expected.TokenDigest || revoked.CSRFDigest != expected.CSRFDigest ||
		!revoked.AuthenticatedAt.Equal(expected.AuthenticatedAt) ||
		!revoked.CreatedAt.Equal(expected.CreatedAt) || !revoked.ExpiresAt.Equal(expected.ExpiresAt) ||
		!sameOptionalSessionID(revoked.RotationParentID, expected.RotationParentID) ||
		!revoked.LastSeenAt.Equal(*revoked.RevokedAt) || revoked.LastSeenAt.Before(expected.LastSeenAt) ||
		!postgresTime(*revoked.RevokedAt) || !validSessionProjection(replacement) ||
		replacement.ID == expected.ID || replacement.ActorID != expected.ActorID ||
		replacement.TokenDigest == expected.TokenDigest || replacement.CSRFDigest == expected.CSRFDigest ||
		replacement.TokenDigest == replacement.CSRFDigest ||
		!replacement.AuthenticatedAt.Equal(expected.AuthenticatedAt) ||
		replacement.RotationParentID == nil || *replacement.RotationParentID != expected.ID ||
		!replacement.CreatedAt.Equal(*revoked.RevokedAt) ||
		!replacement.LastSeenAt.Equal(replacement.CreatedAt) ||
		!replacement.ExpiresAt.Equal(replacement.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)) ||
		!replacement.CreatedAt.Before(expected.ExpiresAt) {
		return false
	}
	return postgresTime(expected.AuthenticatedAt) && postgresTime(expected.CreatedAt) &&
		postgresTime(expected.LastSeenAt) && postgresTime(expected.ExpiresAt) &&
		postgresTime(replacement.AuthenticatedAt) && postgresTime(replacement.CreatedAt) &&
		postgresTime(replacement.LastSeenAt) && postgresTime(replacement.ExpiresAt)
}

func sameOptionalSessionID(left, right *adminauth.SessionID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func postgresTime(value time.Time) bool {
	_, ok := normalizeTime(value)
	return ok && value.Nanosecond()%1_000 == 0
}

func validExactArtifact(value hil.ExactArtifact) bool {
	generated := value.GeneratedBytes()
	canonical := value.CanonicalBytes()
	createdAt, createdOK := normalizeTime(value.ValidationCreatedAt())
	validUntil, expiryOK := normalizeTime(value.ValidationValidUntil())
	return validUUID(value.PolicyID()) && value.PolicyVersion() > 0 && value.PolicyVersion() <= 2_147_483_647 &&
		value.TTLSeconds() >= 60 && value.TTLSeconds() <= 86400 &&
		validIPv4(value.TargetIPv4()) && validDigest(value.PolicyDigest()) &&
		validDigest(value.GeneratedArtifactDigest()) && validDigest(value.CanonicalArtifactDigest()) &&
		validDigest(value.EvidenceSnapshotDigest()) && validDigest(value.ValidationSnapshotDigest()) &&
		len(generated) > 0 && len(generated) <= 256 && len(canonical) > 0 && len(canonical) <= 257 &&
		digestBytes(generated) == value.GeneratedArtifactDigest() &&
		digestBytes(canonical) == value.CanonicalArtifactDigest() &&
		createdOK && expiryOK && validUntil.After(createdAt) && !validUntil.After(createdAt.Add(5*time.Minute))
}

func validUUID(value string) bool   { return uuidPattern.MatchString(value) }
func validDigest(value string) bool { return digestPattern.MatchString(value) }

func validIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 || len(part) > 1 && part[0] == '0' {
			return false
		}
		var number int
		for _, char := range []byte(part) {
			if char < '0' || char > '9' {
				return false
			}
			number = number*10 + int(char-'0')
		}
		if number > 255 {
			return false
		}
	}
	return true
}

func normalizeTime(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	return value.Round(0).UTC(), true
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func zeroDigest(value adminauth.Digest) bool {
	var zero adminauth.Digest
	return subtle.ConstantTimeCompare(value[:], zero[:]) == 1
}
