package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	SessionAbsoluteLifetime = 8 * time.Hour
	SessionIdleLifetime     = 30 * time.Minute
	PasswordStepUpAfter     = 15 * time.Minute
	// PrivilegedDecisionReplayLifetime bounds the read-only recovery window for
	// an exact HIL decision response whose ordinary privileged rotation already
	// revoked the presented browser session. This window never reactivates the
	// session or permits another mutation.
	PrivilegedDecisionReplayLifetime = 5 * time.Minute
	tokenBytes                       = 32
	minimumSessionHMACBytes          = 32
)

const (
	sessionTokenDomain        = "sentinelflow/adminauth/session-token/v1\x00"
	csrfTokenDerivationDomain = "sentinelflow/adminauth/csrf-token-derivation/v1\x00"
	csrfTokenDigestDomain     = "sentinelflow/adminauth/csrf-token-digest/v1\x00"
)

// Digest is the HMAC-SHA256 value persisted for an opaque secret. Its string
// form follows the repository's lowercase sha256: encoding convention.
type Digest [sha256.Size]byte

func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }

// SessionID is a random UUIDv4-compatible identifier. It is not an
// authentication token.
type SessionID [16]byte

func (id SessionID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// ParseSessionID accepts only the canonical lowercase UUIDv4 representation
// emitted by SessionID.String. The identifier is suitable for a cookie lookup
// key but is never authentication by itself.
func ParseSessionID(value string) (SessionID, error) {
	var id SessionID
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return id, ErrSessionInvalid
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 || compact != strings.ToLower(compact) {
		return id, ErrSessionInvalid
	}
	raw, err := hex.DecodeString(compact)
	if err != nil || len(raw) != len(id) {
		return id, ErrSessionInvalid
	}
	copy(id[:], raw)
	clear(raw)
	if id.IsZero() || id[6]>>4 != 4 || id[8]>>6 != 2 || id.String() != value {
		return SessionID{}, ErrSessionInvalid
	}
	return id, nil
}

func (id SessionID) IsZero() bool {
	var zero SessionID
	return subtle.ConstantTimeCompare(id[:], zero[:]) == 1
}

// SessionRecord contains only values safe and intended for persistence. Raw
// session and CSRF tokens are deliberately absent.
type SessionRecord struct {
	ID               SessionID
	ActorID          string
	TokenDigest      Digest
	CSRFDigest       Digest
	AuthenticatedAt  time.Time
	CreatedAt        time.Time
	LastSeenAt       time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RotationParentID *SessionID
}

// IssuedSession contains an independently persistable record plus ephemeral
// response secrets. Its formatting methods always redact the secrets.
type IssuedSession struct {
	Record       SessionRecord
	sessionToken [tokenBytes]byte
	csrfToken    [tokenBytes]byte
}

func (s IssuedSession) SessionToken() string {
	return base64.RawURLEncoding.EncodeToString(s.sessionToken[:])
}

func (s IssuedSession) CSRFToken() string {
	return base64.RawURLEncoding.EncodeToString(s.csrfToken[:])
}

func (s IssuedSession) String() string {
	return fmt.Sprintf("adminauth.IssuedSession{session_id:%s actor_id:%s secrets:[REDACTED]}", s.Record.ID.String(), s.Record.ActorID)
}

func (s IssuedSession) GoString() string { return s.String() }

// SessionRotation revokes one record and issues its replacement. Callers must
// persist both sides atomically.
type SessionRotation struct {
	Revoked SessionRecord
	Issued  IssuedSession
}

func (r SessionRotation) String() string {
	return fmt.Sprintf("adminauth.SessionRotation{revoked_session_id:%s issued:%s}", r.Revoked.ID.String(), r.Issued.String())
}

func (r SessionRotation) GoString() string { return r.String() }

// SessionManager creates and verifies opaque HMAC-digested session secrets.
type SessionManager struct {
	hmacKey []byte
	entropy io.Reader
	clock   Clock
}

func NewSessionManager(hmacKey []byte, entropy io.Reader, clock Clock) (*SessionManager, error) {
	if len(hmacKey) < minimumSessionHMACBytes {
		return nil, ErrInvalidConfiguration
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	keyCopy := make([]byte, len(hmacKey))
	copy(keyCopy, hmacKey)
	return &SessionManager{hmacKey: keyCopy, entropy: entropy, clock: clock}, nil
}

func (m *SessionManager) String() string   { return "adminauth.SessionManager{key:[REDACTED]}" }
func (m *SessionManager) GoString() string { return m.String() }

// IssueLogin creates a new password-authenticated session. It is intentionally
// called only after the login limiter and CredentialVerifier succeed.
func (m *SessionManager) IssueLogin(actorID string) (IssuedSession, error) {
	if m == nil || !validPublicIdentity(actorID) {
		return IssuedSession{}, ErrInvalidConfiguration
	}
	now := clockNow(m.clock)
	return m.issue(actorID, now, now, nil)
}

// Validate authenticates a presented opaque token and advances last-seen time
// in the returned copy. The absolute expiration never moves.
func (m *SessionManager) Validate(record SessionRecord, presentedToken string) (SessionRecord, error) {
	now := clockNow(m.clock)
	if err := validateRecordTimes(record, now); err != nil {
		return SessionRecord{}, err
	}
	presentedDigest, canonical := m.digestPresented(sessionTokenDomain, presentedToken)
	digestOK := subtle.ConstantTimeCompare(record.TokenDigest[:], presentedDigest[:])
	if canonical != 1 || digestOK != 1 {
		return SessionRecord{}, ErrSessionInvalid
	}
	record.LastSeenAt = now
	return record, nil
}

// ValidateBrowserRequest validates the session token, exact Origin allowlist,
// and synchronizer CSRF token. CSRF comparison is constant time.
func (m *SessionManager) ValidateBrowserRequest(record SessionRecord, presentedToken, presentedCSRF, origin string, origins *OriginPolicy) (SessionRecord, error) {
	if origins == nil || origins.Validate(origin) != nil {
		return SessionRecord{}, ErrBrowserRequest
	}
	validated, err := m.Validate(record, presentedToken)
	if err != nil {
		return SessionRecord{}, ErrBrowserRequest
	}
	presentedDigest, canonical := m.digestPresented(csrfTokenDigestDomain, presentedCSRF)
	digestOK := subtle.ConstantTimeCompare(record.CSRFDigest[:], presentedDigest[:])
	if canonical != 1 || digestOK != 1 {
		return SessionRecord{}, ErrBrowserRequest
	}
	return validated, nil
}

// ValidateRevokedBrowserReplay authenticates the exact bearer, CSRF token,
// and Origin of a recently revoked privileged-session parent. It is a
// deliberately read-only recovery primitive: callers must first prove that
// persistence, using its authoritative clock, still has the matching live
// rotation child inside the replay window. This method deliberately performs
// no application-clock authorization. The returned record remains revoked and
// cannot be passed to Validate, Touch, Rotate, or any other live-session
// operation.
func (m *SessionManager) ValidateRevokedBrowserReplay(record SessionRecord, presentedToken, presentedCSRF, origin string, origins *OriginPolicy) (SessionRecord, error) {
	if m == nil || origins == nil || origins.Validate(origin) != nil || record.RevokedAt == nil {
		return SessionRecord{}, ErrBrowserRequest
	}
	revokedAt := record.RevokedAt.Round(0).UTC()
	var zeroDigest Digest
	if record.ID.IsZero() || !validPublicIdentity(record.ActorID) || record.CreatedAt.IsZero() ||
		record.AuthenticatedAt.IsZero() || record.LastSeenAt.IsZero() || record.ExpiresAt.IsZero() ||
		record.TokenDigest == zeroDigest || record.CSRFDigest == zeroDigest ||
		record.TokenDigest == record.CSRFDigest ||
		record.AuthenticatedAt.After(record.CreatedAt) || record.CreatedAt.After(record.LastSeenAt) ||
		!record.LastSeenAt.Before(record.ExpiresAt) ||
		record.ExpiresAt.After(record.CreatedAt.Add(SessionAbsoluteLifetime)) ||
		!record.ExpiresAt.After(record.CreatedAt) || revokedAt.Before(record.LastSeenAt) ||
		!revokedAt.Before(record.ExpiresAt) {
		return SessionRecord{}, ErrBrowserRequest
	}
	if record.RotationParentID != nil &&
		(record.RotationParentID.IsZero() || *record.RotationParentID == record.ID) {
		return SessionRecord{}, ErrBrowserRequest
	}
	presentedSessionDigest, sessionCanonical := m.digestPresented(sessionTokenDomain, presentedToken)
	presentedCSRFDigest, csrfCanonical := m.digestPresented(csrfTokenDigestDomain, presentedCSRF)
	sessionOK := subtle.ConstantTimeCompare(record.TokenDigest[:], presentedSessionDigest[:])
	csrfOK := subtle.ConstantTimeCompare(record.CSRFDigest[:], presentedCSRFDigest[:])
	if sessionCanonical != 1 || csrfCanonical != 1 || sessionOK != 1 || csrfOK != 1 {
		return SessionRecord{}, ErrBrowserRequest
	}
	record.RevokedAt = &revokedAt
	return record, nil
}

// RecoverCSRFToken reconstructs the synchronizer token only after validating
// the live session and its opaque bearer token. The derived value is accepted
// only when its digest matches the persisted row in constant time, so legacy,
// tampered, or differently keyed records fail closed and require a new login.
func (m *SessionManager) RecoverCSRFToken(record SessionRecord, presentedToken string) (string, error) {
	validated, err := m.Validate(record, presentedToken)
	if err != nil {
		return "", ErrSessionInvalid
	}
	csrfToken, ok := m.deriveCSRFToken(validated)
	if !ok {
		return "", ErrSessionInvalid
	}
	defer clear(csrfToken[:])
	digest := m.digest(csrfTokenDigestDomain, csrfToken[:])
	if subtle.ConstantTimeCompare(validated.CSRFDigest[:], digest[:]) != 1 {
		return "", ErrSessionInvalid
	}
	return base64.RawURLEncoding.EncodeToString(csrfToken[:]), nil
}

// RequiresStepUp is false at exactly 15 minutes and true strictly after it.
// Invalid or future-dated records fail closed as ErrSessionInvalid.
func (m *SessionManager) RequiresStepUp(record SessionRecord) (bool, error) {
	now := clockNow(m.clock)
	if err := validateRecordTimes(record, now); err != nil {
		return false, err
	}
	return now.Sub(record.AuthenticatedAt) > PasswordStepUpAfter, nil
}

// RotateAfterPrivilege verifies the current token, revokes it, and issues new
// session and CSRF tokens while preserving independent authenticated_at.
func (m *SessionManager) RotateAfterPrivilege(record SessionRecord, presentedToken string) (SessionRotation, error) {
	validated, err := m.Validate(record, presentedToken)
	if err != nil {
		return SessionRotation{}, err
	}
	// The HIL coordinator persists the revocation and replacement in one
	// PostgreSQL transaction and requires one canonical timestamp for all three
	// projections. Do not retain Validate's application-clock last-seen value:
	// it can differ from the rotation instant and can carry sub-microsecond
	// precision that PostgreSQL cannot round-trip exactly.
	now := clockNow(m.clock).Truncate(time.Microsecond)
	revoked := validated
	revoked.LastSeenAt = now
	revokedAt := now
	revoked.RevokedAt = &revokedAt
	issued, err := m.issue(record.ActorID, record.AuthenticatedAt, now, &record.ID)
	if err != nil {
		return SessionRotation{}, err
	}
	return SessionRotation{Revoked: revoked, Issued: issued}, nil
}

// StepUp performs password verification and, only on success, revokes and
// rotates the session while setting authenticated_at to the current time.
func (m *SessionManager) StepUp(record SessionRecord, presentedToken string, password []byte, verifier *CredentialVerifier) (SessionRotation, error) {
	validated, err := m.Validate(record, presentedToken)
	if err != nil {
		return SessionRotation{}, err
	}
	if verifier == nil || verifier.actorID != record.ActorID || verifier.VerifyPassword(password) != nil {
		return SessionRotation{}, ErrInvalidCredentials
	}
	now := clockNow(m.clock)
	revoked := validated
	revokedAt := now
	revoked.RevokedAt = &revokedAt
	issued, err := m.issue(record.ActorID, now, now, &record.ID)
	if err != nil {
		return SessionRotation{}, err
	}
	return SessionRotation{Revoked: revoked, Issued: issued}, nil
}

// Revoke validates and revokes a session without creating replacement secrets.
func (m *SessionManager) Revoke(record SessionRecord, presentedToken string) (SessionRecord, error) {
	validated, err := m.Validate(record, presentedToken)
	if err != nil {
		return SessionRecord{}, err
	}
	now := clockNow(m.clock)
	validated.RevokedAt = &now
	return validated, nil
}

func (m *SessionManager) issue(actorID string, authenticatedAt, createdAt time.Time, parent *SessionID) (IssuedSession, error) {
	var issued IssuedSession
	// PostgreSQL timestamptz stores microseconds. Persisted session timestamps
	// must be canonical before token issuance so an insert/read-back round trip
	// cannot change an exact-CAS record.
	authenticatedAt = authenticatedAt.UTC().Truncate(time.Microsecond)
	createdAt = createdAt.UTC().Truncate(time.Microsecond)
	if _, err := io.ReadFull(m.entropy, issued.Record.ID[:]); err != nil {
		return IssuedSession{}, fmt.Errorf("session entropy unavailable: %w", err)
	}
	issued.Record.ID[6] = issued.Record.ID[6]&0x0f | 0x40
	issued.Record.ID[8] = issued.Record.ID[8]&0x3f | 0x80
	if _, err := io.ReadFull(m.entropy, issued.sessionToken[:]); err != nil {
		clear(issued.sessionToken[:])
		return IssuedSession{}, fmt.Errorf("session entropy unavailable: %w", err)
	}
	issued.Record.ActorID = actorID
	issued.Record.AuthenticatedAt = authenticatedAt
	issued.Record.CreatedAt = createdAt
	issued.Record.LastSeenAt = createdAt
	issued.Record.ExpiresAt = createdAt.Add(SessionAbsoluteLifetime)
	if parent != nil {
		parentCopy := *parent
		issued.Record.RotationParentID = &parentCopy
	}
	issued.Record.TokenDigest = m.digest(sessionTokenDomain, issued.sessionToken[:])
	csrfToken, ok := m.deriveCSRFToken(issued.Record)
	if !ok {
		clear(issued.sessionToken[:])
		return IssuedSession{}, ErrInvalidConfiguration
	}
	issued.csrfToken = csrfToken
	issued.Record.CSRFDigest = m.digest(csrfTokenDigestDomain, issued.csrfToken[:])
	return issued, nil
}

// deriveCSRFToken binds the recoverable token to immutable current-session
// material using a domain distinct from both bearer-token and CSRF digesting.
// The fixed-width input makes the binding unambiguous without serialization.
func (m *SessionManager) deriveCSRFToken(record SessionRecord) ([tokenBytes]byte, bool) {
	var token [tokenBytes]byte
	if m == nil || len(m.hmacKey) < minimumSessionHMACBytes || record.ID.IsZero() {
		return token, false
	}
	var material [len(SessionID{}) + sha256.Size]byte
	copy(material[:len(record.ID)], record.ID[:])
	copy(material[len(record.ID):], record.TokenDigest[:])
	derived := m.digest(csrfTokenDerivationDomain, material[:])
	clear(material[:])
	copy(token[:], derived[:])
	clear(derived[:])
	return token, true
}

func validateRecordTimes(record SessionRecord, now time.Time) error {
	if record.ID.IsZero() || !validPublicIdentity(record.ActorID) || record.RevokedAt != nil || record.CreatedAt.IsZero() ||
		record.AuthenticatedAt.IsZero() || record.LastSeenAt.IsZero() || record.ExpiresAt.IsZero() ||
		record.AuthenticatedAt.After(record.CreatedAt) || record.CreatedAt.After(record.LastSeenAt) ||
		record.ExpiresAt.After(record.CreatedAt.Add(SessionAbsoluteLifetime)) || !record.ExpiresAt.After(record.CreatedAt) ||
		now.Before(record.CreatedAt) || now.Before(record.AuthenticatedAt) || now.Before(record.LastSeenAt) ||
		!now.Before(record.ExpiresAt) || !now.Before(record.LastSeenAt.Add(SessionIdleLifetime)) {
		return ErrSessionInvalid
	}
	return nil
}

func (m *SessionManager) digest(domain string, raw []byte) Digest {
	mac := hmac.New(sha256.New, m.hmacKey)
	_, _ = io.WriteString(mac, domain)
	_, _ = mac.Write(raw)
	var digest Digest
	copy(digest[:], mac.Sum(nil))
	return digest
}

func (m *SessionManager) digestPresented(domain, encoded string) (Digest, int) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	canonical := 1
	if err != nil || len(decoded) != tokenBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded || strings.Contains(encoded, "=") {
		canonical = 0
		decoded = make([]byte, tokenBytes)
	}
	digest := m.digest(domain, decoded)
	clear(decoded)
	return digest, canonical
}
