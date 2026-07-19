package adminauth

import "net/netip"

// Boundary composes the credential, login-rate, session, browser-request, and
// decision-rate primitives without taking on HTTP or persistence concerns.
type Boundary struct {
	credentials *CredentialVerifier
	sessions    *SessionManager
	login       *LoginLimiter
	decisions   *DecisionLimiter
	origins     *OriginPolicy
}

func NewBoundary(credentials *CredentialVerifier, sessions *SessionManager, login *LoginLimiter, decisions *DecisionLimiter, origins *OriginPolicy) (*Boundary, error) {
	if credentials == nil || sessions == nil || login == nil || decisions == nil || origins == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Boundary{credentials: credentials, sessions: sessions, login: login, decisions: decisions, origins: origins}, nil
}

// Login applies the pre-Argon2 limiter, performs one generic credential check,
// and only then issues opaque session secrets.
func (b *Boundary) Login(source netip.Addr, username string, password []byte) (IssuedSession, error) {
	if b == nil {
		return IssuedSession{}, ErrInvalidConfiguration
	}
	if err := b.login.Allow(source); err != nil {
		return IssuedSession{}, err
	}
	actorID, err := b.credentials.Verify(username, password)
	if err != nil {
		return IssuedSession{}, ErrInvalidCredentials
	}
	return b.sessions.IssueLogin(actorID)
}

// ValidateOrigin authenticates the exact browser Origin before callers spend
// password-hashing or database resources. It deliberately has no proxy-header
// or host-derived fallback.
func (b *Boundary) ValidateOrigin(origin string) error {
	if b == nil || b.origins == nil {
		return ErrBrowserRequest
	}
	return b.origins.Validate(origin)
}

// ValidateSession authenticates an opaque session token for a read-only
// request. Persistence adapters must still exact-CAS Touch the database row
// before placing the returned, database-current record in request context.
func (b *Boundary) ValidateSession(record SessionRecord, sessionToken string) (SessionRecord, error) {
	if b == nil || b.sessions == nil {
		return SessionRecord{}, ErrSessionInvalid
	}
	return b.sessions.Validate(record, sessionToken)
}

func (b *Boundary) ValidateBrowserRequest(record SessionRecord, sessionToken, csrfToken, origin string) (SessionRecord, error) {
	if b == nil {
		return SessionRecord{}, ErrBrowserRequest
	}
	return b.sessions.ValidateBrowserRequest(record, sessionToken, csrfToken, origin, b.origins)
}

// ValidateRevokedBrowserReplay is restricted to exact, read-only HIL response
// recovery. It never makes a revoked record live again.
func (b *Boundary) ValidateRevokedBrowserReplay(record SessionRecord, sessionToken, csrfToken, origin string) (SessionRecord, error) {
	if b == nil || b.sessions == nil {
		return SessionRecord{}, ErrBrowserRequest
	}
	return b.sessions.ValidateRevokedBrowserReplay(record, sessionToken, csrfToken, origin, b.origins)
}

// RecoverCSRFToken returns the current synchronizer token only after the
// server-side session row and opaque bearer token are validated again.
func (b *Boundary) RecoverCSRFToken(record SessionRecord, sessionToken string) (string, error) {
	if b == nil || b.sessions == nil {
		return "", ErrSessionInvalid
	}
	return b.sessions.RecoverCSRFToken(record, sessionToken)
}

func (b *Boundary) RequiresStepUp(record SessionRecord) (bool, error) {
	if b == nil {
		return false, ErrSessionInvalid
	}
	return b.sessions.RequiresStepUp(record)
}

func (b *Boundary) StepUp(record SessionRecord, sessionToken string, password []byte) (SessionRotation, error) {
	if b == nil {
		return SessionRotation{}, ErrSessionInvalid
	}
	return b.sessions.StepUp(record, sessionToken, password, b.credentials)
}

func (b *Boundary) RotateAfterPrivilege(record SessionRecord, sessionToken string) (SessionRotation, error) {
	if b == nil {
		return SessionRotation{}, ErrSessionInvalid
	}
	return b.sessions.RotateAfterPrivilege(record, sessionToken)
}

func (b *Boundary) AllowDecision(sessionID SessionID) error {
	if b == nil {
		return &RateLimitError{Scope: RateLimitCapacity, RetryAfter: limiterWindow}
	}
	return b.decisions.Allow(sessionID)
}

func (b *Boundary) String() string   { return "adminauth.Boundary{secrets:[REDACTED]}" }
func (b *Boundary) GoString() string { return b.String() }
