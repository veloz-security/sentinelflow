package adminauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const sessionCookiePayloadVersion = "v1"

type CookieTransport uint8

const (
	CookieTransportTLS CookieTransport = iota + 1
	CookieTransportExplicitLocalTest
)

// CookiePolicy prevents production callers from silently disabling Secure.
type CookiePolicy struct {
	name      string
	transport CookieTransport
}

// SessionCookieCredential is a strictly parsed, versioned cookie credential.
// Its opaque token is available only through the explicit PresentedToken
// method needed by the authentication adapter. Formatting and JSON encoding
// never reveal the cookie payload.
type SessionCookieCredential struct {
	id    SessionID
	token string
}

func (c SessionCookieCredential) SessionID() SessionID { return c.id }

func (c SessionCookieCredential) PresentedToken() string { return c.token }

func (SessionCookieCredential) String() string {
	return "adminauth.SessionCookieCredential{payload:[REDACTED]}"
}

func (c SessionCookieCredential) GoString() string { return c.String() }

func (SessionCookieCredential) MarshalJSON() ([]byte, error) {
	return nil, ErrSessionInvalid
}

func NewCookiePolicy(name string, transport CookieTransport) (CookiePolicy, error) {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "()<>@,;:\\\"/[]?={} \t\r\n") {
		return CookiePolicy{}, ErrInvalidConfiguration
	}
	if transport != CookieTransportTLS && transport != CookieTransportExplicitLocalTest {
		return CookiePolicy{}, ErrInvalidConfiguration
	}
	return CookiePolicy{name: name, transport: transport}, nil
}

// Valid reports whether the policy could only have been produced by
// NewCookiePolicy. It exposes no cookie name or credential material.
func (p CookiePolicy) Valid() bool {
	return p.name != "" && (p.transport == CookieTransportTLS || p.transport == CookieTransportExplicitLocalTest)
}

func (p CookiePolicy) sessionCookie(value string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     p.name,
		Value:    value,
		Path:     "/",
		Domain:   "",
		Expires:  expiresAt.UTC(),
		Secure:   p.transport == CookieTransportTLS,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// IssuedSessionCookie encodes the only accepted session-cookie payload shape.
func (p CookiePolicy) IssuedSessionCookie(issued IssuedSession) (*http.Cookie, error) {
	if !p.Valid() || issued.Record.ID.IsZero() {
		return nil, ErrInvalidConfiguration
	}
	token := issued.SessionToken()
	if !canonicalSessionToken(token) {
		return nil, ErrSessionInvalid
	}
	value := sessionCookiePayloadVersion + "." + issued.Record.ID.String() + "." + token
	return p.sessionCookie(value, issued.Record.ExpiresAt), nil
}

// ReadSessionCredential rejects missing, duplicated, malformed, unversioned,
// or non-canonical session-cookie payloads.
func (p CookiePolicy) ReadSessionCredential(request *http.Request) (SessionCookieCredential, error) {
	if !p.Valid() || request == nil {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	rawHeaders := request.Header.Values("Cookie")
	if len(rawHeaders) != 1 || len(rawHeaders[0]) == 0 || len(rawHeaders[0]) > 4096 {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	cookies := request.CookiesNamed(p.name)
	if len(cookies) != 1 || cookies[0] == nil {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	parts := strings.Split(cookies[0].Value, ".")
	if len(parts) != 3 || parts[0] != sessionCookiePayloadVersion || !canonicalSessionToken(parts[2]) {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	id, err := ParseSessionID(parts[1])
	if err != nil {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	canonical := sessionCookiePayloadVersion + "." + id.String() + "." + parts[2]
	if canonical != cookies[0].Value {
		return SessionCookieCredential{}, ErrSessionInvalid
	}
	return SessionCookieCredential{id: id, token: parts[2]}, nil
}

func canonicalSessionToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(tokenBytes) || strings.Contains(value, "=") {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	valid := err == nil && len(raw) == tokenBytes && base64.RawURLEncoding.EncodeToString(raw) == value
	clear(raw)
	return valid
}

// ClearSecrets erases the in-memory token buffers after persistence and
// response construction, including failed persistence paths.
func (s *IssuedSession) ClearSecrets() {
	if s == nil {
		return
	}
	clear(s.sessionToken[:])
	clear(s.csrfToken[:])
}

func (r *SessionRotation) ClearSecrets() {
	if r == nil {
		return
	}
	r.Issued.ClearSecrets()
}

func (p CookiePolicy) ExpiredCookie() *http.Cookie {
	cookie := p.sessionCookie("", time.Unix(1, 0).UTC())
	cookie.MaxAge = -1
	return cookie
}

var _ json.Marshaler = SessionCookieCredential{}
