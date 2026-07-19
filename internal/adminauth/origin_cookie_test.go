package adminauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOriginPolicyExactAllowlist(t *testing.T) {
	policy, err := NewOriginPolicy([]string{"https://admin.example.test", "https://admin.example.test:8443", "http://localhost:4173"})
	if err != nil {
		t.Fatal(err)
	}
	for _, accepted := range []string{"https://admin.example.test", "https://admin.example.test:8443", "http://localhost:4173"} {
		if err := policy.Validate(accepted); err != nil {
			t.Fatalf("allowlisted origin rejected: %q: %v", accepted, err)
		}
	}
	for _, rejected := range []string{
		"", "null", "https://admin.example.test/", "https://ADMIN.example.test", "https://admin.example.test:443",
		"https://admin.example.test.evil", "http://admin.example.test", "https://admin.example.test/path",
		"https://user@admin.example.test", "https://admin.example.test?x=1", "https://admin.example.test#x",
		"https://admin.example.test:08443", "https://admin.example.test:0", "https://admin.example.test:65536",
		"https://admin_example.test", "https://admín.example.test", "https://-admin.example.test",
		"https://admin-.example.test", "https://admin..example.test",
	} {
		if err := policy.Validate(rejected); !errors.Is(err, ErrBrowserRequest) {
			t.Fatalf("origin accepted: %q", rejected)
		}
	}
	for _, invalidSet := range [][]string{
		nil,
		{"https://admin.example.test", "https://admin.example.test"},
		{"http://admin.example.test"},
		{"https://ADMIN.example.test"},
		{"https://admin.example.test/"},
	} {
		if _, err := NewOriginPolicy(invalidSet); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid allowlist accepted: %#v (%v)", invalidSet, err)
		}
	}
}

func TestBrowserRequestRequiresOriginSessionAndCSRF(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	origins, err := NewOriginPolicy([]string{"https://admin.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	if _, err := manager.ValidateBrowserRequest(issued.Record, issued.SessionToken(), issued.CSRFToken(), "https://admin.example.test", origins); err != nil {
		t.Fatalf("valid browser request rejected: %v", err)
	}
	for _, test := range []struct {
		session string
		csrf    string
		origin  string
	}{
		{issued.SessionToken(), issued.CSRFToken(), "https://evil.example.test"},
		{issued.SessionToken(), strings43('A'), "https://admin.example.test"},
		{strings43('A'), issued.CSRFToken(), "https://admin.example.test"},
		{issued.SessionToken(), issued.CSRFToken() + "=", "https://admin.example.test"},
	} {
		if _, err := manager.ValidateBrowserRequest(issued.Record, test.session, test.csrf, test.origin, origins); !errors.Is(err, ErrBrowserRequest) {
			t.Fatalf("unsafe browser request result: %v", err)
		}
	}
}

func strings43(value byte) string {
	buffer := make([]byte, 43)
	for i := range buffer {
		buffer[i] = value
	}
	return string(buffer)
}

func TestCookiePolicySecurityAttributes(t *testing.T) {
	policy, err := NewCookiePolicy("__Host-sentinelflow", CookieTransportTLS)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	cookie := policy.sessionCookie("opaque", expires)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || !cookie.Expires.Equal(expires) {
		t.Fatalf("unsafe cookie attributes: %+v", cookie)
	}
	local, err := NewCookiePolicy("sentinelflow_local", CookieTransportExplicitLocalTest)
	if err != nil {
		t.Fatal(err)
	}
	if local.sessionCookie("opaque", expires).Secure {
		t.Fatal("explicit local-test cookie unexpectedly Secure")
	}
	for _, transport := range []CookieTransport{0, 99} {
		if _, err := NewCookiePolicy("sentinelflow", transport); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("implicit insecure transport accepted: %v", err)
		}
	}
	if _, err := NewCookiePolicy("bad name", CookieTransportTLS); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid cookie name accepted: %v", err)
	}
	expired := policy.ExpiredCookie()
	if expired.MaxAge != -1 || !expired.HttpOnly || !expired.Secure || expired.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe expired cookie: %+v", expired)
	}
}

func TestVersionedSessionCookieRoundTripAndConfusionRejection(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewCookiePolicy("__Host-sentinelflow", CookieTransportTLS)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := policy.IssuedSessionCookie(issued)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://admin.example.test/api/v1/session", nil)
	request.AddCookie(cookie)
	credential, err := policy.ReadSessionCredential(request)
	if err != nil || credential.SessionID() != issued.Record.ID || credential.PresentedToken() != issued.SessionToken() {
		t.Fatalf("cookie round trip failed: %v", err)
	}
	formatted := fmt.Sprintf("%v %#v", credential, credential)
	if strings.Contains(formatted, issued.SessionToken()) || strings.Contains(formatted, cookie.Value) {
		t.Fatal("cookie formatting exposed payload")
	}
	if encoded, err := json.Marshal(credential); err == nil || strings.Contains(string(encoded), issued.SessionToken()) {
		t.Fatal("cookie JSON exposed payload")
	}

	for _, raw := range []string{
		"v2." + issued.Record.ID.String() + "." + issued.SessionToken(),
		"v1." + strings.ToUpper(issued.Record.ID.String()) + "." + issued.SessionToken(),
		"v1." + issued.Record.ID.String() + "." + issued.SessionToken() + "=",
		"v1." + issued.Record.ID.String() + "." + strings.Repeat("A", 42),
		"v1.." + issued.SessionToken(),
	} {
		request := httptest.NewRequest(http.MethodGet, "https://admin.example.test/api/v1/session", nil)
		request.Header.Set("Cookie", "__Host-sentinelflow="+raw)
		if _, err := policy.ReadSessionCredential(request); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("malformed cookie accepted: %q", raw)
		}
	}
	duplicate := httptest.NewRequest(http.MethodGet, "https://admin.example.test/api/v1/session", nil)
	duplicate.AddCookie(cookie)
	duplicate.AddCookie(cookie)
	if _, err := policy.ReadSessionCredential(duplicate); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("duplicate session cookie accepted")
	}
	multipleHeaders := httptest.NewRequest(http.MethodGet, "https://admin.example.test/api/v1/session", nil)
	multipleHeaders.Header["Cookie"] = []string{"other=value", cookie.Name + "=" + cookie.Value}
	if _, err := policy.ReadSessionCredential(multipleHeaders); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("multiple Cookie header fields accepted")
	}
}

func TestIssuedSessionSecretClear(t *testing.T) {
	manager := newTestSessionManager(t, newTestClock())
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	issued.ClearSecrets()
	for _, secret := range [][]byte{issued.sessionToken[:], issued.csrfToken[:]} {
		for _, value := range secret {
			if value != 0 {
				t.Fatal("issued secret was not cleared")
			}
		}
	}
}
