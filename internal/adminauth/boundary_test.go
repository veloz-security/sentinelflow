package adminauth

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func newTestBoundary(t *testing.T, clock *testClock, verifier *CredentialVerifier) *Boundary {
	t.Helper()
	sessions := newTestSessionManager(t, clock)
	login, err := NewLoginLimiter(clock, 64)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := NewDecisionLimiter(clock, 64)
	if err != nil {
		t.Fatal(err)
	}
	origins, err := NewOriginPolicy([]string{"https://admin.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := NewBoundary(verifier, sessions, login, decisions, origins)
	if err != nil {
		t.Fatal(err)
	}
	return boundary
}

func TestBoundaryLoginLimitsBeforePasswordWork(t *testing.T) {
	clock := newTestClock()
	verifier := fastVerifier()
	var work atomic.Int32
	verifier.workObserved = func() { work.Add(1) }
	boundary := newTestBoundary(t, clock, verifier)
	source := netip.MustParseAddr("192.0.2.50")

	for i := 0; i < LoginPerSourcePerMinute; i++ {
		_, err := boundary.Login(source, "unknown", otherPassword())
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d did not return generic failure: %v", i, err)
		}
	}
	if got := work.Load(); got != LoginPerSourcePerMinute {
		t.Fatalf("expected one work unit per permitted attempt, got %d", got)
	}
	if _, err := boundary.Login(source, "admin", testPassword()); err == nil {
		t.Fatal("rate-limited valid credentials were accepted")
	} else {
		var limited *RateLimitError
		if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 60 {
			t.Fatalf("missing Retry-After rate error: %v", err)
		}
	}
	if got := work.Load(); got != LoginPerSourcePerMinute {
		t.Fatalf("rate-limited request reached password work: %d", got)
	}

	clock.Add(time.Minute)
	issued, err := boundary.Login(source, "admin", testPassword())
	if err != nil {
		t.Fatalf("valid login failed after window: %v", err)
	}
	if issued.Record.ActorID != "administrator" {
		t.Fatalf("wrong actor: %s", issued.Record.ActorID)
	}
}

func TestBoundaryBrowserStepUpRotationAndDecisionLimit(t *testing.T) {
	clock := newTestClock()
	boundary := newTestBoundary(t, clock, fastVerifier())
	issued, err := boundary.Login(netip.MustParseAddr("192.0.2.51"), "admin", testPassword())
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	validated, err := boundary.ValidateBrowserRequest(issued.Record, issued.SessionToken(), issued.CSRFToken(), "https://admin.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !validated.LastSeenAt.Equal(clock.Now()) {
		t.Fatal("browser validation did not touch session")
	}
	clock.Add(PasswordStepUpAfter)
	stale, err := boundary.RequiresStepUp(validated)
	if err != nil || !stale {
		t.Fatalf("stale authenticated_at not detected: stale=%v err=%v", stale, err)
	}
	rotation, err := boundary.StepUp(validated, issued.SessionToken(), testPassword())
	if err != nil {
		t.Fatal(err)
	}
	if !rotation.Issued.Record.AuthenticatedAt.Equal(clock.Now()) {
		t.Fatal("step-up did not refresh independent authentication time")
	}
	privileged, err := boundary.RotateAfterPrivilege(rotation.Issued.Record, rotation.Issued.SessionToken())
	if err != nil {
		t.Fatal(err)
	}
	if !privileged.Issued.Record.AuthenticatedAt.Equal(rotation.Issued.Record.AuthenticatedAt) {
		t.Fatal("privilege rotation changed independent authentication time")
	}
	for i := 0; i < DecisionsPerSessionMinute; i++ {
		if err := boundary.AllowDecision(privileged.Issued.Record.ID); err != nil {
			t.Fatalf("decision %d rejected: %v", i, err)
		}
	}
	var limited *RateLimitError
	if err := boundary.AllowDecision(privileged.Issued.Record.ID); !errors.As(err, &limited) || limited.Scope != RateLimitDecision {
		t.Fatalf("decision limit not enforced: %v", err)
	}
}

func TestBoundaryRejectsIncompleteComposition(t *testing.T) {
	if _, err := NewBoundary(nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("incomplete boundary accepted: %v", err)
	}
}

func TestBoundarySeparatesOriginAndReadOnlySessionValidation(t *testing.T) {
	clock := newTestClock()
	boundary := newTestBoundary(t, clock, fastVerifier())
	if err := boundary.ValidateOrigin("https://admin.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := boundary.ValidateOrigin("https://evil.example.test"); !errors.Is(err, ErrBrowserRequest) {
		t.Fatalf("untrusted origin accepted: %v", err)
	}
	issued, err := boundary.Login(netip.MustParseAddr("192.0.2.52"), "admin", testPassword())
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	validated, err := boundary.ValidateSession(issued.Record, issued.SessionToken())
	if err != nil || !validated.LastSeenAt.Equal(clock.Now()) {
		t.Fatalf("read-only validation failed: record=%#v err=%v", validated, err)
	}
	recovered, err := boundary.RecoverCSRFToken(validated, issued.SessionToken())
	if err != nil || recovered != issued.CSRFToken() {
		t.Fatalf("authenticated CSRF recovery failed: token=%q err=%v", recovered, err)
	}
	if _, err := boundary.ValidateSession(issued.Record, strings43('A')); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("invalid session token accepted: %v", err)
	}
	if recovered, err := boundary.RecoverCSRFToken(validated, strings43('A')); !errors.Is(err, ErrSessionInvalid) || recovered != "" {
		t.Fatalf("unauthenticated CSRF recovery succeeded: token=%q err=%v", recovered, err)
	}
}
