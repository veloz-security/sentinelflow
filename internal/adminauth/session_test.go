package adminauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestSessionManager(t *testing.T, clock Clock) *SessionManager {
	t.Helper()
	manager, err := NewSessionManager(testHMACKey(), nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestSessionIssuePersistsOnlyDigestsAndRedactsFormatting(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := issued.SessionToken()
	csrfToken := issued.CSRFToken()
	if len(sessionToken) != 43 || len(csrfToken) != 43 || sessionToken == csrfToken {
		t.Fatalf("unexpected opaque token encoding")
	}
	if issued.Record.TokenDigest == issued.Record.CSRFDigest {
		t.Fatal("session and CSRF digests must be distinct")
	}
	if got := issued.Record.ExpiresAt.Sub(issued.Record.CreatedAt); got != SessionAbsoluteLifetime {
		t.Fatalf("wrong absolute lifetime: %s", got)
	}
	formatted := fmt.Sprintf("%v %#v %+v", issued, issued, manager)
	if strings.Contains(formatted, sessionToken) || strings.Contains(formatted, csrfToken) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("secrets leaked through formatting: %s", formatted)
	}
	encoded, err := json.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(sessionToken)) || bytes.Contains(encoded, []byte(csrfToken)) {
		t.Fatalf("ephemeral secrets leaked through JSON: %s", encoded)
	}
	if !strings.HasPrefix(issued.Record.TokenDigest.String(), "sha256:") || len(issued.Record.TokenDigest.String()) != 71 {
		t.Fatalf("wrong digest encoding: %s", issued.Record.TokenDigest)
	}
	if issued.Record.ID.String() == "00000000-0000-0000-0000-000000000000" || issued.Record.ID[6]>>4 != 4 || issued.Record.ID[8]>>6 != 2 {
		t.Fatalf("session ID is not random UUIDv4-compatible: %s", issued.Record.ID)
	}
}

func TestParseSessionIDRequiresCanonicalUUIDv4(t *testing.T) {
	t.Parallel()
	valid := SessionID{0x01, 0x9b, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}
	parsed, err := ParseSessionID(valid.String())
	if err != nil || parsed != valid {
		t.Fatalf("ParseSessionID() = (%v, %v), want canonical value", parsed, err)
	}
	for _, value := range []string{
		"",
		strings.ToUpper(valid.String()),
		strings.Replace(valid.String(), "-", "", 1),
		"019b0000-0000-7000-8000-000000000001",
		"019b0000-0000-4000-c000-000000000001",
		"019b0000-0000-4000-8000-00000000000g",
	} {
		if parsed, err := ParseSessionID(value); err == nil || !parsed.IsZero() {
			t.Fatalf("invalid session ID accepted: %q", value)
		}
	}
}

func TestSessionValidationIdleAbsoluteAndMalformedBoundaries(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}

	clock.Add(SessionIdleLifetime - time.Nanosecond)
	validated, err := manager.Validate(issued.Record, issued.SessionToken())
	if err != nil {
		t.Fatalf("session rejected just before idle boundary: %v", err)
	}
	if !validated.LastSeenAt.Equal(clock.Now()) {
		t.Fatal("last seen was not advanced")
	}

	clock.Set(issued.Record.LastSeenAt.Add(SessionIdleLifetime))
	if _, err := manager.Validate(issued.Record, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session accepted at idle boundary: %v", err)
	}

	nearAbsolute := issued.Record
	nearAbsolute.LastSeenAt = issued.Record.ExpiresAt.Add(-time.Minute)
	clock.Set(issued.Record.ExpiresAt.Add(-time.Nanosecond))
	if _, err := manager.Validate(nearAbsolute, issued.SessionToken()); err != nil {
		t.Fatalf("session rejected just before absolute boundary: %v", err)
	}
	clock.Set(issued.Record.ExpiresAt)
	if _, err := manager.Validate(nearAbsolute, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session accepted at absolute boundary: %v", err)
	}

	clock.Set(issued.Record.CreatedAt.Add(time.Minute))
	for name, token := range map[string]string{
		"wrong":      strings.Repeat("A", 43),
		"padded":     issued.SessionToken() + "=",
		"short":      issued.SessionToken()[:42],
		"non-url":    strings.Repeat("+", 43),
		"whitespace": " " + issued.SessionToken(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.Validate(issued.Record, token); !errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("malformed token accepted: %v", err)
			}
		})
	}
}

func TestStepUpBoundaryAndRotationsPreventReplay(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	verifier := fastVerifier()
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}

	clock.Add(PasswordStepUpAfter)
	required, err := manager.RequiresStepUp(issued.Record)
	if err != nil || required {
		t.Fatalf("step-up required at exact boundary: required=%v err=%v", required, err)
	}
	clock.Add(time.Nanosecond)
	required, err = manager.RequiresStepUp(issued.Record)
	if err != nil || !required {
		t.Fatalf("step-up not required strictly after boundary: required=%v err=%v", required, err)
	}

	privilegeRotation, err := manager.RotateAfterPrivilege(issued.Record, issued.SessionToken())
	if err != nil {
		t.Fatal(err)
	}
	if !privilegeRotation.Issued.Record.AuthenticatedAt.Equal(issued.Record.AuthenticatedAt) {
		t.Fatal("privileged rotation advanced authenticated_at")
	}
	if privilegeRotation.Revoked.RevokedAt == nil ||
		!privilegeRotation.Revoked.LastSeenAt.Equal(*privilegeRotation.Revoked.RevokedAt) ||
		!privilegeRotation.Issued.Record.CreatedAt.Equal(*privilegeRotation.Revoked.RevokedAt) ||
		privilegeRotation.Revoked.RevokedAt.Nanosecond()%1_000 != 0 {
		t.Fatal("privileged rotation did not use one PostgreSQL-canonical timestamp")
	}
	if privilegeRotation.Issued.SessionToken() == issued.SessionToken() || privilegeRotation.Issued.CSRFToken() == issued.CSRFToken() {
		t.Fatal("rotation reused a secret")
	}
	if _, err := manager.Validate(privilegeRotation.Revoked, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("revoked token replay accepted: %v", err)
	}
	formattedRotation := fmt.Sprintf("%+v %#v", privilegeRotation, privilegeRotation)
	if strings.Contains(formattedRotation, issued.SessionToken()) || strings.Contains(formattedRotation, privilegeRotation.Issued.SessionToken()) {
		t.Fatalf("rotation formatting leaked a token: %s", formattedRotation)
	}

	beforeStepUp := clock.Now()
	stepUp, err := manager.StepUp(privilegeRotation.Issued.Record, privilegeRotation.Issued.SessionToken(), testPassword(), verifier)
	if err != nil {
		t.Fatal(err)
	}
	if !stepUp.Issued.Record.AuthenticatedAt.Equal(beforeStepUp.Truncate(time.Microsecond)) {
		t.Fatalf("step-up did not update authenticated_at: %s", stepUp.Issued.Record.AuthenticatedAt)
	}
	if stepUp.Issued.Record.RotationParentID == nil || *stepUp.Issued.Record.RotationParentID != privilegeRotation.Issued.Record.ID {
		t.Fatal("rotation parent not bound")
	}
	if _, err := manager.Validate(stepUp.Revoked, privilegeRotation.Issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("pre-step-up token replay accepted: %v", err)
	}
	required, err = manager.RequiresStepUp(stepUp.Issued.Record)
	if err != nil || required {
		t.Fatalf("fresh step-up remains stale: required=%v err=%v", required, err)
	}
}

func TestRevokedBrowserReplayIsReadOnlyExactAndLeavesTimeAuthorityToPersistence(t *testing.T) {
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
	rotation, err := manager.RotateAfterPrivilege(issued.Record, issued.SessionToken())
	if err != nil {
		t.Fatal(err)
	}
	validated, err := manager.ValidateRevokedBrowserReplay(
		rotation.Revoked, issued.SessionToken(), issued.CSRFToken(),
		"https://admin.example.test", origins,
	)
	if err != nil || validated.RevokedAt == nil || validated.ID != issued.Record.ID {
		t.Fatalf("exact revoked replay rejected or reactivated: record=%+v err=%v", validated, err)
	}
	if _, err := manager.Validate(validated, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("replay projection became a live session: %v", err)
	}

	for name, mutate := range map[string]func(*SessionRecord, *string, *string, *string){
		"live record":  func(record *SessionRecord, _, _, _ *string) { record.RevokedAt = nil },
		"wrong bearer": func(_ *SessionRecord, token, _, _ *string) { *token = strings.Repeat("A", 43) },
		"wrong csrf":   func(_ *SessionRecord, _, csrf, _ *string) { *csrf = strings.Repeat("B", 43) },
		"wrong origin": func(_ *SessionRecord, _, _, origin *string) { *origin = "https://evil.example.test" },
		"revoked before last seen": func(record *SessionRecord, _, _, _ *string) {
			record.LastSeenAt = record.RevokedAt.Add(time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := rotation.Revoked
			token, csrf, origin := issued.SessionToken(), issued.CSRFToken(), "https://admin.example.test"
			mutate(&record, &token, &csrf, &origin)
			if _, err := manager.ValidateRevokedBrowserReplay(record, token, csrf, origin, origins); !errors.Is(err, ErrBrowserRequest) {
				t.Fatalf("unsafe replay accepted: %v", err)
			}
		})
	}

	for _, applicationTime := range []time.Time{
		rotation.Revoked.CreatedAt.Add(-24 * time.Hour),
		rotation.Revoked.RevokedAt.Add(24 * time.Hour),
	} {
		clock.Set(applicationTime)
		if _, err := manager.ValidateRevokedBrowserReplay(
			rotation.Revoked, issued.SessionToken(), issued.CSRFToken(),
			"https://admin.example.test", origins,
		); err != nil {
			t.Fatalf("application clock became replay authority at %s: %v", applicationTime, err)
		}
	}
}

func TestFailedStepUpDoesNotRotateOrInvalidateCurrentSession(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	if _, err := manager.StepUp(issued.Record, issued.SessionToken(), otherPassword(), fastVerifier()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong step-up result: %v", err)
	}
	if _, err := manager.Validate(issued.Record, issued.SessionToken()); err != nil {
		t.Fatalf("failed step-up invalidated current session: %v", err)
	}
}

func TestRecoverCSRFTokenBindsLiveSessionKeyIDAndTokenDigest(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.RecoverCSRFToken(issued.Record, issued.SessionToken())
	if err != nil || recovered != issued.CSRFToken() {
		t.Fatalf("recover current CSRF = (%q, %v)", recovered, err)
	}

	tests := map[string]func(*SessionRecord){
		"session-id": func(record *SessionRecord) {
			record.ID[15] ^= 1
		},
		"token-digest": func(record *SessionRecord) {
			record.TokenDigest[0] ^= 1
		},
		"legacy-random-csrf-digest": func(record *SessionRecord) {
			record.CSRFDigest[0] ^= 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := issued.Record
			mutate(&record)
			if token, recoverErr := manager.RecoverCSRFToken(record, issued.SessionToken()); !errors.Is(recoverErr, ErrSessionInvalid) || token != "" {
				t.Fatalf("tampered row recovered CSRF: token=%q err=%v", token, recoverErr)
			}
		})
	}

	otherKey := bytes.Repeat([]byte{0x7a}, minimumSessionHMACBytes)
	otherManager, err := NewSessionManager(otherKey, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if token, recoverErr := otherManager.RecoverCSRFToken(issued.Record, issued.SessionToken()); !errors.Is(recoverErr, ErrSessionInvalid) || token != "" {
		t.Fatalf("different key recovered CSRF: token=%q err=%v", token, recoverErr)
	}
	if token, recoverErr := manager.RecoverCSRFToken(issued.Record, ""); !errors.Is(recoverErr, ErrSessionInvalid) || token != "" {
		t.Fatalf("unauthenticated recovery succeeded: token=%q err=%v", token, recoverErr)
	}
}

func TestRecoverCSRFTokenRotationInvalidationAndConcurrentRedaction(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	rotation, err := manager.RotateAfterPrivilege(issued.Record, issued.SessionToken())
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.RecoverCSRFToken(rotation.Issued.Record, rotation.Issued.SessionToken())
	if err != nil || recovered != rotation.Issued.CSRFToken() || recovered == issued.CSRFToken() {
		t.Fatalf("rotated recovery = (%q, %v)", recovered, err)
	}
	origins, err := NewOriginPolicy([]string{"https://admin.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ValidateBrowserRequest(rotation.Issued.Record, rotation.Issued.SessionToken(), issued.CSRFToken(), "https://admin.example.test", origins); !errors.Is(err, ErrBrowserRequest) {
		t.Fatalf("pre-rotation CSRF accepted: %v", err)
	}
	if token, recoverErr := manager.RecoverCSRFToken(rotation.Revoked, issued.SessionToken()); !errors.Is(recoverErr, ErrSessionInvalid) || token != "" {
		t.Fatalf("revoked session recovered CSRF: token=%q err=%v", token, recoverErr)
	}

	const workers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			token, recoverErr := manager.RecoverCSRFToken(rotation.Issued.Record, rotation.Issued.SessionToken())
			if recoverErr != nil || token != rotation.Issued.CSRFToken() {
				errorsSeen <- fmt.Errorf("token mismatch: %q %w", token, recoverErr)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for recoverErr := range errorsSeen {
		t.Fatal(recoverErr)
	}
	formatted := fmt.Sprintf("%v %#v", manager, rotation)
	if strings.Contains(formatted, recovered) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("recovered CSRF leaked through formatting: %s", formatted)
	}
}

func TestSessionRecordTimeAndActorFailuresFailClosed(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	tests := map[string]func(*SessionRecord){
		"zero-id":        func(r *SessionRecord) { r.ID = SessionID{} },
		"bad-actor":      func(r *SessionRecord) { r.ActorID = "bad actor" },
		"future-auth":    func(r *SessionRecord) { r.AuthenticatedAt = clock.Now().Add(time.Second) },
		"future-created": func(r *SessionRecord) { r.CreatedAt = clock.Now().Add(time.Second) },
		"future-seen":    func(r *SessionRecord) { r.LastSeenAt = clock.Now().Add(time.Second) },
		"long-absolute":  func(r *SessionRecord) { r.ExpiresAt = r.CreatedAt.Add(SessionAbsoluteLifetime + time.Nanosecond) },
		"revoked": func(r *SessionRecord) {
			now := clock.Now()
			r.RevokedAt = &now
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := issued.Record
			mutate(&record)
			if _, err := manager.Validate(record, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("bad record accepted: %v", err)
			}
		})
	}
}

func TestIssuedSessionTimesUsePostgreSQLPrecision(t *testing.T) {
	clock := newTestClock()
	clock.Set(clock.Now().Add(987 * time.Nanosecond))
	manager, err := NewSessionManager(testHMACKey(), nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.IssueLogin("admin")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]time.Time{
		"authenticated": issued.Record.AuthenticatedAt,
		"created":       issued.Record.CreatedAt,
		"last_seen":     issued.Record.LastSeenAt,
		"expires":       issued.Record.ExpiresAt,
	} {
		if value.Nanosecond()%int(time.Microsecond) != 0 {
			t.Fatalf("%s timestamp is not PostgreSQL-canonical: %s", name, value)
		}
	}
}

func TestSessionEntropyAndConfigurationFailures(t *testing.T) {
	if _, err := NewSessionManager(make([]byte, minimumSessionHMACBytes-1), nil, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("weak HMAC key accepted: %v", err)
	}
	manager, err := NewSessionManager(testHMACKey(), io.LimitReader(bytes.NewReader(make([]byte, 8)), 8), newTestClock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IssueLogin("administrator"); err == nil || strings.Contains(err.Error(), string(testPassword())) {
		t.Fatalf("unsafe entropy error: %v", err)
	}
	manager, err = NewSessionManager(testHMACKey(), io.LimitReader(bytes.NewReader(make([]byte, 16+tokenBytes-1)), int64(16+tokenBytes-1)), newTestClock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IssueLogin("administrator"); err == nil {
		t.Fatal("partial session-token entropy unexpectedly succeeded")
	}
	if _, err := manager.IssueLogin("bad actor"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid actor accepted: %v", err)
	}
}

func TestSessionRevoke(t *testing.T) {
	clock := newTestClock()
	manager := newTestSessionManager(t, clock)
	issued, err := manager.IssueLogin("administrator")
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	revoked, err := manager.Revoke(issued.Record, issued.SessionToken())
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(clock.Now()) {
		t.Fatalf("revoke failed: record=%+v err=%v", revoked, err)
	}
	if _, err := manager.Revoke(revoked, issued.SessionToken()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("revoke replay accepted: %v", err)
	}
}
