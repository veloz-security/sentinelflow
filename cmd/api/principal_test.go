package main

import (
	"context"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminapi"
	"github.com/devwooops/sentinelflow/internal/adminauth"
)

func TestSessionPrincipalProviderUsesEarliestSessionBoundary(t *testing.T) {
	now := time.Date(2026, 7, 18, 9, 30, 0, 0, time.UTC)
	projection := adminapi.SessionProjection{
		ActorID: "administrator", SessionID: "019b0000-0000-4000-8000-000000000001",
		AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(8 * time.Hour),
	}
	provider := sessionPrincipalProvider{
		sessions: func(context.Context) (adminapi.SessionProjection, bool) { return projection, true },
		now:      func() time.Time { return now },
	}

	principal, ok := provider.Principal(context.Background())
	if !ok || principal.ActorID != projection.ActorID || principal.SessionID != projection.SessionID ||
		!principal.ValidatedAt.Equal(now) || !principal.ExpiresAt.Equal(now.Add(adminauth.SessionIdleLifetime)) {
		t.Fatalf("unexpected principal: ok=%t value=%#v", ok, principal)
	}

	projection.ExpiresAt = now.Add(time.Minute)
	principal, ok = provider.Principal(context.Background())
	if !ok || !principal.ExpiresAt.Equal(projection.ExpiresAt) {
		t.Fatalf("absolute expiry was not retained: ok=%t value=%#v", ok, principal)
	}
}

func TestSessionPrincipalProviderFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 18, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		ctx        context.Context
		provider   sessionPrincipalProvider
		projection adminapi.SessionProjection
		found      bool
	}{
		{name: "nil context", ctx: nil, provider: sessionPrincipalProvider{}},
		{name: "missing dependencies", ctx: context.Background(), provider: sessionPrincipalProvider{}},
		{name: "not found", ctx: context.Background(), provider: sessionPrincipalProvider{now: func() time.Time { return now }}},
		{name: "empty actor", ctx: context.Background(), projection: adminapi.SessionProjection{SessionID: "019b0000-0000-4000-8000-000000000001", ExpiresAt: now.Add(time.Hour)}, found: true},
		{name: "expired", ctx: context.Background(), projection: adminapi.SessionProjection{ActorID: "administrator", SessionID: "019b0000-0000-4000-8000-000000000001", ExpiresAt: now}, found: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := test.provider
			if provider.sessions == nil && (test.found || !test.projection.ExpiresAt.IsZero()) {
				provider.sessions = func(context.Context) (adminapi.SessionProjection, bool) {
					return test.projection, test.found
				}
			}
			if provider.now == nil && provider.sessions != nil {
				provider.now = func() time.Time { return now }
			}
			if _, ok := provider.Principal(test.ctx); ok {
				t.Fatal("invalid session projection produced a principal")
			}
		})
	}
}
