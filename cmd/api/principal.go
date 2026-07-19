package main

import (
	"context"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminapi"
	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/investigationapi"
)

type sessionProjectionReader func(context.Context) (adminapi.SessionProjection, bool)

// sessionPrincipalProvider converts the already authenticated, database-touched
// administrator context into the narrow investigation principal. It never
// reads cookies or session secrets itself. The maximum SSE lifetime is shorter
// than the idle bound, but retaining the conservative bound here prevents a
// future caller from extending a principal beyond either session limit.
type sessionPrincipalProvider struct {
	sessions sessionProjectionReader
	now      func() time.Time
}

func newSessionPrincipalProvider() sessionPrincipalProvider {
	return sessionPrincipalProvider{
		sessions: adminapi.SessionFromContext,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (provider sessionPrincipalProvider) Principal(ctx context.Context) (investigationapi.Principal, bool) {
	if ctx == nil || provider.sessions == nil || provider.now == nil {
		return investigationapi.Principal{}, false
	}
	projection, ok := provider.sessions(ctx)
	if !ok || projection.ActorID == "" || projection.SessionID == "" || projection.ExpiresAt.IsZero() {
		return investigationapi.Principal{}, false
	}
	now := provider.now().UTC()
	if now.IsZero() || now.Year() < 2000 || now.Year() > 9999 {
		return investigationapi.Principal{}, false
	}
	expiresAt := projection.ExpiresAt.UTC()
	idleBoundary := now.Add(adminauth.SessionIdleLifetime)
	if idleBoundary.Before(expiresAt) {
		expiresAt = idleBoundary
	}
	if !expiresAt.After(now) {
		return investigationapi.Principal{}, false
	}
	return investigationapi.Principal{
		ActorID:     projection.ActorID,
		SessionID:   projection.SessionID,
		ValidatedAt: now,
		ExpiresAt:   expiresAt,
	}, true
}

var _ investigationapi.PrincipalProvider = sessionPrincipalProvider{}
