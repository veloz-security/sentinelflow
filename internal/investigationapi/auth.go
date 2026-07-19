package investigationapi

import (
	"context"
	"regexp"
	"time"
)

var actorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Principal is asserted by existing authentication/session middleware.
// ExpiresAt is the earliest absolute-expiry, idle-expiry, or required
// revalidation boundary known to that middleware. The investigation package
// never accepts a cookie, token, password, or session lookup dependency and
// cannot authenticate a request by itself.
type Principal struct {
	ActorID     string
	SessionID   string
	ValidatedAt time.Time
	ExpiresAt   time.Time
}

// PrincipalProvider extracts an already validated actor/session from request
// context. Implementations must return false for expired, idle, revoked, or
// otherwise invalid sessions. The handler fails closed when no principal is
// available.
type PrincipalProvider interface {
	Principal(context.Context) (Principal, bool)
}

func validPrincipal(value Principal) bool {
	return actorPattern.MatchString(value.ActorID) && uuidPattern.MatchString(value.SessionID) &&
		!value.ValidatedAt.IsZero() && value.ValidatedAt.Year() >= 2000 && value.ValidatedAt.Year() <= 9999 &&
		!value.ExpiresAt.IsZero() && value.ExpiresAt.Year() >= 2000 && value.ExpiresAt.Year() <= 9999 &&
		utcOffset(value.ValidatedAt) == 0 && utcOffset(value.ExpiresAt) == 0 && value.ExpiresAt.After(value.ValidatedAt)
}

func utcOffset(value time.Time) int {
	_, offset := value.Zone()
	return offset
}
