package adminauth

import "time"

// Clock is injected so boundary behavior can be tested without changing
// process-global time.
type Clock interface {
	Now() time.Time
}

func clockNow(clock Clock) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock.Now().UTC()
}
