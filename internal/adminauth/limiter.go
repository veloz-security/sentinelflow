package adminauth

import (
	"net/netip"
	"sync"
	"time"
)

const (
	LoginPerSourcePerMinute    = 5
	LoginGlobalPerMinute       = 20
	DecisionsPerSessionMinute  = 5
	limiterWindow              = time.Minute
	defaultMaxLoginSources     = 4096
	defaultMaxDecisionSessions = 4096
)

type attemptWindow struct {
	times []time.Time
}

func (w *attemptWindow) prune(cutoff time.Time) {
	first := 0
	for first < len(w.times) && !w.times[first].After(cutoff) {
		first++
	}
	if first == 0 {
		return
	}
	copy(w.times, w.times[first:])
	w.times = w.times[:len(w.times)-first]
}

func (w *attemptWindow) retryAfter(now time.Time) time.Duration {
	if len(w.times) == 0 {
		return time.Second
	}
	retry := w.times[0].Add(limiterWindow).Sub(now)
	if retry <= 0 {
		return time.Second
	}
	return retry
}

// LoginLimiter enforces source and process-wide rolling-window limits before
// password hashing. Its source map is bounded and expired entries are pruned.
type LoginLimiter struct {
	mu         sync.Mutex
	clock      Clock
	maxSources int
	global     attemptWindow
	bySource   map[netip.Addr]*attemptWindow
}

func NewLoginLimiter(clock Clock, maxSources int) (*LoginLimiter, error) {
	if maxSources == 0 {
		maxSources = defaultMaxLoginSources
	}
	if maxSources < 1 || maxSources > 1_000_000 {
		return nil, ErrInvalidConfiguration
	}
	return &LoginLimiter{clock: clock, maxSources: maxSources, bySource: make(map[netip.Addr]*attemptWindow)}, nil
}

// Allow consumes one permitted login attempt. Rate-limited calls do not reach
// Argon2 work and return a positive Retry-After duration.
func (l *LoginLimiter) Allow(source netip.Addr) error {
	if l == nil || !source.IsValid() {
		return &RateLimitError{Scope: RateLimitCapacity, RetryAfter: limiterWindow}
	}
	source = source.Unmap()
	now := clockNow(l.clock)
	cutoff := now.Add(-limiterWindow)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global.prune(cutoff)
	for key, window := range l.bySource {
		window.prune(cutoff)
		if len(window.times) == 0 {
			delete(l.bySource, key)
		}
	}
	if len(l.global.times) >= LoginGlobalPerMinute {
		return &RateLimitError{Scope: RateLimitLoginGlobal, RetryAfter: l.global.retryAfter(now)}
	}
	window := l.bySource[source]
	if window == nil {
		if len(l.bySource) >= l.maxSources {
			return &RateLimitError{Scope: RateLimitCapacity, RetryAfter: l.capacityRetryAfter(now)}
		}
		window = &attemptWindow{}
		l.bySource[source] = window
	}
	if len(window.times) >= LoginPerSourcePerMinute {
		return &RateLimitError{Scope: RateLimitLoginSource, RetryAfter: window.retryAfter(now)}
	}
	window.times = append(window.times, now)
	l.global.times = append(l.global.times, now)
	return nil
}

func (l *LoginLimiter) capacityRetryAfter(now time.Time) time.Duration {
	oldest := time.Time{}
	for _, window := range l.bySource {
		if len(window.times) > 0 && (oldest.IsZero() || window.times[0].Before(oldest)) {
			oldest = window.times[0]
		}
	}
	if oldest.IsZero() {
		return limiterWindow
	}
	retry := oldest.Add(limiterWindow).Sub(now)
	if retry <= 0 {
		return time.Second
	}
	return retry
}

// DecisionLimiter enforces the separate 5/minute/session HIL decision limit.
// It stores only non-secret session IDs and bounded timestamp queues.
type DecisionLimiter struct {
	mu          sync.Mutex
	clock       Clock
	maxSessions int
	bySession   map[SessionID]*attemptWindow
}

func NewDecisionLimiter(clock Clock, maxSessions int) (*DecisionLimiter, error) {
	if maxSessions == 0 {
		maxSessions = defaultMaxDecisionSessions
	}
	if maxSessions < 1 || maxSessions > 1_000_000 {
		return nil, ErrInvalidConfiguration
	}
	return &DecisionLimiter{clock: clock, maxSessions: maxSessions, bySession: make(map[SessionID]*attemptWindow)}, nil
}

func (l *DecisionLimiter) Allow(sessionID SessionID) error {
	if l == nil || sessionID.IsZero() {
		return &RateLimitError{Scope: RateLimitCapacity, RetryAfter: limiterWindow}
	}
	now := clockNow(l.clock)
	cutoff := now.Add(-limiterWindow)
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, window := range l.bySession {
		window.prune(cutoff)
		if len(window.times) == 0 {
			delete(l.bySession, key)
		}
	}
	window := l.bySession[sessionID]
	if window == nil {
		if len(l.bySession) >= l.maxSessions {
			return &RateLimitError{Scope: RateLimitCapacity, RetryAfter: l.decisionCapacityRetryAfter(now)}
		}
		window = &attemptWindow{}
		l.bySession[sessionID] = window
	}
	if len(window.times) >= DecisionsPerSessionMinute {
		return &RateLimitError{Scope: RateLimitDecision, RetryAfter: window.retryAfter(now)}
	}
	window.times = append(window.times, now)
	return nil
}

func (l *DecisionLimiter) decisionCapacityRetryAfter(now time.Time) time.Duration {
	oldest := time.Time{}
	for _, window := range l.bySession {
		if len(window.times) > 0 && (oldest.IsZero() || window.times[0].Before(oldest)) {
			oldest = window.times[0]
		}
	}
	if oldest.IsZero() {
		return limiterWindow
	}
	retry := oldest.Add(limiterWindow).Sub(now)
	if retry <= 0 {
		return time.Second
	}
	return retry
}
