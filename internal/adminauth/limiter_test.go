package adminauth

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginLimiterPerSourceGlobalRetryAndExpiry(t *testing.T) {
	clock := newTestClock()
	limiter, err := NewLoginLimiter(clock, 64)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.10")
	for i := 0; i < LoginPerSourcePerMinute; i++ {
		if err := limiter.Allow(source); err != nil {
			t.Fatalf("attempt %d rejected: %v", i, err)
		}
	}
	err = limiter.Allow(source)
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.Scope != RateLimitLoginSource || limited.RetryAfterSeconds() != 60 {
		t.Fatalf("wrong per-source limit: %#v", err)
	}
	clock.Add(59*time.Second + time.Nanosecond)
	err = limiter.Allow(source)
	if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 1 {
		t.Fatalf("wrong rounded Retry-After: %#v", err)
	}
	clock.Add(time.Second)
	if err := limiter.Allow(source); err != nil {
		t.Fatalf("expired source window not pruned: %v", err)
	}

	clock = newTestClock()
	limiter, _ = NewLoginLimiter(clock, 64)
	for i := 0; i < LoginGlobalPerMinute; i++ {
		address := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		if err := limiter.Allow(address); err != nil {
			t.Fatalf("global attempt %d rejected: %v", i, err)
		}
	}
	err = limiter.Allow(netip.MustParseAddr("198.51.100.1"))
	if !errors.As(err, &limited) || limited.Scope != RateLimitLoginGlobal || limited.RetryAfterSeconds() != 60 {
		t.Fatalf("wrong global limit: %#v", err)
	}
}

func TestLoginLimiterCanonicalSourceCapacityAndConfiguration(t *testing.T) {
	clock := newTestClock()
	limiter, err := NewLoginLimiter(clock, 1)
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	for i := 0; i < 4; i++ {
		if err := limiter.Allow(ipv4); err != nil {
			t.Fatal(err)
		}
	}
	if err := limiter.Allow(mapped); err != nil {
		t.Fatalf("mapped address did not share canonical source: %v", err)
	}
	var limited *RateLimitError
	if err := limiter.Allow(mapped); !errors.As(err, &limited) || limited.Scope != RateLimitLoginSource {
		t.Fatalf("canonical source limit not enforced: %v", err)
	}
	if err := limiter.Allow(netip.MustParseAddr("198.51.100.1")); !errors.As(err, &limited) || limited.Scope != RateLimitCapacity {
		t.Fatalf("capacity did not fail closed: %v", err)
	}
	if err := limiter.Allow(netip.Addr{}); !errors.As(err, &limited) || limited.RetryAfterSeconds() < 1 {
		t.Fatalf("invalid source did not fail closed: %v", err)
	}
	clock.Add(time.Minute + time.Nanosecond)
	if err := limiter.Allow(netip.MustParseAddr("198.51.100.1")); err != nil {
		t.Fatalf("expired capacity entry not reclaimed: %v", err)
	}
	for _, maximum := range []int{-1, 1_000_001} {
		if _, err := NewLoginLimiter(clock, maximum); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid max accepted: %d", maximum)
		}
	}
}

func TestLoginLimiterConcurrentBound(t *testing.T) {
	limiter, err := NewLoginLimiter(newTestClock(), 64)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.20")
	var allowed atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if limiter.Allow(source) == nil {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := allowed.Load(); got != LoginPerSourcePerMinute {
		t.Fatalf("concurrency allowed %d attempts", got)
	}
}

func TestDecisionLimiterBoundaryCapacityAndConcurrency(t *testing.T) {
	clock := newTestClock()
	limiter, err := NewDecisionLimiter(clock, 1)
	if err != nil {
		t.Fatal(err)
	}
	first := SessionID{1}
	second := SessionID{2}
	var allowed atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if limiter.Allow(first) == nil {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := allowed.Load(); got != DecisionsPerSessionMinute {
		t.Fatalf("concurrency allowed %d decision attempts", got)
	}
	var limited *RateLimitError
	if err := limiter.Allow(first); !errors.As(err, &limited) || limited.Scope != RateLimitDecision || limited.RetryAfterSeconds() != 60 {
		t.Fatalf("wrong decision limit: %v", err)
	}
	if err := limiter.Allow(second); !errors.As(err, &limited) || limited.Scope != RateLimitCapacity {
		t.Fatalf("capacity did not fail closed: %v", err)
	}
	clock.Add(time.Minute)
	if err := limiter.Allow(second); err != nil {
		t.Fatalf("expired decision entry not reclaimed: %v", err)
	}
	if err := limiter.Allow(SessionID{}); !errors.As(err, &limited) || limited.RetryAfterSeconds() < 1 {
		t.Fatalf("zero session did not fail closed: %v", err)
	}
	for _, maximum := range []int{-1, 1_000_001} {
		if _, err := NewDecisionLimiter(clock, maximum); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid max accepted: %d", maximum)
		}
	}
}
