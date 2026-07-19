package worker

import (
	"errors"
	"fmt"
	"time"
)

type BackoffPolicy struct {
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

func (p BackoffPolicy) validate() error {
	if p.BaseDelay <= 0 || p.MaxDelay <= 0 || p.BaseDelay > p.MaxDelay {
		return errors.New("worker: invalid backoff policy")
	}
	return nil
}

// Delay returns equal jitter in [exponential/2, exponential], capped by
// MaxDelay. Given an attempt and jitter value it is entirely deterministic.
func (p BackoffPolicy) Delay(attempt int32, jitter uint64) (time.Duration, error) {
	if err := p.validate(); err != nil {
		return 0, err
	}
	if attempt < 1 {
		return 0, fmt.Errorf("worker: invalid attempt")
	}

	delay := p.BaseDelay
	for current := int32(1); current < attempt && delay < p.MaxDelay; current++ {
		if delay > p.MaxDelay/2 {
			delay = p.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}

	floor := delay / 2
	if floor == 0 {
		floor = delay
	}
	span := delay - floor
	if span == 0 {
		return floor, nil
	}
	return floor + time.Duration(jitter%(uint64(span)+1)), nil
}
