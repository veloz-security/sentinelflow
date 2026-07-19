package retention

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrRuntime = errors.New("retention runtime failed")

type runner interface {
	CurrentTime(context.Context) (time.Time, error)
	Run(context.Context, string, time.Time, int) (Result, error)
}

type idFunc func() (string, error)

// Runtime serializes runs inside one process. PostgreSQL additionally holds a
// transaction-scoped advisory lock, so multiple replicas cannot prune in
// parallel either.
type Runtime struct {
	runner  runner
	newID   idFunc
	maxRows int
	mu      sync.Mutex
}

func NewRuntime(database runner, maxRows int) (*Runtime, error) {
	return newRuntime(database, maxRows, randomUUID)
}

func newRuntime(database runner, maxRows int, newID idFunc) (*Runtime, error) {
	if database == nil || maxRows < 1 || maxRows > 10000 || newID == nil {
		return nil, ErrInvariant
	}
	return &Runtime{runner: database, newID: newID, maxRows: maxRows}, nil
}

func (r *Runtime) RunOnce(ctx context.Context) (Result, error) {
	if r == nil || r.runner == nil || ctx == nil {
		return Result{}, ErrInvariant
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	runID, err := r.newID()
	if err != nil || !uuidPattern.MatchString(runID) {
		return Result{}, ErrRuntime
	}
	asOf, err := r.runner.CurrentTime(ctx)
	if err != nil || asOf.IsZero() {
		return Result{}, ErrRuntime
	}
	result, err := r.runner.Run(ctx, runID, asOf, r.maxRows)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Result{}, err
		}
		if errors.Is(err, ErrStaleLiveState) {
			if result.RunID != runID {
				return Result{}, ErrRuntime
			}
			return result, ErrStaleLiveState
		}
		return Result{}, ErrRuntime
	}
	if result.RunID != runID {
		return Result{}, ErrRuntime
	}
	return result, nil
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}
