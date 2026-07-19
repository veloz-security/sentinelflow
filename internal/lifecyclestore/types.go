package lifecyclestore

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	DefaultLeaseDuration = 30 * time.Second
	DefaultRetryBackoff  = 5 * time.Second
	MaxLeaseDuration     = 60 * time.Second
	MaxRetryBackoff      = 5 * time.Minute
)

// TransactionBeginner is implemented by pgx.Conn and pgxpool.Pool.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Config struct {
	SchedulerID   string
	LeaseOwner    string
	LeaseDuration time.Duration
	RetryBackoff  time.Duration
}

func DefaultConfig(schedulerID, leaseOwner string) Config {
	return Config{
		SchedulerID: schedulerID, LeaseOwner: leaseOwner,
		LeaseDuration: DefaultLeaseDuration, RetryBackoff: DefaultRetryBackoff,
	}
}

func (Config) String() string {
	return "lifecyclestore.Config{identity:[REDACTED],durations:bounded}"
}

func (c Config) GoString() string { return c.String() }
