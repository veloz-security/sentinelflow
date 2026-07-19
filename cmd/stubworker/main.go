// Command stubworker runs the deterministic offline analysis adapter against
// the same leased PostgreSQL contract as the production analysis worker. It
// has no OpenAI, administrator, HIL, signing, validator, shell, or nftables
// authority.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/aistub"
	"github.com/devwooops/sentinelflow/internal/analysisstore"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/stubworkerconfig"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	stubLeaseOwner = "stub-analysis-worker-01"
	poolSpareConns = 1
)

var errUnexpectedRuntimeExit = errors.New("stub worker runtime exited unexpectedly")

type stubRuntime interface {
	Run(context.Context) error
}

type databasePool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Ping(context.Context) error
	Close()
}

type runtimeDependencies struct {
	openPool   func(context.Context, stubworkerconfig.Config) (databasePool, error)
	newStore   func(context.Context, stubworkerconfig.Config, databasePool) (analysisworker.Store, error)
	newRuntime func(
		analysisworker.Store,
		analysisworker.Analyzer,
		analysisworker.Config,
	) (stubRuntime, error)
}

func productionDependencies() runtimeDependencies {
	return runtimeDependencies{
		openPool: func(ctx context.Context, config stubworkerconfig.Config) (databasePool, error) {
			return openStubPool(ctx, config, func(ctx context.Context, poolConfig *pgxpool.Config) (databasePool, error) {
				return pgxpool.NewWithConfig(ctx, poolConfig)
			})
		},
		newStore: func(
			ctx context.Context,
			config stubworkerconfig.Config,
			pool databasePool,
		) (analysisworker.Store, error) {
			if !config.DemoMode() {
				return analysisstore.NewPostgreSQLStore(pool)
			}
			proof, proofOK := config.DemoHistoryProof()
			secretFile, secretOK := config.DemoHistoryActivationSecretFile()
			if !proofOK || !secretOK {
				return nil, errors.New("stub worker: demo activation configuration rejected")
			}
			secret, err := demohistoryactivation.Load(secretFile)
			if err != nil {
				return nil, errors.New("stub worker: demo activation capability rejected")
			}
			activated, err := demohistoryproof.Attach(
				ctx, proof, pool, validation.DemoHistoryConsumerAnalysis, secret,
			)
			if err != nil {
				return nil, errors.New("stub worker: demo history activation rejected")
			}
			return analysisstore.NewPostgreSQLActivatedDemoStore(pool, activated)
		},
		newRuntime: func(
			store analysisworker.Store,
			analyzer analysisworker.Analyzer,
			config analysisworker.Config,
		) (stubRuntime, error) {
			return analysisworker.New(store, analyzer, config, analysisworker.Dependencies{})
		},
	}
}

type runtimeSet struct {
	runtime  stubRuntime
	pool     databasePool
	identity string
	adapter  string
	workers  int
}

func (r runtimeSet) close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

type runtimeFailure struct{ cause error }

func (*runtimeFailure) Error() string { return "stub worker runtime failed" }
func (e *runtimeFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, productionDependencies()); err != nil {
		logger.Error("stub worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, dependencies runtimeDependencies) error {
	if ctx == nil || logger == nil {
		return errors.New("stub worker: runtime dependencies are required")
	}
	config, err := stubworkerconfig.Load()
	if err != nil {
		return errors.New("stub worker: configuration rejected")
	}
	runtimes, err := buildStubRuntime(ctx, config, dependencies)
	if err != nil {
		return err
	}
	defer runtimes.close()

	logger.Info("deterministic analysis stub worker configured",
		"service", buildinfo.Name,
		"version", buildinfo.Version,
		"provider_kind", runtimes.identity,
		"adapter_id", runtimes.adapter,
		"concurrency", runtimes.workers,
	)
	return superviseRuntime(ctx, runtimes.runtime)
}

func buildStubRuntime(
	ctx context.Context,
	config stubworkerconfig.Config,
	dependencies runtimeDependencies,
) (runtimeSet, error) {
	if ctx == nil || !config.Valid() || dependencies.openPool == nil ||
		dependencies.newStore == nil || dependencies.newRuntime == nil {
		return runtimeSet{}, errors.New("stub worker: invalid runtime configuration")
	}
	pool, err := dependencies.openPool(ctx, config)
	if err != nil || pool == nil {
		return runtimeSet{}, errors.New("stub worker: database pool unavailable")
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()

	store, err := dependencies.newStore(ctx, config, pool)
	if err != nil || store == nil {
		return runtimeSet{}, errors.New("stub worker: configure atomic analysis store")
	}
	analyzer := aistub.New()
	identity := analyzer.Identity()
	workerConfig := analysisworker.DefaultConfig(stubLeaseOwner, "")
	workerConfig.LeaseDuration = config.LeaseDuration()
	workerConfig.PollInterval = config.PollInterval()
	workerConfig.MaxConcurrency = config.MaxConcurrency()
	runtime, err := dependencies.newRuntime(store, analyzer, workerConfig)
	if err != nil || runtime == nil {
		return runtimeSet{}, errors.New("stub worker: configure deterministic analysis runtime")
	}
	failed = false
	return runtimeSet{
		runtime: runtime, pool: pool, identity: string(identity.Kind()),
		adapter: identity.AdapterID(), workers: workerConfig.MaxConcurrency,
	}, nil
}

type poolConnector func(context.Context, *pgxpool.Config) (databasePool, error)

func openStubPool(
	ctx context.Context,
	config stubworkerconfig.Config,
	connect poolConnector,
) (databasePool, error) {
	if ctx == nil || !config.Valid() || connect == nil {
		return nil, errors.New("stub worker: invalid database pool configuration")
	}
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL())
	if err != nil || poolConfig.ConnConfig.User != "sentinelflow_worker" ||
		poolConfig.ConnConfig.Database == "" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return nil, errors.New("stub worker: invalid database pool configuration")
	}
	poolConfig.MaxConns = int32(config.MaxConcurrency() + poolSpareConns)
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "sentinelflow-stub-worker",
	}

	pool, err := connect(ctx, poolConfig)
	if err != nil || pool == nil {
		return nil, errors.New("stub worker: open database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("stub worker: database readiness check failed")
	}
	return pool, nil
}

func superviseRuntime(ctx context.Context, runtime stubRuntime) error {
	if ctx == nil || runtime == nil {
		return errors.New("stub worker: runtime is required")
	}
	err := invokeRuntime(ctx, runtime)
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = errUnexpectedRuntimeExit
	}
	return &runtimeFailure{cause: err}
}

func invokeRuntime(ctx context.Context, runtime stubRuntime) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("stub worker: runtime panic contained")
		}
	}()
	return runtime.Run(ctx)
}
