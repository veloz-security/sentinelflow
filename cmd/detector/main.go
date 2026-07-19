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

	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/detectionworker"
)

const (
	detectorLeaseOwner = "detector-worker-01"
	detectorMaxConns   = int32(2)
)

var errUnexpectedRuntimeExit = errors.New("detector runtime exited unexpectedly")

type detectorRuntime interface {
	Run(context.Context) error
}

type databasePool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Ping(context.Context) error
	Close()
}

type runtimeDependencies struct {
	openPool   func(context.Context, config.Config) (databasePool, error)
	newStore   func(databasePool) (detectionworker.Store, error)
	newRuntime func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error)
}

func productionDependencies() runtimeDependencies {
	return runtimeDependencies{
		openPool: func(ctx context.Context, runtimeConfig config.Config) (databasePool, error) {
			return openDetectorPool(ctx, runtimeConfig, func(ctx context.Context, poolConfig *pgxpool.Config) (databasePool, error) {
				return pgxpool.NewWithConfig(ctx, poolConfig)
			})
		},
		newStore: func(pool databasePool) (detectionworker.Store, error) {
			return detectionworker.NewPostgreSQLStore(pool)
		},
		newRuntime: func(store detectionworker.Store, detector *detection.Detector, workerConfig detectionworker.Config) (detectorRuntime, error) {
			return detectionworker.New(store, detector, workerConfig, detectionworker.Dependencies{})
		},
	}
}

type runtimeSet struct {
	runtime             detectorRuntime
	pool                databasePool
	configurationDigest string
}

func (r runtimeSet) close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

type runtimeFailure struct{ cause error }

func (*runtimeFailure) Error() string { return "detector runtime failed" }

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
	if err := run(ctx, logger); err != nil {
		logger.Error("detector stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("detector: runtime dependencies are required")
	}
	runtimeConfig, err := config.Load(config.RoleDetector)
	if err != nil {
		return errors.New("detector: configuration rejected")
	}
	runtimes, err := buildDetectorRuntime(ctx, runtimeConfig, productionDependencies())
	if err != nil {
		return err
	}
	defer runtimes.close()

	logger.Info("deterministic detector configured",
		"service", buildinfo.Name,
		"version", buildinfo.Version,
		"configuration_digest", runtimes.configurationDigest,
	)
	return superviseRuntime(ctx, runtimes.runtime)
}

func buildDetectorRuntime(ctx context.Context, runtimeConfig config.Config, dependencies runtimeDependencies) (runtimeSet, error) {
	if ctx == nil || !validRuntimeConfig(runtimeConfig) || dependencies.openPool == nil ||
		dependencies.newStore == nil || dependencies.newRuntime == nil {
		return runtimeSet{}, errors.New("detector: invalid runtime configuration")
	}

	detector, err := detection.New(mapDetectionConfig(runtimeConfig))
	if err != nil {
		return runtimeSet{}, errors.New("detector: frozen detection configuration rejected")
	}
	pool, err := dependencies.openPool(ctx, runtimeConfig)
	if err != nil || pool == nil {
		return runtimeSet{}, errors.New("detector: database pool unavailable")
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()

	store, err := dependencies.newStore(pool)
	if err != nil || store == nil {
		return runtimeSet{}, errors.New("detector: configure PostgreSQL store")
	}
	workerConfig := detectionworker.DefaultConfig(detectorLeaseOwner)
	detectorRuntime, err := dependencies.newRuntime(store, detector, workerConfig)
	if err != nil || detectorRuntime == nil {
		return runtimeSet{}, errors.New("detector: configure deterministic runtime")
	}
	failed = false
	return runtimeSet{
		runtime:             detectorRuntime,
		pool:                pool,
		configurationDigest: detector.ConfigurationDigest(),
	}, nil
}

func validRuntimeConfig(value config.Config) bool {
	if value.Role != config.RoleDetector || !value.Database.WorkerURL.IsSet() {
		return false
	}
	// LoadFrom rejects these inputs before parsing. Repeat the authority check
	// here so tests or future embedders cannot bypass role isolation by building
	// Config directly.
	return !value.Database.MigrationURL.IsSet() &&
		!value.Database.APIURL.IsSet() &&
		!value.Database.ReadURL.IsSet() &&
		!value.Database.DispatcherURL.IsSet() &&
		!value.OpenAI.APIKey.IsSet() &&
		!value.Admin.PasswordArgon2idHash.IsSet() &&
		!value.Admin.SessionHMACKey.IsSet() &&
		!value.Events.GatewayHMACKey.IsSet() &&
		!value.Events.AuthHMACKey.IsSet() &&
		!value.Events.AuthAccountHashKey.IsSet() &&
		value.Enforcement.DispatcherSigningKeyFile == "" &&
		value.Enforcement.ExecutorDispatchPublicKeyFile == "" &&
		value.Enforcement.ExecutorResultPrivateKeyFile == "" &&
		value.Enforcement.DispatcherResultPublicKeyFile == "" &&
		value.Demo.HistoryPublicKeyFile == "" &&
		value.Demo.HistorySimulatorPrivateKeyFile == ""
}

func mapDetectionConfig(runtimeConfig config.Config) detection.Config {
	suspiciousPathIDs := make([]detection.SuspiciousPathID, len(runtimeConfig.Detection.SuspiciousPathIDs))
	for index, value := range runtimeConfig.Detection.SuspiciousPathIDs {
		suspiciousPathIDs[index] = detection.SuspiciousPathID(value)
	}
	return detection.Config{
		Version:                            detection.DefaultConfigurationVersion,
		PathCatalogVersion:                 runtimeConfig.Gateway.PathCatalogVersion,
		LoginRouteLabel:                    runtimeConfig.Gateway.AuthRouteLabel,
		SuspiciousPathIDs:                  suspiciousPathIDs,
		PathScanThreshold:                  runtimeConfig.Detection.PathScanUniquePaths,
		PathScanWindow:                     runtimeConfig.Detection.PathScanWindow,
		RequestBurstThreshold:              runtimeConfig.Detection.RequestBurstCount,
		RequestBurstWindow:                 runtimeConfig.Detection.RequestBurstWindow,
		LoginBruteForceThreshold:           runtimeConfig.Detection.BruteForceFailures,
		LoginBruteForceWindow:              runtimeConfig.Detection.BruteForceWindow,
		CredentialStuffingEventThreshold:   runtimeConfig.Detection.CredentialStuffingFailures,
		CredentialStuffingAccountThreshold: runtimeConfig.Detection.CredentialStuffingUniqueAccounts,
		CredentialStuffingWindow:           runtimeConfig.Detection.CredentialStuffingWindow,
	}
}

type poolConnector func(context.Context, *pgxpool.Config) (databasePool, error)

func openDetectorPool(ctx context.Context, runtimeConfig config.Config, connect poolConnector) (databasePool, error) {
	if ctx == nil || runtimeConfig.Role != config.RoleDetector || !runtimeConfig.Database.WorkerURL.IsSet() || connect == nil {
		return nil, errors.New("detector: invalid database pool configuration")
	}
	poolConfig, err := pgxpool.ParseConfig(runtimeConfig.Database.WorkerURL.Reveal())
	if err != nil {
		return nil, errors.New("detector: invalid database pool configuration")
	}
	poolConfig.MaxConns = detectorMaxConns
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-detector"

	pool, err := connect(ctx, poolConfig)
	if err != nil || pool == nil {
		return nil, errors.New("detector: open database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("detector: database readiness check failed")
	}
	return pool, nil
}

func superviseRuntime(ctx context.Context, runtime detectorRuntime) error {
	if ctx == nil || runtime == nil {
		return errors.New("detector: runtime is required")
	}
	err := runtime.Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = errUnexpectedRuntimeExit
	}
	return &runtimeFailure{cause: err}
}
