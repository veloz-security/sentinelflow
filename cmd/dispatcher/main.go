package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/dispatchruntime"
	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

const (
	dispatcherLeaseOwner = "dispatcher-runtime-01"
	dispatcherDBRole     = "sentinelflow_dispatcher"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("dispatcher stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("dispatcher: runtime dependencies are required")
	}
	cfg, err := config.Load(config.RoleDispatcher)
	if err != nil {
		return errors.New("dispatcher: configuration rejected")
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}
	keys, err := dispatchruntime.LoadKeySet(
		cfg.Enforcement.DispatcherSigningKeyFile,
		cfg.Enforcement.DispatcherResultPublicKeyFile,
	)
	if err != nil {
		return errors.New("dispatcher: key configuration rejected")
	}
	pool, err := openDispatcherPool(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := dispatchstore.NewPostgreSQLStore(
		pool, keys.CapabilityVerifier(), keys.ResultVerifier(), nil,
	)
	if err != nil {
		return errors.New("dispatcher: restricted store configuration rejected")
	}
	runtimeStore, err := dispatchruntime.NewPostgreSQLStore(store)
	if err != nil {
		return errors.New("dispatcher: store adapter configuration rejected")
	}
	issuer, err := dispatchruntime.NewIssuer(
		keys.Issuer(), keys.CapabilityVerifier(), nil,
	)
	if err != nil {
		return errors.New("dispatcher: capability issuer configuration rejected")
	}
	identities := keys.Identities()
	client, err := dispatchruntime.NewUDSClient(
		cfg.Enforcement.ExecutorSocket, cfg.Enforcement.ExecutorIOTimeout,
		identities.ResultKeyID, identities.ExecutorID,
	)
	if err != nil {
		return errors.New("dispatcher: executor IPC configuration rejected")
	}
	runtimeConfig := dispatchruntime.DefaultConfig(dispatcherLeaseOwner)
	runtimeConfig.CapabilityTTL = cfg.Enforcement.DispatchCapabilityTTL
	runtimeConfig.ExchangeTimeout = cfg.Enforcement.ExecutorIOTimeout
	dispatcher, err := dispatchruntime.New(
		runtimeStore, issuer, keys.ResultVerifier(), client, runtimeConfig,
		dispatchruntime.Dependencies{},
	)
	if err != nil {
		return errors.New("dispatcher: runtime configuration rejected")
	}
	logger.Info("dispatcher configured", "service", buildinfo.Name, "version", buildinfo.Version)
	if err := dispatcher.Run(ctx); err != nil {
		if ctx.Err() != nil && !errors.Is(err, dispatchruntime.ErrRecoverRequired) {
			return nil
		}
		return err
	}
	return nil
}

func validateRuntimeConfig(cfg config.Config) error {
	if cfg.Role != config.RoleDispatcher ||
		cfg.Enforcement.ExecutorMaxFrameBytes != ipc.MaxFramePayloadBytes ||
		cfg.Enforcement.ExecutorIOTimeout != ipc.MaxExchangeTimeout ||
		cfg.Enforcement.DispatchCapabilityTTL < time.Second ||
		cfg.Enforcement.DispatchCapabilityTTL > time.Minute {
		return errors.New("dispatcher: frozen runtime contract rejected")
	}
	return nil
}

func openDispatcherPool(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.DispatcherURL.Reveal())
	if err != nil {
		return nil, errors.New("dispatcher: invalid database pool configuration")
	}
	poolConfig.MaxConns = 2
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-dispatcher"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("dispatcher: open restricted database pool")
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return nil, errors.New("dispatcher: database readiness check failed")
	}
	var currentRole string
	var databaseNow time.Time
	if err := pool.QueryRow(ctx, `SELECT current_user, clock_timestamp()`).Scan(
		&currentRole, &databaseNow,
	); err != nil || currentRole != dispatcherDBRole || databaseNow.IsZero() {
		return nil, errors.New("dispatcher: restricted database role check failed")
	}
	failed = false
	return pool, nil
}
