// Command controlmetricsexporter serves aggregate control-plane metrics from a
// private or loopback listener using only the sentinelflow_metrics database role.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/controlmetrics"
)

const databaseRole = "sentinelflow_metrics"

type databasePool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Ping(context.Context) error
	Close()
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow control metrics exporter failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	config, err := controlmetrics.Load()
	if err != nil || !config.Valid() {
		return errors.New("control metrics exporter configuration rejected")
	}
	pool, err := openPool(ctx, config)
	if err != nil {
		return errors.New("control metrics exporter database unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil || validateDatabaseIdentity(ctx, pool) != nil {
		return errors.New("control metrics exporter database identity rejected")
	}
	store, err := controlmetrics.NewStore(pool)
	if err != nil {
		return errors.New("control metrics exporter store rejected")
	}
	handler, err := controlmetrics.Handler(store, config.ScrapeTimeout())
	if err != nil {
		return errors.New("control metrics exporter handler rejected")
	}
	listener, err := net.Listen("tcp4", config.ListenAddress())
	if err != nil {
		return errors.New("control metrics exporter listener unavailable")
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       config.ScrapeTimeout() + time.Second,
		WriteTimeout:      config.ScrapeTimeout() + time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("control metrics exporter shutdown failed")
		}
		err := <-result
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("control metrics exporter server failed")
		}
		return ctx.Err()
	case err := <-result:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("control metrics exporter server failed")
		}
		return nil
	}
}

func openPool(ctx context.Context, config controlmetrics.Config) (databasePool, error) {
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL())
	if err != nil || poolConfig.ConnConfig.User != databaseRole ||
		poolConfig.ConnConfig.Database != "sentinelflow" ||
		poolConfig.ConnConfig.Password == "" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return nil, errors.New("read database configuration rejected")
	}
	poolConfig.MinConns, poolConfig.MaxConns = 1, 2
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-control-metrics"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("read database unavailable")
	}
	return pool, nil
}

func validateDatabaseIdentity(ctx context.Context, pool databasePool) error {
	if controlmetrics.ValidateDatabaseIdentity(ctx, pool) != nil {
		return errors.New("read database identity rejected")
	}
	return nil
}
