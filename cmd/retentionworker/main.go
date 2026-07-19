// Command retentionworker periodically invokes the database-owned retention
// transaction using a dedicated least-privilege role. It has no listener and
// no AI, HIL, dispatcher, executor, validator, or nftables authority.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/retention"
)

const retentionDatabaseRole = "sentinelflow_retention"

type databasePool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Ping(context.Context) error
	Close()
}

type retentionRuntime interface {
	RunOnce(context.Context) (retention.Result, error)
}

type dependencies struct {
	loadConfig func() (retention.Config, error)
	openPool   func(context.Context, retention.Config) (databasePool, error)
	newRuntime func(databasePool, int) (retentionRuntime, error)
	output     io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, productionDependencies()); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow retention worker failed")
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		loadConfig: retention.Load,
		openPool: func(ctx context.Context, config retention.Config) (databasePool, error) {
			poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL())
			if err != nil || poolConfig.ConnConfig.User != retentionDatabaseRole ||
				poolConfig.ConnConfig.Database != "sentinelflow" ||
				poolConfig.ConnConfig.Password == "" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
				return nil, errors.New("retention database configuration rejected")
			}
			poolConfig.MinConns = 1
			poolConfig.MaxConns = 1
			poolConfig.MaxConnLifetime = 30 * time.Minute
			poolConfig.MaxConnIdleTime = 5 * time.Minute
			poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-retention-worker"
			pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
			if err != nil {
				return nil, errors.New("retention database unavailable")
			}
			return pool, nil
		},
		newRuntime: func(pool databasePool, maxRows int) (retentionRuntime, error) {
			store, err := retention.NewStore(pool)
			if err != nil {
				return nil, err
			}
			return retention.NewRuntime(store, maxRows)
		},
		output: os.Stdout,
	}
}

func run(ctx context.Context, deps dependencies) error {
	if ctx == nil || deps.loadConfig == nil || deps.openPool == nil ||
		deps.newRuntime == nil || deps.output == nil {
		return errors.New("retention worker dependencies rejected")
	}
	config, err := deps.loadConfig()
	if err != nil || !config.Valid() {
		return errors.New("retention worker configuration rejected")
	}
	pool, err := deps.openPool(ctx, config)
	if err != nil || pool == nil {
		return errors.New("retention worker database unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("retention worker database readiness failed")
	}
	var currentRole, currentDatabase string
	var boundedRole, membershipFree bool
	if err := pool.QueryRow(ctx, `
SELECT current_user::text, current_database()::text,
       COALESCE((
           SELECT role.rolcanlogin AND NOT role.rolinherit AND NOT role.rolsuper AND
                  NOT role.rolcreatedb AND NOT role.rolcreaterole AND
                  NOT role.rolreplication AND NOT role.rolbypassrls
           FROM pg_roles role WHERE role.rolname = current_user
       ), false),
       NOT EXISTS (
           SELECT 1 FROM pg_auth_members membership
           JOIN pg_roles retention_role
             ON retention_role.oid IN (membership.member, membership.roleid)
           WHERE retention_role.rolname = current_user
       )`).Scan(
		&currentRole, &currentDatabase, &boundedRole, &membershipFree,
	); err != nil || currentRole != retentionDatabaseRole ||
		currentDatabase != "sentinelflow" || !boundedRole || !membershipFree {
		return errors.New("retention worker database identity rejected")
	}
	runtime, err := deps.newRuntime(pool, config.MaxRows())
	if err != nil || runtime == nil {
		return errors.New("retention worker runtime rejected")
	}
	for {
		runContext, cancel := context.WithTimeout(ctx, config.RunTimeout())
		result, runErr := runtime.RunOnce(runContext)
		cancel()
		if runErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !errors.Is(runErr, retention.ErrStaleLiveState) {
				return errors.New("retention worker atomic run failed")
			}
		}
		if err := json.NewEncoder(deps.output).Encode(result); err != nil {
			return errors.New("retention worker safe result output failed")
		}
		timer := time.NewTimer(config.Interval())
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
