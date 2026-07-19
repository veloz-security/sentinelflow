// Command lifecycleworker prepares database-authorized, read-only nftables
// inspection work through a dedicated least-privilege PostgreSQL role. It has
// no listener, mutation bytes, HIL, AI, dispatcher, executor, validator,
// signing-key, or nftables authority.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/lifecycleconfig"
	"github.com/devwooops/sentinelflow/internal/lifecycleruntime"
	"github.com/devwooops/sentinelflow/internal/lifecyclestore"
)

const lifecycleDatabaseRole = "sentinelflow_lifecycle"

const lifecycleAuthorityQuery = `
WITH allowed_functions(function_oid) AS (
    VALUES
      (to_regprocedure(
        'sentinelflow.claim_lifecycle_inspection_schedule_000026(sentinelflow.ascii_id,sentinelflow.ascii_id,integer)'
      )),
      (to_regprocedure(
        'sentinelflow.commit_lifecycle_inspection_000026(uuid,uuid,integer,sentinelflow.ascii_id,uuid,bytea,sentinelflow.sha256_digest,bytea,sentinelflow.sha256_digest)'
      )),
      (to_regprocedure(
        'sentinelflow.finish_lifecycle_inspection_failure_000026(uuid,uuid,integer,sentinelflow.ascii_id,sentinelflow.sha256_digest,integer)'
      ))
), role_state AS (
    SELECT role.rolcanlogin AND role.rolconnlimit = 4 AND
           NOT role.rolinherit AND NOT role.rolsuper AND
           NOT role.rolcreatedb AND NOT role.rolcreaterole AND
           NOT role.rolreplication AND NOT role.rolbypassrls AS bounded
    FROM pg_roles role
    WHERE role.rolname = current_user
)
SELECT
    current_user::text,
    current_database()::text,
    COALESCE((SELECT bounded FROM role_state), false),
    NOT EXISTS (
        SELECT 1
        FROM pg_auth_members membership
        JOIN pg_roles lifecycle_role
          ON lifecycle_role.oid IN (membership.member, membership.roleid)
        WHERE lifecycle_role.rolname = current_user
    ),
    has_schema_privilege(current_user, 'sentinelflow', 'USAGE'),
    NOT has_schema_privilege(current_user, 'sentinelflow', 'CREATE'),
    NOT EXISTS (
        SELECT 1
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'sentinelflow'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (
            has_table_privilege(current_user, relation.oid, 'SELECT') OR
            has_table_privilege(current_user, relation.oid, 'INSERT') OR
            has_table_privilege(current_user, relation.oid, 'UPDATE') OR
            has_table_privilege(current_user, relation.oid, 'DELETE') OR
            has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR
            has_table_privilege(current_user, relation.oid, 'REFERENCES') OR
            has_table_privilege(current_user, relation.oid, 'TRIGGER')
          )
    ),
    NOT EXISTS (
        SELECT 1
        FROM pg_class sequence
        JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
        WHERE namespace.nspname = 'sentinelflow'
          AND sequence.relkind = 'S'
          AND (
            has_sequence_privilege(current_user, sequence.oid, 'SELECT') OR
            has_sequence_privilege(current_user, sequence.oid, 'UPDATE') OR
            has_sequence_privilege(current_user, sequence.oid, 'USAGE')
          )
    ),
    (
        SELECT count(*) = 3 AND bool_and(
            function_oid IS NOT NULL AND
            has_function_privilege(current_user, function_oid, 'EXECUTE')
        )
        FROM allowed_functions
    ),
    NOT EXISTS (
        SELECT 1
        FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        WHERE namespace.nspname = 'sentinelflow'
          AND has_function_privilege(current_user, function.oid, 'EXECUTE')
          AND function.oid NOT IN (
              SELECT function_oid FROM allowed_functions WHERE function_oid IS NOT NULL
          )
    )`

type databasePool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Ping(context.Context) error
	Close()
}

type lifecycleRuntime interface {
	Run(context.Context) error
}

type dependencies struct {
	loadConfig func() (lifecycleconfig.Config, error)
	openPool   func(context.Context, lifecycleconfig.Config) (databasePool, error)
	newRuntime func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, productionDependencies()); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow lifecycle worker failed")
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		loadConfig: lifecycleconfig.Load,
		openPool: func(ctx context.Context, config lifecycleconfig.Config) (databasePool, error) {
			poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL())
			if err != nil || poolConfig.ConnConfig.User != lifecycleDatabaseRole ||
				poolConfig.ConnConfig.Database != "sentinelflow" ||
				poolConfig.ConnConfig.Password == "" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
				return nil, errors.New("lifecycle database configuration rejected")
			}
			poolConfig.MinConns = 1
			poolConfig.MaxConns = 1
			poolConfig.MaxConnLifetime = 30 * time.Minute
			poolConfig.MaxConnIdleTime = 5 * time.Minute
			poolConfig.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-lifecycle-worker"
			pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
			if err != nil {
				return nil, errors.New("lifecycle database unavailable")
			}
			return pool, nil
		},
		newRuntime: func(pool databasePool, config lifecycleconfig.Config) (lifecycleRuntime, error) {
			storeConfig := lifecyclestore.DefaultConfig(config.SchedulerID(), config.LeaseOwner())
			storeConfig.LeaseDuration = config.LeaseDuration()
			storeConfig.RetryBackoff = config.RetryBackoff()
			store, err := lifecyclestore.NewPostgreSQLStore(pool, storeConfig)
			if err != nil {
				return nil, err
			}
			runtimeConfig := lifecycleruntime.DefaultConfig(config.SchedulerID())
			runtimeConfig.PollInterval = config.PollInterval()
			runtimeConfig.CleanupTimeout = config.CleanupTimeout()
			return lifecycleruntime.New(store, runtimeConfig, lifecycleruntime.Dependencies{})
		},
	}
}

func run(ctx context.Context, deps dependencies) error {
	if ctx == nil || deps.loadConfig == nil || deps.openPool == nil || deps.newRuntime == nil {
		return errors.New("lifecycle worker dependencies rejected")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	config, err := deps.loadConfig()
	if err != nil || !config.Valid() {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("lifecycle worker configuration rejected")
	}
	pool, err := deps.openPool(ctx, config)
	if err != nil || pool == nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("lifecycle worker database unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("lifecycle worker database readiness failed")
	}
	if err := verifyDatabaseAuthority(ctx, pool); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("lifecycle worker database authority rejected")
	}
	runtime, err := deps.newRuntime(pool, config)
	if err != nil || runtime == nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("lifecycle worker runtime rejected")
	}
	if err := runtime.Run(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("lifecycle worker runtime failed")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("lifecycle worker runtime stopped")
}

func verifyDatabaseAuthority(ctx context.Context, pool databasePool) error {
	if ctx == nil || pool == nil {
		return errors.New("lifecycle database authority rejected")
	}
	var currentRole, currentDatabase string
	var boundedRole, membershipFree, schemaUsage, schemaCreateFree bool
	var relationFree, sequenceFree, exactFunctions, otherFunctionsFree bool
	row := pool.QueryRow(ctx, lifecycleAuthorityQuery)
	if row == nil {
		return errors.New("lifecycle database authority rejected")
	}
	if err := row.Scan(
		&currentRole, &currentDatabase, &boundedRole, &membershipFree,
		&schemaUsage, &schemaCreateFree, &relationFree, &sequenceFree,
		&exactFunctions, &otherFunctionsFree,
	); err != nil || currentRole != lifecycleDatabaseRole ||
		currentDatabase != "sentinelflow" || !boundedRole || !membershipFree ||
		!schemaUsage || !schemaCreateFree || !relationFree || !sequenceFree ||
		!exactFunctions || !otherFunctionsFree {
		return errors.New("lifecycle database authority rejected")
	}
	return nil
}
