package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/lifecycleconfig"
)

const commandTestDatabaseURL = "postgresql://sentinelflow_lifecycle:lifecycle-secret@postgres:5432/sentinelflow?sslmode=disable"

type scanFunc func(...any) error

func (f scanFunc) Scan(destinations ...any) error { return f(destinations...) }

type fakePool struct {
	role, database                     string
	boundedRole, membershipFree        bool
	schemaUsage, schemaCreateFree      bool
	relationFree, sequenceFree         bool
	exactFunctions, otherFunctionsFree bool
	identityQuery                      string
	pingErr, scanErr                   error
	nilRow                             bool
	closed                             atomic.Bool
}

func authorizedFakePool() *fakePool {
	return &fakePool{
		role: lifecycleDatabaseRole, database: "sentinelflow",
		boundedRole: true, membershipFree: true,
		schemaUsage: true, schemaCreateFree: true,
		relationFree: true, sequenceFree: true,
		exactFunctions: true, otherFunctionsFree: true,
	}
}

func (p *fakePool) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	p.identityQuery = query
	if p.nilRow {
		return nil
	}
	return scanFunc(func(destinations ...any) error {
		if p.scanErr != nil {
			return p.scanErr
		}
		*destinations[0].(*string) = p.role
		*destinations[1].(*string) = p.database
		*destinations[2].(*bool) = p.boundedRole
		*destinations[3].(*bool) = p.membershipFree
		*destinations[4].(*bool) = p.schemaUsage
		*destinations[5].(*bool) = p.schemaCreateFree
		*destinations[6].(*bool) = p.relationFree
		*destinations[7].(*bool) = p.sequenceFree
		*destinations[8].(*bool) = p.exactFunctions
		*destinations[9].(*bool) = p.otherFunctionsFree
		return nil
	})
}
func (*fakePool) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}
func (p *fakePool) Ping(context.Context) error { return p.pingErr }
func (p *fakePool) Close()                     { p.closed.Store(true) }

type runtimeFunc func(context.Context) error

func (f runtimeFunc) Run(ctx context.Context) error { return f(ctx) }

func TestRunVerifiesExactAuthorityBeforeLongRunningRuntimeAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := authorizedFakePool()
	var runtimeCalls atomic.Int32
	err := run(ctx, dependencies{
		loadConfig: testConfig,
		openPool: func(context.Context, lifecycleconfig.Config) (databasePool, error) {
			return pool, nil
		},
		newRuntime: func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
			return runtimeFunc(func(context.Context) error {
				runtimeCalls.Add(1)
				cancel()
				return nil
			}), nil
		},
	})
	if !errors.Is(err, context.Canceled) || !pool.closed.Load() || runtimeCalls.Load() != 1 {
		t.Fatalf("run error=%v closed=%v runtime_calls=%d", err, pool.closed.Load(), runtimeCalls.Load())
	}
	for _, required := range []string{
		"current_user::text", "current_database()::text", "role.rolconnlimit = 4",
		"NOT role.rolinherit",
		"membership.member, membership.roleid", "has_schema_privilege",
		"has_table_privilege", "has_sequence_privilege", "has_function_privilege",
		"claim_lifecycle_inspection_schedule_000026",
		"commit_lifecycle_inspection_000026",
		"finish_lifecycle_inspection_failure_000026",
	} {
		if !strings.Contains(pool.identityQuery, required) {
			t.Errorf("authority query missing %q", required)
		}
	}
}

func TestRunRejectsEveryAuthorityDriftBeforeRuntime(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakePool)
	}{
		{name: "role", mutate: func(p *fakePool) { p.role = "sentinelflow_worker" }},
		{name: "database", mutate: func(p *fakePool) { p.database = "postgres" }},
		{name: "role flags", mutate: func(p *fakePool) { p.boundedRole = false }},
		{name: "membership", mutate: func(p *fakePool) { p.membershipFree = false }},
		{name: "schema usage", mutate: func(p *fakePool) { p.schemaUsage = false }},
		{name: "schema create", mutate: func(p *fakePool) { p.schemaCreateFree = false }},
		{name: "relation", mutate: func(p *fakePool) { p.relationFree = false }},
		{name: "sequence", mutate: func(p *fakePool) { p.sequenceFree = false }},
		{name: "missing exact function", mutate: func(p *fakePool) { p.exactFunctions = false }},
		{name: "other function", mutate: func(p *fakePool) { p.otherFunctionsFree = false }},
		{name: "missing row", mutate: func(p *fakePool) { p.nilRow = true }},
		{name: "query failure", mutate: func(p *fakePool) { p.scanErr = errors.New("database-secret") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := authorizedFakePool()
			test.mutate(pool)
			runtimeCalls := 0
			err := run(context.Background(), dependencies{
				loadConfig: testConfig,
				openPool: func(context.Context, lifecycleconfig.Config) (databasePool, error) {
					return pool, nil
				},
				newRuntime: func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
					runtimeCalls++
					return nil, errors.New("must not be called")
				},
			})
			if err == nil || strings.Contains(err.Error(), "database-secret") || runtimeCalls != 0 || !pool.closed.Load() {
				t.Fatalf("err=%v runtime_calls=%d closed=%v", err, runtimeCalls, pool.closed.Load())
			}
		})
	}
}

func TestRunFailuresAreContentFreeAndRuntimeStopsFailClosed(t *testing.T) {
	secret := "lifecycle-secret"
	tests := []struct {
		name   string
		mutate func(*dependencies, *fakePool)
	}{
		{name: "configuration", mutate: func(deps *dependencies, _ *fakePool) {
			deps.loadConfig = func() (lifecycleconfig.Config, error) { return lifecycleconfig.Config{}, errors.New(secret) }
		}},
		{name: "open", mutate: func(deps *dependencies, _ *fakePool) {
			deps.openPool = func(context.Context, lifecycleconfig.Config) (databasePool, error) {
				return nil, errors.New(secret)
			}
		}},
		{name: "ping", mutate: func(_ *dependencies, pool *fakePool) { pool.pingErr = errors.New(secret) }},
		{name: "construct", mutate: func(deps *dependencies, _ *fakePool) {
			deps.newRuntime = func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
				return nil, errors.New(secret)
			}
		}},
		{name: "runtime error", mutate: func(deps *dependencies, _ *fakePool) {
			deps.newRuntime = func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
				return runtimeFunc(func(context.Context) error { return errors.New(secret) }), nil
			}
		}},
		{name: "unexpected stop", mutate: func(deps *dependencies, _ *fakePool) {
			deps.newRuntime = func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
				return runtimeFunc(func(context.Context) error { return nil }), nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := authorizedFakePool()
			deps := dependencies{
				loadConfig: testConfig,
				openPool: func(context.Context, lifecycleconfig.Config) (databasePool, error) {
					return pool, nil
				},
				newRuntime: func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
					return runtimeFunc(func(context.Context) error { return nil }), nil
				},
			}
			test.mutate(&deps, pool)
			err := run(context.Background(), deps)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), commandTestDatabaseURL) {
				t.Fatalf("unsafe failure: %v", err)
			}
		})
	}
}

func TestRunReturnsPromptlyWhenRuntimeObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := authorizedFakePool()
	started := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		returned <- run(ctx, dependencies{
			loadConfig: testConfig,
			openPool: func(context.Context, lifecycleconfig.Config) (databasePool, error) {
				return pool, nil
			},
			newRuntime: func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
				return runtimeFunc(func(ctx context.Context) error {
					close(started)
					<-ctx.Done()
					return nil
				}), nil
			},
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not start")
	}
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) || !pool.closed.Load() {
			t.Fatalf("run error=%v closed=%v", err, pool.closed.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func TestRunDoesNotOpenDatabaseAfterStartupCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var configCalls, openCalls atomic.Int32
	err := run(ctx, dependencies{
		loadConfig: func() (lifecycleconfig.Config, error) {
			configCalls.Add(1)
			return testConfig()
		},
		openPool: func(context.Context, lifecycleconfig.Config) (databasePool, error) {
			openCalls.Add(1)
			return authorizedFakePool(), nil
		},
		newRuntime: func(databasePool, lifecycleconfig.Config) (lifecycleRuntime, error) {
			return runtimeFunc(func(context.Context) error { return nil }), nil
		},
	})
	if !errors.Is(err, context.Canceled) || configCalls.Load() != 0 || openCalls.Load() != 0 {
		t.Fatalf("error=%v config_calls=%d open_calls=%d", err, configCalls.Load(), openCalls.Load())
	}
}

func TestPostgresLifecycleWorkerAuthority(t *testing.T) {
	databaseURL := os.Getenv("SENTINELFLOW_LIFECYCLE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINELFLOW_LIFECYCLE_TEST_DATABASE_URL is not set")
	}
	values := map[string]string{
		lifecycleconfig.DatabaseURLName: databaseURL,
		lifecycleconfig.EnvironmentName: "test",
	}
	config, err := lifecycleconfig.LoadFrom(
		func(name string) (string, bool) { value, ok := values[name]; return value, ok },
		func() []string {
			return []string{
				lifecycleconfig.DatabaseURLName + "=" + databaseURL,
				lifecycleconfig.EnvironmentName + "=test",
			}
		},
	)
	if err != nil {
		t.Fatal("lifecycle integration configuration rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := productionDependencies().openPool(ctx, config)
	if err != nil {
		t.Fatal("lifecycle integration database unavailable")
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil || verifyDatabaseAuthority(ctx, pool) != nil {
		t.Fatal("lifecycle integration authority rejected")
	}
}

func testConfig() (lifecycleconfig.Config, error) {
	values := map[string]string{
		lifecycleconfig.DatabaseURLName: commandTestDatabaseURL,
		lifecycleconfig.EnvironmentName: "test",
	}
	return lifecycleconfig.LoadFrom(
		func(name string) (string, bool) { value, ok := values[name]; return value, ok },
		func() []string {
			return []string{
				lifecycleconfig.DatabaseURLName + "=" + commandTestDatabaseURL,
				lifecycleconfig.EnvironmentName + "=test",
			}
		},
	)
}
