package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/retention"
)

const commandTestDatabaseURL = "postgresql://sentinelflow_retention:retention-secret@postgres:5432/sentinelflow?sslmode=disable"

type scanFunc func(...any) error

func (f scanFunc) Scan(destinations ...any) error { return f(destinations...) }

type fakePool struct {
	role, database string
	boundedRole    bool
	membershipFree bool
	identityQuery  string
	pingErr        error
	closed         bool
}

func (p *fakePool) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	p.identityQuery = query
	return scanFunc(func(destinations ...any) error {
		*destinations[0].(*string) = p.role
		*destinations[1].(*string) = p.database
		*destinations[2].(*bool) = p.boundedRole
		*destinations[3].(*bool) = p.membershipFree
		return nil
	})
}
func (p *fakePool) Ping(context.Context) error { return p.pingErr }
func (p *fakePool) Close()                     { p.closed = true }

type runtimeFunc func(context.Context) (retention.Result, error)

func (f runtimeFunc) RunOnce(ctx context.Context) (retention.Result, error) { return f(ctx) }

func TestRunEmitsOnlySafeAggregateAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &fakePool{
		role: retentionDatabaseRole, database: "sentinelflow",
		boundedRole: true, membershipFree: true,
	}
	var output bytes.Buffer
	result := retention.Result{
		RunID:                "019f0000-0000-4000-8000-000000000023",
		Outcome:              "succeeded",
		EventEvidenceDeleted: 7, ControlPlaneDeleted: 30,
		TransientDeleted: 4, AuditDeleted: 90,
		RunDigest:   "sha256:" + strings.Repeat("a", 64),
		CompletedAt: time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC),
	}
	err := run(ctx, dependencies{
		loadConfig: testConfig,
		openPool: func(context.Context, retention.Config) (databasePool, error) {
			return pool, nil
		},
		newRuntime: func(databasePool, int) (retentionRuntime, error) {
			return runtimeFunc(func(context.Context) (retention.Result, error) {
				cancel()
				return result, nil
			}), nil
		},
		output: &output,
	})
	if !errors.Is(err, context.Canceled) || !pool.closed {
		t.Fatalf("run error=%v closed=%v", err, pool.closed)
	}
	if !strings.Contains(pool.identityQuery,
		"retention_role.oid IN (membership.member, membership.roleid)") {
		t.Fatalf("identity query omitted a membership direction: %q", pool.identityQuery)
	}
	var decoded retention.Result
	if decodeErr := json.Unmarshal(output.Bytes(), &decoded); decodeErr != nil || decoded != result {
		t.Fatalf("safe output=%q decoded=%+v err=%v", output.String(), decoded, decodeErr)
	}
	for _, forbidden := range []string{
		"retention-secret", commandTestDatabaseURL, "target_ipv4", "policy_bytes",
		"evidence_bytes", "session_digest", "canonical_artifact",
	} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("safe output contains %q", forbidden)
		}
	}
}

func TestRunEmitsAuditedStaleLiveResultAndWaitsBeforeRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &fakePool{
		role: retentionDatabaseRole, database: "sentinelflow",
		boundedRole: true, membershipFree: true,
	}
	want := retention.Result{
		RunID:        "019f0000-0000-4000-8000-000000000023",
		Outcome:      "failed",
		FailureCode:  "stale_live_state",
		AnomalyCount: 1,
		RunDigest:    "sha256:" + strings.Repeat("a", 64),
		CompletedAt:  time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC),
	}
	var calls atomic.Int32
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	returned := make(chan error, 1)
	go func() {
		err := run(ctx, dependencies{
			loadConfig: testConfig,
			openPool: func(context.Context, retention.Config) (databasePool, error) {
				return pool, nil
			},
			newRuntime: func(databasePool, int) (retentionRuntime, error) {
				return runtimeFunc(func(context.Context) (retention.Result, error) {
					calls.Add(1)
					return want, retention.ErrStaleLiveState
				}), nil
			},
			output: writer,
		})
		_ = writer.CloseWithError(err)
		returned <- err
	}()

	decodedResult := make(chan retention.Result, 1)
	decodeErrors := make(chan error, 1)
	go func() {
		var decoded retention.Result
		if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
			decodeErrors <- err
			return
		}
		decodedResult <- decoded
	}()
	select {
	case decoded := <-decodedResult:
		if decoded != want {
			t.Fatalf("stale live output=%+v", decoded)
		}
	case err := <-decodeErrors:
		t.Fatalf("stale live output error=%v", err)
	case <-time.After(time.Second):
		t.Fatal("stale live result was not emitted")
	}
	select {
	case err := <-returned:
		t.Fatalf("worker exited before the next interval: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("runtime calls before next interval=%d", got)
	}

	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) || !pool.closed {
			t.Fatalf("run error=%v closed=%v", err, pool.closed)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func TestRunRejectsWrongRoleAndDatabaseBeforeRuntime(t *testing.T) {
	for _, test := range []struct {
		role, database              string
		boundedRole, membershipFree bool
	}{
		{role: "sentinelflow_worker", database: "sentinelflow", boundedRole: true, membershipFree: true},
		{role: retentionDatabaseRole, database: "postgres", boundedRole: true, membershipFree: true},
		{role: retentionDatabaseRole, database: "sentinelflow", boundedRole: false, membershipFree: true},
		{role: retentionDatabaseRole, database: "sentinelflow", boundedRole: true, membershipFree: false},
	} {
		pool := &fakePool{
			role: test.role, database: test.database,
			boundedRole: test.boundedRole, membershipFree: test.membershipFree,
		}
		runtimeCalls := 0
		err := run(context.Background(), dependencies{
			loadConfig: testConfig,
			openPool: func(context.Context, retention.Config) (databasePool, error) {
				return pool, nil
			},
			newRuntime: func(databasePool, int) (retentionRuntime, error) {
				runtimeCalls++
				return nil, errors.New("must not be called")
			},
			output: &bytes.Buffer{},
		})
		if err == nil || runtimeCalls != 0 || !pool.closed {
			t.Fatalf("role=%s database=%s err=%v runtime_calls=%d closed=%v",
				test.role, test.database, err, runtimeCalls, pool.closed)
		}
	}
}

func TestRunFailuresAreGenericAndProduceNoOutput(t *testing.T) {
	secret := "retention-secret"
	tests := []struct {
		name   string
		mutate func(*dependencies, *fakePool)
	}{
		{name: "open", mutate: func(deps *dependencies, _ *fakePool) {
			deps.openPool = func(context.Context, retention.Config) (databasePool, error) {
				return nil, errors.New(secret)
			}
		}},
		{name: "ping", mutate: func(_ *dependencies, pool *fakePool) {
			pool.pingErr = errors.New(secret)
		}},
		{name: "runtime", mutate: func(deps *dependencies, _ *fakePool) {
			deps.newRuntime = func(databasePool, int) (retentionRuntime, error) {
				return runtimeFunc(func(context.Context) (retention.Result, error) {
					return retention.Result{}, errors.New(secret)
				}), nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := &fakePool{
				role: retentionDatabaseRole, database: "sentinelflow",
				boundedRole: true, membershipFree: true,
			}
			var output bytes.Buffer
			deps := dependencies{
				loadConfig: testConfig,
				openPool: func(context.Context, retention.Config) (databasePool, error) {
					return pool, nil
				},
				newRuntime: func(databasePool, int) (retentionRuntime, error) {
					return runtimeFunc(func(context.Context) (retention.Result, error) {
						return retention.Result{}, errors.New(secret)
					}), nil
				},
				output: &output,
			}
			test.mutate(&deps, pool)
			err := run(context.Background(), deps)
			if err == nil || strings.Contains(err.Error(), secret) || output.Len() != 0 {
				t.Fatalf("unsafe failure err=%v output=%q", err, output.String())
			}
		})
	}
}

func TestPostgresRetentionWorkerDirectLogin(t *testing.T) {
	databaseURL := os.Getenv("SENTINELFLOW_RETENTION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINELFLOW_RETENTION_TEST_DATABASE_URL is not set")
	}
	values := map[string]string{
		retention.DatabaseURLName: databaseURL,
		retention.EnvironmentName: "test",
		retention.IntervalName:    "1h",
		retention.RunTimeoutName:  "5s",
		retention.MaxRowsName:     "1000",
	}
	config, err := retention.LoadFrom(
		func(name string) (string, bool) { value, ok := values[name]; return value, ok },
		func() []string {
			result := make([]string, 0, len(values))
			for name, value := range values {
				result = append(result, name+"="+value)
			}
			return result
		},
	)
	if err != nil {
		t.Fatal("retention integration configuration rejected")
	}
	deps := productionDependencies()
	deps.loadConfig = func() (retention.Config, error) { return config, nil }
	var output bytes.Buffer
	deps.output = &output
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = run(ctx, deps)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retention integration worker error=%v", err)
	}
	var result retention.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.RunID == "" ||
		result.Outcome != "succeeded" || result.RunDigest == "" || result.CompletedAt.IsZero() {
		t.Fatalf("retention integration output rejected: %v", err)
	}
}

func testConfig() (retention.Config, error) {
	values := map[string]string{
		retention.DatabaseURLName: commandTestDatabaseURL,
		retention.EnvironmentName: "test",
	}
	return retention.LoadFrom(
		func(name string) (string, bool) { value, ok := values[name]; return value, ok },
		func() []string {
			return []string{
				retention.DatabaseURLName + "=" + commandTestDatabaseURL,
				retention.EnvironmentName + "=test",
			}
		},
	)
}
