package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/detectionworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func TestMapDetectionConfigBindsEveryFrozenRuntimeSetting(t *testing.T) {
	t.Parallel()
	runtimeConfig := loadDetectorConfig(t, nil)
	got := mapDetectionConfig(runtimeConfig)
	want := detection.DefaultConfig()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapped detector config mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if _, err := detection.New(got); err != nil {
		t.Fatalf("mapped defaults rejected: %v", err)
	}

	configuredRoute := loadDetectorConfig(t, map[string]string{"AUTH_ROUTE_LABEL": "signin"})
	got = mapDetectionConfig(configuredRoute)
	if got.LoginRouteLabel != "signin" {
		t.Fatalf("login route label = %q, want configured value", got.LoginRouteLabel)
	}
	if _, err := detection.New(got); err != nil {
		t.Fatalf("configured versioned route rejected: %v", err)
	}
}

func TestBuildDetectorRuntimeUsesBoundedConstructionSeams(t *testing.T) {
	t.Parallel()
	runtimeConfig := loadDetectorConfig(t, nil)
	pool := &fakePool{}
	store := &stubStore{}
	runtime := runtimeFunc(func(context.Context) error { return nil })
	var capturedDetector detection.Config
	var capturedWorker detectionworker.Config
	dependencies := runtimeDependencies{
		openPool: func(ctx context.Context, got config.Config) (databasePool, error) {
			if ctx == nil || got.Role != config.RoleDetector {
				t.Fatal("pool seam received invalid runtime inputs")
			}
			return pool, nil
		},
		newStore: func(got databasePool) (detectionworker.Store, error) {
			if got != pool {
				t.Fatal("store seam did not receive detector pool")
			}
			return store, nil
		},
		newRuntime: func(gotStore detectionworker.Store, detector *detection.Detector, workerConfig detectionworker.Config) (detectorRuntime, error) {
			if gotStore != store || detector == nil {
				t.Fatal("runtime seam received invalid dependencies")
			}
			capturedDetector = detector.Config()
			capturedWorker = workerConfig
			return runtime, nil
		},
	}

	set, err := buildDetectorRuntime(t.Context(), runtimeConfig, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if set.runtime == nil || set.pool != pool || set.configurationDigest == "" {
		t.Fatalf("unexpected runtime set: %+v", set)
	}
	wantDetector, err := detection.New(detection.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capturedDetector, wantDetector.Config()) {
		t.Fatalf("runtime detector config = %#v", capturedDetector)
	}
	wantWorker := detectionworker.DefaultConfig(detectorLeaseOwner)
	if !reflect.DeepEqual(capturedWorker, wantWorker) || capturedWorker.LeaseOwner != detectorLeaseOwner {
		t.Fatalf("runtime worker config = %#v, want %#v", capturedWorker, wantWorker)
	}
	set.close()
	if pool.closeCount != 1 {
		t.Fatalf("pool close count = %d, want 1", pool.closeCount)
	}
}

func TestBuildDetectorRuntimeRejectsRoleAuthorityAndThresholdDrift(t *testing.T) {
	t.Parallel()
	valid := loadDetectorConfig(t, nil)
	dependencies := nonCallingDependencies(t)

	wrongRole := valid
	wrongRole.Role = config.RoleWorker
	if _, err := buildDetectorRuntime(t.Context(), wrongRole, dependencies); err == nil {
		t.Fatal("worker role accepted as deterministic detector")
	}

	workerConfig, err := config.LoadFrom(config.RoleWorker, mapLookup(map[string]string{
		"DATABASE_WORKER_URL":                   detectorDatabaseURL("worker-secret"),
		"OPENAI_API_KEY":                        "sk-" + strings.Repeat("x", 24),
		"OPENAI_RATE_CARD_VERSION":              "operator-test-v1",
		"OPENAI_INPUT_USD_PER_1M_TOKENS":        "1",
		"OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS": "0.25",
		"OPENAI_OUTPUT_USD_PER_1M_TOKENS":       "5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	workerConfig.Role = config.RoleDetector
	if _, err = buildDetectorRuntime(t.Context(), workerConfig, dependencies); err == nil {
		t.Fatal("detector accepted model or validation authority")
	}

	mutations := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"path threshold", func(value *config.Config) { value.Detection.PathScanUniquePaths-- }},
		{"path window", func(value *config.Config) { value.Detection.PathScanWindow -= time.Second }},
		{"path identifiers", func(value *config.Config) { value.Detection.SuspiciousPathIDs = value.Detection.SuspiciousPathIDs[:7] }},
		{"burst threshold", func(value *config.Config) { value.Detection.RequestBurstCount-- }},
		{"burst window", func(value *config.Config) { value.Detection.RequestBurstWindow += time.Second }},
		{"brute force threshold", func(value *config.Config) { value.Detection.BruteForceFailures++ }},
		{"brute force window", func(value *config.Config) { value.Detection.BruteForceWindow += time.Second }},
		{"stuffing failures", func(value *config.Config) { value.Detection.CredentialStuffingFailures++ }},
		{"stuffing accounts", func(value *config.Config) { value.Detection.CredentialStuffingUniqueAccounts++ }},
		{"stuffing window", func(value *config.Config) { value.Detection.CredentialStuffingWindow += time.Second }},
	}
	for _, test := range mutations {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.Detection.SuspiciousPathIDs = append([]string(nil), valid.Detection.SuspiciousPathIDs...)
			test.mutate(&value)
			if _, err := buildDetectorRuntime(t.Context(), value, dependencies); err == nil {
				t.Fatal("frozen detector contract drift was accepted")
			}
		})
	}
}

func TestBuildDetectorRuntimeClosesPoolOnConstructionFailure(t *testing.T) {
	t.Parallel()
	runtimeConfig := loadDetectorConfig(t, nil)
	for _, test := range []struct {
		name       string
		newStore   func(databasePool) (detectionworker.Store, error)
		newRuntime func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error)
	}{
		{
			name:     "store",
			newStore: func(databasePool) (detectionworker.Store, error) { return nil, errors.New("store failure") },
			newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
				return nil, errors.New("must not run")
			},
		},
		{
			name:     "nil store",
			newStore: func(databasePool) (detectionworker.Store, error) { return nil, nil },
			newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
				return nil, errors.New("must not run")
			},
		},
		{
			name:     "runtime",
			newStore: func(databasePool) (detectionworker.Store, error) { return &stubStore{}, nil },
			newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
				return nil, errors.New("runtime failure")
			},
		},
		{
			name:     "nil runtime",
			newStore: func(databasePool) (detectionworker.Store, error) { return &stubStore{}, nil },
			newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
				return nil, nil
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			pool := &fakePool{}
			_, err := buildDetectorRuntime(t.Context(), runtimeConfig, runtimeDependencies{
				openPool: func(context.Context, config.Config) (databasePool, error) { return pool, nil },
				newStore: test.newStore, newRuntime: test.newRuntime,
			})
			if err == nil || pool.closeCount != 1 {
				t.Fatalf("err=%v close count=%d", err, pool.closeCount)
			}
		})
	}
}

func TestBuildDetectorRuntimeRejectsNilPoolFromSeam(t *testing.T) {
	t.Parallel()
	_, err := buildDetectorRuntime(t.Context(), loadDetectorConfig(t, nil), runtimeDependencies{
		openPool: func(context.Context, config.Config) (databasePool, error) { return nil, nil },
		newStore: func(databasePool) (detectionworker.Store, error) { return &stubStore{}, nil },
		newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
			return runtimeFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err == nil {
		t.Fatal("nil database pool accepted")
	}
}

func TestOpenDetectorPoolPinsBoundsIdentityAndReadiness(t *testing.T) {
	t.Parallel()
	runtimeConfig := loadDetectorConfig(t, nil)
	pool := &fakePool{}
	var captured *pgxpool.Config
	got, err := openDetectorPool(t.Context(), runtimeConfig, func(_ context.Context, value *pgxpool.Config) (databasePool, error) {
		captured = value.Copy()
		return pool, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != pool || pool.pingCount != 1 || pool.closeCount != 0 {
		t.Fatalf("pool=%v ping=%d close=%d", got, pool.pingCount, pool.closeCount)
	}
	if captured == nil || captured.MinConns != 1 || captured.MaxConns != detectorMaxConns ||
		captured.MaxConnLifetime != 30*time.Minute || captured.MaxConnIdleTime != 5*time.Minute ||
		captured.HealthCheckPeriod != 30*time.Second ||
		captured.ConnConfig.RuntimeParams["application_name"] != "sentinelflow-detector" {
		t.Fatalf("unexpected pool config: %+v", captured)
	}
	got.Close()
}

func TestOpenDetectorPoolFailsClosedAndRedactsDatabaseInput(t *testing.T) {
	t.Parallel()
	runtimeConfig := loadDetectorConfig(t, nil)
	const secret = "detector-password"

	connectErr := errors.New("connector included " + secret)
	_, err := openDetectorPool(t.Context(), runtimeConfig, func(context.Context, *pgxpool.Config) (databasePool, error) {
		return nil, connectErr
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe connector error: %v", err)
	}

	pool := &fakePool{pingErr: errors.New("ping included " + secret)}
	_, err = openDetectorPool(t.Context(), runtimeConfig, func(context.Context, *pgxpool.Config) (databasePool, error) {
		return pool, nil
	})
	if err == nil || strings.Contains(err.Error(), secret) || pool.closeCount != 1 {
		t.Fatalf("unsafe readiness error=%v close=%d", err, pool.closeCount)
	}
}

func TestSuperviseRuntimeHandlesCancellationFailureAndUnexpectedExit(t *testing.T) {
	t.Parallel()
	t.Run("graceful cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- superviseRuntime(ctx, runtimeFunc(func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}))
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("graceful shutdown error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("detector did not stop after cancellation")
		}
	})

	t.Run("runtime failure is redacted", func(t *testing.T) {
		secret := "database-row-must-not-leak"
		cause := errors.New(secret)
		err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error { return cause }))
		var failure *runtimeFailure
		if !errors.As(err, &failure) || !errors.Is(err, cause) || strings.Contains(err.Error(), secret) {
			t.Fatalf("failure=%+v err=%v", failure, err)
		}
	})

	t.Run("unexpected successful exit", func(t *testing.T) {
		err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error { return nil }))
		if !errors.Is(err, errUnexpectedRuntimeExit) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestRunRequiresDependenciesBeforeConfiguration(t *testing.T) {
	t.Parallel()
	if err := run(t.Context(), nil); err == nil {
		t.Fatal("nil logger accepted")
	}
	//lint:ignore SA1012 Deliberately exercise the nil-context rejection boundary.
	if err := superviseRuntime(nil, runtimeFunc(func(context.Context) error { return nil })); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := superviseRuntime(t.Context(), nil); err == nil {
		t.Fatal("nil runtime accepted")
	}
}

func nonCallingDependencies(t *testing.T) runtimeDependencies {
	t.Helper()
	return runtimeDependencies{
		openPool: func(context.Context, config.Config) (databasePool, error) {
			t.Fatal("invalid configuration reached pool construction")
			return nil, nil
		},
		newStore: func(databasePool) (detectionworker.Store, error) {
			t.Fatal("invalid configuration reached store construction")
			return nil, nil
		},
		newRuntime: func(detectionworker.Store, *detection.Detector, detectionworker.Config) (detectorRuntime, error) {
			t.Fatal("invalid configuration reached runtime construction")
			return nil, nil
		},
	}
}

func loadDetectorConfig(t *testing.T, extra map[string]string) config.Config {
	t.Helper()
	values := map[string]string{"DATABASE_WORKER_URL": detectorDatabaseURL("detector-password")}
	for name, value := range extra {
		values[name] = value
	}
	result, err := config.LoadFrom(config.RoleDetector, mapLookup(values))
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	if result.OpenAI.APIKey.IsSet() || result.Admin.SessionHMACKey.IsSet() || result.Events.GatewayHMACKey.IsSet() {
		t.Fatal("detector startup unexpectedly depends on a non-database secret")
	}
	return result
}

func mapLookup(values map[string]string) config.LookupFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func detectorDatabaseURL(password string) string {
	return "postgresql://sentinelflow_worker:" + password + "@postgres:5432/sentinelflow?sslmode=disable"
}

type runtimeFunc func(context.Context) error

func (function runtimeFunc) Run(ctx context.Context) error { return function(ctx) }

type fakePool struct {
	pingErr    error
	pingCount  int
	closeCount int
}

func (*fakePool) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("unused")
}
func (*fakePool) QueryRow(context.Context, string, ...any) pgx.Row { return nil }
func (pool *fakePool) Ping(context.Context) error {
	pool.pingCount++
	return pool.pingErr
}
func (pool *fakePool) Close() { pool.closeCount++ }

type stubStore struct{}

func (*stubStore) Lease(context.Context, worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	return worker.LeasedJob{}, false, nil
}
func (*stubStore) Prepare(context.Context, worker.LeasedJob) (detectionworker.Snapshot, bool, error) {
	return detectionworker.Snapshot{}, false, nil
}
func (*stubStore) Finalize(context.Context, detectionworker.FinalizeRequest) (detectionworker.FinalizeResult, bool, error) {
	return detectionworker.FinalizeResult{}, false, nil
}
func (*stubStore) FinishFailure(context.Context, worker.FinishRequest) (bool, error) {
	return false, nil
}
func (*stubStore) CloseIdle(context.Context, int) (int, error) { return 0, nil }
