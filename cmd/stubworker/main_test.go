package main

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/aistub"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/stubworkerconfig"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	testDatabaseURL = "postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=disable"
	testJobID       = "019b0000-0000-4000-8000-000000000001"
	testIncidentID  = "019b0000-0000-7000-8000-000000000101"
	testAnalysisID  = "019b0000-0000-7000-8000-000000000201"
	testSnapshotID  = "019b0000-0000-7000-8000-000000000301"
	testSignalID    = "019b0000-0000-7000-8000-000000000401"
	testToken       = "019b0000-0000-4000-8000-000000000501"
	testDigest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestBuildStubRuntimeWiresOnlyDeterministicAnalyzer(t *testing.T) {
	t.Parallel()
	config := testConfig(t, map[string]string{
		stubworkerconfig.LeaseDurationName:  "5s",
		stubworkerconfig.PollIntervalName:   "25ms",
		stubworkerconfig.MaxConcurrencyName: "1",
	})
	pool := &fakePool{}
	store := &captureStore{}
	runtime := runtimeFunc(func(context.Context) error { return nil })
	var capturedAnalyzer analysisworker.Analyzer
	var capturedConfig analysisworker.Config
	set, err := buildStubRuntime(t.Context(), config, runtimeDependencies{
		openPool: func(context.Context, stubworkerconfig.Config) (databasePool, error) { return pool, nil },
		newStore: func(_ context.Context, gotConfig stubworkerconfig.Config, got databasePool) (analysisworker.Store, error) {
			if got != pool {
				t.Fatal("store did not receive the least-privilege pool")
			}
			if gotConfig.DatabaseURL() != config.DatabaseURL() {
				t.Fatal("store did not receive the frozen stub configuration")
			}
			return store, nil
		},
		newRuntime: func(got analysisworker.Store, analyzer analysisworker.Analyzer, value analysisworker.Config) (stubRuntime, error) {
			if got != store {
				t.Fatal("runtime did not receive the atomic store")
			}
			capturedAnalyzer, capturedConfig = analyzer, value
			return runtime, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := capturedAnalyzer.Identity()
	if identity.Kind() != ai.ProviderDeterministicStub || identity.AdapterID() != aistub.AdapterID ||
		identity.Model() != "" || identity.ReasoningEffort() != "" || identity.RateCardVersion() != "" {
		t.Fatalf("unexpected analyzer identity: kind=%s adapter=%s", identity.Kind(), identity.AdapterID())
	}
	if capturedConfig.LeaseOwner != stubLeaseOwner || capturedConfig.LeaseDuration != 5*time.Second ||
		capturedConfig.PollInterval != 25*time.Millisecond || capturedConfig.MaxConcurrency != 1 ||
		capturedConfig.RateCardVersion != "" {
		t.Fatalf("unexpected runtime config: %+v", capturedConfig)
	}
	if set.identity != string(ai.ProviderDeterministicStub) || set.adapter != aistub.AdapterID || set.workers != 1 {
		t.Fatalf("unexpected runtime metadata: %+v", set)
	}
	set.close()
	if pool.closeCount != 1 {
		t.Fatalf("pool close count=%d", pool.closeCount)
	}
}

func TestBuildStubRuntimeStopsBeforeAnalyzerRuntimeWhenStoreActivationFails(t *testing.T) {
	t.Parallel()
	config := testConfig(t, nil)
	pool := &fakePool{}
	secret := "activation-secret-proof-evidence"
	runtimeConstructed := false

	_, err := buildStubRuntime(t.Context(), config, runtimeDependencies{
		openPool: func(context.Context, stubworkerconfig.Config) (databasePool, error) {
			return pool, nil
		},
		newStore: func(context.Context, stubworkerconfig.Config, databasePool) (analysisworker.Store, error) {
			return nil, errors.New(secret)
		},
		newRuntime: func(analysisworker.Store, analysisworker.Analyzer, analysisworker.Config) (stubRuntime, error) {
			runtimeConstructed = true
			return runtimeFunc(func(context.Context) error { return nil }), nil
		},
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe activation failure: %v", err)
	}
	if runtimeConstructed {
		t.Fatal("runtime was constructed after activation failed closed")
	}
	if pool.closeCount != 1 {
		t.Fatalf("pool close count=%d", pool.closeCount)
	}
}

func TestCommandWiringProducesNullShapedBillableProvenance(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Add(10 * time.Minute)
	store := &captureStore{snapshot: validSnapshot(now), finalizeOK: true}
	config := analysisworker.DefaultConfig(stubLeaseOwner, "")
	config.MaxConcurrency = 1
	runtime, err := analysisworker.New(store, aistub.New(), config, analysisworker.Dependencies{
		Clock: fixedClock{now: now}, Tokens: fixedToken(testToken), Jitter: fixedJitter(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunOnce(t.Context())
	if err != nil || result.Outcome != worker.OutcomeCompleted {
		t.Fatalf("RunOnce() result=%+v err=%v", result, err)
	}
	mutation := store.finalized.Mutation
	if mutation == nil || mutation.Success == nil {
		t.Fatalf("missing success mutation: %+v", mutation)
	}
	success := mutation.Success
	if success.ProviderKind != string(ai.ProviderDeterministicStub) || success.AdapterID != aistub.AdapterID ||
		success.Model != "" || success.ReasoningEffort != "" || success.RateCardVersion != "" ||
		success.Usage != (ai.Usage{}) || !strings.HasPrefix(success.ResponseID, "stub_") {
		t.Fatalf("stub was mislabeled or billable: provider=%s adapter=%s model=%q reasoning=%q rate=%q usage=%+v",
			success.ProviderKind, success.AdapterID, success.Model, success.ReasoningEffort,
			success.RateCardVersion, success.Usage)
	}
}

func TestAnalysisRuntimeContinuesAfterLeaseLossAndStopsOnCancellation(t *testing.T) {
	t.Parallel()
	store := &leaseLossStore{secondLease: make(chan struct{})}
	config := analysisworker.DefaultConfig(stubLeaseOwner, "")
	config.MaxConcurrency = 1
	config.PollInterval = 25 * time.Millisecond
	runtime, err := analysisworker.New(store, aistub.New(), config, analysisworker.Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-store.secondLease:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("runtime did not retry after losing a lease")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled runtime returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop after cancellation")
	}
}

func TestSuperviseRuntimeContainsPanicCancellationAndSupportsFreshRestart(t *testing.T) {
	t.Parallel()
	secret := "panic-output-evidence-command-api-key"
	err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error { panic(secret) }))
	var failure *runtimeFailure
	if !errors.As(err, &failure) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe panic error: %v", err)
	}

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
	if err = <-done; err != nil {
		t.Fatalf("graceful cancellation returned %v", err)
	}

	// A prior runtime failure leaves no package-global state; a newly built
	// process runtime can start and terminate independently.
	if err = superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error { return nil })); !errors.Is(err, errUnexpectedRuntimeExit) {
		t.Fatalf("fresh restart boundary returned %v", err)
	}
}

func TestOpenStubPoolPinsRoleBoundsTLSAndReadiness(t *testing.T) {
	t.Parallel()
	config := testConfig(t, nil)
	pool := &fakePool{}
	var captured *pgxpool.Config
	got, err := openStubPool(t.Context(), config, func(_ context.Context, value *pgxpool.Config) (databasePool, error) {
		captured = value.Copy()
		return pool, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != pool || pool.pingCount != 1 || pool.closeCount != 0 {
		t.Fatalf("pool=%v ping=%d close=%d", got, pool.pingCount, pool.closeCount)
	}
	if captured.ConnConfig.User != "sentinelflow_worker" || captured.ConnConfig.TLSConfig != nil ||
		captured.MinConns != 1 || captured.MaxConns != 3 ||
		captured.MaxConnLifetime != 30*time.Minute || captured.MaxConnIdleTime != 5*time.Minute ||
		captured.HealthCheckPeriod != 30*time.Second ||
		!reflect.DeepEqual(captured.ConnConfig.RuntimeParams, map[string]string{"application_name": "sentinelflow-stub-worker"}) {
		t.Fatalf("unexpected pool configuration: %+v", captured)
	}
	got.Close()
}

func TestOpenStubPoolFailsClosedOnDatabaseOutageAndRedactsErrors(t *testing.T) {
	t.Parallel()
	config := testConfig(t, nil)
	secret := "database-password-input-output-evidence-command"
	_, err := openStubPool(t.Context(), config, func(context.Context, *pgxpool.Config) (databasePool, error) {
		return nil, errors.New(secret)
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe connector error: %v", err)
	}
	pool := &fakePool{pingErr: errors.New(secret)}
	_, err = openStubPool(t.Context(), config, func(context.Context, *pgxpool.Config) (databasePool, error) {
		return pool, nil
	})
	if err == nil || strings.Contains(err.Error(), secret) || pool.closeCount != 1 {
		t.Fatalf("unsafe readiness error=%v close=%d", err, pool.closeCount)
	}
}

func TestConstructionAndSupervisorRejectNilBoundaries(t *testing.T) {
	t.Parallel()
	config := testConfig(t, nil)
	if _, err := buildStubRuntime(t.Context(), config, runtimeDependencies{}); err == nil {
		t.Fatal("nil construction seams accepted")
	}
	if err := run(t.Context(), nil, runtimeDependencies{}); err == nil {
		t.Fatal("nil logger accepted")
	}
	//lint:ignore SA1012 Explicit nil-context rejection tests.
	if err := superviseRuntime(nil, runtimeFunc(func(context.Context) error { return nil })); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := superviseRuntime(t.Context(), nil); err == nil {
		t.Fatal("nil runtime accepted")
	}
}

func TestProductionSourceHasNoShellHTTPOrEnforcementClient(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	paths := []string{filepath.Join(root, "cmd", "stubworker"), filepath.Join(root, "internal", "stubworkerconfig")}
	for _, path := range paths {
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			filePath := filepath.Join(path, entry.Name())
			parsed, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imported := range parsed.Imports {
				name, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if name == "net/http" || name == "os/exec" || name == "plugin" ||
					strings.Contains(name, "/enforcement/") || strings.Contains(name, "/dispatcher") ||
					strings.Contains(name, "/executor") || strings.Contains(name, "/nft") {
					t.Fatalf("forbidden production dependency %q in %s", name, filePath)
				}
			}
		}
	}
}

type runtimeFunc func(context.Context) error

func (function runtimeFunc) Run(ctx context.Context) error { return function(ctx) }

type fakePool struct {
	pingErr    error
	pingCount  int
	closeCount int
}

func (*fakePool) QueryRow(context.Context, string, ...any) pgx.Row { return errorRow{} }
func (p *fakePool) Ping(context.Context) error {
	p.pingCount++
	return p.pingErr
}
func (p *fakePool) Close() { p.closeCount++ }

type errorRow struct{}

func (errorRow) Scan(...any) error { return errors.New("unused fake row") }

type captureStore struct {
	mu         sync.Mutex
	snapshot   analysisworker.Snapshot
	finalizeOK bool
	finalized  analysisworker.FinalizeRequest
}

func (s *captureStore) Lease(_ context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	return leasedJob(request), true, nil
}
func (s *captureStore) Prepare(context.Context, analysisworker.PrepareRequest) (analysisworker.Snapshot, bool, error) {
	return s.snapshot, true, nil
}
func (s *captureStore) Finalize(_ context.Context, request analysisworker.FinalizeRequest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalized = request
	return s.finalizeOK, nil
}

type leaseLossStore struct {
	mu          sync.Mutex
	leases      int
	secondLease chan struct{}
}

func (s *leaseLossStore) Lease(_ context.Context, request worker.LeaseRequest) (worker.LeasedJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases++
	if s.leases == 1 {
		return leasedJob(request), true, nil
	}
	if s.leases == 2 {
		close(s.secondLease)
	}
	return worker.LeasedJob{}, false, nil
}
func (*leaseLossStore) Prepare(context.Context, analysisworker.PrepareRequest) (analysisworker.Snapshot, bool, error) {
	return analysisworker.Snapshot{}, false, nil
}
func (*leaseLossStore) Finalize(context.Context, analysisworker.FinalizeRequest) (bool, error) {
	return false, errors.New("must not finalize a lost lease")
}

func leasedJob(request worker.LeaseRequest) worker.LeasedJob {
	return worker.LeasedJob{
		Job: worker.Job{
			JobID: testJobID, Kind: worker.JobAnalyze, AggregateType: "incident",
			AggregateID: testIncidentID, AggregateVersion: 1, Attempt: 1, MaxAttempts: 3,
		},
		State: "leased", LeaseToken: request.LeaseToken, LeaseOwner: request.LeaseOwner,
		LeaseGrantedAt: request.Now, LeaseExpiresAt: request.LeaseExpiresAt,
	}
}

func validSnapshot(now time.Time) analysisworker.Snapshot {
	windowStart := now.Add(-time.Minute)
	return analysisworker.Snapshot{
		IncidentID: testIncidentID, IncidentVersion: 1, AnalysisID: testAnalysisID,
		GeneratedAt: now, EvidenceSnapshotID: testSnapshotID, EvidenceSnapshotDigest: testDigest,
		SourceIP: "203.0.113.20", ServiceLabel: "demo-app",
		WindowStart: windowStart, WindowEnd: now, DetectorConfigVersion: "detector-v1",
		Signals: []analysisworker.Signal{{
			SignalID: testSignalID, RuleID: "path_scan.v1", Classification: "path_scan",
			WindowStart: windowStart, WindowEnd: now, EventCount: 8,
			DistinctSuspiciousPathCount: 8, EvidenceDigest: testDigest,
		}},
		HistoricalImpact: analysisworker.HistoricalImpact{
			LookbackStart: now.Add(-24 * time.Hour), LookbackEnd: now, ImpactDigest: testDigest,
		},
	}
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
func (fixedClock) Sleep(ctx context.Context, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

type fixedToken string

func (token fixedToken) NewLeaseToken() (string, error) { return string(token), nil }

type fixedJitter uint64

func (jitter fixedJitter) Uint64() (uint64, error) { return uint64(jitter), nil }

func testConfig(t *testing.T, extra map[string]string) stubworkerconfig.Config {
	t.Helper()
	values := map[string]string{stubworkerconfig.DatabaseWorkerURLName: testDatabaseURL}
	for name, value := range extra {
		values[name] = value
	}
	config, err := stubworkerconfig.LoadFrom(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}
