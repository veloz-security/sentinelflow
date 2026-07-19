//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const activatorKillHelperEnvironment = "SENTINELFLOW_TEST_ACTIVATOR_KILL_HELPER"

// TestSIGKILLStopsActivatorProcessWithoutCompletingOrRetrying is deliberately
// bounded to process-local evidence. SIGKILL cannot run Go defers, so this test
// does not claim that the client can fence its own database role after the
// signal. It proves that run has no detached continuation: the sole client
// process is gone, its one in-flight activation call cannot complete, and no
// second call appears after death.
func TestSIGKILLStopsActivatorProcessWithoutCompletingOrRetrying(t *testing.T) {
	attemptMarker := filepath.Join(t.TempDir(), "activation-attempts")
	completedMarker := filepath.Join(t.TempDir(), "activation-completed")
	command := exec.Command(os.Args[0], "-test.run=^TestActivatorSIGKILLHelper$")
	command.Env = append(os.Environ(),
		activatorKillHelperEnvironment+"=1",
		"SENTINELFLOW_TEST_ACTIVATOR_ATTEMPT_MARKER="+attemptMarker,
		"SENTINELFLOW_TEST_ACTIVATOR_COMPLETED_MARKER="+completedMarker,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	waitForMarker(t, attemptMarker)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("SIGKILL helper exited successfully")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("activator client remained alive after SIGKILL")
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected process status after SIGKILL: %v", command.ProcessState)
	}
	if err := command.Process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("activator client still accepts signals after Wait")
	}
	time.Sleep(200 * time.Millisecond)
	attempts, err := os.ReadFile(attemptMarker)
	if err != nil {
		t.Fatal(err)
	}
	if string(attempts) != "attempt\n" {
		t.Fatalf("activation was not exactly once before kill: %q", attempts)
	}
	if _, err := os.Stat(completedMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation completed after SIGKILL: %v", err)
	}
}

func TestActivatorSIGKILLHelper(t *testing.T) {
	if os.Getenv(activatorKillHelperEnvironment) != "1" {
		return
	}
	environment := validActivatorEnvironment()
	events := make([]string, 0, 8)
	pool := &activatorTestPool{
		events: &events, role: activatorDatabaseRole, fencePhaseOne: true, fencePhaseTwo: true,
	}
	deps := activatorDependencies{
		lookup: mapActivatorLookup(environment), environ: mapActivatorEnviron(environment),
		openPool: func(context.Context, *pgxpool.Config) (activatorPool, error) { return pool, nil },
		loadSecret: func(string) (demohistoryactivation.Secret, error) {
			return demohistoryactivation.Secret{}, nil
		},
		activate: func(context.Context, demohistoryproof.Config, validation.DemoHistoryActivationDB,
			demohistoryactivation.Secret, demohistoryactivation.Secret) error {
			if err := appendMarker(os.Getenv("SENTINELFLOW_TEST_ACTIVATOR_ATTEMPT_MARKER"), "attempt\n"); err != nil {
				return err
			}
			<-time.After(24 * time.Hour)
			return os.WriteFile(os.Getenv("SENTINELFLOW_TEST_ACTIVATOR_COMPLETED_MARKER"), []byte("completed\n"), 0o600)
		},
	}
	if err := run(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
}

func TestActivatorContextCancellationRunsBothFencePhasesAndClosesClient(t *testing.T) {
	environment := validActivatorEnvironment()
	events := make([]string, 0, 12)
	pool := &activatorTestPool{
		events: &events, role: activatorDatabaseRole, fencePhaseOne: true, fencePhaseTwo: true,
	}
	entered := make(chan struct{})
	activationCalls := 0
	deps := activatorDependencies{
		lookup: mapActivatorLookup(environment), environ: mapActivatorEnviron(environment),
		openPool: func(context.Context, *pgxpool.Config) (activatorPool, error) { return pool, nil },
		loadSecret: func(string) (demohistoryactivation.Secret, error) {
			return demohistoryactivation.Secret{}, nil
		},
		activate: func(ctx context.Context, _ demohistoryproof.Config, _ validation.DemoHistoryActivationDB,
			_ demohistoryactivation.Secret, _ demohistoryactivation.Secret) error {
			activationCalls++
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, deps) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("activation did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled activation succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled activator did not return")
	}
	if activationCalls != 1 || pool.closeCalls != 1 {
		t.Fatalf("activation calls=%d close calls=%d", activationCalls, pool.closeCalls)
	}
	wantTail := []string{"fence-phase-one", "fence-phase-two", "close"}
	if len(events) < len(wantTail) || strings.Join(events[len(events)-len(wantTail):], ",") != strings.Join(wantTail, ",") {
		t.Fatalf("cancellation did not complete both fence phases before close: %v", events)
	}
}

func waitForMarker(t testing.TB, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("marker was not created: %s", filepath.Base(path))
}

func appendMarker(path, value string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(value); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
