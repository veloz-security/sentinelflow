//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/demohistoryimport"
)

const importerKillHelperEnvironment = "SENTINELFLOW_TEST_IMPORTER_KILL_HELPER"

type cancellableDatasetReader struct {
	entered chan<- struct{}
}

func (reader cancellableDatasetReader) ReadPinnedDataset(ctx context.Context) ([]byte, error) {
	close(reader.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

type importerKillProbePool struct {
	beginMarker string
}

func (pool *importerKillProbePool) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	if err := appendImporterMarker(pool.beginMarker, "begin\n"); err != nil {
		return nil, err
	}
	<-time.After(24 * time.Hour)
	return nil, errors.New("unexpected import transaction")
}

func (*importerKillProbePool) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if query == `SELECT current_user` {
		return stagedFenceRow(func(destination ...any) error {
			*destination[0].(*string) = importerDatabaseRole
			return nil
		})
	}
	return stagedFenceRow(func(destination ...any) error {
		*destination[0].(*bool) = true
		return nil
	})
}

func (*importerKillProbePool) Ping(context.Context) error { return nil }
func (*importerKillProbePool) Close()                     {}

// TestSIGKILLStopsImporterProcessWithoutCompletingOrRetrying is deliberately
// bounded to process-local evidence. SIGKILL cannot run Go defers, so server
// session cleanup and role expiry require independent PostgreSQL/Compose
// evidence. This test proves that no detached client survives and that a sole
// in-flight atomic-import attempt cannot later complete or retry.
func TestSIGKILLStopsImporterProcessWithoutCompletingOrRetrying(t *testing.T) {
	beginMarker := filepath.Join(t.TempDir(), "import-begins")
	completedMarker := filepath.Join(t.TempDir(), "import-completed")
	command := exec.Command(os.Args[0], "-test.run=^TestImporterSIGKILLHelper$")
	command.Env = append(os.Environ(),
		importerKillHelperEnvironment+"=1",
		"SENTINELFLOW_TEST_IMPORTER_BEGIN_MARKER="+beginMarker,
		"SENTINELFLOW_TEST_IMPORTER_COMPLETED_MARKER="+completedMarker,
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
	waitForImporterMarker(t, beginMarker)
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
		t.Fatal("importer client remained alive after SIGKILL")
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected process status after SIGKILL: %v", command.ProcessState)
	}
	if err := command.Process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("importer client still accepts signals after Wait")
	}
	time.Sleep(200 * time.Millisecond)
	attempts, err := os.ReadFile(beginMarker)
	if err != nil {
		t.Fatal(err)
	}
	if string(attempts) != "begin\n" {
		t.Fatalf("atomic import was not attempted exactly once before kill: %q", attempts)
	}
	if _, err := os.Stat(completedMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("atomic import completed after SIGKILL: %v", err)
	}
}

func TestImporterSIGKILLHelper(t *testing.T) {
	if os.Getenv(importerKillHelperEnvironment) != "1" {
		return
	}
	values, dataset, bundle, _ := validHandoff(t)
	pool := &importerKillProbePool{beginMarker: os.Getenv("SENTINELFLOW_TEST_IMPORTER_BEGIN_MARKER")}
	deps := dependencies{
		getenv: mapGetenv(values), environ: mapEnviron(values), output: os.Stdout,
		datasetRoot: "/app", bundleRoot: "/run/sentinelflow-demo-history",
		openPool: func(context.Context, string) (databasePool, error) { return pool, nil },
		readBundle: func(string) ([]byte, []byte, error) {
			return bundle.SignedEnvelope(), bundle.PublicAssertions(), nil
		},
		newReader: func(string) (demohistoryimport.DatasetReader, error) {
			return staticDatasetReader{raw: dataset}, nil
		},
	}
	err := run(context.Background(), deps)
	if writeErr := os.WriteFile(os.Getenv("SENTINELFLOW_TEST_IMPORTER_COMPLETED_MARKER"), []byte("completed\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestImporterContextCancellationRunsBothFencePhasesAndClosesClient(t *testing.T) {
	values, _, bundle, _ := validHandoff(t)
	pool := &stagedFencePool{}
	entered := make(chan struct{})
	deps := dependencies{
		getenv: mapGetenv(values), environ: mapEnviron(values), output: os.Stdout,
		datasetRoot: "/app", bundleRoot: "/run/sentinelflow-demo-history",
		openPool: func(context.Context, string) (databasePool, error) { return pool, nil },
		readBundle: func(string) ([]byte, []byte, error) {
			return bundle.SignedEnvelope(), bundle.PublicAssertions(), nil
		},
		newReader: func(string) (demohistoryimport.DatasetReader, error) {
			return cancellableDatasetReader{entered: entered}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, deps) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("dataset read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled import succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled importer did not return")
	}
	if pool.importerFenceCalls != 1 || pool.importerFinalizeCalls != 1 || pool.closeCalls != 1 {
		t.Fatalf("fence phases=%d/%d close=%d", pool.importerFenceCalls, pool.importerFinalizeCalls, pool.closeCalls)
	}
}

func waitForImporterMarker(t testing.TB, path string) {
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

func appendImporterMarker(path, value string) error {
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

var _ demohistoryimport.DatasetReader = cancellableDatasetReader{}
