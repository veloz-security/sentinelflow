//go:build integration

package adminstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/jackc/pgx/v5"
)

// TestPostgreSQLStoreAgainstPostgreSQL17 is opt-in because it starts a
// disposable PostgreSQL container and applies every repository migration. It
// proves the adapter works while SET ROLE sentinelflow_api is active and that
// cleanup remains unavailable to that request-serving role.
func TestPostgreSQLStoreAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-adminstore-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	connection, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatal("connect to disposable PostgreSQL 17")
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	applyAdminStoreMigrations(t, ctx, connection)

	var versionText string
	if err = connection.QueryRow(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		t.Fatal("query PostgreSQL version")
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version/10000 != 17 {
		t.Fatalf("expected PostgreSQL 17, got %q", versionText)
	}
	var canSelect, canInsert, canUpdate, canDelete bool
	if err = connection.QueryRow(ctx, `
SELECT
    has_table_privilege('sentinelflow_api', 'sentinelflow.admin_sessions', 'SELECT'),
    has_table_privilege('sentinelflow_api', 'sentinelflow.admin_sessions', 'INSERT'),
    has_table_privilege('sentinelflow_api', 'sentinelflow.admin_sessions', 'UPDATE'),
    has_table_privilege('sentinelflow_api', 'sentinelflow.admin_sessions', 'DELETE')`).Scan(
		&canSelect, &canInsert, &canUpdate, &canDelete,
	); err != nil || !canSelect || !canInsert || !canUpdate || canDelete {
		t.Fatalf("unexpected API session privileges: select=%v insert=%v update=%v delete=%v", canSelect, canInsert, canUpdate, canDelete)
	}

	oldID := testSessionID(61)
	childID := testSessionID(62)
	expiredID := testSessionID(63)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = connection.Exec(cleanupContext, `RESET ROLE`)
		_, _ = connection.Exec(cleanupContext, `
DELETE FROM sentinelflow.admin_sessions
WHERE session_id IN ($1::uuid, $2::uuid, $3::uuid)`, childID.String(), oldID.String(), expiredID.String())
	})

	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set least-privilege API role")
	}
	var databaseNow time.Time
	if err = connection.QueryRow(ctx, databaseClockSQL).Scan(&databaseNow); err != nil {
		t.Fatal("query database clock")
	}
	old := testLoginRecord(61, databaseNow.UTC())
	store, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := store.InsertLogin(ctx, old)
	if err != nil {
		t.Fatalf("insert login under API role: %v", err)
	}
	loaded, err := store.LoadByID(ctx, oldID)
	if err != nil || !exactRecord(loaded, inserted) {
		t.Fatalf("load login under API role: record=%+v err=%v", loaded, err)
	}
	touched, err := store.Touch(ctx, loaded)
	if err != nil || !touched.LastSeenAt.After(loaded.LastSeenAt) {
		t.Fatalf("touch under API role: record=%+v err=%v", touched, err)
	}
	if err = connection.QueryRow(ctx, databaseClockSQL).Scan(&databaseNow); err != nil {
		t.Fatal("query rotation clock")
	}
	replacement := testReplacementRecord(62, touched, databaseNow.UTC())
	rotated, err := store.Rotate(ctx, touched, replacement)
	if err != nil || !exactRecord(rotated, replacement) {
		t.Fatalf("rotate under API role: record=%+v err=%v", rotated, err)
	}
	replayParent, err := store.LoadRevokedDecisionReplayParent(ctx, oldID)
	if err != nil || replayParent.RevokedAt == nil || replayParent.ID != oldID || replayParent.ActorID != touched.ActorID {
		t.Fatalf("load exact revoked replay parent: record=%+v err=%v", replayParent, err)
	}

	second, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatal("connect second PostgreSQL session")
	}
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	if _, err = second.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set second API role")
	}
	secondStore, err := NewPostgreSQLStore(second)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, target := range []*PostgreSQLStore{store, secondStore} {
		go func() {
			<-start
			_, revokeErr := target.Revoke(ctx, rotated)
			results <- revokeErr
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		switch result := <-results; {
		case result == nil:
			successes++
		case errors.Is(result, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent revoke result: %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent revokes: success=%d conflict=%d", successes, conflicts)
	}
	if _, err = store.LoadByID(ctx, childID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session remained loadable: %v", err)
	}
	if _, err = store.LoadRevokedDecisionReplayParent(ctx, oldID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked child left old replay parent usable: %v", err)
	}
	if _, err = store.DeleteExpired(ctx, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("API role unexpectedly received cleanup authority: %v", err)
	}

	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset API role")
	}
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_migration`); err != nil {
		t.Fatal("set migration-owner role for bounded cleanup")
	}
	expired := testLoginRecord(63, databaseNow.Add(-adminauth.SessionAbsoluteLifetime-time.Minute))
	if _, err = connection.Exec(ctx, insertSessionSQL, recordArguments(expired)...); err != nil {
		t.Fatal("seed expired session as migration owner")
	}
	ownerStore, err := NewPostgreSQLStore(connection)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := ownerStore.DeleteExpired(ctx, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("migration-owner cleanup deleted=%d err=%v", deleted, err)
	}
}

func applyAdminStoreMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test")
	}
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	sort.Strings(migrations)
	for _, migration := range migrations {
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read %s", filepath.Base(migration))
		}
		if _, applyErr := connection.Exec(ctx, string(contents)); applyErr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(migration), applyErr)
		}
	}
}

func waitForIntegrationPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL readiness: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become ready")
}

func integrationDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runIntegrationDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runIntegrationDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
