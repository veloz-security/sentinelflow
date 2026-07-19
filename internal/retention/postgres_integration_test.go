package retention

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresRetentionDirectLogin proves the runtime contract through a
// direct sentinelflow_retention login. The test URL must point to a disposable
// PostgreSQL 17 database with migrations through 000023 and must never be a
// shared or production database.
func TestPostgresRetentionDirectLogin(t *testing.T) {
	databaseURL := os.Getenv("SENTINELFLOW_RETENTION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINELFLOW_RETENTION_TEST_DATABASE_URL is not set")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || poolConfig.ConnConfig.User != "sentinelflow_retention" ||
		poolConfig.ConnConfig.Database != "sentinelflow" || poolConfig.ConnConfig.Password == "" {
		t.Fatal("retention integration database configuration rejected")
	}
	poolConfig.MinConns, poolConfig.MaxConns = 1, 2
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal("retention integration database unavailable")
	}
	defer pool.Close()
	var role, database string
	var version int
	var serverNow time.Time
	var membershipCount int
	if err := pool.QueryRow(ctx, `
SELECT current_user::text, current_database()::text,
       current_setting('server_version_num')::integer, clock_timestamp(),
       (SELECT count(*) FROM pg_auth_members membership
        JOIN pg_roles retention_role
          ON retention_role.oid IN (membership.member, membership.roleid)
        WHERE retention_role.rolname = current_user)`).Scan(
		&role, &database, &version, &serverNow, &membershipCount,
	); err != nil || role != "sentinelflow_retention" ||
		database != "sentinelflow" || version < 170000 || membershipCount != 0 {
		t.Fatal("retention integration database identity rejected")
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	lockTransaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("retention integration lock transaction unavailable")
	}
	if _, err := lockTransaction.Exec(ctx, `SELECT pg_advisory_xact_lock(1735289911, 23)`); err != nil {
		_ = lockTransaction.Rollback(ctx)
		t.Fatal("retention integration advisory lock unavailable")
	}
	blockedRunID, err := randomUUID()
	if err != nil {
		_ = lockTransaction.Rollback(ctx)
		t.Fatal("retention integration run identity unavailable")
	}
	if _, err := store.Run(ctx, blockedRunID, serverNow.UTC(), 1000); !errors.Is(err, ErrPersistence) {
		_ = lockTransaction.Rollback(ctx)
		t.Fatalf("concurrent retention run was not rejected: %v", err)
	}
	if err := lockTransaction.Rollback(ctx); err != nil {
		t.Fatal("retention integration advisory lock release failed")
	}

	runID, err := randomUUID()
	if err != nil {
		t.Fatal("retention integration run identity unavailable")
	}
	first, err := store.Run(ctx, runID, serverNow.UTC(), 1000)
	if err != nil || first.Replayed || first.Outcome != "succeeded" {
		t.Fatalf("first retention integration run failed or replayed: %v", err)
	}
	second, err := store.Run(ctx, runID, serverNow.UTC(), 1000)
	if err != nil || !second.Replayed || second.RunDigest != first.RunDigest ||
		!second.CompletedAt.Equal(first.CompletedAt) {
		t.Fatalf("exact retention integration replay failed: %v", err)
	}
}
