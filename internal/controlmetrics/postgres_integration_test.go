package controlmetrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresControlMetricsDirectLogin proves the aggregate-only runtime
// contract through a direct sentinelflow_metrics login to disposable PostgreSQL
// 17 with migrations through 000028.
func TestPostgresControlMetricsDirectLogin(t *testing.T) {
	databaseURL := os.Getenv("SENTINELFLOW_CONTROL_METRICS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SENTINELFLOW_CONTROL_METRICS_TEST_DATABASE_URL is not set")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || poolConfig.ConnConfig.User != "sentinelflow_metrics" ||
		poolConfig.ConnConfig.Database != "sentinelflow" || poolConfig.ConnConfig.Password == "" {
		t.Fatal("control metrics integration database configuration rejected")
	}
	poolConfig.MinConns, poolConfig.MaxConns = 1, 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal("control metrics integration database unavailable")
	}
	defer pool.Close()
	if err := ValidateDatabaseIdentity(ctx, pool); err != nil {
		t.Fatal("control metrics integration database identity rejected")
	}
	var role, database string
	var version int
	if err := pool.QueryRow(ctx, `SELECT current_user::text, current_database()::text,
current_setting('server_version_num')::integer`).Scan(&role, &database, &version); err != nil ||
		role != "sentinelflow_metrics" || database != "sentinelflow" || version < 170000 {
		t.Fatal("control metrics integration database identity rejected")
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	samples, err := store.Collect(ctx)
	if err != nil || len(samples) != expectedSampleCount {
		t.Fatalf("aggregate samples=%d err=%v", len(samples), err)
	}
	handler, err := Handler(store, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != openMetricsContentType {
		t.Fatalf("metrics status=%d content_type=%q", response.Code, response.Header().Get("Content-Type"))
	}
}
