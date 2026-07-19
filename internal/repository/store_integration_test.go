//go:build integration

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

const (
	integrationGatewaySender = "gateway.integration"
	integrationAuthSender    = "auth.integration"
	integrationEpochA        = "AAAAAAAAAAAAAAAAAAAAAA"
	integrationEpochB        = "AQEBAQEBAQEBAQEBAQEBAQ"
)

var integrationKey = []byte("sentinelflow-repository-test-key-32-bytes-only")

func TestSourceCoverageMigrationDownOnEmptyDatabase(t *testing.T) {
	database := startPostgreSQL17(t)
	ctx := context.Background()
	if _, err := database.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source coverage down migration")
	}
	down, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "..", "..", "db", "migrations", "000015_source_coverage.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(ctx, string(down)); err != nil {
		t.Fatalf("empty source coverage down migration: %v", err)
	}
	var versionCount int
	if err = database.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.schema_migrations WHERE version = 15`).Scan(&versionCount); err != nil {
		t.Fatal(err)
	}
	if versionCount != 0 {
		t.Fatal("source coverage schema version survived down migration")
	}
	var tableName *string
	if err = database.QueryRow(ctx, `SELECT to_regclass('sentinelflow.source_coverage_attestations')::text`).Scan(&tableName); err != nil {
		t.Fatal(err)
	}
	if tableName != nil {
		t.Fatalf("source coverage table survived down migration: %s", *tableName)
	}
}

func TestPostgreSQLBatchStoreAtomicIngest(t *testing.T) {
	database := startPostgreSQL17(t)
	store, err := NewPostgreSQLBatchStore(&diagnosticBeginner{testing: t, connection: database})
	if err != nil {
		t.Fatalf("NewPostgreSQLBatchStore() error = %v", err)
	}
	ctx := context.Background()
	receivedAt := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)

	firstBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 1, 1, 101,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	first := authenticateBatch(t, ingestion.GatewayEventsPath, firstBatch, 1, receivedAt)
	outcome, err := store.StoreBatch(ctx, ingestion.GatewayEventsPath, first, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertCount(t, database, "sentinelflow.ingest_replay_nonces", 1)
	assertCount(t, database, "sentinelflow.ingest_batches", 1)
	assertCount(t, database, "sentinelflow.gateway_events", 1)
	assertCount(t, database, "sentinelflow.outbox_jobs", 1)
	assertCheckpoint(t, database, integrationGatewaySender, integrationEpochA, 1)

	duplicate := authenticateBatch(t, ingestion.GatewayEventsPath, firstBatch, 2, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, duplicate, receivedAt)
	assertOutcome(t, outcome, err, api.StoreDuplicate)
	assertCount(t, database, "sentinelflow.ingest_replay_nonces", 2)
	assertCount(t, database, "sentinelflow.ingest_batches", 1)
	assertCount(t, database, "sentinelflow.gateway_events", 1)
	assertCount(t, database, "sentinelflow.outbox_jobs", 1)

	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, duplicate, receivedAt)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("replayed nonce error = %v, want ErrBatchRejected", err)
	}
	assertCount(t, database, "sentinelflow.ingest_replay_nonces", 2)

	conflictingBatch := firstBatch
	conflictingBatch.Records = append([]events.EventRecordV1(nil), firstBatch.Records...)
	conflictingEvent := *conflictingBatch.Records[0].GatewayHTTP
	conflictingEvent.StatusCode = 403
	conflictingBatch.Records[0] = events.GatewayHTTPRecord(conflictingEvent)
	conflicting := authenticateBatch(t, ingestion.GatewayEventsPath, conflictingBatch, 3, receivedAt)
	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, conflicting, receivedAt)
	if !errors.Is(err, api.ErrBatchConflict) {
		t.Fatalf("conflicting batch error = %v, want ErrBatchConflict", err)
	}
	assertCount(t, database, "sentinelflow.ingest_replay_nonces", 2)

	collidingBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 2, 2, 102,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	collidingBatch.Records[0].GatewayHTTP.EventID = firstBatch.Records[0].GatewayHTTP.EventID
	colliding := authenticateBatch(t, ingestion.GatewayEventsPath, collidingBatch, 4, receivedAt)
	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, colliding, receivedAt)
	if !errors.Is(err, api.ErrBatchConflict) {
		t.Fatalf("event collision error = %v, want ErrBatchConflict", err)
	}
	assertCount(t, database, "sentinelflow.ingest_replay_nonces", 2)
	assertCount(t, database, "sentinelflow.ingest_batches", 1)
	assertCount(t, database, "sentinelflow.outbox_jobs", 1)
	assertCheckpoint(t, database, integrationGatewaySender, integrationEpochA, 1)

	boundaryBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 2, 3, 103,
		receivedAt, receivedAt.Add(-recordPastSkew), receivedAt.Add(recordFutureSkew))
	boundary := authenticateBatch(t, ingestion.GatewayEventsPath, boundaryBatch, 5, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, boundary, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertEventTrust(t, database, boundaryBatch.Records[0].GatewayHTTP.EventID, "trusted", "none")

	skewedBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 3, 4, 104,
		receivedAt, receivedAt.Add(-recordPastSkew-time.Nanosecond), receivedAt)
	skewed := authenticateBatch(t, ingestion.GatewayEventsPath, skewedBatch, 6, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, skewed, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertEventTrust(t, database, skewedBatch.Records[0].GatewayHTTP.EventID, "untrusted", "timestamp_skew")

	gapBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 5, 5, 105,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	gap := authenticateBatch(t, ingestion.GatewayEventsPath, gapBatch, 7, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, gap, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochA, 4, 4, true)
	assertCount(t, database, "sentinelflow.source_health_intervals", 0)

	lateBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 4, 6, 106,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	late := authenticateBatch(t, ingestion.GatewayEventsPath, lateBatch, 8, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, late, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochA, 4, 4, false)
	assertResolution(t, database, integrationGatewaySender, integrationEpochA, 4, "late_arrival", 1)
	assertCheckpoint(t, database, integrationGatewaySender, integrationEpochA, 5)

	oldEpochGapBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 7, 7, 107,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, oldEpochGapBatch, 9, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochA, 6, 6, true)

	newEpochBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochB, 1, 8, 108,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, newEpochBatch, 10, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertCheckpoint(t, database, integrationGatewaySender, integrationEpochB, 1)

	oldEpochLateBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochA, 6, 9, 109,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, oldEpochLateBatch, 11, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochA, 6, 6, false)
	assertResolution(t, database, integrationGatewaySender, integrationEpochA, 6, "late_arrival", 1)
	assertCheckpoint(t, database, integrationGatewaySender, integrationEpochB, 1)

	newEpochGapBatch := gatewayBatch(t, integrationGatewaySender, integrationEpochB, 3, 10, 110,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, newEpochGapBatch, 12, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochB, 2, 2, true)

	healthBatch := sourceHealthBatch(t, integrationGatewaySender, integrationEpochB, 4, 11, 111,
		receivedAt, integrationEpochB, 2, 2)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, healthBatch, 13, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	assertGap(t, database, integrationGatewaySender, integrationEpochB, 2, 2, false)
	assertResolution(t, database, integrationGatewaySender, integrationEpochB, 2, "permanent_loss", 1)
	assertCount(t, database, "sentinelflow.source_health_intervals", 1)

	authBatch := authenticatedApplicationBatch(t, integrationAuthSender, integrationEpochA, 1, 12, 112, receivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.AuthEventsPath,
		authenticateBatch(t, ingestion.AuthEventsPath, authBatch, 14, receivedAt), receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	var bindingDeadline time.Time
	if err = database.QueryRow(ctx, `SELECT binding_deadline FROM sentinelflow.auth_events WHERE event_id = $1`,
		authBatch.Records[0].AuthEvent.EventID).Scan(&bindingDeadline); err != nil {
		t.Fatalf("query auth binding deadline: %v", err)
	}
	if !bindingDeadline.Equal(receivedAt.Add(5 * time.Minute)) {
		t.Fatalf("binding deadline = %s, want %s", bindingDeadline, receivedAt.Add(5*time.Minute))
	}

	concurrentConnection, err := pgx.Connect(ctx, database.Config().ConnString())
	if err != nil {
		t.Fatalf("open concurrent integration connection: %v", err)
	}
	t.Cleanup(func() { _ = concurrentConnection.Close(context.Background()) })
	if _, err = concurrentConnection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatalf("set concurrent API role: %v", err)
	}
	concurrentStore, err := NewPostgreSQLBatchStore(&diagnosticBeginner{testing: t, connection: concurrentConnection})
	if err != nil {
		t.Fatalf("create concurrent store: %v", err)
	}
	concurrentBatch := gatewayBatch(t, "gateway.concurrent", integrationEpochA, 1, 13, 113,
		receivedAt, receivedAt.Add(-time.Second), receivedAt)
	concurrentReceipts := []ingestion.AuthenticatedBatch{
		authenticateBatch(t, ingestion.GatewayEventsPath, concurrentBatch, 15, receivedAt),
		authenticateBatch(t, ingestion.GatewayEventsPath, concurrentBatch, 16, receivedAt),
	}
	type storeResult struct {
		outcome api.StoreOutcome
		err     error
	}
	results := make(chan storeResult, 2)
	start := make(chan struct{})
	for index, target := range []*PostgreSQLBatchStore{store, concurrentStore} {
		go func(target *PostgreSQLBatchStore, authenticated ingestion.AuthenticatedBatch) {
			<-start
			result, storeErr := target.StoreBatch(ctx, ingestion.GatewayEventsPath, authenticated, receivedAt)
			results <- storeResult{outcome: result, err: storeErr}
		}(target, concurrentReceipts[index])
	}
	close(start)
	seenOutcomes := map[api.StoreOutcome]int{}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent StoreBatch() error = %v", result.err)
		}
		seenOutcomes[result.outcome]++
	}
	if seenOutcomes[api.StoreAccepted] != 1 || seenOutcomes[api.StoreDuplicate] != 1 {
		t.Fatalf("concurrent outcomes = %#v, want one accepted and one duplicate", seenOutcomes)
	}
	assertSenderCounts(t, database, "gateway.concurrent", 2, 1, 1)

	var batches, outbox int
	if err = database.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.ingest_batches`).Scan(&batches); err != nil {
		t.Fatalf("query batch count: %v", err)
	}
	if err = database.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.outbox_jobs`).Scan(&outbox); err != nil {
		t.Fatalf("query outbox count: %v", err)
	}
	if batches != outbox {
		t.Fatalf("outbox count = %d, want one for each of %d accepted receipts", outbox, batches)
	}

	exerciseSourceCoveragePersistence(t, database, store)
}

func exerciseSourceCoveragePersistence(
	t *testing.T,
	database *pgx.Conn,
	store *PostgreSQLBatchStore,
) {
	t.Helper()
	ctx := context.Background()
	registry, err := NewPostgreSQLSourceRegistry(database)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := registry.Register(ctx, ExpectedSourceBinding{
		BindingID:    integrationUUID(9001),
		SenderID:     "gateway.coverage",
		EndpointKind: SourceEndpointGateway,
		ServiceLabel: "demo",
		KeyID:        "integration-key",
		ConfigDigest: integrationDigest(9001),
	})
	if err != nil {
		t.Fatalf("register expected source: %v", err)
	}
	receivedAt := binding.EffectiveAt.Add(time.Millisecond).UTC().Truncate(time.Millisecond)
	segmentID := events.CoverageSegmentID("gateway.coverage", integrationEpochA, "epoch-start")

	firstBatch := gatewayBatch(t, "gateway.coverage", integrationEpochA, 1, 9101, 9201,
		receivedAt, receivedAt, receivedAt)
	firstCoverage, err := events.NewSourceCoverageV1(
		firstBatch.SenderID, firstBatch.SenderEpoch, segmentID, nil,
		receivedAt, receivedAt, firstBatch.BatchID, firstBatch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstBatch.Records = append(firstBatch.Records, events.SourceCoverageRecord(firstCoverage))
	firstAuthenticated := authenticateBatch(t, ingestion.GatewayEventsPath, firstBatch, 31, receivedAt)
	outcome, err := store.StoreBatch(ctx, ingestion.GatewayEventsPath, firstAuthenticated, receivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	firstDigest, err := firstCoverage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assertCoverage(t, database, firstCoverage.EventID, firstDigest, firstAuthenticated.BodyDigest, 1)
	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatchWithKeyID(t, ingestion.GatewayEventsPath, firstBatch, 36, receivedAt, "wrong-key"),
		receivedAt)
	if !errors.Is(err, api.ErrBatchConflict) {
		t.Fatalf("duplicate under different key ID error = %v, want ErrBatchConflict", err)
	}

	secondReceivedAt := receivedAt.Add(200 * time.Millisecond)
	secondEnd := receivedAt.Add(100 * time.Millisecond)
	secondBatch := gatewayBatch(t, "gateway.coverage", integrationEpochA, 2, 9102, 9202,
		secondReceivedAt, secondEnd, secondEnd)
	secondCoverage, err := events.NewSourceCoverageV1(
		secondBatch.SenderID, secondBatch.SenderEpoch, segmentID, &firstDigest,
		receivedAt, secondEnd, secondBatch.BatchID, secondBatch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondBatch.Records = append(secondBatch.Records, events.SourceCoverageRecord(secondCoverage))
	secondAuthenticated := authenticateBatch(t, ingestion.GatewayEventsPath, secondBatch, 32, secondReceivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, secondAuthenticated, secondReceivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	secondDigest, err := secondCoverage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assertCoverage(t, database, secondCoverage.EventID, secondDigest, secondAuthenticated.BodyDigest, 2)

	// The narrow outbox append converges only for the exact immutable batch and
	// deterministic identity; no direct table INSERT grant is needed.
	outbox := batchOutboxIdentity(secondBatch)
	var duplicateJobID string
	if err = database.QueryRow(ctx, insertOutboxSQL,
		secondBatch.SenderID, secondBatch.BatchID, secondAuthenticated.BodyDigest,
		outbox.jobID, outbox.idempotencyKey,
	).Scan(&duplicateJobID); err != nil || duplicateJobID != outbox.jobID {
		t.Fatalf("idempotent outbox append = %q err=%v", duplicateJobID, err)
	}
	if _, err = database.Exec(ctx, `INSERT INTO sentinelflow.outbox_jobs (
        job_id, kind, aggregate_type, aggregate_id, aggregate_version,
        idempotency_key, state, available_at, max_attempts
    ) VALUES ($1, 'detect', 'ingest_batch', $2, 1, $3, 'pending', clock_timestamp(), 8)`,
		integrationUUID(9991), secondBatch.BatchID, integrationDigest(9991)); err == nil {
		t.Fatal("API retained direct outbox INSERT authority")
	}
	if err = database.QueryRow(ctx, insertOutboxSQL,
		secondBatch.SenderID, secondBatch.BatchID, integrationDigest(9992),
		outbox.jobID, outbox.idempotencyKey,
	).Scan(&duplicateJobID); err == nil {
		t.Fatal("outbox append accepted a different raw body digest")
	}

	healthReceivedAt := secondReceivedAt.Add(200 * time.Millisecond)
	healthBatch := recoveryHealthBatch(t, "gateway.coverage", integrationEpochA, 3, 9103, 9203,
		healthReceivedAt, secondEnd, healthReceivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, healthBatch, 33, healthReceivedAt), healthReceivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)

	resetReceivedAt := healthReceivedAt.Add(200 * time.Millisecond)
	resetEnd := healthReceivedAt.Add(100 * time.Millisecond)
	resetBatch := gatewayBatch(t, "gateway.coverage", integrationEpochA, 4, 9104, 9204,
		resetReceivedAt, resetEnd, resetEnd)
	resetSegmentID := events.CoverageSegmentID(resetBatch.SenderID, resetBatch.SenderEpoch, healthBatch.BatchID)
	resetCoverage, err := events.NewSourceCoverageV1(
		resetBatch.SenderID, resetBatch.SenderEpoch, resetSegmentID, nil,
		healthReceivedAt, resetEnd, resetBatch.BatchID, resetBatch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	resetBatch.Records = append(resetBatch.Records, events.SourceCoverageRecord(resetCoverage))
	resetAuthenticated := authenticateBatch(t, ingestion.GatewayEventsPath, resetBatch, 34, resetReceivedAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, resetAuthenticated, resetReceivedAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	resetDigest, err := resetCoverage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assertCoverage(t, database, resetCoverage.EventID, resetDigest, resetAuthenticated.BodyDigest, 4)
	if resetCoverage.PreviousCoverageDigest != nil || resetCoverage.SegmentID == secondCoverage.SegmentID {
		t.Fatal("health reset bridged the previous coverage segment")
	}

	// Opening sequence 5 as a gap happens before marker persistence in the same
	// transaction, so a sequence-6 positive claim fails and all effects roll back.
	gapReceivedAt := resetReceivedAt.Add(200 * time.Millisecond)
	gapBatch := gatewayBatch(t, "gateway.coverage", integrationEpochA, 6, 9106, 9206,
		gapReceivedAt, gapReceivedAt, gapReceivedAt)
	gapCoverage, err := events.NewSourceCoverageV1(
		gapBatch.SenderID, gapBatch.SenderEpoch, resetSegmentID, &resetDigest,
		resetEnd, gapReceivedAt, gapBatch.BatchID, gapBatch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	gapBatch.Records = append(gapBatch.Records, events.SourceCoverageRecord(gapCoverage))
	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatch(t, ingestion.GatewayEventsPath, gapBatch, 35, gapReceivedAt), gapReceivedAt)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("gap coverage error = %v, want ErrBatchRejected", err)
	}
	var gapBatchCount int
	if err = database.QueryRow(ctx, `SELECT count(*) FROM sentinelflow.ingest_batches
        WHERE sender_id = $1 AND batch_id = $2`, gapBatch.SenderID, gapBatch.BatchID).Scan(&gapBatchCount); err != nil {
		t.Fatal(err)
	}
	if gapBatchCount != 0 {
		t.Fatal("rejected gap coverage left a partial batch")
	}

	legacyAt := gapReceivedAt.Add(time.Second)
	legacyBatch := gatewayBatch(t, "gateway.legacy", integrationEpochA, 1, 9401, 9501,
		legacyAt, legacyAt, legacyAt)
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatchWithKeyID(t, ingestion.GatewayEventsPath, legacyBatch, 40, legacyAt, ""), legacyAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	var legacyKeyID *string
	if err = database.QueryRow(ctx, `SELECT auth_key_id FROM sentinelflow.ingest_batches
        WHERE sender_id = $1 AND batch_id = $2`, legacyBatch.SenderID, legacyBatch.BatchID).Scan(&legacyKeyID); err != nil {
		t.Fatal(err)
	}
	if legacyKeyID != nil {
		t.Fatalf("legacy non-coverage batch gained key authority: %q", *legacyKeyID)
	}

	for index, test := range []struct {
		name, senderID, authenticatedKeyID string
	}{
		{name: "empty", senderID: "gateway.coverage-empty", authenticatedKeyID: ""},
		{name: "wrong", senderID: "gateway.coverage-wrong", authenticatedKeyID: "wrong-key"},
	} {
		binding, registerErr := registry.Register(ctx, ExpectedSourceBinding{
			BindingID: integrationUUID(9600 + index), SenderID: test.senderID,
			EndpointKind: SourceEndpointGateway, ServiceLabel: "demo",
			KeyID: "expected-key", ConfigDigest: integrationDigest(9600 + index),
		})
		if registerErr != nil {
			t.Fatalf("register %s key binding: %v", test.name, registerErr)
		}
		at := binding.EffectiveAt.Add(time.Millisecond).UTC().Truncate(time.Millisecond)
		batch := initialCoverageBatch(t, test.senderID, integrationEpochA, 1,
			9700+index, 9800+index, at, "key-negative")
		_, storeErr := store.StoreBatch(ctx, ingestion.GatewayEventsPath,
			authenticateBatchWithKeyID(t, ingestion.GatewayEventsPath, batch, byte(41+index), at, test.authenticatedKeyID), at)
		if !errors.Is(storeErr, api.ErrBatchRejected) {
			t.Fatalf("%s key coverage error = %v, want ErrBatchRejected", test.name, storeErr)
		}
	}

	oldBinding, err := registry.Register(ctx, ExpectedSourceBinding{
		BindingID: integrationUUID(9901), SenderID: "gateway.coverage-rotated",
		EndpointKind: SourceEndpointGateway, ServiceLabel: "demo",
		KeyID: "old-key", ConfigDigest: integrationDigest(9901),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Retire(ctx, SourceBindingRetirement{
		RetirementID: integrationUUID(9902), BindingID: oldBinding.BindingID,
		ReasonDigest: integrationDigest(9902),
	}); err != nil {
		t.Fatal(err)
	}
	newBinding, err := registry.Register(ctx, ExpectedSourceBinding{
		BindingID: integrationUUID(9903), SenderID: "gateway.coverage-rotated",
		EndpointKind: SourceEndpointGateway, ServiceLabel: "demo",
		KeyID: "new-key", ConfigDigest: integrationDigest(9903),
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationAt := newBinding.EffectiveAt.Add(time.Millisecond).UTC().Truncate(time.Millisecond)
	rotationBatch := initialCoverageBatch(t, "gateway.coverage-rotated", integrationEpochA, 1,
		9910, 9920, rotationAt, "rotated")
	_, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath,
		authenticateBatchWithKeyID(t, ingestion.GatewayEventsPath, rotationBatch, 43, rotationAt, "old-key"),
		rotationAt)
	if !errors.Is(err, api.ErrBatchRejected) {
		t.Fatalf("stale key coverage error = %v, want ErrBatchRejected", err)
	}
	rotationAuthenticated := authenticateBatchWithKeyID(
		t, ingestion.GatewayEventsPath, rotationBatch, 44, rotationAt, "new-key")
	outcome, err = store.StoreBatch(ctx, ingestion.GatewayEventsPath, rotationAuthenticated, rotationAt)
	assertOutcome(t, outcome, err, api.StoreAccepted)
	var rotationKeyID string
	if err = database.QueryRow(ctx, `SELECT auth_key_id FROM sentinelflow.ingest_batches
        WHERE sender_id = $1 AND batch_id = $2`, rotationBatch.SenderID, rotationBatch.BatchID).Scan(&rotationKeyID); err != nil {
		t.Fatal(err)
	}
	if rotationKeyID != "new-key" {
		t.Fatalf("rotated batch key ID = %q", rotationKeyID)
	}

	if _, err = database.Exec(ctx, `UPDATE sentinelflow.source_coverage_attestations
        SET trust_reason = trust_reason WHERE coverage_event_id = $1`, firstCoverage.EventID); err == nil {
		t.Fatal("API mutated append-only source coverage evidence")
	}
	setIntegrationRole(t, database, "sentinelflow_worker")
	var ignored string
	err = database.QueryRow(ctx, registerExpectedSourceBindingSQL,
		integrationUUID(9301), "worker.forbidden", SourceEndpointGateway,
		"demo", "worker-key", integrationDigest(9301),
	).Scan(&ignored, &ignored, &ignored, &ignored, &ignored, &ignored, &ignored, &ignored, new(time.Time))
	if err == nil {
		t.Fatal("worker executed expected-source registration")
	}
	setIntegrationRole(t, database, "sentinelflow_read")
	err = database.QueryRow(ctx, insertOutboxSQL,
		secondBatch.SenderID, secondBatch.BatchID, secondAuthenticated.BodyDigest,
		outbox.jobID, outbox.idempotencyKey,
	).Scan(&ignored)
	if err == nil {
		t.Fatal("read role executed ingest outbox append")
	}
	setIntegrationRole(t, database, "sentinelflow_api")

	// A down migration must refuse to erase live authority or evidence.
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source coverage down migration")
	}
	down, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "..", "..", "db", "migrations", "000015_source_coverage.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(ctx, string(down)); err == nil {
		t.Fatal("source coverage down migration discarded live evidence")
	}
	_, _ = database.Exec(ctx, `ROLLBACK`)
	if _, err = database.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal(err)
	}
}

func assertCoverage(
	t *testing.T,
	database *pgx.Conn,
	eventID, expectedDigest, expectedRawBodyDigest string,
	expectedSequence int64,
) {
	t.Helper()
	var digest, rawBodyDigest string
	var sequence int64
	if err := database.QueryRow(context.Background(), `
SELECT coverage_digest, raw_body_digest, covered_through_sequence
FROM sentinelflow.source_coverage_attestations
WHERE coverage_event_id = $1`, eventID).Scan(&digest, &rawBodyDigest, &sequence); err != nil {
		t.Fatal(err)
	}
	if digest != expectedDigest || rawBodyDigest != expectedRawBodyDigest || sequence != expectedSequence {
		t.Fatalf("coverage persistence = (%q, %q, %d), want (%q, %q, %d)",
			digest, rawBodyDigest, sequence, expectedDigest, expectedRawBodyDigest, expectedSequence)
	}
}

func setIntegrationRole(t *testing.T, database *pgx.Conn, role string) {
	t.Helper()
	allowed := map[string]bool{
		"sentinelflow_api": true, "sentinelflow_worker": true, "sentinelflow_read": true,
	}
	if !allowed[role] {
		t.Fatalf("unsafe integration role %q", role)
	}
	if _, err := database.Exec(context.Background(), `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(context.Background(), `SET ROLE `+role); err != nil {
		t.Fatal(err)
	}
}

func assertSenderCounts(
	t *testing.T,
	database *pgx.Conn,
	senderID string,
	wantNonces, wantBatches, wantEvents int,
) {
	t.Helper()
	var nonces, batches, eventCount int
	if err := database.QueryRow(context.Background(), `
SELECT
    (SELECT count(*) FROM sentinelflow.ingest_replay_nonces WHERE sender_id = $1),
    (SELECT count(*) FROM sentinelflow.ingest_batches WHERE sender_id = $1),
    (SELECT count(*) FROM sentinelflow.gateway_events WHERE sender_id = $1)`, senderID).Scan(
		&nonces, &batches, &eventCount,
	); err != nil {
		t.Fatalf("query sender counts: %v", err)
	}
	if nonces != wantNonces || batches != wantBatches || eventCount != wantEvents {
		t.Fatalf("sender counts = (%d, %d, %d), want (%d, %d, %d)",
			nonces, batches, eventCount, wantNonces, wantBatches, wantEvents)
	}
}

type diagnosticBeginner struct {
	testing    *testing.T
	connection *pgx.Conn
}

func (b *diagnosticBeginner) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := b.connection.BeginTx(ctx, options)
	if err != nil {
		b.testing.Logf("BeginTx failed: %v", err)
		return nil, err
	}
	return &diagnosticTx{Tx: tx, testing: b.testing}, nil
}

type diagnosticTx struct {
	pgx.Tx
	testing *testing.T
}

func (tx *diagnosticTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	tag, err := tx.Tx.Exec(ctx, sql, arguments...)
	if err != nil {
		tx.testing.Logf("transaction Exec failed: %v", err)
	}
	return tag, err
}

func (tx *diagnosticTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return &diagnosticRow{Row: tx.Tx.QueryRow(ctx, sql, arguments...), testing: tx.testing}
}

func (tx *diagnosticTx) Commit(ctx context.Context) error {
	err := tx.Tx.Commit(ctx)
	if err != nil {
		tx.testing.Logf("transaction Commit failed: %v", err)
	}
	return err
}

type diagnosticRow struct {
	pgx.Row
	testing *testing.T
}

func (row *diagnosticRow) Scan(destinations ...any) error {
	err := row.Row.Scan(destinations...)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		row.testing.Logf("transaction QueryRow scan failed: %v", err)
	}
	return err
}

func startPostgreSQL17(t *testing.T) *pgx.Conn {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("integration tests require Docker: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	container := fmt.Sprintf("sentinelflow-repository-%d-%d", os.Getpid(), time.Now().UnixNano())
	password := "sentinelflow-test-only"
	runDocker(t, ctx, nil, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD="+password, "--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", container).Run()
	})

	ready := false
	consecutiveReady := 0
	for attempt := 0; attempt < 240; attempt++ {
		command := exec.CommandContext(ctx, "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "postgres")
		if command.Run() == nil {
			consecutiveReady++
			// The official image briefly exposes its initialization server and
			// then restarts PostgreSQL. Require a stable window so migrations do
			// not race that handoff.
			if consecutiveReady >= 5 {
				ready = true
				break
			}
		} else {
			consecutiveReady = 0
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatal("disposable PostgreSQL 17 did not become ready")
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository integration test")
	}
	migrations, err := filepath.Glob(filepath.Join(filepath.Dir(currentFile), "..", "..", "db", "migrations", "*.up.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("locate migrations: %v", err)
	}
	for _, migration := range migrations {
		contents, readErr := os.ReadFile(migration)
		if readErr != nil {
			t.Fatalf("read migration %s: %v", filepath.Base(migration), readErr)
		}
		runDocker(t, ctx, contents, "exec", "-i", container, "psql", "--set", "ON_ERROR_STOP=1",
			"--username", "postgres", "--dbname", "postgres")
	}

	portOutput := runDocker(t, ctx, nil, "port", container, "5432/tcp")
	address := strings.TrimSpace(string(portOutput))
	colon := strings.LastIndexByte(address, ':')
	if colon < 0 || colon == len(address)-1 {
		t.Fatalf("unexpected Docker port output %q", address)
	}
	url := fmt.Sprintf("postgresql://postgres:%s@127.0.0.1:%s/postgres?sslmode=disable", password, address[colon+1:])
	connection, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect to disposable PostgreSQL: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = connection.Close(closeCtx)
	})
	if _, err = connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatalf("set least-privilege API role: %v", err)
	}
	return connection
}

func runDocker(t *testing.T, ctx context.Context, input []byte, arguments ...string) []byte {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker command failed: %v\n%s", err, output)
	}
	return output
}

func authenticateBatch(t *testing.T, endpointPath string, batch events.EventBatchV1, nonceID byte, now time.Time) ingestion.AuthenticatedBatch {
	return authenticateBatchWithKeyID(t, endpointPath, batch, nonceID, now, "integration-key")
}

func authenticateBatchWithKeyID(
	t *testing.T,
	endpointPath string,
	batch events.EventBatchV1,
	nonceID byte,
	now time.Time,
	keyID string,
) ingestion.AuthenticatedBatch {
	t.Helper()
	rawBody, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal event batch: %v", err)
	}
	registry, err := ingestion.NewRegistry([]ingestion.Binding{{
		SenderID: batch.SenderID, EndpointPath: endpointPath, KeyID: keyID, Key: integrationKey,
	}})
	if err != nil {
		t.Fatalf("create sender registry: %v", err)
	}
	nonce := make([]byte, 16)
	for index := range nonce {
		nonce[index] = nonceID + byte(index)
	}
	headers, err := ingestion.Sign(endpointPath, batch.SenderID, integrationKey, rawBody, nonce, now)
	if err != nil {
		t.Fatalf("sign event batch: %v", err)
	}
	authenticated, err := registry.Authenticate(endpointPath, headers, rawBody, now)
	if err != nil {
		t.Fatalf("authenticate event batch: %v", err)
	}
	return authenticated
}

func gatewayBatch(
	t *testing.T,
	senderID, senderEpoch string,
	sequence uint64,
	batchNumber, eventNumber int,
	sentAt, startedAt, completedAt time.Time,
) events.EventBatchV1 {
	t.Helper()
	return events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      senderID,
		SenderEpoch:   senderEpoch,
		BatchID:       integrationUUID(batchNumber),
		Sequence:      sequence,
		SentAt:        mustTimestamp(t, sentAt),
		Records: []events.EventRecordV1{events.GatewayHTTPRecord(events.GatewayHTTPV1{
			SchemaVersion:      events.GatewayHTTPV1Schema,
			EventID:            integrationUUID(eventNumber),
			RequestID:          integrationUUID(eventNumber + 1000),
			TraceID:            integrationUUID(eventNumber + 2000),
			IdempotencyKey:     integrationDigest(eventNumber),
			StartedAt:          mustTimestamp(t, startedAt),
			CompletedAt:        mustTimestamp(t, completedAt),
			SourceIP:           "192.0.2.10",
			Method:             "GET",
			Protocol:           "HTTP/1.1",
			RouteLabel:         "unknown",
			PathCatalogVersion: events.PathCatalogV1,
			SuspiciousPathID:   events.SuspiciousPathNone,
			Host:               "example.test",
			ServiceLabel:       "demo",
			StatusCode:         200,
			ResponseBytes:      64,
			LatencyMS:          1,
		})},
	}
}

func initialCoverageBatch(
	t *testing.T,
	senderID, senderEpoch string,
	sequence uint64,
	batchNumber, eventNumber int,
	at time.Time,
	segmentToken string,
) events.EventBatchV1 {
	t.Helper()
	batch := gatewayBatch(t, senderID, senderEpoch, sequence, batchNumber, eventNumber, at, at, at)
	coverage, err := events.NewSourceCoverageV1(
		senderID, senderEpoch, events.CoverageSegmentID(senderID, senderEpoch, segmentToken), nil,
		at, at, batch.BatchID, batch.Sequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	batch.Records = append(batch.Records, events.SourceCoverageRecord(coverage))
	return batch
}

func sourceHealthBatch(
	t *testing.T,
	senderID, senderEpoch string,
	sequence uint64,
	batchNumber, eventNumber int,
	receivedAt time.Time,
	affectedEpoch string,
	sequenceStart, sequenceEnd uint64,
) events.EventBatchV1 {
	t.Helper()
	oldIntervalStart := mustTimestamp(t, receivedAt.Add(-24*time.Hour))
	oldIntervalEnd := mustTimestamp(t, receivedAt.Add(-23*time.Hour))
	return events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      senderID,
		SenderEpoch:   senderEpoch,
		BatchID:       integrationUUID(batchNumber),
		Sequence:      sequence,
		SentAt:        mustTimestamp(t, receivedAt),
		Records: []events.EventRecordV1{events.SourceHealthRecord(events.SourceHealthV1{
			SchemaVersion:       events.SourceHealthV1Schema,
			EventID:             integrationUUID(eventNumber),
			IdempotencyKey:      integrationDigest(eventNumber),
			OccurredAt:          mustTimestamp(t, receivedAt),
			SourceID:            senderID,
			Cause:               events.SourceHealthPermanentLoss,
			State:               events.SourceHealthStateLost,
			AffectedSenderEpoch: affectedEpoch,
			SequenceStart:       &sequenceStart,
			SequenceEnd:         &sequenceEnd,
			IntervalStart:       &oldIntervalStart,
			IntervalEnd:         &oldIntervalEnd,
			DroppedCount:        sequenceEnd - sequenceStart + 1,
			DetailCode:          events.SourceHealthDetailKnownRange,
		})},
	}
}

func recoveryHealthBatch(
	t *testing.T,
	senderID, senderEpoch string,
	sequence uint64,
	batchNumber, eventNumber int,
	receivedAt, intervalStart, intervalEnd time.Time,
) events.EventBatchV1 {
	t.Helper()
	start := mustTimestamp(t, intervalStart)
	end := mustTimestamp(t, intervalEnd)
	return events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      senderID,
		SenderEpoch:   senderEpoch,
		BatchID:       integrationUUID(batchNumber),
		Sequence:      sequence,
		SentAt:        mustTimestamp(t, receivedAt),
		Records: []events.EventRecordV1{events.SourceHealthRecord(events.SourceHealthV1{
			SchemaVersion:       events.SourceHealthV1Schema,
			EventID:             integrationUUID(eventNumber),
			IdempotencyKey:      integrationDigest(eventNumber),
			OccurredAt:          mustTimestamp(t, receivedAt),
			SourceID:            senderID,
			Cause:               events.SourceHealthRecovered,
			State:               events.SourceHealthStateRecovered,
			AffectedSenderEpoch: senderEpoch,
			IntervalStart:       &start,
			IntervalEnd:         &end,
			DetailCode:          events.SourceHealthDetailDeliveryRestored,
		})},
	}
}

func authenticatedApplicationBatch(
	t *testing.T,
	senderID, senderEpoch string,
	sequence uint64,
	batchNumber, eventNumber int,
	receivedAt time.Time,
) events.EventBatchV1 {
	t.Helper()
	return events.EventBatchV1{
		SchemaVersion: events.EventBatchV1Schema,
		SenderID:      senderID,
		SenderEpoch:   senderEpoch,
		BatchID:       integrationUUID(batchNumber),
		Sequence:      sequence,
		SentAt:        mustTimestamp(t, receivedAt),
		Records: []events.EventRecordV1{events.AuthEventRecord(events.AuthEventV1{
			SchemaVersion:    events.AuthEventV1Schema,
			EventID:          integrationUUID(eventNumber),
			GatewayRequestID: integrationUUID(eventNumber + 1000),
			TraceID:          integrationUUID(eventNumber + 2000),
			IdempotencyKey:   integrationDigest(eventNumber),
			OccurredAt:       mustTimestamp(t, receivedAt),
			SourceIP:         "192.0.2.20",
			ServiceLabel:     "demo",
			RouteLabel:       "login",
			AccountHash:      fmt.Sprintf("hmac-sha256:%064x", eventNumber),
			Outcome:          events.AuthOutcomeFailed,
		})},
	}
}

func integrationUUID(value int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", value)
}

func integrationDigest(value int) string {
	return fmt.Sprintf("sha256:%064x", value)
}

func assertOutcome(t *testing.T, got api.StoreOutcome, err error, want api.StoreOutcome) {
	t.Helper()
	if err != nil || got != want {
		t.Fatalf("StoreBatch() = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func assertCount(t *testing.T, database *pgx.Conn, table string, want int) {
	t.Helper()
	if !strings.HasPrefix(table, "sentinelflow.") {
		t.Fatalf("unsafe test table %q", table)
	}
	var got int
	if err := database.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("count %s = %d, want %d", table, got, want)
	}
}

func assertCheckpoint(t *testing.T, database *pgx.Conn, senderID, wantEpoch string, wantSequence int64) {
	t.Helper()
	var epoch string
	var sequence int64
	if err := database.QueryRow(context.Background(), `
SELECT sender_epoch, last_acknowledged_sequence
FROM sentinelflow.sender_checkpoints
WHERE sender_id = $1 AND endpoint_kind = 'gateway'`, senderID).Scan(&epoch, &sequence); err != nil {
		t.Fatalf("query checkpoint: %v", err)
	}
	if epoch != wantEpoch || sequence != wantSequence {
		t.Fatalf("checkpoint = (%q, %d), want (%q, %d)", epoch, sequence, wantEpoch, wantSequence)
	}
}

func assertEventTrust(t *testing.T, database *pgx.Conn, eventID, wantState, wantReason string) {
	t.Helper()
	var state, reason string
	if err := database.QueryRow(context.Background(), `
SELECT trust_state, trust_reason FROM sentinelflow.gateway_events WHERE event_id = $1`, eventID).Scan(&state, &reason); err != nil {
		t.Fatalf("query event trust: %v", err)
	}
	if state != wantState || reason != wantReason {
		t.Fatalf("event trust = (%q, %q), want (%q, %q)", state, reason, wantState, wantReason)
	}
}

func assertGap(
	t *testing.T,
	database *pgx.Conn,
	senderID, epoch string,
	start, end int64,
	want bool,
) {
	t.Helper()
	var found bool
	if err := database.QueryRow(context.Background(), `
SELECT EXISTS (
    SELECT 1 FROM sentinelflow.ingest_sequence_gaps
    WHERE sender_id = $1 AND endpoint_kind = 'gateway' AND sender_epoch = $2
      AND sequence_start = $3 AND sequence_end = $4
)`, senderID, epoch, start, end).Scan(&found); err != nil {
		t.Fatalf("query sequence gap: %v", err)
	}
	if found != want {
		t.Fatalf("gap %s/%d-%d found = %t, want %t", epoch, start, end, found, want)
	}
}

func assertResolution(
	t *testing.T,
	database *pgx.Conn,
	senderID, epoch string,
	sequence int64,
	resolution string,
	want int,
) {
	t.Helper()
	var got int
	if err := database.QueryRow(context.Background(), `
SELECT count(*) FROM sentinelflow.ingest_sequence_gap_resolutions
WHERE sender_id = $1 AND endpoint_kind = 'gateway' AND sender_epoch = $2
  AND sequence_start = $3 AND sequence_end = $3 AND resolution = $4`,
		senderID, epoch, sequence, resolution).Scan(&got); err != nil {
		t.Fatalf("query gap resolution: %v", err)
	}
	if got != want {
		t.Fatalf("resolution %s/%d/%s count = %d, want %d", epoch, sequence, resolution, got, want)
	}
}
