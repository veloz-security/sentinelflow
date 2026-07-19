//go:build integration

package validationstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryimport"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationworker"
	"github.com/devwooops/sentinelflow/internal/worker"
)

func TestActivatedDemoValidationRunOnceAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-demo-activation-validation-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432",
		"postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	url := fmt.Sprintf("postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port)
	admin := connectWithRetry(t, ctx, url)
	defer admin.Close(context.Background())
	applyMigrations(t, ctx, admin)

	analysisSecret := []byte(strings.Repeat("a", 32))
	validationSecret := []byte(strings.Repeat("v", 32))
	prepareDemoActivationRoles(t, ctx, admin, analysisSecret, validationSecret)
	importerPool := demoValidationImporterPool(t, ctx, url)
	proof := importFreshDemoHistory(t, ctx, importerPool)
	if err := demohistoryactivation.FenceImporter(ctx, importerPool); err != nil {
		t.Fatalf("fence demo history importer: %v", err)
	}
	importerPool.Close()

	fixtureAt := proof.binding.HistoryCutoff().At()
	insertValidationFixtureAt(t, ctx, admin, "203.0.113.20", fixtureAt)

	activator := demoValidationActivatorConnection(t, ctx, admin, url)
	pair, err := validation.CreateDemoHistoryRuntimeActivationPair(
		ctx, activator, analysisSecret, validationSecret, proof.verifier,
		validation.DemoHistoryVerificationInput{
			SignedManifestEnvelope: proof.envelope,
			ImportedRowsDigest:     validation.PinnedDemoHistoryImportedRowsDigest,
			ImportedRecordCount:    validation.PinnedDemoHistoryDatasetRecordCount,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	validationActivation, validationOK := pair.Validation()
	if _, analysisOK := pair.Analysis(); !analysisOK || !validationOK {
		t.Fatal("activated demo validation receipt unavailable")
	}
	if err := demohistoryactivation.FenceBootstrap(ctx, activator); err != nil {
		t.Fatalf("fence demo history activator: %v", err)
	}
	activator.Close(context.Background())

	workerPool := demoValidationWorkerPool(t, ctx, url)
	defer workerPool.Close()
	store, err := NewPostgreSQLActivatedDemoStore(workerPool, validationActivation)
	if err != nil {
		t.Fatal(err)
	}
	protectedContract, err := validation.LoadProtectedContractFile(filepath.Join(
		demoValidationRepositoryRoot(t), "contracts", "enforcement", "protected_ipv4_v1.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	protectedGate, err := validation.NewProtectedGate(protectedContract, validation.ProtectedConfig{
		Environment: validation.EnvironmentDemo,
		Demo: validation.DemoExceptionConfig{
			Profile: validation.DemoExceptionIsolatedRFC5737, AllowRFC5737: true,
			IsolationVerified: true, HostRulesetUnchanged: true,
			ClientCIDR: "203.0.113.0/24", AttackSourceIPv4: "203.0.113.20",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	baseContract, err := os.ReadFile(filepath.Join(
		demoValidationRepositoryRoot(t), "contracts", "enforcement", "nft_base_chain_v1.nft",
	))
	if err != nil {
		t.Fatal(err)
	}
	liveSchema, err := os.ReadFile(filepath.Join(
		demoValidationRepositoryRoot(t), "contracts", "enforcement", "nft_base_chain_v1.live.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	config := validationworker.DefaultConfig(
		"validation-worker", testDigest, "nftables v1.0.9", testDigest, testDigest,
	)
	config.Environment = validation.EnvironmentDemo
	config.LeaseDuration = 30 * time.Second
	runtime, err := validationworker.New(store, config, validationworker.Dependencies{
		Clock: runtimeTestClock{now: now}, Tokens: runtimeTestTokenSource{},
		Jitter: runtimeTestJitter{}, ProtectedGate: protectedGate,
		SyntaxChecker: runtimeTestSyntaxChecker{}, BaseContract: baseContract, LiveSchema: liveSchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.RunOnce(ctx)
	if err != nil || result.Outcome != worker.OutcomeCompleted ||
		result.State != validationworker.StateValid {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var jobState, claimState string
	var gateCount, runtimeUses, policyCount int
	if err := admin.QueryRow(ctx, `SELECT
  (SELECT state FROM sentinelflow.outbox_jobs WHERE job_id = $1::uuid),
  (SELECT state FROM sentinelflow.validation_attempt_claims WHERE job_id = $1::uuid),
  (SELECT count(*) FROM sentinelflow.validation_attempt_gates gate
     JOIN sentinelflow.validation_attempt_claims claim
       ON claim.validation_attempt_id = gate.validation_attempt_id
    WHERE claim.job_id = $1::uuid),
  (SELECT count(*) FROM sentinelflow.demo_history_runtime_uses
    WHERE consumer = 'validation' AND job_id = $1::uuid
      AND aggregate_id = $2::uuid AND aggregate_version = 1),
  (SELECT count(*) FROM sentinelflow.policy_proposals WHERE analysis_id = $2::uuid)`,
		testJobID, testAnalysisID).Scan(
		&jobState, &claimState, &gateCount, &runtimeUses, &policyCount,
	); err != nil || jobState != "completed" || claimState != "valid" ||
		gateCount != 6 || runtimeUses != 1 || policyCount != 1 {
		t.Fatalf("job=%s claim=%s gates=%d uses=%d policies=%d err=%v",
			jobState, claimState, gateCount, runtimeUses, policyCount, err)
	}
}

type freshDemoHistoryProof struct {
	binding  validation.VerifiedDemoHistoryBinding
	issuedAt time.Time
	verifier *validation.StrictDemoHistoryManifestVerifier
	envelope []byte
}

func importFreshDemoHistory(
	t testing.TB,
	ctx context.Context,
	pool *pgxpool.Pool,
) freshDemoHistoryProof {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clockAt := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	runScope := "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000900"
	manifest := map[string]any{
		"clock_at":               clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_end":           clockAt.Format("2006-01-02T15:04:05.000Z"),
		"coverage_start":         clockAt.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
		"dataset_digest":         validation.PinnedDemoHistoryDatasetDigest,
		"dataset_id":             validation.PinnedDemoHistoryDatasetID,
		"dataset_record_count":   validation.PinnedDemoHistoryDatasetRecordCount,
		"dataset_schema_version": validation.DemoHistoryDatasetSchemaVersion,
		"import_id":              "019b0000-0000-7000-8000-000000000501",
		"issued_at":              issuedAt.Format("2006-01-02T15:04:05.000Z"),
		"manifest_id":            "019b0000-0000-7000-8000-000000000500",
		"path_catalog_version":   "path-catalog-v1",
		"profile":                validation.DemoHistoryProfile,
		"schema_version":         validation.DemoHistoryManifestSchemaVersion,
		"source_health_digest":   validation.PinnedDemoHistorySourceHealthDigest,
	}
	manifestJCS, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest(manifestJCS)
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(manifestDigest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, append([]byte(validation.DemoHistorySignatureDomain+"\n"), digestBytes...))
	envelope, err := json.Marshal(map[string]any{
		"fixture_only":        false,
		"key_scope":           runScope,
		"manifest":            manifest,
		"manifest_digest":     manifestDigest,
		"manifest_jcs_b64url": base64.RawURLEncoding.EncodeToString(manifestJCS),
		"public_key_b64url":   base64.RawURLEncoding.EncodeToString(publicKey),
		"schema_version":      validation.DemoHistorySignedManifestSchemaVersion,
		"signature_b64url":    base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := validation.NewStrictDemoHistoryManifestVerifier(validation.DemoHistoryManifestVerifierConfig{
		Environment: validation.EnvironmentDemo, ExpectedPublicKey: publicKey,
		ExpectedRunScope:                 runScope,
		ExpectedImportID:                 "019b0000-0000-7000-8000-000000000501",
		ExpectedClockAt:                  clockAt,
		ExpectedImpactSourceHealthDigest: validation.PinnedDemoHistoryImpactSourceHealthDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := demohistoryimport.NewFixedDatasetFile(demoValidationRepositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	importer, err := demohistoryimport.New(pool, reader, verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := importer.Import(ctx, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return freshDemoHistoryProof{
		binding: result.VerifiedBinding(), issuedAt: issuedAt,
		verifier: verifier, envelope: append([]byte(nil), envelope...),
	}
}

func prepareDemoActivationRoles(
	t testing.TB,
	ctx context.Context,
	connection *pgx.Conn,
	analysisSecret []byte,
	validationSecret []byte,
) {
	t.Helper()
	database := pgx.Identifier{"postgres"}.Sanitize()
	statements := []string{
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + database + " SET statement_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + database + " SET transaction_timeout = '2min'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + database + " SET idle_in_transaction_session_timeout = '5s'",
		"ALTER ROLE sentinelflow_demo_importer IN DATABASE " + database + " SET idle_session_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + database + " SET statement_timeout = '15s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + database + " SET transaction_timeout = '30s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + database + " SET idle_in_transaction_session_timeout = '5s'",
		"ALTER ROLE sentinelflow_demo_activator IN DATABASE " + database + " SET idle_session_timeout = '30s'",
	}
	for _, statement := range statements {
		if _, err := connection.Exec(ctx, statement); err != nil {
			t.Fatalf("configure demo activation role: %v", err)
		}
	}
	deadline := time.Now().UTC().Add(4 * time.Minute).Truncate(time.Millisecond)
	if _, err := connection.Exec(ctx, fmt.Sprintf(
		"ALTER ROLE sentinelflow_demo_importer LOGIN PASSWORD 'demo-importer-test-only' VALID UNTIL '%s'",
		deadline.Format(time.RFC3339Nano),
	)); err != nil {
		t.Fatalf("enable demo importer: %v", err)
	}
	var pinned bool
	if err := connection.QueryRow(ctx,
		`SELECT sentinelflow.pin_demo_history_runtime_capability_expectation_000030($1,$2,$3)`,
		digest(analysisSecret), digest(validationSecret), deadline,
	).Scan(&pinned); err != nil || !pinned {
		t.Fatalf("pin demo activation capabilities: pinned=%v err=%v", pinned, err)
	}
}

func demoValidationImporterPool(t testing.TB, ctx context.Context, url string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.ConnConfig.User = "sentinelflow_demo_importer"
	config.ConnConfig.Password = "demo-importer-test-only"
	config.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-history-importer-test"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func demoValidationActivatorConnection(
	t testing.TB,
	ctx context.Context,
	admin *pgx.Conn,
	url string,
) *pgx.Conn {
	t.Helper()
	deadline := time.Now().UTC().Add(4 * time.Minute).Truncate(time.Millisecond)
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"ALTER ROLE sentinelflow_demo_activator LOGIN PASSWORD 'demo-activator-test-only' VALID UNTIL '%s'",
		deadline.Format(time.RFC3339Nano),
	)); err != nil {
		t.Fatalf("enable demo activator: %v", err)
	}
	config, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "sentinelflow_demo_activator"
	config.Password = "demo-activator-test-only"
	config.RuntimeParams["application_name"] = "sentinelflow-demo-activator-test"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect demo activator: %v", err)
	}
	return connection
}

func demoValidationWorkerPool(t testing.TB, ctx context.Context, url string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 6
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "SET ROLE sentinelflow_worker")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func demoValidationRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
