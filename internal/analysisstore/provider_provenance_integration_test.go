//go:build integration

package analysisstore

import (
	"context"
	"encoding/json"
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

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
)

func TestAnalysisProviderProvenanceAgainstPostgreSQL17(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-analysis-provider-%d", time.Now().UnixNano())
	runDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForPostgreSQL(t, ctx, container)
	port := dockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	admin, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	applyProviderMigrationPrefix(t, ctx, admin, 20)
	installAnalysisProducerHistory(t, ctx, admin)

	workerConnection := connectAnalysisWorker(t, ctx, connectionString)
	t.Cleanup(func() { _ = workerConnection.Close(context.Background()) })
	store, err := NewPostgreSQLStore(workerConnection)
	if err != nil {
		t.Fatal(err)
	}

	// Produce one valid legacy row through the pre-000021 finalizer, prove that
	// ambiguous drift aborts the migration, then backfill the exact legacy tuple.
	legacy := insertAnalysisLifecycleFixture(t, ctx, admin, 0xd00, 1, true)
	legacyJob := leaseLifecycleJob(t, ctx, store, legacy, 0xd10, "provider-legacy")
	legacySnapshot := prepareLifecycleJob(t, ctx, store, legacyJob)
	finalizeLegacyProviderRow(t, ctx, workerConnection,
		lifecycleSuccessFinalize(legacyJob, legacySnapshot))
	if _, err = admin.Exec(ctx, `
UPDATE sentinelflow.ai_analyses SET model = 'drifted-model'
WHERE analysis_id = $1::uuid`, legacySnapshot.AnalysisID); err != nil {
		t.Fatal(err)
	}
	up, down := providerMigrationFiles(t)
	if _, err = admin.Exec(ctx, string(up)); err == nil ||
		!strings.Contains(err.Error(), "legacy analysis provider provenance is ambiguous") {
		t.Fatalf("ambiguous legacy migration err=%v", err)
	}
	if _, err = admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `
UPDATE sentinelflow.ai_analyses SET model = 'gpt-5.6-sol'
WHERE analysis_id = $1::uuid`, legacySnapshot.AnalysisID); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000021 legacy backfill: %v", err)
	}
	assertProviderRows(t, ctx, admin, legacySnapshot.AnalysisID,
		"openai_responses", "openai-responses-v1", ai.Model,
		ai.ReasoningEffort, "operator-v1", true)

	// OpenAI-only data can safely cycle down/up, and repeated up is idempotent.
	if _, err = admin.Exec(ctx, string(down)); err != nil {
		t.Fatalf("000021 safe down: %v", err)
	}
	if _, err = admin.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000021 safe re-up: %v", err)
	}
	if _, err = admin.Exec(ctx, string(up)); err != nil {
		t.Fatalf("000021 idempotent re-up: %v", err)
	}
	assertProviderRows(t, ctx, admin, legacySnapshot.AnalysisID,
		"openai_responses", "openai-responses-v1", ai.Model,
		ai.ReasoningEffort, "operator-v1", true)

	openAI := insertAnalysisLifecycleFixture(t, ctx, admin, 0xe00, 1, true)
	openAIJob := leaseLifecycleJob(t, ctx, store, openAI, 0xe10, "provider-openai")
	openAISnapshot := prepareLifecycleJob(t, ctx, store, openAIJob)
	openAIRequest := lifecycleSuccessFinalize(openAIJob, openAISnapshot)
	assertProviderMutationRejected(t, ctx, workerConnection, openAIRequest,
		"unknown analysis provider", func(success map[string]any) {
			success["provider_kind"] = "unknown_provider"
		})
	assertProviderMutationRejected(t, ctx, workerConnection, openAIRequest,
		"invalid deterministic stub provenance", func(success map[string]any) {
			success["provider_kind"] = string(ai.ProviderDeterministicStub)
			success["adapter_id"] = ai.DeterministicStubAdapterID
		})
	assertProviderMutationRejected(t, ctx, workerConnection, openAIRequest,
		"invalid OpenAI analysis provenance", func(success map[string]any) {
			success["rate_card_version"] = ""
		})
	finished, err := store.Finalize(ctx, openAIRequest)
	if err != nil || !finished {
		t.Fatalf("OpenAI finalize finished=%v err=%v", finished, err)
	}
	if replayed, replayErr := store.Finalize(ctx, openAIRequest); replayErr != nil || replayed {
		t.Fatalf("OpenAI replay finished=%v err=%v", replayed, replayErr)
	}
	assertProviderRows(t, ctx, admin, openAISnapshot.AnalysisID,
		"openai_responses", "openai-responses-v1", ai.Model,
		ai.ReasoningEffort, "operator-v1", true)

	stub := insertAnalysisLifecycleFixture(t, ctx, admin, 0xf00, 1, true)
	stubJob := leaseLifecycleJob(t, ctx, store, stub, 0xf10, "provider-stub")
	stubSnapshot := prepareLifecycleJob(t, ctx, store, stubJob)
	stubRequest := lifecycleSuccessFinalize(stubJob, stubSnapshot)
	stubRequest.Mutation.Success.ProviderKind = string(ai.ProviderDeterministicStub)
	stubRequest.Mutation.Success.AdapterID = ai.DeterministicStubAdapterID
	stubRequest.Mutation.Success.Model = ""
	stubRequest.Mutation.Success.ReasoningEffort = ""
	stubRequest.Mutation.Success.RateCardVersion = ""
	stubRequest.Mutation.Success.ResponseID = "stub_" + strings.Repeat("b", 64)
	stubRequest.Mutation.Success.Usage = ai.Usage{}
	finished, err = store.Finalize(ctx, stubRequest)
	if err != nil || !finished {
		t.Fatalf("stub finalize finished=%v err=%v", finished, err)
	}
	assertProviderRows(t, ctx, admin, stubSnapshot.AnalysisID,
		"deterministic_stub", ai.DeterministicStubAdapterID, "", "", "", false)

	if _, err = admin.Exec(ctx, `
UPDATE sentinelflow.ai_analyses SET adapter_id = 'spoofed-adapter'
WHERE analysis_id = $1::uuid`, stubSnapshot.AnalysisID); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Fatalf("provenance mutation err=%v", err)
	}
	if _, err = admin.Exec(ctx, string(down)); err == nil ||
		!strings.Contains(err.Error(), "cannot discard deterministic stub provenance") {
		t.Fatalf("stub-populated down err=%v", err)
	}
	if _, err = admin.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}

func assertProviderMutationRejected(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	request analysisworker.FinalizeRequest,
	want string,
	mutate func(map[string]any),
) {
	t.Helper()
	payload, err := encodeMutation(request.Mutation)
	if err != nil {
		t.Fatal(err)
	}
	var mutation map[string]any
	if err = json.Unmarshal(payload, &mutation); err != nil {
		t.Fatal(err)
	}
	mutate(mutation["success"].(map[string]any))
	payload, err = json.Marshal(mutation)
	if err != nil {
		t.Fatal(err)
	}
	var ignoredJob, ignoredState string
	err = connection.QueryRow(ctx, finalizeSQL,
		request.Finish.JobID, request.Finish.LeaseToken, string(request.Finish.State),
		nil, request.Finish.Now.UTC(), nil, nil, payload,
	).Scan(&ignoredJob, &ignoredState)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("provider mutation %q err=%v", want, err)
	}
	var persisted bool
	if err = connection.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM sentinelflow.ai_analyses WHERE analysis_id = $1::uuid
)`, request.Mutation.AnalysisID).Scan(&persisted); err != nil || persisted {
		t.Fatalf("rejected provider mutation persisted=%v err=%v", persisted, err)
	}
}

func finalizeLegacyProviderRow(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	request analysisworker.FinalizeRequest,
) {
	t.Helper()
	payload, err := encodeMutation(request.Mutation)
	if err != nil {
		t.Fatal(err)
	}
	var mutation map[string]any
	if err = json.Unmarshal(payload, &mutation); err != nil {
		t.Fatal(err)
	}
	success := mutation["success"].(map[string]any)
	delete(success, "provider_kind")
	delete(success, "adapter_id")
	payload, err = json.Marshal(mutation)
	if err != nil {
		t.Fatal(err)
	}
	var jobID, state string
	err = connection.QueryRow(ctx, finalizeSQL,
		request.Finish.JobID, request.Finish.LeaseToken, string(request.Finish.State),
		nil, request.Finish.Now.UTC(), nil, nil, payload,
	).Scan(&jobID, &state)
	if err != nil || jobID != request.Finish.JobID || state != "completed" {
		t.Fatalf("legacy finalize job=%s state=%s err=%v", jobID, state, err)
	}
}

func assertProviderRows(
	t *testing.T,
	ctx context.Context,
	admin *pgx.Conn,
	analysisID, wantKind, wantAdapter, wantModel, wantReasoning, wantRateCard string,
	wantUsage bool,
) {
	t.Helper()
	var kind, adapter string
	var model, reasoning, rateCard *string
	var inputTokens, cachedTokens, outputTokens *int
	err := admin.QueryRow(ctx, `
SELECT provider_kind, adapter_id, model, reasoning_effort, rate_card_version,
       input_tokens, cached_input_tokens, output_tokens
FROM sentinelflow.ai_analyses WHERE analysis_id = $1::uuid`, analysisID).Scan(
		&kind, &adapter, &model, &reasoning, &rateCard,
		&inputTokens, &cachedTokens, &outputTokens,
	)
	if err != nil || kind != wantKind || adapter != wantAdapter ||
		pointerString(model) != wantModel || pointerString(reasoning) != wantReasoning ||
		pointerString(rateCard) != wantRateCard ||
		wantUsage != (inputTokens != nil && cachedTokens != nil && outputTokens != nil) {
		t.Fatalf("analysis provider kind=%s adapter=%s model=%v reasoning=%v rate=%v usage=%v/%v/%v err=%v",
			kind, adapter, model, reasoning, rateCard, inputTokens, cachedTokens, outputTokens, err)
	}
	err = admin.QueryRow(ctx, `
SELECT provider_kind, adapter_id, model, reasoning_effort, rate_card_version,
       input_tokens, cached_input_tokens, output_tokens
FROM sentinelflow.analysis_attempt_results WHERE analysis_id = $1::uuid`, analysisID).Scan(
		&kind, &adapter, &model, &reasoning, &rateCard,
		&inputTokens, &cachedTokens, &outputTokens,
	)
	if err != nil || kind != wantKind || adapter != wantAdapter ||
		pointerString(model) != wantModel || pointerString(reasoning) != wantReasoning ||
		pointerString(rateCard) != wantRateCard ||
		wantUsage != (inputTokens != nil && cachedTokens != nil && outputTokens != nil) {
		t.Fatalf("result provider kind=%s adapter=%s model=%v reasoning=%v rate=%v usage=%v/%v/%v err=%v",
			kind, adapter, model, reasoning, rateCard, inputTokens, cachedTokens, outputTokens, err)
	}
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func applyProviderMigrationPrefix(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	maximum int,
) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate provider integration test")
	}
	paths, err := filepath.Glob(filepath.Join(
		filepath.Dir(file), "..", "..", "db", "migrations", "*.up.sql",
	))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		name := filepath.Base(path)
		if len(name) < 6 {
			continue
		}
		version, parseErr := strconv.Atoi(name[:6])
		if parseErr != nil || version > maximum {
			continue
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = connection.Exec(ctx, string(contents)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

func providerMigrationFiles(t *testing.T) (up, down []byte) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate provider integration test")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations")
	var err error
	up, err = os.ReadFile(filepath.Join(root, "000021_analysis_provider_provenance.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	down, err = os.ReadFile(filepath.Join(root, "000021_analysis_provider_provenance.down.sql"))
	if err != nil {
		t.Fatal(err)
	}
	return up, down
}
