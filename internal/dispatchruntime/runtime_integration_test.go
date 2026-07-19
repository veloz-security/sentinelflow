//go:build integration

package dispatchruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	enforcementexecutor "github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

// TestRuntimePostgreSQLRecoveryCompletesWithoutSecondUDSExchange proves the
// process-crash boundary end to end: one exact UDS request produces one signed
// result, that result is durable before an uncertain Finish, and a later lease
// owner completes from the restricted recovery function without contacting the
// executor or minting a second capability.
func TestRuntimePostgreSQLRecoveryCompletesWithoutSecondUDSExchange(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-dispatchruntime-%d", time.Now().UnixNano())
	runtimeDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForRuntimePostgreSQL(t, ctx, container)
	port := runtimeDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	owner := connectRuntimePostgreSQL(t, ctx, connectionString)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyRuntimeMigrations(t, ctx, owner)
	seedRuntimeDispatchFixture(t, ctx, owner)

	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	identities, err := keyidentity.Derive(
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilityIssuer, _ := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	capabilityVerifier, _ := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPrivate.Public().(ed25519.PublicKey),
	)
	resultSigner, _ := capability.NewResultSigner(identities.ResultKeyID, identities.ExecutorID, resultPrivate)
	resultVerifier, _ := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPrivate.Public().(ed25519.PublicKey),
	)
	issuer, err := NewIssuer(capabilityIssuer, capabilityVerifier, nil)
	if err != nil {
		t.Fatal(err)
	}

	var privilegedExchanges atomic.Int32
	server := startUDSServer(t, func(_ context.Context, payload []byte) ([]byte, error) {
		privilegedExchanges.Add(1)
		envelope, decodeErr := ipc.DecodeRequestEnvelope(payload)
		if decodeErr != nil {
			return nil, decodeErr
		}
		signed := capability.NewUntrustedSignedCapability(
			identities.DispatchKeyID, envelope.CapabilityJCS(),
			envelope.CapabilitySignature(), envelope.Artifact(),
		)
		verified, verifyErr := capabilityVerifier.Verify(signed)
		if verifyErr != nil {
			return nil, verifyErr
		}
		result := signAddResult(nil, resultSigner, verified,
			capability.ClassificationApplied, capability.NFTExitSuccess,
			verified.Value().NotBefore)
		response, responseErr := ipc.NewResponseEnvelope(result.CanonicalBytes(), result.Signature())
		if responseErr != nil {
			return nil, responseErr
		}
		return ipc.EncodeResponseEnvelope(response)
	})
	client, err := NewUDSClient(
		server.path, ipc.MaxExchangeTimeout, identities.ResultKeyID, identities.ExecutorID,
	)
	if err != nil {
		t.Fatal(err)
	}

	firstConnection := runtimeDispatchRoleConnection(t, ctx, connectionString)
	firstRestricted, err := dispatchstore.NewPostgreSQLStore(
		firstConnection, capabilityVerifier, resultVerifier, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstStore, _ := NewPostgreSQLStore(firstRestricted)
	uncertainFinish := &failFirstFinishStore{Store: firstStore}
	runtimeConfig := DefaultConfig("dispatcher-integration-one")
	runtimeConfig.LeaseDuration = 2 * time.Second
	runtimeConfig.CapabilityTTL = time.Second
	firstRuntime, err := New(
		uncertainFinish, issuer, resultVerifier, client, runtimeConfig, Dependencies{},
	)
	if err != nil {
		t.Fatal(err)
	}
	firstOutcome, firstErr := firstRuntime.ProcessNext(ctx)
	if firstOutcome != OutcomeRecoverRequired || !errors.Is(firstErr, ErrRecoverRequired) ||
		privilegedExchanges.Load() != 1 {
		t.Fatalf("first outcome=%s exchanges=%d err=%v", firstOutcome, privilegedExchanges.Load(), firstErr)
	}
	server.wait(t)

	const jobID = "019b0000-0000-7000-8000-000000009114"
	var state string
	var leaseUntil time.Time
	var capabilityCount, resultCount int
	if err := owner.QueryRow(ctx, `
SELECT job.state, job.lease_expires_at,
       (SELECT count(*) FROM sentinelflow.execution_capabilities WHERE job_id = job.job_id),
       (SELECT count(*) FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = job.job_id)
FROM sentinelflow.outbox_jobs job WHERE job.job_id = $1::uuid`, jobID).Scan(
		&state, &leaseUntil, &capabilityCount, &resultCount,
	); err != nil || state != "leased" || capabilityCount != 1 || resultCount != 1 {
		t.Fatalf("uncertain durable state=%s cap=%d result=%d err=%v", state, capabilityCount, resultCount, err)
	}
	waitForRuntimeInstant(t, ctx, leaseUntil.Add(30*time.Millisecond))

	secondConnection := runtimeDispatchRoleConnection(t, ctx, connectionString)
	secondRestricted, err := dispatchstore.NewPostgreSQLStore(
		secondConnection, capabilityVerifier, resultVerifier, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, _ := NewPostgreSQLStore(secondRestricted)
	never := &neverExchange{}
	runtimeConfig.LeaseOwner = "dispatcher-integration-two"
	secondRuntime, err := New(
		secondStore, issuer, resultVerifier, never, runtimeConfig, Dependencies{},
	)
	if err != nil {
		t.Fatal(err)
	}
	secondOutcome, secondErr := secondRuntime.ProcessNext(ctx)
	if secondErr != nil || secondOutcome != OutcomeCompleted || never.calls.Load() != 0 ||
		privilegedExchanges.Load() != 1 {
		t.Fatalf("recovery outcome=%s second_uds=%d all_uds=%d err=%v",
			secondOutcome, never.calls.Load(), privilegedExchanges.Load(), secondErr)
	}
	if err := owner.QueryRow(ctx, `
SELECT job.state,
       (SELECT count(*) FROM sentinelflow.execution_capabilities WHERE job_id = job.job_id),
       (SELECT count(*) FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = job.job_id)
FROM sentinelflow.outbox_jobs job WHERE job.job_id = $1::uuid`, jobID).Scan(
		&state, &capabilityCount, &resultCount,
	); err != nil || state != "completed" || capabilityCount != 1 || resultCount != 1 {
		t.Fatalf("recovered state=%s cap=%d result=%d err=%v", state, capabilityCount, resultCount, err)
	}
}

func TestExpiredCapabilityConvergesTerminalJournalAheadOfPostgreSQL(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-dispatch-journal-recovery-%d", time.Now().UnixNano())
	runtimeDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD=sentinelflow-test-only",
		"--publish", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	waitForRuntimePostgreSQL(t, ctx, container)
	port := runtimeDockerPort(t, ctx, container)
	connectionString := fmt.Sprintf(
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:%s/postgres?sslmode=disable", port,
	)
	owner := connectRuntimePostgreSQL(t, ctx, connectionString)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyRuntimeMigrations(t, ctx, owner)
	seedRuntimeDispatchFixture(t, ctx, owner)

	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x74}, ed25519.SeedSize))
	identities, err := keyidentity.Derive(
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	capabilityIssuer, _ := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	capabilityVerifier, _ := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPrivate.Public().(ed25519.PublicKey),
	)
	resultSigner, _ := capability.NewResultSigner(identities.ResultKeyID, identities.ExecutorID, resultPrivate)
	resultVerifier, _ := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPrivate.Public().(ed25519.PublicKey),
	)
	issuer, err := NewIssuer(capabilityIssuer, capabilityVerifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := journal.Open(journal.Options{
		Path:               filepath.Join(t.TempDir(), "replay.json"),
		CapabilityVerifier: capabilityVerifier, ResultVerifier: resultVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replay.Close() })
	runner := &integrationExecutorRunner{}
	service, err := enforcementexecutor.New(enforcementexecutor.Config{
		CapabilityVerifier: capabilityVerifier, ResultSigner: resultSigner,
		Journal: replay, Runner: runner, DispatchKeyID: identities.DispatchKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var exchanges atomic.Int32
	firstServer := startUDSServer(t, func(handlerCtx context.Context, payload []byte) ([]byte, error) {
		exchanges.Add(1)
		return service.HandlePayload(handlerCtx, payload)
	})
	firstClient, err := NewUDSClient(
		firstServer.path, ipc.MaxExchangeTimeout, identities.ResultKeyID, identities.ExecutorID,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstConnection := runtimeDispatchRoleConnection(t, ctx, connectionString)
	firstRestricted, err := dispatchstore.NewPostgreSQLStore(
		firstConnection, capabilityVerifier, resultVerifier, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstStore, _ := NewPostgreSQLStore(firstRestricted)
	ahead := &failResultPersistenceStore{Store: firstStore}
	config := DefaultConfig("dispatcher-terminal-ahead-one")
	config.LeaseDuration = 2 * time.Second
	config.CapabilityTTL = time.Second
	firstRuntime, err := New(ahead, issuer, resultVerifier, firstClient, config, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	firstOutcome, firstErr := firstRuntime.ProcessNext(ctx)
	if firstOutcome != OutcomeRecoverRequired || !errors.Is(firstErr, ErrRecoverRequired) ||
		ahead.persistResultCalls.Load() != int32(config.ResultPersistenceTries) || exchanges.Load() != 1 {
		t.Fatalf("terminal-ahead outcome=%s persist_attempts=%d exchanges=%d err=%v",
			firstOutcome, ahead.persistResultCalls.Load(), exchanges.Load(), firstErr)
	}
	firstServer.wait(t)
	journalOutcome, err := replay.Lookup(ahead.signedCapability)
	terminal, terminalOK := journalOutcome.Terminal()
	if err != nil || journalOutcome.State() != journal.StateTerminal || !terminalOK ||
		runner.mutationCount() != 1 {
		t.Fatalf("journal state=%s terminal=%v mutations=%d err=%v",
			journalOutcome.State(), terminalOK, runner.mutationCount(), err)
	}

	const jobID = "019b0000-0000-7000-8000-000000009114"
	var state string
	var leaseUntil time.Time
	var capabilityCount, resultCount int
	if err := owner.QueryRow(ctx, `
SELECT job.state, job.lease_expires_at,
       (SELECT count(*) FROM sentinelflow.execution_capabilities WHERE job_id = job.job_id),
       (SELECT count(*) FROM sentinelflow.execution_results result
        JOIN sentinelflow.execution_capabilities capability USING (capability_id)
        WHERE capability.job_id = job.job_id)
FROM sentinelflow.outbox_jobs job WHERE job.job_id = $1::uuid`, jobID).Scan(
		&state, &leaseUntil, &capabilityCount, &resultCount,
	); err != nil || state != "leased" || capabilityCount != 1 || resultCount != 0 {
		t.Fatalf("terminal-ahead database state=%s cap=%d result=%d err=%v",
			state, capabilityCount, resultCount, err)
	}
	waitForRuntimeInstant(t, ctx, leaseUntil.Add(30*time.Millisecond))

	secondServer := startUDSServer(t, func(handlerCtx context.Context, payload []byte) ([]byte, error) {
		exchanges.Add(1)
		return service.HandlePayload(handlerCtx, payload)
	})
	secondClient, err := NewUDSClient(
		secondServer.path, ipc.MaxExchangeTimeout, identities.ResultKeyID, identities.ExecutorID,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondConnection := runtimeDispatchRoleConnection(t, ctx, connectionString)
	secondRestricted, err := dispatchstore.NewPostgreSQLStore(
		secondConnection, capabilityVerifier, resultVerifier, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, _ := NewPostgreSQLStore(secondRestricted)
	config.LeaseOwner = "dispatcher-terminal-ahead-two"
	secondRuntime, err := New(secondStore, issuer, resultVerifier, secondClient, config, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	secondOutcome, secondErr := secondRuntime.ProcessNext(ctx)
	if secondErr != nil || secondOutcome != OutcomeCompleted || exchanges.Load() != 2 ||
		runner.mutationCount() != 1 {
		t.Fatalf("convergence outcome=%s exchanges=%d mutations=%d err=%v",
			secondOutcome, exchanges.Load(), runner.mutationCount(), secondErr)
	}
	secondServer.wait(t)
	verifiedTerminal, err := resultVerifier.Verify(terminal.SignedResult())
	if err != nil {
		t.Fatal(err)
	}
	var resultDigest string
	if err := owner.QueryRow(ctx, `
SELECT job.state, result.result_digest::text
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.execution_capabilities capability USING (job_id)
JOIN sentinelflow.execution_results result USING (capability_id)
WHERE job.job_id = $1::uuid`, jobID).Scan(&state, &resultDigest); err != nil ||
		state != "completed" || resultDigest != verifiedTerminal.Digest() {
		t.Fatalf("converged state=%s digest=%s want=%s err=%v",
			state, resultDigest, verifiedTerminal.Digest(), err)
	}
}

type failResultPersistenceStore struct {
	Store
	signedCapability   capability.SignedCapability
	persistResultCalls atomic.Int32
}

func (s *failResultPersistenceStore) PersistCapability(
	ctx context.Context,
	claim Claim,
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
) (StoredCapability, error) {
	stored, err := s.Store.PersistCapability(ctx, claim, signed, verified)
	if err == nil {
		s.signedCapability = signed
	}
	return stored, err
}

func (s *failResultPersistenceStore) PersistResult(
	context.Context,
	StoredCapability,
	capability.SignedResult,
	capability.VerifiedResult,
) (StoredResult, error) {
	s.persistResultCalls.Add(1)
	return StoredResult{}, dispatchstore.ErrUnavailable
}

type integrationExecutorRunner struct {
	mu        sync.Mutex
	active    bool
	mutations int
}

func (r *integrationExecutorRunner) Mutate(_ context.Context, mutation enforcementexecutor.Mutation) (enforcementexecutor.MutationOutcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mutations++
	r.active = mutation.Operation() == capability.OperationAdd
	return enforcementexecutor.MutationOutcome{ExitClass: capability.NFTExitSuccess}, nil
}

func (r *integrationExecutorRunner) Inspect(_ context.Context, inspection enforcementexecutor.Inspection) (enforcementexecutor.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := capability.ReadbackAbsent
	ttl := uint64(0)
	if r.active {
		state = capability.ReadbackActive
		ttl = 30
	}
	return enforcementexecutor.Observation{
		State: state, TargetIPv4: inspection.TargetIPv4(),
		OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, RemainingTTLSeconds: ttl,
	}, nil
}

func (r *integrationExecutorRunner) mutationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutations
}

type failFirstFinishStore struct {
	Store
	failed atomic.Bool
}

func (s *failFirstFinishStore) Finish(ctx context.Context, claim Claim, request FinishRequest) error {
	if s.failed.CompareAndSwap(false, true) {
		return dispatchstore.ErrUnavailable
	}
	return s.Store.Finish(ctx, claim, request)
}

type neverExchange struct{ calls atomic.Int32 }

func (n *neverExchange) Exchange(context.Context, capability.SignedCapability) (capability.SignedResult, error) {
	n.calls.Add(1)
	return capability.SignedResult{}, ErrTransport
}

func runtimeDispatchRoleConnection(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	connection := connectRuntimePostgreSQL(t, ctx, connectionString)
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		t.Fatal("set dispatcher role")
	}
	return connection
}

func connectRuntimePostgreSQL(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	for range 40 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL connection: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("connect to PostgreSQL 17")
	return nil
}

func applyRuntimeMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	root := runtimeRepositoryRoot(t)
	migrations, err := filepath.Glob(filepath.Join(root, "db", "migrations", "*.up.sql"))
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

func seedRuntimeDispatchFixture(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(runtimeRepositoryRoot(t), "db", "test", "verify_hil.sql"))
	if err != nil {
		t.Fatal("read HIL database fixture")
	}
	marker := "DO $approved_dispatch_view$"
	index := strings.Index(string(contents), marker)
	if index < 0 {
		t.Fatal("reviewed HIL fixture marker is missing")
	}
	prefix := string(contents[:index])
	artifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.30 timeout 30m }\n")
	prefix = strings.ReplaceAll(prefix,
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		digestTestBytes(artifact),
	)
	prefix = strings.ReplaceAll(prefix,
		"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		nftvalidate.PinnedLiveSchemaDigest,
	)
	if _, err := connection.Exec(ctx, prefix+"\nCOMMIT;"); err != nil {
		t.Fatalf("seed approved dispatch fixture: %v", err)
	}
}

func runtimeRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate repository")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func waitForRuntimePostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 80 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
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

func waitForRuntimeInstant(t *testing.T, ctx context.Context, instant time.Time) {
	t.Helper()
	delay := time.Until(instant)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatalf("wait for recovery lease: %v", ctx.Err())
	case <-timer.C:
	}
}

func runtimeDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runtimeDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runtimeDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
