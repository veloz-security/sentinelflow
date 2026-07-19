// Command testfixture creates and recovers production-format dispatch/journal
// states for the PostgreSQL 17 backup/restore gate. It is test-only and never
// ships in SentinelFlow runtime images.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/dispatchruntime"
	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/keymaterial"
)

type options struct {
	database        string
	journal         string
	dispatchPrivate string
	resultPrivate   string
	resultPublic    string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "recovery fixture rejected")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("mode required")
	}
	mode := arguments[0]
	set := flag.NewFlagSet("recovery-fixture", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	var configured options
	set.StringVar(&configured.database, "database", "", "database")
	set.StringVar(&configured.journal, "journal", "", "journal")
	set.StringVar(&configured.dispatchPrivate, "dispatch-private-key", "", "dispatcher private key")
	set.StringVar(&configured.resultPrivate, "result-private-key", "", "executor result private key")
	set.StringVar(&configured.resultPublic, "result-public-key", "", "executor result public key")
	if err := set.Parse(arguments[1:]); err != nil || set.NArg() != 0 ||
		configured.journal == "" || configured.dispatchPrivate == "" ||
		configured.resultPrivate == "" || configured.resultPublic == "" {
		return errors.New("invalid arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture, err := openFixture(ctx, configured, mode != "init")
	if err != nil {
		return err
	}
	defer fixture.close()
	switch mode {
	case "init":
		return nil
	case "terminal":
		return fixture.runTerminal(ctx)
	case "started":
		return fixture.runStarted(ctx, false)
	case "terminal-ahead":
		return fixture.runStarted(ctx, true)
	case "recover-started":
		return fixture.recover(ctx, 1)
	case "recover-terminal":
		return fixture.recover(ctx, 0)
	default:
		return errors.New("unknown mode")
	}
}

type fixture struct {
	connection         *pgx.Conn
	store              *dispatchruntime.PostgreSQLStore
	issuer             *dispatchruntime.Issuer
	capabilityVerifier capability.CapabilityVerifier
	resultVerifier     capability.ResultVerifier
	resultSigner       capability.ResultSigner
	journal            *journal.Journal
}

func openFixture(ctx context.Context, configured options, withDatabase bool) (*fixture, error) {
	keys, err := dispatchruntime.LoadKeySet(configured.dispatchPrivate, configured.resultPublic)
	if err != nil {
		return nil, err
	}
	resultPrivate, err := keymaterial.LoadPrivateFile(configured.resultPrivate)
	if err != nil {
		return nil, err
	}
	defer clear(resultPrivate)
	resultPublic, ok := resultPrivate.Public().(ed25519.PublicKey)
	expectedResultPublic, publicErr := keymaterial.LoadPublicFile(configured.resultPublic)
	if !ok || publicErr != nil || !resultPublic.Equal(expectedResultPublic) {
		return nil, errors.New("result key mismatch")
	}
	resultSigner, err := capability.NewResultSigner(
		keys.Identities().ResultKeyID, keys.Identities().ExecutorID, resultPrivate,
	)
	if err != nil {
		return nil, err
	}
	issuer, err := dispatchruntime.NewIssuer(keys.Issuer(), keys.CapabilityVerifier(), nil)
	if err != nil {
		return nil, err
	}
	replay, err := journal.Open(journal.Options{
		Path: configured.journal, CapabilityVerifier: keys.CapabilityVerifier(),
		ResultVerifier: keys.ResultVerifier(),
	})
	if err != nil {
		return nil, err
	}
	result := &fixture{
		issuer: issuer, capabilityVerifier: keys.CapabilityVerifier(),
		resultVerifier: keys.ResultVerifier(), resultSigner: resultSigner, journal: replay,
	}
	if !withDatabase {
		return result, nil
	}
	if configured.database == "" {
		result.close()
		return nil, errors.New("database required")
	}
	connection, err := pgx.Connect(ctx, fmt.Sprintf(
		"postgresql://postgres@/%s?host=/var/run/postgresql&sslmode=disable", configured.database,
	))
	if err != nil {
		result.close()
		return nil, err
	}
	result.connection = connection
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_dispatcher`); err != nil {
		result.close()
		return nil, err
	}
	restricted, err := dispatchstore.NewPostgreSQLStore(
		connection, keys.CapabilityVerifier(), keys.ResultVerifier(), nil,
	)
	if err != nil {
		result.close()
		return nil, err
	}
	result.store, err = dispatchruntime.NewPostgreSQLStore(restricted)
	if err != nil {
		result.close()
		return nil, err
	}
	return result, nil
}

func (f *fixture) close() {
	if f.connection != nil {
		_ = f.connection.Close(context.Background())
	}
	if f.journal != nil {
		_ = f.journal.Close()
	}
}

func (f *fixture) runTerminal(ctx context.Context) error {
	runner := &stateRunner{}
	service, err := executor.New(executor.Config{
		CapabilityVerifier: f.capabilityVerifier, ResultSigner: f.resultSigner,
		Journal: f.journal, Runner: runner, DispatchKeyID: f.capabilityVerifier.KeyID(),
	})
	if err != nil {
		return err
	}
	runtime, err := f.runtime(service)
	if err != nil {
		return err
	}
	outcome, err := runtime.ProcessNext(ctx)
	if err != nil || outcome != dispatchruntime.OutcomeCompleted ||
		runner.mutations != 1 || runner.inspections < 2 {
		return errors.New("terminal fixture did not complete")
	}
	return nil
}

func (f *fixture) runStarted(ctx context.Context, terminalAhead bool) error {
	claim, found, err := f.store.ClaimNext(ctx, dispatchruntime.ClaimRequest{
		LeaseOwner: "recovery-fixture", LeaseDuration: 10 * time.Second, CandidateLimit: 8,
	})
	if err != nil || !found {
		return errors.New("fixture claim failed")
	}
	issued, err := f.issuer.Issue(claim, time.Second)
	if err != nil {
		return err
	}
	if _, err := f.store.PersistCapability(ctx, claim, issued.Signed, issued.Verified); err != nil {
		return err
	}
	received := time.Now().UTC().Truncate(time.Millisecond)
	if received.Before(issued.Verified.Value().NotBefore) {
		received = issued.Verified.Value().NotBefore
	}
	deadline := issued.Verified.Value().ExpiresAt
	if !deadline.After(received) {
		return errors.New("fixture capability expired")
	}
	if _, err := f.journal.Begin(issued.Signed, received, deadline); err != nil {
		return err
	}
	if err := f.store.Finish(ctx, claim, dispatchruntime.FinishRequest{
		Outcome: dispatchruntime.FinishDead, ErrorCode: "fixture_started",
		ErrorDigest: digest([]byte("fixture_started")),
	}); err != nil {
		return err
	}
	if terminalAhead {
		runner := &stateRunner{active: true}
		service, err := executor.New(executor.Config{
			CapabilityVerifier: f.capabilityVerifier, ResultSigner: f.resultSigner,
			Journal: f.journal, Runner: runner, DispatchKeyID: f.capabilityVerifier.KeyID(),
		})
		if err != nil {
			return err
		}
		if _, err := service.ProcessRecovery(ctx, issued.Signed); err != nil ||
			runner.mutations != 0 || runner.inspections != 1 {
			return errors.New("terminal-ahead fixture failed")
		}
	}
	return nil
}

func (f *fixture) recover(ctx context.Context, expectedInspections int) error {
	var targetJobID string
	if err := f.connection.QueryRow(ctx, `
SELECT job_id::text
FROM sentinelflow.dispatcher_recovery_outbox_000025
ORDER BY available_at, job_id
LIMIT 1`).Scan(&targetJobID); err != nil {
		return errors.New("recovery fixture target missing")
	}
	runner := &stateRunner{active: true}
	service, err := executor.New(executor.Config{
		CapabilityVerifier: f.capabilityVerifier, ResultSigner: f.resultSigner,
		Journal: f.journal, Runner: runner, DispatchKeyID: f.capabilityVerifier.KeyID(),
	})
	if err != nil {
		return err
	}
	runtime, err := f.runtime(service)
	if err != nil {
		return err
	}
	outcome, err := runtime.ProcessNext(ctx)
	if err != nil || outcome != dispatchruntime.OutcomeCompleted || runner.mutations != 0 ||
		runner.inspections != expectedInspections {
		return errors.New("recovery fixture did not converge")
	}
	if _, err := f.connection.Exec(ctx, `RESET ROLE`); err != nil {
		return err
	}
	var state string
	var deadState string
	var results, jobVersion, deadVersion, applicationVersion int
	var applicationDigestMatches, markerMatches bool
	if err := f.connection.QueryRow(ctx, `
SELECT job.state,
       (SELECT count(*)::integer
        FROM sentinelflow.execution_results counted_result
        WHERE counted_result.capability_id = capability.capability_id),
       job.aggregate_version, dead.aggregate_version,
       dead.resolution_state, application.resulting_action_version,
       application.result_digest = result.result_digest,
       dead.resolution_digest = sentinelflow.dispatch_recovery_marker_000025(
           job.job_id, capability.capability_digest,
           dead.failure_code, dead.failure_digest
       )
FROM sentinelflow.outbox_jobs job
JOIN sentinelflow.execution_capabilities capability USING (job_id)
JOIN sentinelflow.execution_results result USING (capability_id)
JOIN sentinelflow.lifecycle_result_applications_000026 application USING (result_id)
JOIN sentinelflow.dead_letter_jobs dead USING (job_id)
WHERE job.job_id = $1::uuid`, targetJobID).Scan(
		&state, &results, &jobVersion, &deadVersion, &deadState,
		&applicationVersion, &applicationDigestMatches, &markerMatches,
	); err != nil || state != "completed" || results != 1 || deadState != "resolved" ||
		deadVersion+1 != jobVersion || applicationVersion != jobVersion ||
		!applicationDigestMatches || !markerMatches {
		return fmt.Errorf(
			"database recovery terminal missing: state=%s results=%d job_version=%d dead_version=%d dead_state=%s application_version=%d application_digest=%t marker=%t error=%v",
			state, results, jobVersion, deadVersion, deadState, applicationVersion,
			applicationDigestMatches, markerMatches, err,
		)
	}
	return nil
}

func (f *fixture) runtime(service *executor.Service) (*dispatchruntime.Runtime, error) {
	client := directClient{service: service}
	config := dispatchruntime.DefaultConfig("recovery-fixture")
	config.LeaseDuration = 10 * time.Second
	config.CapabilityTTL = time.Second
	return dispatchruntime.New(
		f.store, f.issuer, f.resultVerifier, client, config, dispatchruntime.Dependencies{},
	)
}

type directClient struct {
	service *executor.Service
}

func (c directClient) Exchange(ctx context.Context, signed capability.SignedCapability) (capability.SignedResult, error) {
	return c.service.Process(ctx, signed)
}

func (c directClient) ExchangeRecovery(ctx context.Context, signed capability.SignedCapability) (capability.SignedResult, error) {
	return c.service.ProcessRecovery(ctx, signed)
}

type stateRunner struct {
	active      bool
	mutations   int
	inspections int
}

func (r *stateRunner) Mutate(context.Context, executor.Mutation) (executor.MutationOutcome, error) {
	r.mutations++
	r.active = true
	return executor.MutationOutcome{ExitClass: capability.NFTExitSuccess}, nil
}

func (r *stateRunner) Inspect(_ context.Context, request executor.Inspection) (executor.Observation, error) {
	r.inspections++
	state := capability.ReadbackAbsent
	ttl := uint64(0)
	if r.active {
		state = capability.ReadbackActive
		ttl = 30
	}
	return executor.Observation{
		State: state, TargetIPv4: request.TargetIPv4(),
		OwnedSchemaDigest:   nftvalidate.PinnedLiveSchemaDigest,
		RemainingTTLSeconds: ttl,
	}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
