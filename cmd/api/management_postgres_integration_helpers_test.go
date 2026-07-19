//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
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
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

const (
	integrationDBPassword       = "sentinelflow-test-only"
	integrationAPIPassword      = "sentinelflow-api-test-only"
	integrationAdminUser        = "admin"
	integrationAdminPass        = "SentinelFlow-Admin-Test-Only-42"
	integrationOrigin           = "https://admin.example.test"
	managementPostgreSQL17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
)

type managementPGFixture struct {
	ctx       context.Context
	owner     *pgx.Conn
	pool      *pgxpool.Pool
	config    config.Config
	container string
	clock     adminauth.Clock
}

const (
	managementClockSamples        = 16
	managementClockQueryTimeout   = 2 * time.Second
	managementClockMaxUncertainty = time.Millisecond
)

// managementDatabaseAlignedClock models the single Docker-VM clock domain
// used by the production Compose API and PostgreSQL containers. The local Go
// integration process runs outside that VM, so one bounded midpoint sample is
// advanced only with the local monotonic clock after initialization.
type managementDatabaseAlignedClock struct {
	databaseAtResponse time.Time
	localResponse      time.Time
	elapsed            func(time.Time) time.Duration
}

func (clock *managementDatabaseAlignedClock) Now() time.Time {
	if clock == nil || clock.databaseAtResponse.IsZero() || clock.localResponse.IsZero() {
		return time.Time{}
	}
	elapsed := clock.elapsed
	if elapsed == nil {
		elapsed = time.Since
	}
	return clock.databaseAtResponse.Add(elapsed(clock.localResponse)).UTC()
}

func TestManagementDatabaseAlignedClockUsesConservativeResponseBound(t *testing.T) {
	t.Parallel()
	databaseSample := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	localResponse := time.Now()
	const elapsed = 3 * time.Millisecond
	clock := &managementDatabaseAlignedClock{
		databaseAtResponse: databaseSample,
		localResponse:      localResponse,
		elapsed: func(reference time.Time) time.Duration {
			if !reference.Equal(localResponse) {
				t.Errorf("elapsed reference=%s want response bound", reference)
			}
			return elapsed
		},
	}
	if got, want := clock.Now(), databaseSample.Add(elapsed); !got.Equal(want) {
		t.Fatalf("aligned clock=%s want=%s", got, want)
	}
}

func newManagementPGFixture(t *testing.T) *managementPGFixture {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is required for PostgreSQL 17 integration coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.Cleanup(cancel)
	container := fmt.Sprintf("sentinelflow-api-management-%d", time.Now().UnixNano())
	runManagementDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"--env", "POSTGRES_PASSWORD="+integrationDBPassword,
		"--publish", "127.0.0.1::5432", managementPostgreSQL17Image)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", container).Run()
	})
	port := managementDockerPort(t, ctx, container)
	waitForManagementPostgreSQL(t, ctx, container)
	waitForManagementTCP(t, ctx, "127.0.0.1:"+port)
	ownerURL := "postgresql://postgres:" + integrationDBPassword + "@127.0.0.1:" + port + "/postgres?sslmode=disable"
	owner := connectManagementPostgreSQL(t, ctx, ownerURL)
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	applyManagementMigrations(t, ctx, owner)
	if _, err := owner.Exec(ctx, `ALTER ROLE sentinelflow_api LOGIN PASSWORD '`+integrationAPIPassword+`'`); err != nil {
		t.Fatal("enable disposable API login role")
	}
	apiURL := "postgresql://sentinelflow_api:" + integrationAPIPassword + "@127.0.0.1:" + port + "/postgres?sslmode=disable"
	cfg := managementIntegrationConfig(t, apiURL)
	poolConfig, err := pgxpool.ParseConfig(apiURL)
	if err != nil {
		t.Fatal("parse API connection URL")
	}
	poolConfig.MaxConns = 12
	poolConfig.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal("open API-role pool")
	}
	t.Cleanup(pool.Close)
	if err = pool.Ping(ctx); err != nil {
		t.Fatal("ping API-role pool")
	}
	if err = requireDatabaseRole(ctx, pool, "sentinelflow_api"); err != nil {
		t.Fatal(err)
	}
	clock := newManagementDatabaseAlignedClock(t, pool)
	return &managementPGFixture{
		ctx: ctx, owner: owner, pool: pool, config: cfg, container: container,
		clock: clock,
	}
}

func newManagementDatabaseAlignedClock(
	t *testing.T,
	pool *pgxpool.Pool,
) *managementDatabaseAlignedClock {
	t.Helper()
	if pool == nil {
		t.Fatal("management clock requires PostgreSQL")
	}
	type sample struct {
		database time.Time
		before   time.Time
		after    time.Time
	}
	var best sample
	bestRoundTrip := time.Duration(1<<63 - 1)
	for range managementClockSamples {
		queryCtx, cancel := context.WithTimeout(context.Background(), managementClockQueryTimeout)
		before := time.Now()
		var databaseNow time.Time
		err := pool.QueryRow(queryCtx, `SELECT clock_timestamp()`).Scan(&databaseNow)
		after := time.Now()
		cancel()
		if err != nil {
			t.Fatalf("sample PostgreSQL clock: %v", err)
		}
		roundTrip := after.Sub(before)
		if roundTrip >= 0 && roundTrip < bestRoundTrip {
			bestRoundTrip = roundTrip
			best = sample{database: databaseNow.UTC(), before: before, after: after}
		}
	}
	uncertainty := bestRoundTrip / 2
	if best.database.IsZero() || bestRoundTrip < 0 || uncertainty > managementClockMaxUncertainty {
		t.Fatalf("PostgreSQL clock sampling uncertainty=%s exceeds %s",
			uncertainty, managementClockMaxUncertainty)
	}
	midpoint := best.before.Add(bestRoundTrip / 2)
	offset := best.database.Sub(midpoint)
	t.Logf("PostgreSQL clock alignment offset=%s uncertainty<=%s conservative_lag<=%s",
		offset, uncertainty, bestRoundTrip)
	// The database sample occurred no later than response receipt. Mapping that
	// sample to best.after prevents this test clock from leading PostgreSQL;
	// it may trail by at most the measured RTT. This assumes the Docker VM and
	// local monotonic clocks advance at materially the same rate for the
	// fixture's bounded 150-second lifetime. A <=1 ms midpoint uncertainty
	// keeps the conservative lag below 2 ms without weakening any time gate.
	return &managementDatabaseAlignedClock{
		databaseAtResponse: best.database,
		localResponse:      best.after,
	}
}

func managementIntegrationConfig(t *testing.T, apiURL string) config.Config {
	t.Helper()
	sessionKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	eventKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	salt := []byte("sentinelflow-salt")
	derived := argon2.IDKey([]byte(integrationAdminPass), salt, 3, 65536, 2, 32)
	phc := "$argon2id$v=19$m=65536,t=3,p=2$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
	clear(derived)
	values := map[string]string{
		"SENTINELFLOW_ENV":                   "test",
		"DATABASE_API_URL":                   apiURL,
		"GATEWAY_EVENT_HMAC_KEY":             eventKey,
		"AUTH_EVENT_HMAC_KEY":                eventKey,
		"GATEWAY_EVENT_HMAC_KEY_ID":          "gateway-key-v1",
		"AUTH_EVENT_HMAC_KEY_ID":             "auth-key-v1",
		"GATEWAY_EXPECTED_SOURCE_BINDING_ID": "11111111-1111-4111-8111-111111111111",
		"AUTH_EXPECTED_SOURCE_BINDING_ID":    "22222222-2222-4222-8222-222222222222",
		"GATEWAY_SOURCE_CONFIG_SHA256":       strings.Repeat("1", 64),
		"AUTH_SOURCE_CONFIG_SHA256":          strings.Repeat("2", 64),
		"ADMIN_USERNAME":                     integrationAdminUser,
		"ADMIN_PASSWORD_ARGON2ID_HASH":       phc,
		"SESSION_HMAC_KEY":                   sessionKey,
		"ADMIN_ALLOWED_ORIGINS":              integrationOrigin,
		"ADMIN_COOKIE_TRANSPORT":             "tls",
	}
	cfg, err := config.LoadFrom(config.RoleAPI, func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("load production-shaped management config: %v", err)
	}
	return cfg
}

type exactFixture struct {
	Exact      hil.ExactArtifact
	Policy     policy.CheckedResponsePolicy
	Evidence   validation.CheckedEvidenceSnapshot
	Validation validation.CheckedValidationSnapshot
	Command    nftvalidate.Artifact
	IDs        fixtureIDs
}

type fixtureIDs struct {
	Incident, Policy, Analysis, Validation, Candidate, Signal, Event, Evidence string
}

func managementExactFixture(t *testing.T, seed int, now time.Time) exactFixture {
	t.Helper()
	ids := fixtureIDs{
		Incident: fixtureUUID(seed, 101), Policy: fixtureUUID(seed, 102),
		Analysis: fixtureUUID(seed, 103), Validation: fixtureUUID(seed, 104),
		Candidate: fixtureUUID(seed, 105), Signal: fixtureUUID(seed, 106),
		Event: fixtureUUID(seed, 107), Evidence: fixtureUUID(seed, 108),
	}
	target := fmt.Sprintf("203.0.113.%d", 20+seed)
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion, SnapshotID: ids.Evidence,
		IncidentID: ids.Incident, IncidentVersion: 1, SourceIPv4: target, ServiceLabel: "demo-app",
		WindowStart: now.Add(-10 * time.Minute), WindowEnd: now.Add(-2 * time.Minute),
		SourceHealthDigest: managementDigest('b'), EventIDs: []string{ids.Event},
		SignalIDs: []string{ids.Signal}, CreatedAt: now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("check evidence fixture: %v", err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion, PolicyID: ids.Policy, PolicyVersion: 3,
		IncidentID: ids.Incident, AnalysisID: ids.Analysis, Action: policy.ActionBlockIP,
		TargetIPv4: target, TTLSeconds: 1800, EvidenceSnapshotDigest: evidence.Digest(),
		EvidenceIDs: []string{ids.Signal}, RationaleDigest: managementDigest('c'),
		CreatedAt: now.Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatalf("check policy fixture: %v", err)
	}
	command, err := nftvalidate.Canonicalize([]byte("add element inet sentinelflow blacklist_ipv4 { "+target+" timeout 1800s }\n"), 1800)
	if err != nil {
		t.Fatalf("canonicalize fixture command: %v", err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('d')},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('e')},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('f')},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('1')},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('2')},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: managementDigest('3')},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion: validation.ValidationSnapshotSchemaVersion, ValidationID: ids.Validation,
		PolicyDigest: checkedPolicy.Digest(), EvidenceSnapshotDigest: evidence.Digest(),
		AnalysisInputDigest: managementDigest('4'), AnalysisOutputSchemaDigest: managementDigest('5'),
		PromptDigest: managementDigest('6'), GeneratedCandidateDigest: command.GeneratedDigest(),
		CanonicalArtifactDigest: command.CanonicalDigest(), GrammarVersion: nftvalidate.GrammarVersion,
		ParserVersion: nftvalidate.ParserVersion, ValidatorVersion: nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: managementDigest('8'), NFTBinaryDigest: managementDigest('9'),
		NFTVersion: "1.1.0", HistoricalImpactDigest: managementDigest('0'), Checks: checks,
		CreatedAt: now, ValidUntil: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("check validation fixture: %v", err)
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: evidence, Validation: checkedValidation,
	})
	if err != nil {
		t.Fatalf("check exact fixture: %v", err)
	}
	return exactFixture{Exact: exact, Policy: checkedPolicy, Evidence: evidence, Validation: checkedValidation, Command: command, IDs: ids}
}

func seedManagementExactFixture(t *testing.T, fixture *managementPGFixture, exact exactFixture, now time.Time) {
	t.Helper()
	ctx, connection := fixture.ctx, fixture.owner
	ids, artifact := exact.IDs, exact.Exact
	signalDigest := managementSeedDigest(ids.Policy, "signal")
	historyEvidenceDigest := managementIncidentEvidenceDigest(ids.Incident, 1, ids.Signal, signalDigest)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sentinelflow.incidents (
            incident_id, kind, state, source_ip, service_label, first_seen,
            last_seen, deterministic_score, version, evidence_version
        ) VALUES ($1::uuid, 'path_scan', 'review_ready', $2, 'demo-app', $3, $4, 0.95, 3, 1)`,
			[]any{ids.Incident, artifact.TargetIPv4(), now.Add(-10 * time.Minute), now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.signals (
            signal_id, schema_version, rule_id, rule_version, kind, source_ip,
            service_label, window_start, window_end, observed_count,
            distinct_count, threshold_count, threshold_distinct,
            source_health_status, evidence_digest, configuration_version,
            configuration_digest, signal_digest
        ) VALUES ($1::uuid, 'signal-v1', 'path_scan.v1', 1, 'path_scan', $2,
            'demo-app', $3, $4, 8, 8, 8, 8, 'complete', $5,
            'detector-v1', $6, $7)`,
			[]any{ids.Signal, artifact.TargetIPv4(), now.Add(-10 * time.Minute), now.Add(-2 * time.Minute),
				managementDigest('2'), managementDigest('f'), signalDigest}},
		{`INSERT INTO sentinelflow.incident_signals (
            incident_id, signal_id, incident_version, relation_reason, linked_at
        ) VALUES ($1::uuid, $2::uuid, 3, 'same_source_overlap', $3)`,
			[]any{ids.Incident, ids.Signal, now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.incident_version_history (
            incident_id, incident_version, state, kind, source_ip, service_label,
            first_seen, last_seen, deterministic_score, mutation_kind,
            mutation_digest, evidence_digest, signal_count, recorded_at
        ) VALUES ($1::uuid, 1, 'open', 'path_scan', $2, 'demo-app', $3, $4,
            0.95, 'created', $5, $6, 1, $7)`,
			[]any{ids.Incident, artifact.TargetIPv4(), now.Add(-10 * time.Minute), now.Add(-2 * time.Minute),
				managementSeedDigest(ids.Policy, "incident-mutation"), historyEvidenceDigest, now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.incident_version_signals (
            incident_id, incident_version, signal_id, ordinal
        ) VALUES ($1::uuid, 1, $2::uuid, 1)`, []any{ids.Incident, ids.Signal}},
		{`INSERT INTO sentinelflow.evidence_snapshots (
            evidence_snapshot_id, schema_version, incident_id, incident_version,
            source_ip, service_label, window_start, window_end,
            source_health_status, signal_count, expanded_event_count,
            snapshot_digest, created_at, expires_at
        ) VALUES ($1::uuid, 'evidence-snapshot-v1', $2::uuid, 1, $3,
            'demo-app', $4, $5, 'complete', 1, 1, $6, $7, $8)`,
			[]any{ids.Evidence, ids.Incident, artifact.TargetIPv4(), now.Add(-10 * time.Minute),
				now.Add(-2 * time.Minute), artifact.EvidenceSnapshotDigest(), now.Add(-2 * time.Minute), now.Add(30 * 24 * time.Hour)}},
		{`INSERT INTO sentinelflow.evidence_snapshot_signals (
            evidence_snapshot_id, ordinal, signal_id, evidence_id,
            evidence_digest, expanded_event_count
        ) VALUES ($1::uuid, 1, $2::uuid, $2::text, $3, 1)`,
			[]any{ids.Evidence, ids.Signal, managementDigest('2')}},
		{`INSERT INTO sentinelflow.evidence_snapshot_artifacts (
            evidence_snapshot_id, schema_version, source_health_digest,
            canonical_bytes, canonical_digest, created_at
        ) VALUES ($1::uuid, 'evidence-snapshot-v1', $2, $3, $4, $5)`,
			[]any{ids.Evidence, managementDigest('b'), exact.Evidence.CanonicalBytes(), exact.Evidence.Digest(), now.Add(-2 * time.Minute)}},
		{`INSERT INTO sentinelflow.ai_analyses (
            analysis_id, incident_id, incident_version, evidence_snapshot_id,
            evidence_snapshot_digest, attempt, provider_kind, adapter_id,
            model, reasoning_effort, rate_card_version, store_enabled,
            input_schema_digest, prompt_digest, output_schema_digest,
            input_digest, input_bytes, result_state, output_digest,
            incident_summary, classification, confidence, uncertainty,
            input_tokens, cached_input_tokens, output_tokens, started_at, completed_at
        ) VALUES ($1::uuid, $2::uuid, 1, $3::uuid, $4, 1,
            'openai_responses', 'openai-responses-v1', 'gpt-5.6-sol', 'medium',
            'operator-test-v1', false, $5, $6, $7, $8, 2048, 'succeeded', $9,
            'Synthetic management HTTP integration fixture.', 'path_scan', 0.95,
            'Synthetic isolated integration evidence only.', 400, 0, 180, $10, $11)`,
			[]any{ids.Analysis, ids.Incident, ids.Evidence, artifact.EvidenceSnapshotDigest(),
				managementDigest('4'), managementDigest('6'), managementDigest('5'), managementDigest('7'),
				managementDigest('a'), now.Add(-90 * time.Second), now.Add(-80 * time.Second)}},
		{`INSERT INTO sentinelflow.command_candidates (
            command_candidate_id, schema_version, analysis_id,
            evidence_snapshot_id, evidence_snapshot_digest, target_ipv4,
            timeout_token, ttl_seconds, generated_command,
            generated_artifact_digest, parse_state, canonical_artifact,
            canonical_artifact_digest
        ) VALUES ($1::uuid, 'nft-blacklist-v1', $2::uuid, $3::uuid, $4,
            $5, '1800s', $6, $7, $8, 'valid', $9, $10)`,
			[]any{ids.Candidate, ids.Analysis, ids.Evidence, artifact.EvidenceSnapshotDigest(), artifact.TargetIPv4(),
				artifact.TTLSeconds(), string(artifact.GeneratedBytes()), artifact.GeneratedArtifactDigest(),
				artifact.CanonicalBytes(), artifact.CanonicalArtifactDigest()}},
		{`INSERT INTO sentinelflow.policy_proposals (
            policy_id, version, schema_version, incident_id, incident_version,
            analysis_id, command_candidate_id, evidence_snapshot_id,
            evidence_snapshot_digest, policy_digest, generated_artifact_digest,
            canonical_artifact_digest, target_ipv4, action, ttl_seconds,
            rationale, state
        ) VALUES ($1::uuid, $2, 'response-policy-v1', $3::uuid, 1, $4::uuid,
            $5::uuid, $6::uuid, $7, $8, $9, $10, $11, 'block_ip', $12,
            'Synthetic management HTTP integration fixture.', 'draft')`,
			[]any{artifact.PolicyID(), artifact.PolicyVersion(), ids.Incident, ids.Analysis, ids.Candidate,
				ids.Evidence, artifact.EvidenceSnapshotDigest(), artifact.PolicyDigest(),
				artifact.GeneratedArtifactDigest(), artifact.CanonicalArtifactDigest(),
				artifact.TargetIPv4(), artifact.TTLSeconds()}},
		{`INSERT INTO sentinelflow.validation_snapshots (
            validation_snapshot_id, schema_version, policy_id, policy_version,
            command_candidate_id, evidence_snapshot_id, snapshot_digest,
            policy_digest, evidence_snapshot_digest, analysis_input_digest,
            analysis_output_schema_digest, prompt_digest,
            generated_candidate_digest, canonical_artifact_digest,
            grammar_version, parser_version, validator_version,
            base_chain_contract_raw_digest, live_owned_schema_digest,
            protected_ipv4_static_digest, protected_ipv4_effective_config_digest,
            nft_binary_digest, nft_version, historical_impact_digest, target_ipv4,
            ttl_seconds, historical_impact_lookback_seconds, state,
            source_health_status, created_at, valid_until
        ) VALUES ($1::uuid, 'validation-snapshot-v1', $2::uuid, $3, $4::uuid,
            $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
            'nft-blacklist-v1', $14, $15, $16, $17, $18, $19, $20,
            '1.1.0', $21, $22, $23, 86400, 'draft', 'complete', $24, $25)`,
			[]any{ids.Validation, artifact.PolicyID(), artifact.PolicyVersion(), ids.Candidate, ids.Evidence,
				artifact.ValidationSnapshotDigest(), artifact.PolicyDigest(), artifact.EvidenceSnapshotDigest(),
				managementDigest('4'), managementDigest('5'), managementDigest('6'),
				artifact.GeneratedArtifactDigest(), artifact.CanonicalArtifactDigest(), nftvalidate.ParserVersion,
				nftvalidate.ValidatorVersion, nftvalidate.PinnedBaseChainRawDigest, nftvalidate.PinnedLiveSchemaDigest,
				validation.PinnedProtectedIPv4Digest, managementDigest('8'), managementDigest('9'), managementDigest('0'),
				artifact.TargetIPv4(), artifact.TTLSeconds(), artifact.ValidationCreatedAt(), artifact.ValidationValidUntil()}},
	}
	for index, statement := range statements {
		if _, err := connection.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed management fixture %s statement %d: %v", seedFromFixture(ids), index+1, err)
		}
	}
	for index, name := range []string{
		"structured_output", "command_grammar", "policy_evidence_command_consistency",
		"protected_network", "owned_schema_syntax", "historical_impact",
	} {
		if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.validation_gates (
    validation_snapshot_id, gate_order, gate_name, passed, result_code,
    input_digest, result_digest, checked_at
) VALUES ($1::uuid, $2, $3, true, 'ok', $4, $5, $6)`,
			ids.Validation, index+1, name, managementDigest('d'), managementDigest('e'), now); err != nil {
			t.Fatalf("seed validation gate %d: %v", index+1, err)
		}
	}
	if _, err := connection.Exec(ctx, `UPDATE sentinelflow.policy_proposals
SET state = $3, state_revision = state_revision + 1, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2`, artifact.PolicyID(), artifact.PolicyVersion(), "validating"); err != nil {
		t.Fatalf("transition policy to validating: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE sentinelflow.validation_snapshots
SET state = 'valid' WHERE validation_snapshot_id = $1::uuid`, ids.Validation); err != nil {
		t.Fatalf("finalize validation fixture: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE sentinelflow.policy_proposals
SET state = $3, state_revision = state_revision + 1, updated_at = clock_timestamp()
WHERE policy_id = $1::uuid AND version = $2`, artifact.PolicyID(), artifact.PolicyVersion(), "valid"); err != nil {
		t.Fatalf("transition policy to valid: %v", err)
	}
	if _, err := connection.Exec(ctx, `
INSERT INTO sentinelflow.hil_exact_artifacts (
    policy_id, policy_version, command_candidate_id, validation_snapshot_id,
    evidence_snapshot_id, target_ipv4, ttl_seconds, policy_bytes, policy_digest,
    evidence_bytes, evidence_digest, validation_bytes, validation_digest,
    generated_bytes, generated_digest, canonical_bytes, canonical_digest,
    validation_created_at, validation_valid_until
) VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5::uuid, $6, $7,
    $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		artifact.PolicyID(), artifact.PolicyVersion(), ids.Candidate, ids.Validation, ids.Evidence,
		artifact.TargetIPv4(), artifact.TTLSeconds(), exact.Policy.CanonicalBytes(), exact.Policy.Digest(),
		exact.Evidence.CanonicalBytes(), exact.Evidence.Digest(), exact.Validation.CanonicalBytes(),
		exact.Validation.Digest(), artifact.GeneratedBytes(), artifact.GeneratedArtifactDigest(),
		artifact.CanonicalBytes(), artifact.CanonicalArtifactDigest(), artifact.ValidationCreatedAt(),
		artifact.ValidationValidUntil()); err != nil {
		t.Fatalf("seed immutable exact artifact: %v", err)
	}
}

func fixtureUUID(seed, suffix int) string {
	return fmt.Sprintf("019b0000-0000-4000-8000-%012x", seed*0x1000+suffix)
}

func seedFromFixture(ids fixtureIDs) string { return ids.Policy }

func managementDigest(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }

func managementSeedDigest(seed, label string) string {
	digest := sha256.Sum256([]byte("sentinelflow-management-integration-v1\n" + seed + "\n" + label + "\n"))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func managementIncidentEvidenceDigest(incidentID string, version int, signalID, signalDigest string) string {
	values := []string{"incident-evidence-v1", incidentID, strconv.Itoa(version), signalID, signalDigest}
	hash := sha256.New()
	for _, value := range values {
		_, _ = fmt.Fprintf(hash, "%d:%s\n", len(value), value)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func applyManagementMigrations(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate management integration helper")
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

func waitForManagementTCP(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	consecutive := 0
	for range 100 {
		connection, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			consecutive++
			if consecutive == 2 {
				return
			}
		} else {
			consecutive = 0
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL TCP readiness: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not pass two consecutive TCP readiness checks")
}

func waitForManagementPostgreSQL(t *testing.T, ctx context.Context, container string) {
	t.Helper()
	for range 100 {
		if exec.CommandContext(ctx, "docker", "exec", container,
			"pg_isready", "-U", "postgres", "-d", "postgres").Run() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PostgreSQL readiness: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("PostgreSQL 17 did not become query-ready")
}

func connectManagementPostgreSQL(t *testing.T, ctx context.Context, connectionString string) *pgx.Conn {
	t.Helper()
	var lastErr error
	// Docker Desktop can report the published TCP socket and in-container
	// pg_isready before its host-side forwarding path carries a complete
	// PostgreSQL startup exchange. Keep retrying protocol handshakes within the
	// fixture deadline instead of treating that short forwarding window as a
	// database failure.
	for range 100 {
		connection, err := pgx.Connect(ctx, connectionString)
		if err == nil {
			return connection
		}
		lastErr = err
		select {
		case <-ctx.Done():
			t.Fatalf("connect PostgreSQL 17: %v", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("connect PostgreSQL 17: %v", lastErr)
	return nil
}

func managementDockerPort(t *testing.T, ctx context.Context, container string) string {
	t.Helper()
	output := runManagementDocker(t, ctx, "port", container, "5432/tcp")
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		t.Fatalf("unexpected docker port output %q", output)
	}
	return parts[len(parts)-1]
}

func runManagementDocker(t *testing.T, ctx context.Context, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
