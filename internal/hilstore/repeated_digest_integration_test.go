package hilstore

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const repeatedDigestPostgreSQL17Image = "postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"

func TestPostgreSQL17IndependentlyApprovesRepeatedCommandContent(t *testing.T) {
	if testing.Short() {
		t.Skip("PostgreSQL 17 integration test disabled by -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container := fmt.Sprintf("sentinelflow-hilstore-repeated-digest-%d", time.Now().UnixNano())
	runIntegrationDocker(t, ctx, "run", "-d", "--rm", "--name", container,
		"-e", "POSTGRES_PASSWORD=sentinelflow-test-only", "-p", "127.0.0.1::5432", repeatedDigestPostgreSQL17Image)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", container).Run()
	})
	waitForIntegrationPostgreSQL(t, ctx, container)
	port := integrationDockerPort(t, ctx, container)
	connection := connectIntegrationPostgreSQL(t, ctx,
		"postgresql://postgres:sentinelflow-test-only@127.0.0.1:"+port+"/postgres?sslmode=disable")
	defer connection.Close(context.Background())
	applyIntegrationMigrations(t, ctx, connection)

	now := time.Now().UTC().Truncate(time.Microsecond)
	firstIDs := integrationChallengeFixtureIDs{
		incidentID: "019b0000-0000-4000-8000-000000000201", signalID: "019b0000-0000-4000-8000-000000000202",
		analysisID: "019b0000-0000-4000-8000-000000000203", candidateID: "019b0000-0000-4000-8000-000000000204",
		evidenceID: "019b0000-0000-4000-8000-000000000205", validationID: "019b0000-0000-4000-8000-000000000206",
		signalDigestByte: '3', signalEvidenceDigestByte: '4', historyMutationDigestByte: '7',
	}
	secondIDs := integrationChallengeFixtureIDs{
		incidentID: "019b0000-0000-4000-8000-000000000301", signalID: "019b0000-0000-4000-8000-000000000302",
		analysisID: "019b0000-0000-4000-8000-000000000303", candidateID: "019b0000-0000-4000-8000-000000000304",
		evidenceID: "019b0000-0000-4000-8000-000000000305", validationID: "019b0000-0000-4000-8000-000000000306",
		signalDigestByte: '5', signalEvidenceDigestByte: '6', historyMutationDigestByte: '8',
	}
	first := repeatedCommandIssueRequest(t, now, firstIDs,
		"019b0000-0000-4000-8000-000000000207", []byte("first-repeated-command-idempotency"), 0)
	second := repeatedCommandIssueRequest(t, now, secondIDs,
		"019b0000-0000-4000-8000-000000000307", []byte("second-repeated-command-idempotency"), 0x40)

	if !bytes.Equal(first.Artifact.GeneratedBytes(), second.Artifact.GeneratedBytes()) ||
		!bytes.Equal(first.Artifact.CanonicalBytes(), second.Artifact.CanonicalBytes()) ||
		first.Artifact.GeneratedArtifactDigest() != second.Artifact.GeneratedArtifactDigest() ||
		first.Artifact.CanonicalArtifactDigest() != second.Artifact.CanonicalArtifactDigest() {
		t.Fatal("fixture does not share byte-identical generated and canonical command content")
	}
	if first.Artifact.PolicyID() == second.Artifact.PolicyID() ||
		first.Artifact.PolicyDigest() == second.Artifact.PolicyDigest() ||
		first.Artifact.EvidenceSnapshotDigest() == second.Artifact.EvidenceSnapshotDigest() ||
		first.Artifact.ValidationSnapshotDigest() == second.Artifact.ValidationSnapshotDigest() {
		t.Fatal("fixture did not retain independent policy, evidence, and validation bindings")
	}

	seedChallengeFixtureWithIDs(t, ctx, connection, first, now, firstIDs)
	seedChallengeFixtureWithIDs(t, ctx, connection, second, now, secondIDs)
	if _, err := connection.Exec(ctx, `SET ROLE sentinelflow_api`); err != nil {
		t.Fatal("set API role")
	}
	store, err := NewPostgreSQLStore(connection, deterministicEntropy(16384))
	if err != nil {
		t.Fatal(err)
	}

	firstIssued, err := store.Issue(ctx, first)
	if err != nil {
		t.Fatalf("issue first challenge: %v", err)
	}
	secondIssued, err := store.Issue(ctx, second)
	if err != nil {
		t.Fatalf("issue second challenge: %v", err)
	}
	firstNonce := takeCheckedIntegrationNonce(t, firstIssued)
	secondNonce := takeCheckedIntegrationNonce(t, secondIssued)
	if firstNonce.digest == secondNonce.digest ||
		firstIssued.Challenge().Value().ChallengeID == secondIssued.Challenge().Value().ChallengeID {
		t.Fatal("independent approvals reused challenge or nonce authority")
	}

	firstReason := checkedIntegrationReason(t, "First independent repeated-command approval")
	secondReason := checkedIntegrationReason(t, "Second independent repeated-command approval")
	firstLookup := DecisionLookup{Browser: first.Browser, Challenge: firstIssued.Challenge(), Nonce: firstNonce,
		Artifact: first.Artifact, Reason: firstReason}
	secondLookup := DecisionLookup{Browser: second.Browser, Challenge: secondIssued.Challenge(), Nonce: secondNonce,
		Artifact: second.Artifact, Reason: secondReason}
	firstStored, err := store.Commit(ctx,
		fixturePrivilegedCommit(t, firstLookup, firstIssued.Challenge().Value().IssuedAt))
	if err != nil {
		t.Fatalf("commit first approval: %v", err)
	}
	secondStored, err := store.Commit(ctx,
		fixturePrivilegedCommit(t, secondLookup, secondIssued.Challenge().Value().IssuedAt))
	if err != nil {
		t.Fatalf("commit second approval: %v", err)
	}
	if firstStored.ActionID() == secondStored.ActionID() ||
		firstStored.AuthorizationDigest() == secondStored.AuthorizationDigest() ||
		firstStored.Decision().Value().DecisionID == secondStored.Decision().Value().DecisionID {
		t.Fatal("independent approvals collapsed action, authorization, or decision identity")
	}
	if _, err = connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal("reset API role")
	}

	type persistedBinding struct {
		actionID, authorizationID, decisionID, policyID   string
		analysisID, candidateID, evidenceID, validationID string
		nonceDigest, auditEventID                         string
	}
	loadBinding := func(actionID string) persistedBinding {
		t.Helper()
		var binding persistedBinding
		err := connection.QueryRow(ctx, `
SELECT act.action_id::text, authz.authorization_id::text,
       authz.approval_decision_id::text, act.policy_id::text,
       policy.analysis_id::text, act.command_candidate_id::text,
       act.evidence_snapshot_id::text, act.validation_snapshot_id::text,
       authz.decision_nonce_digest::text, audit.event_id::text
FROM sentinelflow.enforcement_actions act
JOIN sentinelflow.enforcement_authorizations authz
  ON authz.authorization_id = act.add_authorization_id
JOIN sentinelflow.policy_proposals policy
  ON policy.policy_id = act.policy_id AND policy.version = act.policy_version
JOIN sentinelflow.audit_events audit
  ON audit.enforcement_action_id = act.action_id AND audit.action = 'policy_approved'
WHERE act.action_id = $1::uuid`, actionID).Scan(
			&binding.actionID, &binding.authorizationID, &binding.decisionID, &binding.policyID,
			&binding.analysisID, &binding.candidateID, &binding.evidenceID, &binding.validationID,
			&binding.nonceDigest, &binding.auditEventID,
		)
		if err != nil {
			t.Fatalf("load persisted approval binding %s: %v", actionID, err)
		}
		return binding
	}
	firstBinding := loadBinding(firstStored.ActionID())
	secondBinding := loadBinding(secondStored.ActionID())
	if firstBinding.policyID != first.Artifact.PolicyID() || firstBinding.analysisID != firstIDs.analysisID ||
		firstBinding.candidateID != firstIDs.candidateID || firstBinding.evidenceID != firstIDs.evidenceID ||
		firstBinding.validationID != firstIDs.validationID || firstBinding.nonceDigest != firstNonce.digest {
		t.Fatalf("first persisted binding drifted: %+v", firstBinding)
	}
	if secondBinding.policyID != second.Artifact.PolicyID() || secondBinding.analysisID != secondIDs.analysisID ||
		secondBinding.candidateID != secondIDs.candidateID || secondBinding.evidenceID != secondIDs.evidenceID ||
		secondBinding.validationID != secondIDs.validationID || secondBinding.nonceDigest != secondNonce.digest {
		t.Fatalf("second persisted binding drifted: %+v", secondBinding)
	}
	if firstBinding.authorizationID == secondBinding.authorizationID ||
		firstBinding.policyID == secondBinding.policyID || firstBinding.auditEventID == secondBinding.auditEventID {
		t.Fatal("independent approvals collapsed authorization, policy, or audit identity")
	}
	var actionCount, authorizationCount, auditCount int
	if err = connection.QueryRow(ctx, `
SELECT (SELECT count(*)::integer FROM sentinelflow.enforcement_actions
         WHERE canonical_artifact_digest = $1),
       (SELECT count(*)::integer FROM sentinelflow.enforcement_authorizations
         WHERE canonical_artifact_digest = $1
           AND generated_artifact_digest = $2
           AND authorization_kind = 'add'),
       (SELECT count(*)::integer FROM sentinelflow.audit_events
		 WHERE enforcement_action_id = ANY($3::uuid[]) AND action = 'policy_approved')`,
		first.Artifact.CanonicalArtifactDigest(), first.Artifact.GeneratedArtifactDigest(),
		[]string{firstStored.ActionID(), secondStored.ActionID()},
	).Scan(&actionCount, &authorizationCount, &auditCount); err != nil {
		t.Fatalf("count repeated-content approval evidence: %v", err)
	}
	if actionCount != 2 || authorizationCount != 2 || auditCount != 2 {
		t.Fatalf("repeated-content approvals actions=%d authorizations=%d audits=%d",
			actionCount, authorizationCount, auditCount)
	}
}

func repeatedCommandIssueRequest(
	t *testing.T,
	now time.Time,
	ids integrationChallengeFixtureIDs,
	policyID string,
	idempotencyKey []byte,
	sessionSalt byte,
) IssueRequest {
	t.Helper()
	session := fixtureSession(now)
	session.ID[15] ^= sessionSalt
	session.TokenDigest[0] ^= sessionSalt
	session.CSRFDigest[0] ^= sessionSalt
	key, err := CheckIdempotencyKey(idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := BindValidatedBrowserRequest(session, key)
	if err != nil {
		t.Fatal(err)
	}
	return IssueRequest{
		Operation: hil.OperationApprove,
		Browser:   browser,
		Artifact:  repeatedCommandExactArtifact(t, now, ids, policyID),
	}
}

func repeatedCommandExactArtifact(
	t *testing.T,
	now time.Time,
	ids integrationChallengeFixtureIDs,
	policyID string,
) hil.ExactArtifact {
	t.Helper()
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion, SnapshotID: ids.evidenceID,
		IncidentID: ids.incidentID, IncidentVersion: 1, SourceIPv4: "203.0.113.20",
		ServiceLabel: "demo-app", WindowStart: now.Add(-10 * time.Minute), WindowEnd: now.Add(-2 * time.Minute),
		SourceHealthDigest: testDigest('b'), EventIDs: []string{ids.signalID}, SignalIDs: []string{ids.signalID},
		CreatedAt: now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion, PolicyID: policyID, PolicyVersion: 1,
		IncidentID: ids.incidentID, AnalysisID: ids.analysisID, Action: policy.ActionBlockIP,
		TargetIPv4: "203.0.113.20", TTLSeconds: 1800, EvidenceSnapshotDigest: evidence.Digest(),
		EvidenceIDs: []string{ids.signalID}, RationaleDigest: testDigest(ids.signalDigestByte),
		CreatedAt: now.Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	command, err := nftvalidate.Canonicalize(
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }\n"), 1800)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('1')},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('2')},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('3')},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('4')},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('5')},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('6')},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion: validation.ValidationSnapshotSchemaVersion, ValidationID: ids.validationID,
		PolicyDigest: checkedPolicy.Digest(), EvidenceSnapshotDigest: evidence.Digest(),
		AnalysisInputDigest: testDigest('4'), AnalysisOutputSchemaDigest: testDigest('5'), PromptDigest: testDigest('6'),
		GeneratedCandidateDigest: command.GeneratedDigest(), CanonicalArtifactDigest: command.CanonicalDigest(),
		GrammarVersion: nftvalidate.GrammarVersion, ParserVersion: nftvalidate.ParserVersion,
		ValidatorVersion: nftvalidate.ValidatorVersion, BaseChainContractRawDigest: nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest, ProtectedIPv4StaticDigest: validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: testDigest('8'), NFTBinaryDigest: testDigest('9'), NFTVersion: "1.1.0",
		HistoricalImpactDigest: testDigest('0'), Checks: checks, CreatedAt: now.Add(-time.Minute), ValidUntil: now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("validation: %v", err)
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: evidence, Validation: checkedValidation,
	})
	if err != nil {
		t.Fatalf("exact artifact: %v", err)
	}
	return exact
}

func takeCheckedIntegrationNonce(t *testing.T, issued *IssuedChallenge) DecisionNonce {
	t.Helper()
	raw, err := issued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	checked, err := CheckDecisionNonce(raw)
	if err != nil {
		t.Fatal(err)
	}
	return checked
}

func checkedIntegrationReason(t *testing.T, text string) hil.CheckedReason {
	t.Helper()
	reason, err := hil.CheckReason(hil.Reason{
		SchemaVersion: hil.ReasonSchemaVersion, ReasonCode: hil.ReasonThreatConfirmed, ReasonText: text,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reason
}
