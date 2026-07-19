package hilartifactstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

const (
	policyID     = "019b0000-0000-7000-8000-00000000b001"
	analysisID   = "019b0000-0000-7000-8000-00000000b002"
	incidentID   = "019b0000-0000-7000-8000-00000000b003"
	evidenceID   = "019b0000-0000-7000-8000-00000000b004"
	signalID     = "019b0000-0000-7000-8000-00000000b005"
	eventID      = "019b0000-0000-7000-8000-00000000b006"
	candidateID  = "019b0000-0000-7000-8000-00000000b007"
	validationID = "019b0000-0000-7000-8000-00000000b008"
	testDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var now = time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)

func TestLoadRechecksEveryCanonicalArtifact(t *testing.T) {
	t.Parallel()
	row := fixtureRow(t)
	store, _ := NewPostgreSQLStore(&stub{row: scanRow(row)})
	exact, err := store.Load(context.Background(), policyID, 1, now.Add(time.Minute))
	if err != nil || exact.PolicyID() != policyID || exact.TargetIPv4() != "8.8.8.8" {
		t.Fatalf("exact=%+v err=%v", exact, err)
	}
}

func TestLoadFailsClosedForMissingTamperedOversizedAndStaleRows(t *testing.T) {
	t.Parallel()
	missing, _ := NewPostgreSQLStore(&stub{row: rowFunc(func(...any) error { return pgx.ErrNoRows })})
	if _, err := missing.Load(context.Background(), policyID, 1, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing err=%v", err)
	}
	for _, mutate := range []func(*rowValue){
		func(row *rowValue) { row.PolicyBytes[1] ^= 1 },
		func(row *rowValue) { row.EvidenceBytes = make([]byte, validation.MaxEvidenceSnapshotBytes+1) },
		func(row *rowValue) { row.CanonicalDigest = testDigest },
		func(row *rowValue) { row.ValidationSnapshotID = candidateID },
	} {
		row := fixtureRow(t)
		mutate(&row)
		store, _ := NewPostgreSQLStore(&stub{row: scanRow(row)})
		if _, err := store.Load(context.Background(), policyID, 1, now.Add(time.Minute)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("tamper err=%v", err)
		}
	}
	stale, _ := NewPostgreSQLStore(&stub{row: scanRow(fixtureRow(t))})
	if _, err := stale.Load(context.Background(), policyID, 1, now.Add(5*time.Minute)); !errors.Is(err, ErrStale) {
		t.Fatalf("stale err=%v", err)
	}
	historical, _ := NewPostgreSQLStore(&stub{row: scanRow(fixtureRow(t))})
	exact, err := historical.LoadHistorical(context.Background(), policyID, 1)
	if err != nil || exact.PolicyID() != policyID {
		t.Fatalf("immutable historical artifact rejected: exact=%v err=%v", exact, err)
	}
	tamperedRow := fixtureRow(t)
	tamperedRow.GeneratedBytes[0] ^= 1
	tamperedHistorical, _ := NewPostgreSQLStore(&stub{row: scanRow(tamperedRow)})
	if _, err := tamperedHistorical.LoadHistorical(context.Background(), policyID, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered historical artifact accepted: %v", err)
	}
	failing, _ := NewPostgreSQLStore(&stub{row: rowFunc(func(...any) error {
		return errors.New("password=secret")
	})})
	if _, err := failing.Load(context.Background(), policyID, 1, now); !errors.Is(err, ErrPersistence) ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("persistence err=%v", err)
	}
}

func fixtureRow(t *testing.T) rowValue {
	t.Helper()
	generated := []byte("add element inet sentinelflow blacklist_ipv4 { 8.8.8.8 timeout 30m }")
	command, err := nftvalidate.Canonicalize(generated, 1800)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion: validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:    evidenceID, IncidentID: incidentID, IncidentVersion: 1,
		SourceIPv4: "8.8.8.8", ServiceLabel: "gateway",
		WindowStart: now.Add(-time.Minute), WindowEnd: now, CreatedAt: now,
		SourceHealthDigest: testDigest, EventIDs: []string{eventID}, SignalIDs: []string{signalID},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion: policy.PolicySchemaVersion, PolicyID: policyID, PolicyVersion: 1,
		IncidentID: incidentID, AnalysisID: analysisID, Action: policy.ActionBlockIP,
		TargetIPv4: "8.8.8.8", TTLSeconds: 1800,
		EvidenceSnapshotDigest: evidence.Digest(), EvidenceIDs: []string{signalID},
		RationaleDigest: policy.Digest([]byte("synthetic rationale")), CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: testDigest},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: command.GeneratedDigest()},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: checkedPolicy.Digest()},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: validation.PinnedProtectedIPv4Digest},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: command.CanonicalDigest()},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: testDigest},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion: validation.ValidationSnapshotSchemaVersion, ValidationID: validationID,
		PolicyDigest: checkedPolicy.Digest(), EvidenceSnapshotDigest: evidence.Digest(),
		AnalysisInputDigest: testDigest, AnalysisOutputSchemaDigest: testDigest,
		PromptDigest: testDigest, GeneratedCandidateDigest: command.GeneratedDigest(),
		CanonicalArtifactDigest: command.CanonicalDigest(), GrammarVersion: nftvalidate.GrammarVersion,
		ParserVersion: nftvalidate.ParserVersion, ValidatorVersion: nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: testDigest, NFTBinaryDigest: testDigest,
		NFTVersion: "1.0.9", HistoricalImpactDigest: testDigest, Checks: checks,
		CreatedAt: now, ValidUntil: now.Add(validation.ValidationSnapshotLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: evidence, Validation: checkedValidation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rowValue{
		PolicyID: policyID, PolicyVersion: 1, CommandCandidateID: candidateID,
		ValidationSnapshotID: validationID, EvidenceSnapshotID: evidenceID,
		TargetIPv4: exact.TargetIPv4(), TTLSeconds: int64(exact.TTLSeconds()),
		PolicyBytes: checkedPolicy.CanonicalBytes(), PolicyDigest: checkedPolicy.Digest(),
		EvidenceBytes: evidence.CanonicalBytes(), EvidenceDigest: evidence.Digest(),
		ValidationBytes: checkedValidation.CanonicalBytes(), ValidationDigest: checkedValidation.Digest(),
		GeneratedBytes: command.GeneratedBytes(), GeneratedDigest: command.GeneratedDigest(),
		CanonicalBytes: command.CanonicalBytes(), CanonicalDigest: command.CanonicalDigest(),
		ValidationCreatedAt: now, ValidationValidUntil: now.Add(validation.ValidationSnapshotLifetime),
	}
}

type rowFunc func(...any) error

func (row rowFunc) Scan(dest ...any) error { return row(dest...) }

func scanRow(row rowValue) pgx.Row {
	return rowFunc(func(dest ...any) error {
		*dest[0].(*string) = row.PolicyID
		*dest[1].(*int64) = row.PolicyVersion
		*dest[2].(*string) = row.CommandCandidateID
		*dest[3].(*string) = row.ValidationSnapshotID
		*dest[4].(*string) = row.EvidenceSnapshotID
		*dest[5].(*string) = row.TargetIPv4
		*dest[6].(*int64) = row.TTLSeconds
		*dest[7].(*[]byte) = append([]byte(nil), row.PolicyBytes...)
		*dest[8].(*string) = row.PolicyDigest
		*dest[9].(*[]byte) = append([]byte(nil), row.EvidenceBytes...)
		*dest[10].(*string) = row.EvidenceDigest
		*dest[11].(*[]byte) = append([]byte(nil), row.ValidationBytes...)
		*dest[12].(*string) = row.ValidationDigest
		*dest[13].(*[]byte) = append([]byte(nil), row.GeneratedBytes...)
		*dest[14].(*string) = row.GeneratedDigest
		*dest[15].(*[]byte) = append([]byte(nil), row.CanonicalBytes...)
		*dest[16].(*string) = row.CanonicalDigest
		*dest[17].(*time.Time) = row.ValidationCreatedAt
		*dest[18].(*time.Time) = row.ValidationValidUntil
		return nil
	})
}

type stub struct{ row pgx.Row }

func (s *stub) QueryRow(context.Context, string, ...any) pgx.Row { return s.row }
