package validation

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/policy"
)

func TestEvidenceSnapshotCanonicalGoldenAndImmutability(t *testing.T) {
	t.Parallel()
	value := validEvidenceSnapshot()
	checked, err := CheckEvidenceSnapshot(value)
	if err != nil {
		t.Fatalf("CheckEvidenceSnapshot() error = %v", err)
	}
	if checked.Digest() != "sha256:c34e8a31163a99cff6b6a4929fb2626d4babe9383562f50a781e13ce8bfe7f13" {
		t.Fatalf("evidence golden digest = %s", checked.Digest())
	}
	if !bytes.Equal(checked.CanonicalBytes(), checked.DigestInput()) ||
		digestBytes(checked.DigestInput()) != checked.Digest() {
		t.Fatal("evidence digest input is not the exact canonical object")
	}
	if !bytes.HasPrefix(checked.CanonicalBytes(), []byte(`{"created_at":`)) ||
		!bytes.Contains(checked.CanonicalBytes(), []byte(`,"schema_version":"evidence-snapshot-v1",`)) {
		t.Fatalf("unexpected JCS key order: %s", checked.CanonicalBytes())
	}

	value.EventIDs[0] = consistencyID(999)
	value.SignalIDs[0] = consistencyID(998)
	bytesCopy := checked.CanonicalBytes()
	bytesCopy[0] = '['
	frozen := checked.Value()
	if frozen.EventIDs[0] == consistencyID(999) || frozen.SignalIDs[0] == consistencyID(998) ||
		checked.CanonicalBytes()[0] != '{' {
		t.Fatal("checked evidence snapshot retained mutable caller storage")
	}

	parsed, err := ParseCanonicalEvidenceSnapshot(checked.CanonicalBytes())
	if err != nil || parsed.Digest() != checked.Digest() {
		t.Fatalf("ParseCanonicalEvidenceSnapshot() = %s, %v", parsed.Digest(), err)
	}
}

func TestEvidenceSnapshotSupportsCompleteBurstExpansion(t *testing.T) {
	t.Parallel()
	value := validEvidenceSnapshot()
	value.EventIDs = make([]string, 120)
	for index := range value.EventIDs {
		value.EventIDs[index] = consistencyID(1000 + index)
	}
	checked, err := CheckEvidenceSnapshot(value)
	if err != nil {
		t.Fatalf("120-event request-burst expansion was rejected: %v", err)
	}
	if len(checked.Value().EventIDs) != 120 {
		t.Fatal("complete request-burst expansion was truncated")
	}
}

func TestEvidenceSnapshotRejectsInvalidFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*EvidenceSnapshot)
		code   SnapshotErrorCode
	}{
		{"schema", func(v *EvidenceSnapshot) { v.SchemaVersion = "v2" }, SnapshotErrorSchema},
		{"snapshot id", func(v *EvidenceSnapshot) { v.SnapshotID = "bad" }, SnapshotErrorID},
		{"incident version", func(v *EvidenceSnapshot) { v.IncidentVersion = 0 }, SnapshotErrorID},
		{"noncanonical IPv4", func(v *EvidenceSnapshot) { v.SourceIPv4 = "203.000.113.20" }, SnapshotErrorField},
		{"service", func(v *EvidenceSnapshot) { v.ServiceLabel = "Demo App" }, SnapshotErrorField},
		{"health digest", func(v *EvidenceSnapshot) { v.SourceHealthDigest = "bad" }, SnapshotErrorDigest},
		{"event order", func(v *EvidenceSnapshot) { v.EventIDs[0], v.EventIDs[1] = v.EventIDs[1], v.EventIDs[0] }, SnapshotErrorEvidence},
		{"duplicate signal", func(v *EvidenceSnapshot) { v.SignalIDs[1] = v.SignalIDs[0] }, SnapshotErrorEvidence},
		{"window order", func(v *EvidenceSnapshot) { v.WindowEnd = v.WindowStart.Add(-time.Nanosecond) }, SnapshotErrorTime},
		{"created before evidence", func(v *EvidenceSnapshot) { v.CreatedAt = v.WindowEnd.Add(-time.Nanosecond) }, SnapshotErrorTime},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validEvidenceSnapshot()
			test.mutate(&value)
			_, err := CheckEvidenceSnapshot(value)
			assertSnapshotError(t, err, test.code)
		})
	}
}

func TestEvidenceSnapshotParserRejectsNonCanonicalAndAmbiguousJSON(t *testing.T) {
	t.Parallel()
	checked, err := CheckEvidenceSnapshot(validEvidenceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	canonical := checked.CanonicalBytes()
	tests := [][]byte{
		append([]byte(" "), canonical...),
		append(append([]byte(nil), canonical...), '\n'),
		bytes.Replace(canonical, []byte(`{"created_at":`), []byte(`{"unknown":true,"created_at":`), 1),
		bytes.Replace(canonical, []byte(`{"created_at":`), []byte(`{"created_at":"2026-07-18T03:00:01Z","created_at":`), 1),
	}
	for index, input := range tests {
		if _, err := ParseCanonicalEvidenceSnapshot(input); err == nil {
			t.Fatalf("ambiguous evidence JSON case %d accepted", index)
		}
	}
}

func TestValidationSnapshotCanonicalGoldenAndFreshness(t *testing.T) {
	t.Parallel()
	value := validValidationSnapshot()
	checked, err := CheckValidationSnapshot(value)
	if err != nil {
		t.Fatalf("CheckValidationSnapshot() error = %v", err)
	}
	if checked.Digest() != "sha256:1fdcebf78f4ed72117342dea070041c9e8dd8ded924ce95089534e2ce91c24e5" {
		t.Fatalf("validation golden digest = %s", checked.Digest())
	}
	if !bytes.Equal(checked.CanonicalBytes(), checked.DigestInput()) ||
		digestBytes(checked.DigestInput()) != checked.Digest() {
		t.Fatal("validation digest input is not the exact canonical object")
	}
	if !checked.FreshAt(value.CreatedAt) || !checked.FreshAt(value.ValidUntil.Add(-time.Nanosecond)) ||
		checked.FreshAt(value.CreatedAt.Add(-time.Nanosecond)) || checked.FreshAt(value.ValidUntil) ||
		checked.FreshAt(value.ValidUntil.Add(time.Nanosecond)) {
		t.Fatal("validation freshness boundary is not fail-closed")
	}

	value.Checks[0].InputDigest = digestBytes([]byte("mutated"))
	canonical := checked.CanonicalBytes()
	canonical[0] = '['
	if checked.Value().Checks[0].InputDigest == value.Checks[0].InputDigest ||
		checked.CanonicalBytes()[0] != '{' {
		t.Fatal("checked validation snapshot retained mutable caller storage")
	}
	parsed, err := ParseCanonicalValidationSnapshot(checked.CanonicalBytes())
	if err != nil || parsed.Digest() != checked.Digest() {
		t.Fatalf("ParseCanonicalValidationSnapshot() = %s, %v", parsed.Digest(), err)
	}
}

func TestValidationSnapshotRejectsGateAndBindingMutations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ValidationSnapshot)
		code   SnapshotErrorCode
	}{
		{"schema", func(v *ValidationSnapshot) { v.SchemaVersion = "v2" }, SnapshotErrorSchema},
		{"grammar", func(v *ValidationSnapshot) { v.GrammarVersion = "shell-v1" }, SnapshotErrorSchema},
		{"validation id", func(v *ValidationSnapshot) { v.ValidationID = "bad" }, SnapshotErrorID},
		{"parser", func(v *ValidationSnapshot) { v.ParserVersion = "Bad" }, SnapshotErrorField},
		{"nft version", func(v *ValidationSnapshot) { v.NFTVersion = "1.0" }, SnapshotErrorField},
		{"policy digest", func(v *ValidationSnapshot) { v.PolicyDigest = "bad" }, SnapshotErrorDigest},
		{"missing gate", func(v *ValidationSnapshot) { v.Checks = v.Checks[:5] }, SnapshotErrorChecks},
		{"reordered gate", func(v *ValidationSnapshot) { v.Checks[0], v.Checks[1] = v.Checks[1], v.Checks[0] }, SnapshotErrorChecks},
		{"failed gate", func(v *ValidationSnapshot) { v.Checks[2].Result = "fail" }, SnapshotErrorChecks},
		{"reason", func(v *ValidationSnapshot) { v.Checks[2].ReasonCode = "mismatch" }, SnapshotErrorChecks},
		{"gate input", func(v *ValidationSnapshot) { v.Checks[2].InputDigest = "bad" }, SnapshotErrorChecks},
		{"short validity", func(v *ValidationSnapshot) { v.ValidUntil = v.ValidUntil.Add(-time.Nanosecond) }, SnapshotErrorValidity},
		{"long validity", func(v *ValidationSnapshot) { v.ValidUntil = v.ValidUntil.Add(time.Nanosecond) }, SnapshotErrorValidity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validValidationSnapshot()
			test.mutate(&value)
			_, err := CheckValidationSnapshot(value)
			assertSnapshotError(t, err, test.code)
		})
	}
}

func TestValidationSnapshotParserRejectsNonCanonicalAndDuplicateFields(t *testing.T) {
	t.Parallel()
	checked, err := CheckValidationSnapshot(validValidationSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	canonical := checked.CanonicalBytes()
	tests := [][]byte{
		append([]byte(" "), canonical...),
		append(append([]byte(nil), canonical...), []byte(`{}`)...),
		bytes.Replace(canonical, []byte(`{"analysis_input_digest":`), []byte(`{"unknown":true,"analysis_input_digest":`), 1),
		bytes.Replace(canonical, []byte(`{"analysis_input_digest":`), []byte(`{"analysis_input_digest":"sha256:`+strings.Repeat("0", 64)+`","analysis_input_digest":`), 1),
	}
	for index, input := range tests {
		if _, err := ParseCanonicalValidationSnapshot(input); err == nil {
			t.Fatalf("ambiguous validation JSON case %d accepted", index)
		}
	}
}

func validEvidenceSnapshot() EvidenceSnapshot {
	windowStart := time.Date(2026, 7, 18, 2, 59, 50, 0, time.UTC)
	windowEnd := time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)
	return EvidenceSnapshot{
		SchemaVersion:      EvidenceSnapshotSchemaVersion,
		SnapshotID:         consistencyID(201),
		IncidentID:         consistencyID(202),
		IncidentVersion:    3,
		SourceIPv4:         "203.0.113.20",
		ServiceLabel:       "demo-app",
		WindowStart:        windowStart,
		WindowEnd:          windowEnd,
		SourceHealthDigest: digestBytes([]byte("source health complete")),
		EventIDs:           []string{consistencyID(301), consistencyID(302), consistencyID(303)},
		SignalIDs:          []string{consistencyID(401), consistencyID(402)},
		CreatedAt:          windowEnd.Add(time.Second),
	}
}

func validValidationSnapshot() ValidationSnapshot {
	createdAt := time.Date(2026, 7, 18, 3, 1, 0, 123456789, time.UTC)
	checks := make([]ValidationCheck, len(orderedValidationCheckIDs))
	for index, checkID := range orderedValidationCheckIDs {
		checks[index] = ValidationCheck{
			CheckID:     checkID,
			Result:      "pass",
			ReasonCode:  "ok",
			InputDigest: digestBytes([]byte(fmt.Sprintf("gate input %d", index))),
		}
	}
	return ValidationSnapshot{
		SchemaVersion:                      ValidationSnapshotSchemaVersion,
		ValidationID:                       consistencyID(501),
		PolicyDigest:                       digestBytes([]byte("policy")),
		EvidenceSnapshotDigest:             digestBytes([]byte("evidence")),
		AnalysisInputDigest:                digestBytes([]byte("analysis input")),
		AnalysisOutputSchemaDigest:         digestBytes([]byte("analysis schema")),
		PromptDigest:                       digestBytes([]byte("prompt")),
		GeneratedCandidateDigest:           digestBytes([]byte("generated command")),
		CanonicalArtifactDigest:            digestBytes([]byte("canonical command")),
		GrammarVersion:                     policy.CandidateSchemaVersion,
		ParserVersion:                      "nft-parser-v1",
		ValidatorVersion:                   "validation-pipeline-v1",
		BaseChainContractRawDigest:         digestBytes([]byte("base chain raw")),
		LiveOwnedSchemaDigest:              digestBytes([]byte("live schema")),
		ProtectedIPv4StaticDigest:          PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: digestBytes([]byte("effective protected config")),
		NFTBinaryDigest:                    digestBytes([]byte("nft binary")),
		NFTVersion:                         "1.1.1",
		HistoricalImpactDigest:             digestBytes([]byte("historical impact")),
		Checks:                             checks,
		CreatedAt:                          createdAt,
		ValidUntil:                         createdAt.Add(ValidationSnapshotLifetime),
	}
}

func assertSnapshotError(t *testing.T, err error, code SnapshotErrorCode) {
	t.Helper()
	var snapshotError *SnapshotError
	if !errorsAs(err, &snapshotError) || snapshotError.Code != code {
		t.Fatalf("error = %v, want snapshot code %s", err, code)
	}
}

// Keep the tests' dependency surface small while still exercising errors.As.
func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}
