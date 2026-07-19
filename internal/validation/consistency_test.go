package validation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/policy"
	"golang.org/x/text/unicode/norm"
)

func TestConsistencyGateBindsPolicyEvidenceAndCommand(t *testing.T) {
	t.Parallel()
	input := validConsistencyInput(t)
	result := CheckConsistency(input)
	if result.Status != ConsistencyPassed || result.FailureCode != ConsistencyFailureNone {
		t.Fatalf("CheckConsistency() = %+v", result)
	}
	value := input.Policy.Value()
	if result.TargetIPv4 != value.TargetIPv4 || result.PolicyDigest != input.Policy.Digest() ||
		result.GeneratedCommandDigest != input.Candidate.GeneratedDigest() ||
		result.CanonicalCommandDigest != input.Candidate.CanonicalDigest() ||
		result.EvidenceSnapshotDigest != value.EvidenceSnapshotDigest ||
		result.AnalysisInputDigest != input.Analysis.AnalysisInputDigest ||
		result.AnalysisOutputDigest != digestBytes(input.Analysis.Output) ||
		result.RationaleDigest != value.RationaleDigest {
		t.Fatalf("consistency binding incomplete: %+v", result)
	}
}

func TestConsistencyGateFailureClasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ConsistencyInput)
		code   ConsistencyFailureCode
	}{
		{"schema prerequisite", func(i *ConsistencyInput) { i.SchemaGate.Status = "failed" }, ConsistencyFailurePrerequisite},
		{"output digest prerequisite", func(i *ConsistencyInput) { i.SchemaGate.AnalysisOutputDigest = digestBytes([]byte("other")) }, ConsistencyFailurePrerequisite},
		{"schema digest prerequisite", func(i *ConsistencyInput) { i.ExpectedOutputSchemaDigest = digestBytes([]byte("other schema")) }, ConsistencyFailurePrerequisite},
		{"missing candidate", func(i *ConsistencyInput) { i.Candidate = policy.Artifact{} }, ConsistencyFailurePrerequisite},
		{"analysis id", func(i *ConsistencyInput) { i.Analysis.AnalysisID = consistencyID(99) }, ConsistencyFailureAnalysis},
		{"analysis incident", func(i *ConsistencyInput) { i.Analysis.IncidentID = consistencyID(99) }, ConsistencyFailureAnalysis},
		{"analysis incident version", func(i *ConsistencyInput) { i.Analysis.IncidentVersion++ }, ConsistencyFailureAnalysis},
		{"analysis input digest", func(i *ConsistencyInput) { i.Analysis.AnalysisInputDigest = digestBytes([]byte("other input")) }, ConsistencyFailureAnalysis},
		{"snapshot digest", func(i *ConsistencyInput) { i.Evidence.SnapshotDigest = digestBytes([]byte("other snapshot")) }, ConsistencyFailureEvidenceSnapshot},
		{"snapshot incident", func(i *ConsistencyInput) {
			i.Evidence.IncidentID = consistencyID(99)
		}, ConsistencyFailureAnalysis},
		{"snapshot source", func(i *ConsistencyInput) { i.Evidence.SourceIPv4 = "203.0.113.21" }, ConsistencyFailureEvidenceSnapshot},
		{"snapshot source health digest", func(i *ConsistencyInput) { i.Evidence.SourceHealthDigest = "bad" }, ConsistencyFailureEvidenceSnapshot},
		{"snapshot health", func(i *ConsistencyInput) { i.Evidence.SourceHealthStatus = "incomplete" }, ConsistencyFailureEvidenceIncomplete},
		{"signal order", func(i *ConsistencyInput) {
			i.Evidence.SignalIDs[0], i.Evidence.SignalIDs[1] = i.Evidence.SignalIDs[1], i.Evidence.SignalIDs[0]
		}, ConsistencyFailureEvidenceMembership},
		{"signal binding id", func(i *ConsistencyInput) { i.Evidence.Signals[0].SignalID = consistencyID(99) }, ConsistencyFailureEvidenceMembership},
		{"signal digest", func(i *ConsistencyInput) { i.Evidence.Signals[0].SignalDigest = "bad" }, ConsistencyFailureEvidenceMembership},
		{"event union", func(i *ConsistencyInput) { i.Evidence.EventIDs = i.Evidence.EventIDs[:2] }, ConsistencyFailureEvidenceMembership},
		{"signal target", func(i *ConsistencyInput) { i.Evidence.Signals[0].SourceIPv4 = "203.0.113.21" }, ConsistencyFailureEvidenceTarget},
		{"threshold", func(i *ConsistencyInput) { i.Evidence.Signals[0].ThresholdReproduced = false }, ConsistencyFailureEvidenceIncomplete},
		{"signal health", func(i *ConsistencyInput) { i.Evidence.Signals[0].SourceHealthStatus = "incomplete" }, ConsistencyFailureEvidenceIncomplete},
		{"top output evidence", mutateOutput(func(o *analysisOutput) { o.EvidenceIDs = o.EvidenceIDs[:1] }), ConsistencyFailureEvidenceMembership},
		{"policy output evidence", mutateOutput(func(o *analysisOutput) { o.Policy.EvidenceIDs = o.Policy.EvidenceIDs[:1] }), ConsistencyFailureEvidenceMembership},
		{"candidate output evidence", mutateOutput(func(o *analysisOutput) { o.Candidate.EvidenceIDs = o.Candidate.EvidenceIDs[:1] }), ConsistencyFailureEvidenceMembership},
		{"policy target", mutateOutput(func(o *analysisOutput) { o.Policy.TargetIP = "203.0.113.21" }), ConsistencyFailurePolicy},
		{"policy ttl", mutateOutput(func(o *analysisOutput) { o.Policy.TTLSeconds = 60 }), ConsistencyFailurePolicy},
		{"rationale", mutateOutput(func(o *analysisOutput) { o.Policy.Rationale = "different" }), ConsistencyFailureRationale},
		{"candidate target", mutateOutput(func(o *analysisOutput) { o.Candidate.TargetIP = "203.0.113.21" }), ConsistencyFailureCandidate},
		{"candidate timeout", mutateOutput(func(o *analysisOutput) { o.Candidate.Timeout = "1800s" }), ConsistencyFailureCandidate},
		{"candidate command", mutateOutput(func(o *analysisOutput) { o.Candidate.Command += "\n" }), ConsistencyFailureCandidate},
		{"unknown output field", func(i *ConsistencyInput) {
			i.Analysis.Output = append(bytes.TrimSuffix(i.Analysis.Output, []byte("}")), []byte(`,"unexpected":true}`)...)
			refreshOutputDigest(i)
		}, ConsistencyFailureOutput},
		{"duplicate output field", func(i *ConsistencyInput) {
			i.Analysis.Output = bytes.Replace(i.Analysis.Output, []byte(`{"schema_version":`), []byte(`{"schema_version":"sentinelflow_analysis_v1","schema_version":`), 1)
			refreshOutputDigest(i)
		}, ConsistencyFailureOutput},
		{"trailing output", func(i *ConsistencyInput) {
			i.Analysis.Output = append(i.Analysis.Output, []byte(`{}`)...)
			refreshOutputDigest(i)
		}, ConsistencyFailureOutput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validConsistencyInput(t)
			test.mutate(&input)
			result := CheckConsistency(input)
			if result.Status != ConsistencyFailed || result.FailureCode != test.code {
				t.Fatalf("CheckConsistency() = %+v, want failure %s", result, test.code)
			}
		})
	}
}

func TestConsistencyGateRejectsPolicyEvidenceMismatchBeforeProtectedGate(t *testing.T) {
	t.Parallel()
	input := validConsistencyInput(t)
	input.Evidence.SignalIDs = []string{consistencyID(4), consistencyID(6)}
	input.Evidence.Signals[1].SignalID = consistencyID(6)
	result := CheckConsistency(input)
	if result.Status != ConsistencyFailed || result.FailureCode != ConsistencyFailureEvidenceMembership {
		t.Fatalf("mismatched evidence result = %+v", result)
	}
	protected := (&ProtectedGate{}).Check(ProtectedInput{TargetIPv4: input.Policy.Value().TargetIPv4, Consistency: result})
	if protected.Allowed() || protected.Reason != ReasonConsistencyNotPassed {
		t.Fatalf("protected gate accepted failed consistency: %+v", protected)
	}
}

func TestConsistencyRationaleUsesNFCBytes(t *testing.T) {
	t.Parallel()
	input := validConsistencyInput(t)
	var output analysisOutput
	if err := json.Unmarshal(input.Analysis.Output, &output); err != nil {
		t.Fatal(err)
	}
	if norm.NFC.IsNormalString(output.Policy.Rationale) {
		t.Fatal("fixture rationale must exercise NFC normalization")
	}
	if result := CheckConsistency(input); result.Status != ConsistencyPassed {
		t.Fatalf("NFC rationale was not consistently digested: %+v", result)
	}
}

func TestConsistencyInputsAreNotMutated(t *testing.T) {
	t.Parallel()
	input := validConsistencyInput(t)
	outputBefore := bytes.Clone(input.Analysis.Output)
	policyBefore := input.Policy.CanonicalBytes()
	candidateBefore := input.Candidate.GeneratedBytes()
	evidenceBefore := append([]string(nil), input.Evidence.EventIDs...)
	_ = CheckConsistency(input)
	if !bytes.Equal(outputBefore, input.Analysis.Output) || !bytes.Equal(policyBefore, input.Policy.CanonicalBytes()) ||
		!bytes.Equal(candidateBefore, input.Candidate.GeneratedBytes()) || !equalStringSlices(evidenceBefore, input.Evidence.EventIDs) {
		t.Fatal("consistency gate mutated immutable input")
	}
}

func FuzzDecodeAnalysisOutputStrict(f *testing.F) {
	input := validConsistencyInput(f)
	f.Add(input.Analysis.Output)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"sentinelflow_analysis_v1","schema_version":"duplicate"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeAnalysisOutput(data)
	})
}

type testingFataler interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
}

func validConsistencyInput(t testingFataler) ConsistencyInput {
	t.Helper()
	ids := []string{consistencyID(4), consistencyID(5)}
	const target = "203.0.113.20"
	const rationale = "Cafe\u0301"
	rationaleDigest := digestBytes([]byte(norm.NFC.String(rationale)))
	snapshotDigest := digestBytes([]byte("evidence snapshot"))
	analysisInputDigest := digestBytes([]byte("analysis input"))
	outputSchemaDigest := digestBytes([]byte("checked output schema"))

	fullPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion:          policy.PolicySchemaVersion,
		PolicyID:               consistencyID(1),
		PolicyVersion:          1,
		IncidentID:             consistencyID(2),
		AnalysisID:             consistencyID(3),
		Action:                 policy.ActionBlockIP,
		TargetIPv4:             target,
		TTLSeconds:             1800,
		EvidenceSnapshotDigest: snapshotDigest,
		EvidenceIDs:            append([]string(nil), ids...),
		RationaleDigest:        rationaleDigest,
		CreatedAt:              time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("check policy: %v", err)
	}
	command := "add element inet sentinelflow blacklist_ipv4 { " + target + " timeout 30m }"
	artifact, err := policy.BuildArtifact(policy.Policy{
		SchemaVersion: policy.PolicySchemaVersion,
		Action:        policy.ActionBlockIP,
		TargetIPv4:    target,
		TTLSeconds:    1800,
		EvidenceIDs:   append([]string(nil), ids...),
	}, policy.Candidate{
		SchemaVersion:  policy.CandidateSchemaVersion,
		TargetIPv4:     target,
		TimeoutToken:   "30m",
		EvidenceIDs:    append([]string(nil), ids...),
		GeneratedBytes: []byte(command),
	})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}

	var output analysisOutput
	output.SchemaVersion = AnalysisOutputSchemaV1
	output.IncidentSummary = "Synthetic bounded summary"
	output.Classification = "mixed"
	output.Confidence = 0.9
	output.Uncertainty = "Synthetic uncertainty"
	output.FalsePositiveFactors = []string{"Synthetic test"}
	output.EvidenceIDs = append([]string(nil), ids...)
	output.Policy.SchemaVersion = policy.PolicySchemaVersion
	output.Policy.Action = policy.ActionBlockIP
	output.Policy.TargetIP = target
	output.Policy.TTLSeconds = 1800
	output.Policy.EvidenceIDs = append([]string(nil), ids...)
	output.Policy.Rationale = rationale
	output.Candidate.SchemaVersion = policy.CandidateSchemaVersion
	output.Candidate.TargetIP = target
	output.Candidate.Timeout = "30m"
	output.Candidate.EvidenceIDs = append([]string(nil), ids...)
	output.Candidate.Command = command
	outputBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}

	return ConsistencyInput{
		ExpectedOutputSchemaDigest: outputSchemaDigest,
		SchemaGate: SchemaGateBinding{
			Status:               SchemaGatePassed,
			AnalysisOutputDigest: digestBytes(outputBytes),
			OutputSchemaDigest:   outputSchemaDigest,
		},
		Analysis: AnalysisBinding{
			AnalysisID:          consistencyID(3),
			IncidentID:          consistencyID(2),
			IncidentVersion:     1,
			AnalysisInputDigest: analysisInputDigest,
			OutputSchemaDigest:  outputSchemaDigest,
			Output:              outputBytes,
		},
		Policy:    fullPolicy,
		Candidate: artifact,
		Evidence: EvidenceSnapshotBinding{
			SnapshotDigest:      snapshotDigest,
			IncidentID:          consistencyID(2),
			IncidentVersion:     1,
			AnalysisInputDigest: analysisInputDigest,
			SourceIPv4:          target,
			SourceHealthDigest:  digestBytes([]byte("complete source health")),
			SourceHealthStatus:  SourceHealthComplete,
			SignalIDs:           append([]string(nil), ids...),
			EventIDs:            []string{consistencyID(10), consistencyID(11), consistencyID(12)},
			Signals: []SignalEvidenceBinding{
				{
					SignalID:            ids[0],
					SignalDigest:        digestBytes([]byte("signal 1")),
					SourceIPv4:          target,
					EventIDs:            []string{consistencyID(10), consistencyID(11)},
					ThresholdReproduced: true,
					SourceHealthStatus:  SourceHealthComplete,
				},
				{
					SignalID:            ids[1],
					SignalDigest:        digestBytes([]byte("signal 2")),
					SourceIPv4:          target,
					EventIDs:            []string{consistencyID(11), consistencyID(12)},
					ThresholdReproduced: true,
					SourceHealthStatus:  SourceHealthComplete,
				},
			},
		},
	}
}

func mutateOutput(mutate func(*analysisOutput)) func(*ConsistencyInput) {
	return func(input *ConsistencyInput) {
		var output analysisOutput
		if err := json.Unmarshal(input.Analysis.Output, &output); err != nil {
			panic(err)
		}
		mutate(&output)
		encoded, err := json.Marshal(output)
		if err != nil {
			panic(err)
		}
		input.Analysis.Output = encoded
		refreshOutputDigest(input)
	}
}

func refreshOutputDigest(input *ConsistencyInput) {
	input.SchemaGate.AnalysisOutputDigest = digestBytes(input.Analysis.Output)
}

func consistencyID(number int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012x", number)
}

func TestConsistencyFailureCodesContainNoArtifactData(t *testing.T) {
	t.Parallel()
	input := validConsistencyInput(t)
	input.Analysis.Output = []byte(`{"super-secret":"do not log"}`)
	refreshOutputDigest(&input)
	result := CheckConsistency(input)
	serialized := fmt.Sprintf("%+v", result)
	if strings.Contains(serialized, "super-secret") || strings.Contains(serialized, "do not log") {
		t.Fatalf("result leaked analysis content: %s", serialized)
	}
}
