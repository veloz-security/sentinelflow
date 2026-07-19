package policy

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestResponsePolicyGoldenJCSAndDigestInput(t *testing.T) {
	t.Parallel()
	checked, err := CheckResponsePolicy(validResponsePolicy())
	if err != nil {
		t.Fatalf("CheckResponsePolicy() error = %v", err)
	}
	want := `{"action":"block_ip","analysis_id":"00000000-0000-0000-0000-000000000003","created_at":"2026-07-18T02:00:00.123Z","evidence_ids":["00000000-0000-0000-0000-000000000004","00000000-0000-0000-0000-000000000005"],"evidence_snapshot_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","incident_id":"00000000-0000-0000-0000-000000000002","policy_id":"00000000-0000-0000-0000-000000000001","policy_version":1,"rationale_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","schema_version":"response-policy-v1","target_ipv4":"203.0.113.20","ttl_seconds":1800}`
	if string(checked.CanonicalBytes()) != want {
		t.Fatalf("canonical bytes = %s\nwant = %s", checked.CanonicalBytes(), want)
	}
	if !bytes.Equal(checked.DigestInput(), checked.CanonicalBytes()) {
		t.Fatal("versioned JCS digest input differs from canonical bytes")
	}
	if PolicyDigestDomain != "response-policy-v1" {
		t.Fatalf("digest domain = %q", PolicyDigestDomain)
	}
	const wantDigest = "sha256:904e809a524d1431c57dcbf4108194040272d07b5f6f0e186a6213ce4fe35286"
	if checked.Digest() != wantDigest {
		t.Fatalf("digest = %s, want %s", checked.Digest(), wantDigest)
	}

	parsed, err := ParseCanonicalResponsePolicy([]byte(want))
	if err != nil {
		t.Fatalf("ParseCanonicalResponsePolicy() error = %v", err)
	}
	if parsed.Digest() != checked.Digest() || !bytes.Equal(parsed.CanonicalBytes(), checked.CanonicalBytes()) {
		t.Fatal("canonical parse changed bytes or digest")
	}
}

func TestSemanticallyEqualTypedPoliciesHaveIdenticalBytes(t *testing.T) {
	t.Parallel()
	first := validResponsePolicy()
	second := validResponsePolicy()
	second.CreatedAt = first.CreatedAt.In(time.FixedZone("UTC alias", 0))
	second.EvidenceIDs = append([]string(nil), first.EvidenceIDs...)

	left, err := CheckResponsePolicy(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CheckResponsePolicy(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left.CanonicalBytes(), right.CanonicalBytes()) || left.Digest() != right.Digest() {
		t.Fatal("semantically equal typed policies did not converge")
	}
}

func TestResponsePolicyRejectsInvalidTypedFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ResponsePolicy)
		code   PolicyErrorCode
	}{
		{"schema", func(p *ResponsePolicy) { p.SchemaVersion = "response-policy-v2" }, PolicyErrorSchema},
		{"policy id", func(p *ResponsePolicy) { p.PolicyID = "not-a-uuid" }, PolicyErrorID},
		{"zero version", func(p *ResponsePolicy) { p.PolicyVersion = 0 }, PolicyErrorVersion},
		{"large version", func(p *ResponsePolicy) { p.PolicyVersion = math.MaxInt32 + 1 }, PolicyErrorVersion},
		{"incident", func(p *ResponsePolicy) { p.IncidentID = "not-a-uuid" }, PolicyErrorIncident},
		{"analysis", func(p *ResponsePolicy) { p.AnalysisID = "not-a-uuid" }, PolicyErrorAnalysis},
		{"action", func(p *ResponsePolicy) { p.Action = "allow_ip" }, PolicyErrorAction},
		{"ipv6", func(p *ResponsePolicy) { p.TargetIPv4 = "2001:db8::1" }, PolicyErrorTarget},
		{"noncanonical ipv4", func(p *ResponsePolicy) { p.TargetIPv4 = "203.0.113.020" }, PolicyErrorTarget},
		{"ttl low", func(p *ResponsePolicy) { p.TTLSeconds = 59 }, PolicyErrorTTL},
		{"ttl high", func(p *ResponsePolicy) { p.TTLSeconds = 86401 }, PolicyErrorTTL},
		{"snapshot digest", func(p *ResponsePolicy) { p.EvidenceSnapshotDigest = "SHA256:" + strings.Repeat("1", 64) }, PolicyErrorDigest},
		{"reason digest", func(p *ResponsePolicy) { p.RationaleDigest = "sha256:abc" }, PolicyErrorDigest},
		{"missing evidence", func(p *ResponsePolicy) { p.EvidenceIDs = nil }, PolicyErrorEvidence},
		{"duplicate evidence", func(p *ResponsePolicy) { p.EvidenceIDs[1] = p.EvidenceIDs[0] }, PolicyErrorEvidence},
		{"unordered evidence", func(p *ResponsePolicy) { p.EvidenceIDs[0], p.EvidenceIDs[1] = p.EvidenceIDs[1], p.EvidenceIDs[0] }, PolicyErrorEvidence},
		{"zero creation", func(p *ResponsePolicy) { p.CreatedAt = time.Time{} }, PolicyErrorCreatedAt},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validResponsePolicy()
			test.mutate(&value)
			_, err := CheckResponsePolicy(value)
			assertPolicyError(t, err, test.code)
		})
	}
}

func TestCanonicalPolicyParserRejectsRepairAndAmbiguity(t *testing.T) {
	t.Parallel()
	checked, err := CheckResponsePolicy(validResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(checked.CanonicalBytes())
	tests := []struct {
		name  string
		input string
		code  PolicyErrorCode
	}{
		{"leading whitespace", " " + canonical, PolicyErrorCanonical},
		{"trailing newline", canonical + "\n", PolicyErrorCanonical},
		{"duplicate field", strings.Replace(canonical, `{"action":`, `{"action":"block_ip","action":`, 1), PolicyErrorEncoding},
		{"unknown field", strings.TrimSuffix(canonical, "}") + `,"unexpected":true}`, PolicyErrorEncoding},
		{"noncanonical timestamp", strings.Replace(canonical, "02:00:00.123Z", "02:00:00.123+00:00", 1), PolicyErrorCanonical},
		{"uppercase digest", strings.Replace(canonical, "sha256:1111", "sha256:AAAA", 1), PolicyErrorDigest},
		{"noncanonical number", strings.Replace(canonical, `"policy_version":1`, `"policy_version":1.0`, 1), PolicyErrorEncoding},
		{"second value", canonical + `{}`, PolicyErrorEncoding},
		{"array", `[]`, PolicyErrorEncoding},
		{"empty", "", PolicyErrorEncoding},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseCanonicalResponsePolicy([]byte(test.input))
			assertPolicyError(t, err, test.code)
		})
	}
	if _, err := ParseCanonicalResponsePolicy(bytes.Repeat([]byte{'x'}, MaxPolicyBytes+1)); err == nil {
		t.Fatal("oversized policy was accepted")
	}
}

func TestCheckedResponsePolicyDefensiveCopies(t *testing.T) {
	t.Parallel()
	value := validResponsePolicy()
	checked, err := CheckResponsePolicy(value)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := checked.Digest()
	value.EvidenceIDs[0] = testEvidenceID(99)
	copyBytes := checked.CanonicalBytes()
	copyBytes[0] = '['
	copyInput := checked.DigestInput()
	copyInput[0] = '['
	copyValue := checked.Value()
	copyValue.EvidenceIDs[0] = testEvidenceID(98)
	if checked.Digest() != originalDigest || checked.Value().EvidenceIDs[0] != testEvidenceID(4) || checked.CanonicalBytes()[0] != '{' || checked.DigestInput()[0] != '{' {
		t.Fatal("checked policy retained mutable caller-owned state")
	}
}

func TestPolicyRevisionMustAdvanceVersionAndDigest(t *testing.T) {
	t.Parallel()
	previous, err := CheckResponsePolicy(validResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	nextValue := previous.Value()
	nextValue.PolicyVersion++
	nextValue.TTLSeconds = 3600
	nextValue.CreatedAt = nextValue.CreatedAt.Add(time.Second)
	next, err := ReviseResponsePolicy(previous, nextValue)
	if err != nil {
		t.Fatalf("ReviseResponsePolicy() error = %v", err)
	}
	if next.Value().PolicyVersion != 2 || next.Digest() == previous.Digest() || bytes.Equal(next.CanonicalBytes(), previous.CanonicalBytes()) {
		t.Fatal("revision did not advance immutable version and digest")
	}

	invalid := nextValue
	invalid.PolicyVersion = 1
	_, err = ReviseResponsePolicy(previous, invalid)
	assertPolicyError(t, err, PolicyErrorRevision)
	invalid = nextValue
	invalid.PolicyID = testEvidenceID(9)
	_, err = ReviseResponsePolicy(previous, invalid)
	assertPolicyError(t, err, PolicyErrorRevision)
	invalid = nextValue
	invalid.CreatedAt = previous.Value().CreatedAt
	_, err = ReviseResponsePolicy(previous, invalid)
	assertPolicyError(t, err, PolicyErrorRevision)
}

func TestPolicyLifecycleAllowedTransitionsAndCAS(t *testing.T) {
	t.Parallel()
	checked, err := CheckResponsePolicy(validResponsePolicy())
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewPolicyLifecycle(checked)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.State() != PolicyStateDraft || lifecycle.StateRevision() != 1 || lifecycle.PolicyVersion() != 1 {
		t.Fatalf("new lifecycle = %+v", lifecycle)
	}

	idempotent, err := lifecycle.Transition(1, PolicyStateDraft)
	if err != nil || idempotent.StateRevision() != 1 {
		t.Fatalf("idempotent transition = %+v, %v", idempotent, err)
	}
	if _, err := lifecycle.Transition(2, PolicyStateValidating); err == nil {
		t.Fatal("stale optimistic revision was accepted")
	} else {
		assertPolicyError(t, err, PolicyErrorStateRevision)
	}

	flow := []PolicyState{
		PolicyStateValidating,
		PolicyStateValid,
		PolicyStateApproved,
		PolicyStateQueued,
		PolicyStateActive,
		PolicyStateExpired,
	}
	current := lifecycle
	for _, next := range flow {
		current, err = current.Transition(current.StateRevision(), next)
		if err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if current.State() != PolicyStateExpired || current.StateRevision() != uint64(len(flow)+1) {
		t.Fatalf("final lifecycle = %+v", current)
	}
	if _, err := current.Transition(current.StateRevision(), PolicyStateApproved); err == nil {
		t.Fatal("terminal state transitioned back to approved")
	} else {
		assertPolicyError(t, err, PolicyErrorTransition)
	}
}

func TestPolicyLifecycleSafetyTransitions(t *testing.T) {
	t.Parallel()
	allowed := [][2]PolicyState{
		{PolicyStateDraft, PolicyStateValidating},
		{PolicyStateDraft, PolicyStateStale},
		{PolicyStateValidating, PolicyStateValid},
		{PolicyStateValidating, PolicyStateInvalid},
		{PolicyStateValidating, PolicyStateStale},
		{PolicyStateValid, PolicyStateApproved},
		{PolicyStateValid, PolicyStateRejected},
		{PolicyStateValid, PolicyStateStale},
		{PolicyStateApproved, PolicyStateQueued},
		{PolicyStateApproved, PolicyStateStale},
		{PolicyStateQueued, PolicyStateActive},
		{PolicyStateQueued, PolicyStateFailed},
		{PolicyStateQueued, PolicyStateIndeterminate},
		{PolicyStateQueued, PolicyStateStale},
		{PolicyStateActive, PolicyStateExpired},
		{PolicyStateActive, PolicyStateFailed},
		{PolicyStateActive, PolicyStateRevoked},
		{PolicyStateActive, PolicyStateIndeterminate},
		{PolicyStateIndeterminate, PolicyStateActive},
		{PolicyStateIndeterminate, PolicyStateExpired},
		{PolicyStateIndeterminate, PolicyStateFailed},
		{PolicyStateIndeterminate, PolicyStateRevoked},
	}
	for _, pair := range allowed {
		if !CanTransitionPolicy(pair[0], pair[1]) {
			t.Errorf("expected %s -> %s to be allowed", pair[0], pair[1])
		}
		lifecycle, err := RestorePolicyLifecycle(testEvidenceID(1), 1, pair[0], 9)
		if err != nil {
			t.Fatal(err)
		}
		next, err := lifecycle.Transition(9, pair[1])
		if err != nil || next.StateRevision() != 10 {
			t.Errorf("transition %s -> %s = %+v, %v", pair[0], pair[1], next, err)
		}
	}

	for _, state := range []PolicyState{PolicyStateInvalid, PolicyStateStale, PolicyStateRejected, PolicyStateExpired, PolicyStateFailed, PolicyStateRevoked} {
		if CanTransitionPolicy(state, PolicyStateApproved) {
			t.Errorf("unsafe %s -> approved transition is allowed", state)
		}
	}
	for _, state := range []PolicyState{PolicyStateDraft, PolicyStateValidating, PolicyStateInvalid, PolicyStateStale, PolicyStateRejected, PolicyStateQueued, PolicyStateActive, PolicyStateExpired, PolicyStateFailed, PolicyStateRevoked, PolicyStateIndeterminate} {
		if state != PolicyStateValid && CanTransitionPolicy(state, PolicyStateApproved) {
			t.Errorf("%s can bypass validation into approved", state)
		}
	}
}

func TestRestorePolicyLifecycleRejectsInvalidState(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		id       string
		version  uint32
		state    PolicyState
		revision uint64
	}{
		{"bad", 1, PolicyStateDraft, 1},
		{testEvidenceID(1), 0, PolicyStateDraft, 1},
		{testEvidenceID(1), 1, "unknown", 1},
		{testEvidenceID(1), 1, PolicyStateDraft, 0},
	} {
		if _, err := RestorePolicyLifecycle(test.id, test.version, test.state, test.revision); err == nil {
			t.Fatalf("invalid lifecycle accepted: %+v", test)
		}
	}
	overflow, err := RestorePolicyLifecycle(testEvidenceID(1), 1, PolicyStateDraft, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	_, err = overflow.Transition(math.MaxUint64, PolicyStateValidating)
	assertPolicyError(t, err, PolicyErrorTransition)
}

func TestPolicyErrorsDoNotEchoInput(t *testing.T) {
	t.Parallel()
	secretShaped := []byte(`{"schema_version":"response-policy-v1","unexpected":"super-secret"}`)
	_, err := ParseCanonicalResponsePolicy(secretShaped)
	if err == nil || strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), string(secretShaped)) {
		t.Fatalf("unsafe policy error = %v", err)
	}
}

func FuzzCanonicalResponsePolicyParser(f *testing.F) {
	checked, err := CheckResponsePolicy(validResponsePolicy())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(checked.CanonicalBytes())
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schema_version":"response-policy-v1"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseCanonicalResponsePolicy(data)
		if err != nil {
			return
		}
		if !bytes.Equal(data, parsed.CanonicalBytes()) || parsed.Digest() != Digest(data) {
			t.Fatal("accepted policy did not round-trip byte exactly")
		}
	})
}

func validResponsePolicy() ResponsePolicy {
	return ResponsePolicy{
		SchemaVersion:          PolicySchemaVersion,
		PolicyID:               testEvidenceID(1),
		PolicyVersion:          1,
		IncidentID:             testEvidenceID(2),
		AnalysisID:             testEvidenceID(3),
		Action:                 ActionBlockIP,
		TargetIPv4:             "203.0.113.20",
		TTLSeconds:             1800,
		EvidenceSnapshotDigest: "sha256:" + strings.Repeat("1", 64),
		EvidenceIDs:            []string{testEvidenceID(4), testEvidenceID(5)},
		RationaleDigest:        "sha256:" + strings.Repeat("2", 64),
		CreatedAt:              time.Date(2026, 7, 18, 2, 0, 0, 123_000_000, time.UTC),
	}
}

func assertPolicyError(t *testing.T, err error, code PolicyErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var typed *PolicyError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}
