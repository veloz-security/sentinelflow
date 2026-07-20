package capability

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAppliedResult(capability VerifiedCapability) Result {
	start := capability.Value().NotBefore.Add(time.Second)
	exit := NFTExitSuccess
	return Result{
		ResultID: "019b0000-0000-7000-8000-000000000310", CapabilityID: capability.Value().CapabilityID,
		CapabilityDigest: capability.Digest(), Operation: OperationAdd, ActionID: capability.Value().ActionID,
		ArtifactDigest: capability.Value().ArtifactDigest, TargetIPv4: capability.Value().TargetIPv4,
		Classification: ClassificationApplied, NFTExitClass: &exit, ReadbackState: ReadbackActive,
		ElementHandle: nil, RemainingTTLSeconds: ptr(uint64(1799)),
		OwnedSchemaDigest: capability.Value().OwnedSchemaDigest, StartedAt: start,
		CompletedAt: start.Add(50 * time.Millisecond), JournalSequence: 2, ErrorCode: ResultErrorNone,
	}
}

func TestGoldenResultsVerifyAndBind(t *testing.T) {
	bundle := loadGolden(t)
	capPrivate := keyFromSeed(t, dispatchSeedHex)
	capVerifier, _ := NewCapabilityVerifier("dispatcher-vector-v1", "executor-demo", capPrivate.Public().(ed25519.PublicKey))
	addArtifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")
	revokeArtifact := []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n")
	inspectArtifact := marshalInspection(InspectArtifact{SchemaVersion: InspectSchemaVersion, ActionID: "019b0000-0000-7000-8000-000000000200", TargetIPv4: "203.0.113.20", OriginalAddDigest: digestBytes(addArtifact), OwnedSchemaDigest: "sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997", Purpose: "reconciliation"})
	capabilityInputs := []struct {
		vector   goldenVector
		artifact []byte
		results  []goldenVector
	}{
		{bundle.Vectors.CapabilityAdd, addArtifact, []goldenVector{bundle.Vectors.ResultApplied, bundle.Vectors.ResultRecovered}},
		{bundle.Vectors.CapabilityRevoke, revokeArtifact, []goldenVector{bundle.Vectors.ResultRevoked}},
		{bundle.Vectors.CapabilityInspect, inspectArtifact, []goldenVector{bundle.Vectors.ResultInspect}},
	}
	resultPrivate := keyFromSeed(t, resultSeedHex)
	resultVerifier, _ := NewResultVerifier("executor-result-vector-v1", "executor-demo", resultPrivate.Public().(ed25519.PublicKey))
	for _, input := range capabilityInputs {
		capability, err := capVerifier.Verify(NewUntrustedSignedCapability("dispatcher-vector-v1", decodeURL(t, input.vector.JCSB64URL), decodeURL(t, input.vector.SignatureB64URL), input.artifact))
		if err != nil {
			t.Fatal(err)
		}
		for _, vector := range input.results {
			verified, err := resultVerifier.Verify(NewUntrustedSignedResult("executor-result-vector-v1", "executor-demo", decodeURL(t, vector.JCSB64URL), decodeURL(t, vector.SignatureB64URL)))
			if err != nil {
				t.Fatal(err)
			}
			if verified.Digest() != vector.Digest {
				t.Fatalf("digest mismatch: got %s want %s", verified.Digest(), vector.Digest)
			}
			if _, err := verified.BindTo(capability); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestResultSigningBindingAndCopies(t *testing.T) {
	capability := testVerifiedAdd(t)
	checked, err := CheckResult(testAppliedResult(capability))
	if err != nil {
		t.Fatal(err)
	}
	if checked.Value().Classification != ClassificationApplied || checked.Digest() == "" {
		t.Fatal("checked result getters lost state")
	}
	private := keyFromSeed(t, resultSeedHex)
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", private)
	signed, err := signer.SignFor(capability, checked)
	if err != nil {
		t.Fatal(err)
	}
	canonical := signed.CanonicalBytes()
	signature := signed.Signature()
	canonical[0] = 'X'
	signature[0] ^= 1
	if signed.CanonicalBytes()[0] != '{' || bytes.Equal(signature, signed.Signature()) {
		t.Fatal("signed result aliases getter memory")
	}
	if signed.KeyID() != "executor-result-v1" || signed.ExecutorID() != "executor-demo" {
		t.Fatal("signed result key identity lost")
	}
	verifier, _ := NewResultVerifier("executor-result-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	verified, err := verifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := verified.BindTo(capability)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Value().Classification != ClassificationApplied || len(verified.CanonicalBytes()) == 0 ||
		verified.Digest() == "" || verified.KeyID() == "" || verified.ExecutorID() != "executor-demo" ||
		bound.Result().Digest() != verified.Digest() || bound.Capability().Digest() != capability.Digest() {
		t.Fatal("verified/bound result getters lost state")
	}

	mutated := testAppliedResult(capability)
	mutated.ArtifactDigest = testDigest("different")
	bad, err := CheckResult(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignFor(capability, bad); err == nil {
		t.Fatal("executor signed a result for different artifact")
	}
}

func TestResultVerifierRejectsOversizedCanonicalBytes(t *testing.T) {
	private := keyFromSeed(t, resultSeedHex)
	verifier, err := NewResultVerifier("executor-result-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	signed := NewUntrustedSignedResult(
		"executor-result-v1",
		"executor-demo",
		bytes.Repeat([]byte("x"), MaxResultBytes+1),
		make([]byte, ed25519.SignatureSize),
	)
	if _, err := verifier.Verify(signed); err == nil {
		t.Fatal("oversized canonical result accepted")
	}
}

func TestV2ResultBindsReadbackBracketAndUsesSeparateSignatureDomain(t *testing.T) {
	verifiedCapability := testVerifiedAdd(t)
	value := testAppliedResult(verifiedCapability)
	value.SchemaVersion = ResultV2SchemaVersion
	readbackStarted := value.StartedAt.Add(10 * time.Millisecond)
	readbackCompleted := readbackStarted.Add(20 * time.Millisecond)
	value.ReadbackStartedAt = &readbackStarted
	value.ReadbackCompletedAt = &readbackCompleted
	checked, err := CheckResult(value)
	if err != nil {
		t.Fatal(err)
	}
	private := keyFromSeed(t, resultSeedHex)
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", private)
	signed, err := signer.SignFor(verifiedCapability, checked)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewResultVerifier("executor-result-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	if _, err := verifier.Verify(signed); err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(private.Public().(ed25519.PublicKey), signingInput(ResultSigningDomain, signed.CanonicalBytes()), signed.Signature()) {
		t.Fatal("v2 signature verified under the v1 domain")
	}

	for _, mutate := range []func(*Result){
		func(result *Result) { result.ReadbackStartedAt = nil },
		func(result *Result) { result.ReadbackCompletedAt = nil },
		func(result *Result) {
			late := result.CompletedAt.Add(time.Millisecond)
			result.ReadbackCompletedAt = &late
		},
		func(result *Result) {
			early := result.StartedAt.Add(-time.Millisecond)
			result.ReadbackStartedAt = &early
		},
	} {
		invalid := cloneResultValue(value)
		mutate(&invalid)
		if _, err := CheckResult(invalid); err == nil {
			t.Fatal("invalid v2 readback bracket accepted")
		}
	}
}

func TestResultBindingUsesActualPostExpiryRecoveryTime(t *testing.T) {
	verifiedCapability := testVerifiedAdd(t)
	late := verifiedCapability.Value().ExpiresAt.Add(time.Hour)
	notInvoked := NFTExitNotInvoked
	result := testAppliedResult(verifiedCapability)
	result.StartedAt = late
	result.CompletedAt = late.Add(time.Millisecond)
	result.Classification = ClassificationRecoveredActive
	result.NFTExitClass = &notInvoked
	checked, err := CheckResult(result)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", keyFromSeed(t, resultSeedHex))
	if _, err := signer.SignFor(verifiedCapability, checked); err != nil {
		t.Fatalf("actual post-expiry recovery observation rejected: %v", err)
	}

	tooEarly := result
	tooEarly.StartedAt = verifiedCapability.Value().NotBefore.Add(-time.Millisecond)
	tooEarly.CompletedAt = tooEarly.StartedAt.Add(time.Millisecond)
	checked, err = CheckResult(tooEarly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignFor(verifiedCapability, checked); err == nil {
		t.Fatal("pre-authority result observation accepted")
	}
}

func TestAllValidResultOutcomeShapes(t *testing.T) {
	capability := testVerifiedAdd(t)
	base := testAppliedResult(capability)
	notInvoked := NFTExitNotInvoked
	nonzero := NFTExitNonzero
	timeout := NFTExitTimeout
	signaled := NFTExitSignaled
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{"recovered", func(r *Result) { r.Classification = ClassificationRecoveredActive; r.NFTExitClass = &notInvoked }},
		{"revoke", func(r *Result) {
			r.Operation = OperationRevoke
			r.Classification = ClassificationRevoked
			r.ReadbackState = ReadbackAbsent
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
		}},
		{"inspect active", func(r *Result) { r.Operation = OperationInspect; r.Classification = ClassificationInspectActive }},
		{"inspect absent", func(r *Result) {
			r.Operation = OperationInspect
			r.Classification = ClassificationInspectAbsent
			r.ReadbackState = ReadbackAbsent
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
		}},
		{"inspect mismatch", func(r *Result) {
			r.Operation = OperationInspect
			r.Classification = ClassificationInspectMismatch
			r.ReadbackState = ReadbackMismatch
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
		}},
		{"failed nonzero", func(r *Result) {
			r.Classification = ClassificationFailed
			r.NFTExitClass = &nonzero
			r.ReadbackState = ReadbackUnavailable
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
			r.ErrorCode = ResultErrorNFTFailed
		}},
		{"failed timeout", func(r *Result) {
			r.Classification = ClassificationFailed
			r.NFTExitClass = &timeout
			r.ReadbackState = ReadbackUnavailable
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
			r.ErrorCode = ResultErrorDeadlineExceeded
		}},
		{"failed signaled", func(r *Result) {
			r.Classification = ClassificationFailed
			r.NFTExitClass = &signaled
			r.ReadbackState = ReadbackUnavailable
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
			r.ErrorCode = ResultErrorNFTFailed
		}},
		{"indeterminate", func(r *Result) {
			r.Classification = ClassificationIndeterminate
			r.NFTExitClass = nil
			r.ReadbackState = ReadbackUnavailable
			r.ElementHandle = nil
			r.RemainingTTLSeconds = nil
			r.ErrorCode = ResultErrorIndeterminate
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneResultValue(base)
			test.mutate(&value)
			if _, err := CheckResult(value); err != nil {
				t.Fatalf("valid outcome rejected: %v", err)
			}
		})
	}
}

func TestResultOutcomeAndBindingMutations(t *testing.T) {
	capability := testVerifiedAdd(t)
	base := testAppliedResult(capability)
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{"cross operation", func(r *Result) { r.Operation = OperationRevoke }},
		{"wrong readback", func(r *Result) { r.ReadbackState = ReadbackAbsent }},
		{"set handle substituted for unavailable element handle", func(r *Result) { r.ElementHandle = ptr(uint64(42)) }},
		{"zero active ttl", func(r *Result) { r.RemainingTTLSeconds = ptr(uint64(0)) }},
		{"ttl overflow", func(r *Result) { r.RemainingTTLSeconds = ptr(uint64(86401)) }},
		{"success with error", func(r *Result) { r.ErrorCode = ResultErrorNFTFailed }},
		{"long execution", func(r *Result) { r.CompletedAt = r.StartedAt.Add(2*time.Second + time.Nanosecond) }},
		{"zero sequence", func(r *Result) { r.JournalSequence = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneResultValue(base)
			test.mutate(&value)
			if _, err := CheckResult(value); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}

	value := testAppliedResult(capability)
	value.RemainingTTLSeconds = ptr(uint64(1801))
	checked, err := CheckResult(value)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", keyFromSeed(t, resultSeedHex))
	if _, err := signer.SignFor(capability, checked); err == nil {
		t.Fatal("result TTL exceeding authorized add TTL accepted")
	}
}

func TestResultStrictEncodingAndKeyRole(t *testing.T) {
	capability := testVerifiedAdd(t)
	checked, _ := CheckResult(testAppliedResult(capability))
	private := keyFromSeed(t, resultSeedHex)
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", private)
	signed, _ := signer.SignFor(capability, checked)
	for _, malformed := range [][]byte{
		append(checked.CanonicalBytes(), '\n'),
		append([]byte{' '}, checked.CanonicalBytes()...),
		append(checked.CanonicalBytes()[:len(checked.CanonicalBytes())-1], []byte(`,"x":1}`)...),
	} {
		if _, err := ParseCanonicalResult(malformed); err == nil {
			t.Fatal("malformed result accepted")
		}
	}
	canonicalText := string(checked.CanonicalBytes())
	for _, variant := range []string{
		strings.Replace(canonicalText, ".000Z", "Z", 1),
		strings.Replace(canonicalText, ".000Z", ".0Z", 1),
		strings.Replace(canonicalText, ".000Z", ".0000Z", 1),
		strings.Replace(canonicalText, ".000Z", ".000+00:00", 1),
		strings.Replace(canonicalText, ".000Z", ".000001Z", 1),
	} {
		if _, err := ParseCanonicalResult([]byte(variant)); err == nil {
			t.Fatal("alternate result timestamp accepted")
		}
	}
	wrongID, _ := NewResultVerifier("other", "executor-demo", private.Public().(ed25519.PublicKey))
	if _, err := wrongID.Verify(signed); err == nil {
		t.Fatal("wrong result key ID accepted")
	}
	wrongExecutor, _ := NewResultVerifier("executor-result-v1", "executor-other", private.Public().(ed25519.PublicKey))
	if _, err := wrongExecutor.Verify(signed); err == nil {
		t.Fatal("wrong executor identity accepted")
	}
}

func TestInvalidResultKeyConstructors(t *testing.T) {
	private := keyFromSeed(t, resultSeedHex)
	public := private.Public().(ed25519.PublicKey)
	if _, err := NewResultSigner("Bad", "executor", private); err == nil {
		t.Fatal("invalid result signer ID accepted")
	}
	if _, err := NewResultSigner("valid", "executor", private[:2]); err == nil {
		t.Fatal("short result private key accepted")
	}
	if _, err := NewResultVerifier("valid", "Bad", public); err == nil {
		t.Fatal("invalid result executor identity accepted")
	}
	if _, err := NewResultVerifier("valid", "executor", public[:2]); err == nil {
		t.Fatal("short result public key accepted")
	}
}

func TestConcurrentResultVerification(t *testing.T) {
	capability := testVerifiedAdd(t)
	checked, _ := CheckResult(testAppliedResult(capability))
	private := keyFromSeed(t, resultSeedHex)
	signer, _ := NewResultSigner("executor-result-v1", "executor-demo", private)
	signed, _ := signer.SignFor(capability, checked)
	verifier, _ := NewResultVerifier("executor-result-v1", "executor-demo", private.Public().(ed25519.PublicKey))

	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			verified, err := verifier.Verify(signed)
			if err == nil {
				_, err = verified.BindTo(capability)
			}
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}
