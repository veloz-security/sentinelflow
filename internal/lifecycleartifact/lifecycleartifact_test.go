package lifecycleartifact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	vectorActionID          = "019b0000-0000-7000-8000-000000000200"
	vectorPolicyID          = "019b0000-0000-7000-8000-000000000201"
	vectorAuthorizationID   = "019b0000-0000-7000-8000-000000000232"
	vectorTargetIPv4        = "203.0.113.20"
	vectorOriginalAddDigest = "sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6"
	vectorOriginalAuth      = "sha256:03f97cab15bf5a71ea86a486e46e9d5198aa72566bdff5bc1ff495abd544ae94"
	vectorEvidenceDigest    = "sha256:ea1271f46a383bd32b27e66c5d1b06fda9a5c4cf2fe7dbe81a02c1ba15af3acc"
	vectorValidationDigest  = "sha256:eac360a5f975cd8730522b3b5846b14899dfdbfa0e7e607fab7eb3b8983c07f8"
	vectorOwnedDigest       = "sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997"
	vectorIdempotencyDigest = "sha256:954e6c6e6a1cc8cfac44084f6f2068828304cb08964203e13dace53e4bca7335"
	vectorInspectDigest     = "sha256:e3665d79f4f821a3410cb62004224b2882a7a559e1f0ce5b2943a850e61d741f"
	vectorAuthorizationHash = "sha256:75099ce4451094f49e99fc1ebe0c1b1468195e0c17334370fda0f1663b75c999"
	vectorRevokeDigest      = "sha256:85847c58f49d2e055c5547554fb78b1bfe370c826393cf705a3456d7ca2d1cd4"

	vectorInspectJCS       = `{"action_id":"019b0000-0000-7000-8000-000000000200","operation":"inspect","original_add_digest":"sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6","owned_schema_digest":"sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997","purpose":"reconciliation","schema_version":"nft-inspect-v1","target_ipv4":"203.0.113.20"}`
	vectorAuthorizationJCS = `{"action_id":"019b0000-0000-7000-8000-000000000200","artifact_digest":"sha256:e3665d79f4f821a3410cb62004224b2882a7a559e1f0ce5b2943a850e61d741f","authorization_id":"019b0000-0000-7000-8000-000000000232","evidence_snapshot_digest":"sha256:ea1271f46a383bd32b27e66c5d1b06fda9a5c4cf2fe7dbe81a02c1ba15af3acc","idempotency_key_digest":"sha256:954e6c6e6a1cc8cfac44084f6f2068828304cb08964203e13dace53e4bca7335","original_add_digest":"sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6","original_authorization_digest":"sha256:03f97cab15bf5a71ea86a486e46e9d5198aa72566bdff5bc1ff495abd544ae94","owned_schema_digest":"sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997","policy_id":"019b0000-0000-7000-8000-000000000201","policy_version":1,"purpose":"reconciliation","requested_at":"2026-07-18T02:20:00.000Z","scheduler_id":"reconciler","schema_version":"inspection-authorization-v1","target_ipv4":"203.0.113.20","valid_until":"2026-07-18T02:21:00.000Z","validation_snapshot_digest":"sha256:eac360a5f975cd8730522b3b5846b14899dfdbfa0e7e607fab7eb3b8983c07f8"}`
	vectorRevokeArtifact   = "delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"
)

var vectorRequestedAt = time.Date(2026, 7, 18, 2, 20, 0, 0, time.UTC)

func validInspectInput() InspectInput {
	return InspectInput{
		ActionID: vectorActionID, TargetIPv4: vectorTargetIPv4,
		OriginalAddDigest: vectorOriginalAddDigest, OwnedSchemaDigest: vectorOwnedDigest,
		Purpose: PurposeReconciliation,
	}
}

func checkedVectorInspect(t testing.TB) CheckedInspectArtifact {
	t.Helper()
	checked, err := CheckInspectArtifact(validInspectInput())
	if err != nil {
		t.Fatalf("check vector inspect: %v", err)
	}
	return checked
}

func validAuthorizationInput(inspect CheckedInspectArtifact) InspectionAuthorizationInput {
	return InspectionAuthorizationInput{
		AuthorizationID: vectorAuthorizationID, PolicyID: vectorPolicyID, PolicyVersion: 1,
		OriginalAuthorizationDigest: vectorOriginalAuth,
		EvidenceSnapshotDigest:      vectorEvidenceDigest,
		ValidationSnapshotDigest:    vectorValidationDigest,
		SchedulerID:                 "reconciler",
		RequestedAt:                 vectorRequestedAt,
		ValidUntil:                  vectorRequestedAt.Add(time.Minute),
		IdempotencyKeyDigest:        vectorIdempotencyDigest,
		Inspect:                     inspect,
	}
}

func checkedVectorAuthorization(t testing.TB, inspect CheckedInspectArtifact) CheckedInspectionAuthorization {
	t.Helper()
	checked, err := CheckInspectionAuthorization(validAuthorizationInput(inspect))
	if err != nil {
		t.Fatalf("check vector authorization: %v", err)
	}
	return checked
}

func TestFrozenGoldenVectors(t *testing.T) {
	inspect := checkedVectorInspect(t)
	if got := string(inspect.CanonicalBytes()); got != vectorInspectJCS {
		t.Fatalf("inspect JCS drift:\n got %s\nwant %s", got, vectorInspectJCS)
	}
	if inspect.Digest() != vectorInspectDigest {
		t.Fatalf("inspect digest = %s", inspect.Digest())
	}
	parsedInspect, err := ParseCanonicalInspectArtifact([]byte(vectorInspectJCS))
	if err != nil || parsedInspect.Value() != inspect.Value() || parsedInspect.Digest() != inspect.Digest() {
		t.Fatalf("inspect roundtrip: value=%+v err=%v", parsedInspect.Value(), err)
	}

	authorization := checkedVectorAuthorization(t, inspect)
	if got := string(authorization.CanonicalBytes()); got != vectorAuthorizationJCS {
		t.Fatalf("authorization JCS drift:\n got %s\nwant %s", got, vectorAuthorizationJCS)
	}
	if authorization.Digest() != vectorAuthorizationHash {
		t.Fatalf("authorization digest = %s", authorization.Digest())
	}
	parsedAuthorization, err := ParseCanonicalInspectionAuthorization([]byte(vectorAuthorizationJCS), inspect)
	if err != nil || parsedAuthorization.Value() != authorization.Value() ||
		parsedAuthorization.Digest() != authorization.Digest() {
		t.Fatalf("authorization roundtrip: value=%+v err=%v", parsedAuthorization.Value(), err)
	}
	if parsedAuthorization.InspectArtifact().Digest() != inspect.Digest() {
		t.Fatal("authorization lost inspect binding")
	}

	revoke, err := CheckRevokeArtifact(vectorTargetIPv4)
	if err != nil || string(revoke.CanonicalBytes()) != vectorRevokeArtifact || revoke.Digest() != vectorRevokeDigest {
		t.Fatalf("revoke vector: bytes=%q digest=%s err=%v", revoke.CanonicalBytes(), revoke.Digest(), err)
	}
	parsedRevoke, err := ParseCanonicalRevokeArtifact([]byte(vectorRevokeArtifact))
	if err != nil || parsedRevoke.Value() != revoke.Value() || parsedRevoke.Digest() != revoke.Digest() {
		t.Fatalf("revoke roundtrip: value=%+v err=%v", parsedRevoke.Value(), err)
	}
}

func TestInspectRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*InspectInput)
		code ErrorCode
	}{
		{"empty action", func(v *InspectInput) { v.ActionID = "" }, ErrorIdentity},
		{"uppercase action", func(v *InspectInput) { v.ActionID = strings.ToUpper(v.ActionID) }, ErrorIdentity},
		{"leading-zero address", func(v *InspectInput) { v.TargetIPv4 = "203.0.113.020" }, ErrorArtifact},
		{"ipv6 address", func(v *InspectInput) { v.TargetIPv4 = "2001:db8::1" }, ErrorArtifact},
		{"bad original digest", func(v *InspectInput) { v.OriginalAddDigest = "sha256:00" }, ErrorDigest},
		{"uppercase schema digest", func(v *InspectInput) { v.OwnedSchemaDigest = strings.ToUpper(v.OwnedSchemaDigest) }, ErrorDigest},
		{"unknown purpose", func(v *InspectInput) { v.Purpose = "add" }, ErrorArtifact},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInspectInput()
			test.edit(&input)
			_, err := CheckInspectArtifact(input)
			if !IsCode(err, test.code) {
				t.Fatalf("err=%v, want %s", err, test.code)
			}
		})
	}
}

func TestInspectStrictParsing(t *testing.T) {
	valid := vectorInspectJCS
	cases := []struct {
		name string
		data []byte
		code ErrorCode
	}{
		{"leading whitespace", []byte(" " + valid), ErrorCanonical},
		{"trailing newline", []byte(valid + "\n"), ErrorCanonical},
		{"schema order", []byte(`{"schema_version":"nft-inspect-v1","operation":"inspect","action_id":"` + vectorActionID + `","target_ipv4":"` + vectorTargetIPv4 + `","original_add_digest":"` + vectorOriginalAddDigest + `","owned_schema_digest":"` + vectorOwnedDigest + `","purpose":"reconciliation"}`), ErrorCanonical},
		{"unknown field", []byte(strings.Replace(valid, `{"action_id":`, `{"authority":"add","action_id":`, 1)), ErrorEncoding},
		{"duplicate field", []byte(strings.Replace(valid, `{"action_id":"`+vectorActionID+`"`, `{"action_id":"`+vectorActionID+`","action_id":"`+vectorActionID+`"`, 1)), ErrorEncoding},
		{"delete operation", []byte(strings.Replace(valid, `"operation":"inspect"`, `"operation":"delete"`, 1)), ErrorSchema},
		{"additional statement", []byte(valid + "; delete element inet x y { 1.2.3.4 }"), ErrorEncoding},
		{"invalid utf8", []byte{0xff, 0xfe}, ErrorEncoding},
		{"oversized", bytes.Repeat([]byte{'x'}, MaxInspectArtifactBytes+1), ErrorEncoding},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCanonicalInspectArtifact(test.data)
			if !IsCode(err, test.code) {
				t.Fatalf("err=%v, want %s", err, test.code)
			}
		})
	}
}

func TestAuthorizationRejectsInvalidInputs(t *testing.T) {
	inspect := checkedVectorInspect(t)
	tests := []struct {
		name string
		edit func(*InspectionAuthorizationInput)
		code ErrorCode
	}{
		{"unchecked inspect", func(v *InspectionAuthorizationInput) { v.Inspect = CheckedInspectArtifact{} }, ErrorUnchecked},
		{"authorization identity", func(v *InspectionAuthorizationInput) { v.AuthorizationID = "bad" }, ErrorIdentity},
		{"policy identity", func(v *InspectionAuthorizationInput) { v.PolicyID = "bad" }, ErrorIdentity},
		{"zero policy version", func(v *InspectionAuthorizationInput) { v.PolicyVersion = 0 }, ErrorSchema},
		{"large policy version", func(v *InspectionAuthorizationInput) { v.PolicyVersion = math.MaxInt32 + 1 }, ErrorSchema},
		{"original authorization digest", func(v *InspectionAuthorizationInput) { v.OriginalAuthorizationDigest = "bad" }, ErrorDigest},
		{"evidence digest", func(v *InspectionAuthorizationInput) { v.EvidenceSnapshotDigest = "bad" }, ErrorDigest},
		{"validation digest", func(v *InspectionAuthorizationInput) { v.ValidationSnapshotDigest = "bad" }, ErrorDigest},
		{"idempotency digest", func(v *InspectionAuthorizationInput) { v.IdempotencyKeyDigest = "bad" }, ErrorDigest},
		{"empty scheduler", func(v *InspectionAuthorizationInput) { v.SchedulerID = "" }, ErrorSchema},
		{"uppercase scheduler", func(v *InspectionAuthorizationInput) { v.SchedulerID = "Reconciler" }, ErrorSchema},
		{"long scheduler", func(v *InspectionAuthorizationInput) { v.SchedulerID = strings.Repeat("a", 129) }, ErrorSchema},
		{"zero requested time", func(v *InspectionAuthorizationInput) { v.RequestedAt = time.Time{} }, ErrorTime},
		{"equal validity", func(v *InspectionAuthorizationInput) { v.ValidUntil = v.RequestedAt }, ErrorTime},
		{"reverse validity", func(v *InspectionAuthorizationInput) { v.ValidUntil = v.RequestedAt.Add(-time.Nanosecond) }, ErrorTime},
		{"over five minutes", func(v *InspectionAuthorizationInput) {
			v.ValidUntil = v.RequestedAt.Add(5*time.Minute + time.Nanosecond)
		}, ErrorTime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validAuthorizationInput(inspect)
			test.edit(&input)
			_, err := CheckInspectionAuthorization(input)
			if !IsCode(err, test.code) {
				t.Fatalf("err=%v, want %s", err, test.code)
			}
		})
	}

	input := validAuthorizationInput(inspect)
	input.ValidUntil = input.RequestedAt.Add(MaxAuthorizationValidity)
	if _, err := CheckInspectionAuthorization(input); err != nil {
		t.Fatalf("exact five-minute validity rejected: %v", err)
	}
}

func TestAuthorizationBindsEveryInspectField(t *testing.T) {
	inspect := checkedVectorInspect(t)
	mutations := []struct {
		name string
		old  string
		new  string
	}{
		{"action", vectorActionID, "019b0000-0000-7000-8000-000000000299"},
		{"target", vectorTargetIPv4, "203.0.113.21"},
		{"original add", vectorOriginalAddDigest, "sha256:" + strings.Repeat("0", 64)},
		{"artifact", vectorInspectDigest, "sha256:" + strings.Repeat("1", 64)},
		{"owned schema", vectorOwnedDigest, "sha256:" + strings.Repeat("2", 64)},
		{"purpose", "reconciliation", "expiry_confirmation"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			data := []byte(strings.Replace(vectorAuthorizationJCS, mutation.old, mutation.new, 1))
			_, err := ParseCanonicalInspectionAuthorization(data, inspect)
			if !IsCode(err, ErrorBinding) {
				t.Fatalf("err=%v, want binding failure", err)
			}
		})
	}
}

func TestAuthorizationStrictParsingAndCompleteShape(t *testing.T) {
	inspect := checkedVectorInspect(t)
	valid := vectorAuthorizationJCS
	cases := []struct {
		name string
		data []byte
		code ErrorCode
	}{
		{"leading whitespace", []byte(" " + valid), ErrorCanonical},
		{"trailing newline", []byte(valid + "\n"), ErrorCanonical},
		{"unknown field", []byte(strings.Replace(valid, `{"action_id":`, `{"hil_nonce":"forbidden","action_id":`, 1)), ErrorEncoding},
		{"duplicate field", []byte(strings.Replace(valid, `{"action_id":"`+vectorActionID+`"`, `{"action_id":"`+vectorActionID+`","action_id":"`+vectorActionID+`"`, 1)), ErrorEncoding},
		{"offset time", []byte(strings.Replace(valid, "2026-07-18T02:20:00.000Z", "2026-07-18T02:20:00+00:00", 1)), ErrorTime},
		{"missing fraction", []byte(strings.Replace(valid, "2026-07-18T02:20:00.000Z", "2026-07-18T02:20:00Z", 1)), ErrorTime},
		{"redundant fraction", []byte(strings.Replace(valid, "2026-07-18T02:20:00.000Z", "2026-07-18T02:20:00.0000Z", 1)), ErrorTime},
		{"invalid scheduler", []byte(strings.Replace(valid, `"scheduler_id":"reconciler"`, `"scheduler_id":"Reconciler"`, 1)), ErrorSchema},
		{"missing idempotency", []byte(strings.Replace(valid, `"idempotency_key_digest":"`+vectorIdempotencyDigest+`",`, "", 1)), ErrorDigest},
		{"oversized", bytes.Repeat([]byte{'x'}, MaxAuthorizationBytes+1), ErrorEncoding},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCanonicalInspectionAuthorization(test.data, inspect)
			if !IsCode(err, test.code) {
				t.Fatalf("err=%v, want %s", err, test.code)
			}
		})
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &object); err != nil {
		t.Fatal(err)
	}
	if len(object) != 17 {
		t.Fatalf("authorization fields=%d, want 17", len(object))
	}
}

func TestAuthorizationCanonicalUTCNanoTime(t *testing.T) {
	inspect := checkedVectorInspect(t)
	input := validAuthorizationInput(inspect)
	zone := time.FixedZone("example", 9*60*60)
	input.RequestedAt = time.Date(2026, 7, 18, 11, 20, 0, 123400000, zone)
	input.ValidUntil = input.RequestedAt.Add(2500*time.Millisecond + 500*time.Nanosecond)
	checked, err := CheckInspectionAuthorization(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(checked.CanonicalBytes())
	if !strings.Contains(canonical, `"requested_at":"2026-07-18T02:20:00.1234Z"`) ||
		!strings.Contains(canonical, `"valid_until":"2026-07-18T02:20:02.6234005Z"`) {
		t.Fatalf("non-canonical UTC nano times: %s", canonical)
	}
	if _, err := ParseCanonicalInspectionAuthorization(checked.CanonicalBytes(), inspect); err != nil {
		t.Fatalf("nano time roundtrip: %v", err)
	}
}

func TestRevokeRejectsGeneralNFTAndShellSurface(t *testing.T) {
	invalidTargets := []string{"", "203.0.113.020", "2001:db8::1", "203.0.113.20;flush ruleset"}
	for _, target := range invalidTargets {
		if _, err := CheckRevokeArtifact(target); !IsCode(err, ErrorArtifact) {
			t.Fatalf("target %q err=%v", target, err)
		}
	}
	invalidArtifacts := []string{
		strings.TrimSuffix(vectorRevokeArtifact, "\n"),
		vectorRevokeArtifact + "\n",
		"delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20, 203.0.113.21 }\n",
		"delete element ip sentinelflow blacklist_ipv4 { 203.0.113.20 }\n",
		"delete set inet sentinelflow blacklist_ipv4\n",
		"flush ruleset\n",
		vectorRevokeArtifact + "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1h }\n",
		"sh -c '" + strings.TrimSpace(vectorRevokeArtifact) + "'\n",
	}
	for _, artifact := range invalidArtifacts {
		if _, err := ParseCanonicalRevokeArtifact([]byte(artifact)); err == nil {
			t.Fatalf("unsafe revoke accepted: %q", artifact)
		}
	}
}

func TestReturnedBytesAreIndependentAndConcurrentSafe(t *testing.T) {
	inspect := checkedVectorInspect(t)
	authorization := checkedVectorAuthorization(t, inspect)
	revoke, err := CheckRevokeArtifact(vectorTargetIPv4)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{vectorInspectJCS, vectorAuthorizationJCS, vectorRevokeArtifact}
	accessors := []func() []byte{inspect.CanonicalBytes, authorization.CanonicalBytes, revoke.CanonicalBytes}

	for index, accessor := range accessors {
		first := accessor()
		first[0] ^= 0xff
		if got := string(accessor()); got != expected[index] {
			t.Fatalf("accessor %d exposed mutable backing bytes", index)
		}
	}

	var wait sync.WaitGroup
	errors := make(chan string, 64)
	for worker := 0; worker < 64; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 200; iteration++ {
				for index, accessor := range accessors {
					value := accessor()
					if string(value) != expected[index] {
						errors <- "concurrent canonical read drift"
						return
					}
					value[len(value)-1] ^= 0xff
				}
				if authorization.InspectArtifact().Digest() != vectorInspectDigest {
					errors <- "concurrent inspect binding drift"
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for failure := range errors {
		t.Fatal(failure)
	}
}

func TestCheckedArtifactFormattingIsContentFree(t *testing.T) {
	inspect := checkedVectorInspect(t)
	authorization := checkedVectorAuthorization(t, inspect)
	revoke, err := CheckRevokeArtifact(vectorTargetIPv4)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "inspect",
			value: inspect,
			want:  "lifecycleartifact.CheckedInspectArtifact{artifact:[REDACTED]}",
		},
		{
			name:  "inspection authorization",
			value: authorization,
			want:  "lifecycleartifact.CheckedInspectionAuthorization{artifact:[REDACTED]}",
		},
		{
			name:  "revoke",
			value: revoke,
			want:  "lifecycleartifact.CheckedRevokeArtifact{artifact:[REDACTED]}",
		},
	}
	forbidden := []string{
		vectorInspectJCS,
		vectorAuthorizationJCS,
		vectorRevokeArtifact,
		vectorTargetIPv4,
		vectorActionID,
		vectorPolicyID,
		vectorAuthorizationID,
		vectorOriginalAddDigest,
		vectorOriginalAuth,
		vectorEvidenceDigest,
		vectorValidationDigest,
		vectorOwnedDigest,
		vectorIdempotencyDigest,
		vectorInspectDigest,
		vectorAuthorizationHash,
		vectorRevokeDigest,
		"reconciler",
		"delete element",
	}
	formats := []string{"%v", "%+v", "%#v"}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range formats {
				formatted := fmt.Sprintf(format, test.value)
				if formatted != test.want {
					t.Fatalf("format %q = %q, want %q", format, formatted, test.want)
				}
				for _, sensitive := range forbidden {
					if strings.Contains(formatted, sensitive) {
						t.Fatalf("format %q exposed %q in %q", format, sensitive, formatted)
					}
				}
			}
		})
	}
}

func TestSingleByteMutationsCannotPreserveDigest(t *testing.T) {
	inspect := checkedVectorInspect(t)
	authorization := checkedVectorAuthorization(t, inspect)
	revoke, err := CheckRevokeArtifact(vectorTargetIPv4)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		bytes  []byte
		digest string
		parse  func([]byte) (string, error)
	}{
		{"inspect", inspect.CanonicalBytes(), inspect.Digest(), func(data []byte) (string, error) {
			parsed, err := ParseCanonicalInspectArtifact(data)
			return parsed.Digest(), err
		}},
		{"authorization", authorization.CanonicalBytes(), authorization.Digest(), func(data []byte) (string, error) {
			parsed, err := ParseCanonicalInspectionAuthorization(data, inspect)
			return parsed.Digest(), err
		}},
		{"revoke", revoke.CanonicalBytes(), revoke.Digest(), func(data []byte) (string, error) {
			parsed, err := ParseCanonicalRevokeArtifact(data)
			return parsed.Digest(), err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index := range test.bytes {
				mutated := bytes.Clone(test.bytes)
				mutated[index] ^= 1
				digest, err := test.parse(mutated)
				if err == nil && digest == test.digest {
					t.Fatalf("mutation at byte %d preserved digest", index)
				}
			}
		})
	}
}
