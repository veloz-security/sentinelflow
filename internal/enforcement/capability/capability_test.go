package capability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoldenCapabilitiesVerify(t *testing.T) {
	bundle := loadGolden(t)
	private := keyFromSeed(t, dispatchSeedHex)
	verifier, err := NewCapabilityVerifier("dispatcher-vector-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	addArtifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")
	revokeArtifact := []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n")
	inspectArtifact := marshalInspection(InspectArtifact{
		SchemaVersion: InspectSchemaVersion, ActionID: "019b0000-0000-7000-8000-000000000200",
		TargetIPv4: "203.0.113.20", OriginalAddDigest: digestBytes(addArtifact),
		OwnedSchemaDigest: "sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997",
		Purpose:           "reconciliation",
	})
	tests := []struct {
		name      string
		vector    goldenVector
		artifact  []byte
		operation Operation
		now       time.Time
	}{
		{"add", bundle.Vectors.CapabilityAdd, addArtifact, OperationAdd, time.Date(2026, 7, 18, 2, 0, 30, 0, time.UTC)},
		{"revoke", bundle.Vectors.CapabilityRevoke, revokeArtifact, OperationRevoke, time.Date(2026, 7, 18, 2, 10, 30, 0, time.UTC)},
		{"inspect", bundle.Vectors.CapabilityInspect, inspectArtifact, OperationInspect, time.Date(2026, 7, 18, 2, 20, 30, 0, time.UTC)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signed := NewUntrustedSignedCapability("dispatcher-vector-v1", decodeURL(t, test.vector.JCSB64URL), decodeURL(t, test.vector.SignatureB64URL), test.artifact)
			verified, err := verifier.Verify(signed)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Digest() != test.vector.Digest || verified.Value().Operation != test.operation {
				t.Fatalf("unexpected vector: digest=%s operation=%s", verified.Digest(), verified.Value().Operation)
			}
			switch test.operation {
			case OperationAdd:
				executable, err := verified.AddAt(test.now)
				if err != nil || executable.TTLSeconds() != 1800 || !bytes.Equal(executable.CanonicalCommand(), test.artifact) {
					t.Fatalf("add authorization failed: ttl=%d err=%v", executable.TTLSeconds(), err)
				}
			case OperationRevoke:
				executable, err := verified.RevokeAt(test.now)
				if err != nil || !bytes.Equal(executable.CanonicalDelete(), test.artifact) {
					t.Fatalf("revoke authorization failed: %v", err)
				}
			case OperationInspect:
				executable, err := verified.InspectAt(test.now)
				if err != nil || executable.Request().Purpose != "reconciliation" {
					t.Fatalf("inspect authorization failed: %v", err)
				}
			}
		})
	}
}

func TestConstructorsAndDefensiveCopies(t *testing.T) {
	command := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")
	input := Add{Common: testCommon(OperationAdd), CanonicalCommand: command}
	checked, err := CheckAdd(input)
	if err != nil {
		t.Fatal(err)
	}
	command[0] = 'X'
	firstCanonical := checked.CanonicalBytes()
	firstArtifact := checked.ArtifactBytes()
	firstCanonical[0] = 'X'
	firstArtifact[0] = 'X'
	if checked.CanonicalBytes()[0] != '{' || checked.ArtifactBytes()[0] != 'a' {
		t.Fatal("checked capability aliases caller or getter memory")
	}
	if checked.Value().Operation != OperationAdd || checked.Digest() == "" {
		t.Fatal("checked capability getters lost state")
	}

	private := keyFromSeed(t, dispatchSeedHex)
	issuer, _ := NewCapabilityIssuer("dispatch-test-v1", private)
	if issuer.KeyID() != "dispatch-test-v1" {
		t.Fatal("issuer key identity lost")
	}
	signed, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	signature := signed.Signature()
	signature[0] ^= 1
	if bytes.Equal(signature, signed.Signature()) {
		t.Fatal("signature getter aliases internal memory")
	}
	// Mutating original private-key memory after construction cannot change the issuer.
	for index := range private {
		private[index] = 0
	}
	if _, err := issuer.Sign(checked); err != nil {
		t.Fatalf("issuer did not defensively copy key: %v", err)
	}
}

func TestTypedRevokeAndInspectConstruction(t *testing.T) {
	revokeCommon := testCommon(OperationRevoke)
	original := testDigest("original add")
	revoke, err := CheckRevoke(Revoke{
		Common: revokeCommon, OriginalAddDigest: original,
		CanonicalDelete: []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"),
	})
	if err != nil || revoke.Value().Operation != OperationRevoke {
		t.Fatalf("valid revoke rejected: %v", err)
	}
	inspectCommon := testCommon(OperationInspect)
	inspectCommon.ActorID = "reconciler"
	inspect, err := CheckInspect(Inspect{
		Common: inspectCommon, OriginalAddDigest: original,
		Artifact: InspectArtifact{SchemaVersion: InspectSchemaVersion, ActionID: inspectCommon.ActionID,
			TargetIPv4: inspectCommon.TargetIPv4, OriginalAddDigest: original,
			OwnedSchemaDigest: inspectCommon.OwnedSchemaDigest, Purpose: "operator_status"},
	})
	if err != nil || inspect.Value().Operation != OperationInspect {
		t.Fatalf("valid inspect rejected: %v", err)
	}
	badInspect := Inspect{Common: inspectCommon, OriginalAddDigest: original,
		Artifact: InspectArtifact{SchemaVersion: InspectSchemaVersion, ActionID: inspectCommon.ActionID,
			TargetIPv4: "203.0.113.21", OriginalAddDigest: original,
			OwnedSchemaDigest: inspectCommon.OwnedSchemaDigest, Purpose: "operator_status"}}
	if _, err := CheckInspect(badInspect); err == nil {
		t.Fatal("mismatched inspection artifact accepted")
	}
	if _, err := CheckRevoke(Revoke{Common: revokeCommon, OriginalAddDigest: "bad", CanonicalDelete: revoke.ArtifactBytes()}); err == nil {
		t.Fatal("invalid original add digest accepted")
	}
}

func TestOperationSubstitutionRejected(t *testing.T) {
	private := keyFromSeed(t, dispatchSeedHex)
	issuer, _ := NewCapabilityIssuer("dispatch-test-v1", private)
	signed, _ := issuer.Sign(testCheckedAdd(t))
	verifier, _ := NewCapabilityVerifier("dispatch-test-v1", "executor-demo", private.Public().(ed25519.PublicKey))

	substitutions := [][]byte{
		[]byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"),
		marshalInspection(InspectArtifact{SchemaVersion: InspectSchemaVersion, ActionID: "019b0000-0000-7000-8000-000000000200", TargetIPv4: "203.0.113.20", OriginalAddDigest: testDigest("add"), OwnedSchemaDigest: testDigest("schema"), Purpose: "operator_status"}),
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 60s }\n"),
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.21 timeout 30m }\n"),
	}
	for _, artifact := range substitutions {
		_, err := verifier.Verify(NewUntrustedSignedCapability(signed.KeyID(), signed.CanonicalBytes(), signed.Signature(), artifact))
		if err == nil {
			t.Fatalf("substitution accepted: %q", artifact)
		}
	}
}

func TestStrictCanonicalParsing(t *testing.T) {
	checked := testCheckedAdd(t)
	canonical := checked.CanonicalBytes()
	artifact := checked.ArtifactBytes()

	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(object, "", "  ")
	unknown := append(canonical[:len(canonical)-1:len(canonical)-1], []byte(`,"unknown":true}`)...)
	duplicate := append([]byte(`{"action_id":"019b0000-0000-7000-8000-000000000200",`), canonical[1:]...)
	for _, input := range [][]byte{pretty, append(canonical, '\n'), unknown, duplicate, {}, bytes.Repeat([]byte{'x'}, MaxCapabilityBytes+1)} {
		if _, err := ParseCanonicalCapability(input, artifact); err == nil {
			t.Fatalf("malformed/noncanonical capability accepted: %q", input)
		}
	}
}

func TestFreshnessAndOperationTypeBoundary(t *testing.T) {
	verified := testVerifiedAdd(t)
	if verified.KeyID() == "" || verified.ExecutorID() != "executor-demo" || len(verified.CanonicalBytes()) == 0 {
		t.Fatal("verified identity getters lost state")
	}
	start := verified.Value().NotBefore
	if _, err := verified.AddAt(start.Add(-time.Nanosecond)); err == nil {
		t.Fatal("future capability accepted")
	} else {
		assertCode(t, err, ErrorNotYetValid)
	}
	if _, err := verified.AddAt(verified.Value().ExpiresAt); err == nil {
		t.Fatal("expired capability accepted")
	} else {
		assertCode(t, err, ErrorExpired)
	}
	if _, err := verified.RevokeAt(start); err == nil {
		t.Fatal("add capability converted to revoke")
	}
	if _, err := verified.InspectAt(start); err == nil {
		t.Fatal("add capability converted to inspect")
	}
}

func TestValidityIsAtMostSixtySeconds(t *testing.T) {
	common := testCommon(OperationAdd)
	common.ExpiresAt = common.IssuedAt.Add(60 * time.Second)
	if _, err := CheckAdd(Add{Common: common, CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")}); err != nil {
		t.Fatalf("exact 60 second validity rejected: %v", err)
	}
	common.ExpiresAt = common.IssuedAt.Add(60*time.Second + time.Millisecond)
	if _, err := CheckAdd(Add{Common: common, CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")}); err == nil {
		t.Fatal("validity above 60 seconds accepted")
	}
}

func TestCanonicalTimestampVariantsRejected(t *testing.T) {
	checked := testCheckedAdd(t)
	canonical := string(checked.CanonicalBytes())
	artifact := checked.ArtifactBytes()
	variants := []string{
		strings.Replace(canonical, "2026-07-18T02:00:05.000Z", "2026-07-18T02:00:05Z", 1),
		strings.Replace(canonical, "2026-07-18T02:00:05.000Z", "2026-07-18T02:00:05.0Z", 1),
		strings.Replace(canonical, "2026-07-18T02:00:05.000Z", "2026-07-18T02:00:05.0000Z", 1),
		strings.Replace(canonical, "2026-07-18T02:00:05.000Z", "2026-07-18T02:00:05.000+00:00", 1),
		strings.Replace(canonical, "2026-07-18T02:00:05.000Z", "2026-07-18T02:00:05.000001Z", 1),
	}
	for _, variant := range variants {
		if _, err := ParseCanonicalCapability([]byte(variant), artifact); err == nil {
			t.Fatalf("alternate timestamp accepted: %s", variant)
		}
	}
	common := testCommon(OperationAdd)
	common.IssuedAt = common.IssuedAt.Add(time.Microsecond)
	common.NotBefore = common.NotBefore.Add(time.Microsecond)
	if _, err := CheckAdd(Add{Common: common, CanonicalCommand: artifact}); err == nil {
		t.Fatal("sub-millisecond constructor time accepted")
	}
}

func TestKeyAndSignatureConfusionRejected(t *testing.T) {
	private := keyFromSeed(t, dispatchSeedHex)
	issuer, _ := NewCapabilityIssuer("dispatch-a", private)
	signed, _ := issuer.Sign(testCheckedAdd(t))
	verifier, _ := NewCapabilityVerifier("dispatch-b", "executor-demo", private.Public().(ed25519.PublicKey))
	if _, err := verifier.Verify(signed); err == nil {
		t.Fatal("wrong key ID accepted")
	}

	other := keyFromSeed(t, resultSeedHex)
	wrongVerifier, _ := NewCapabilityVerifier("dispatch-a", "executor-demo", other.Public().(ed25519.PublicKey))
	if _, err := wrongVerifier.Verify(signed); err == nil {
		t.Fatal("result-role key accepted as dispatch key")
	}
	mutated := signed.Signature()
	mutated[len(mutated)-1] ^= 1
	validVerifier, _ := NewCapabilityVerifier("dispatch-a", "executor-demo", private.Public().(ed25519.PublicKey))
	if _, err := validVerifier.Verify(NewUntrustedSignedCapability("dispatch-a", signed.CanonicalBytes(), mutated, signed.ArtifactBytes())); err == nil {
		t.Fatal("mutated signature accepted")
	}
}

func TestConcurrentVerificationIsRaceFree(t *testing.T) {
	private := keyFromSeed(t, dispatchSeedHex)
	issuer, _ := NewCapabilityIssuer("dispatch-test-v1", private)
	signed, _ := issuer.Sign(testCheckedAdd(t))
	verifier, _ := NewCapabilityVerifier("dispatch-test-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	var wait sync.WaitGroup
	errors := make(chan error, 64)
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			verified, err := verifier.Verify(signed)
			if err == nil {
				_, err = verified.AddAt(verified.Value().NotBefore)
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

func TestInvalidConstructionTable(t *testing.T) {
	valid := testCommon(OperationAdd)
	tests := []struct {
		name   string
		mutate func(*Common)
	}{
		{"capability id", func(c *Common) { c.CapabilityID = "no" }},
		{"version", func(c *Common) { c.PolicyVersion = 0 }},
		{"target", func(c *Common) { c.TargetIPv4 = "203.0.113.020" }},
		{"digest", func(c *Common) { c.AuthorizationDigest = "SHA256:no" }},
		{"actor", func(c *Common) { c.ActorID = "Admin" }},
		{"nonce", func(c *Common) { c.Nonce = "short" }},
		{"order", func(c *Common) { c.NotBefore = c.IssuedAt.Add(-time.Second) }},
		{"validity", func(c *Common) { c.ExpiresAt = c.IssuedAt.Add(MaxValidity + time.Nanosecond) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			common := valid
			test.mutate(&common)
			if _, err := CheckAdd(Add{Common: common, CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")}); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestInvalidKeyConstructorsAndSafeErrors(t *testing.T) {
	private := keyFromSeed(t, dispatchSeedHex)
	public := private.Public().(ed25519.PublicKey)
	if _, err := NewCapabilityIssuer("Bad", private); err == nil {
		t.Fatal("invalid issuer key ID accepted")
	}
	if _, err := NewCapabilityIssuer("valid", private[:3]); err == nil {
		t.Fatal("short private key accepted")
	}
	if _, err := NewCapabilityVerifier("valid", "Bad", public); err == nil {
		t.Fatal("invalid executor identity accepted")
	}
	if _, err := NewCapabilityVerifier("valid", "executor", public[:3]); err == nil {
		t.Fatal("short public key accepted")
	}
	if (&Error{Code: ErrorArtifact}).Error() == "" || (*Error)(nil).Error() == "" {
		t.Fatal("safe error text missing")
	}
}
