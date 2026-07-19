package lifecycleartifact

import (
	"bytes"
	"testing"
)

func FuzzParseCanonicalInspectArtifact(f *testing.F) {
	f.Add([]byte(vectorInspectJCS))
	f.Add([]byte(`{"operation":"add"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		checked, err := ParseCanonicalInspectArtifact(data)
		if err != nil {
			return
		}
		if !bytes.Equal(data, checked.CanonicalBytes()) {
			t.Fatal("accepted inspect did not roundtrip byte-exactly")
		}
		reparsed, err := ParseCanonicalInspectArtifact(checked.CanonicalBytes())
		if err != nil || reparsed.Digest() != checked.Digest() || reparsed.Value() != checked.Value() {
			t.Fatalf("accepted inspect failed stable roundtrip: %v", err)
		}
	})
}

func FuzzParseCanonicalInspectionAuthorization(f *testing.F) {
	inspect, err := CheckInspectArtifact(validInspectInput())
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(vectorAuthorizationJCS))
	f.Add([]byte(`{"schema_version":"inspection-authorization-v1"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		checked, err := ParseCanonicalInspectionAuthorization(data, inspect)
		if err != nil {
			return
		}
		if !bytes.Equal(data, checked.CanonicalBytes()) {
			t.Fatal("accepted authorization did not roundtrip byte-exactly")
		}
		reparsed, err := ParseCanonicalInspectionAuthorization(checked.CanonicalBytes(), inspect)
		if err != nil || reparsed.Digest() != checked.Digest() || reparsed.Value() != checked.Value() {
			t.Fatalf("accepted authorization failed stable roundtrip: %v", err)
		}
	})
}

func FuzzParseCanonicalRevokeArtifact(f *testing.F) {
	f.Add([]byte(vectorRevokeArtifact))
	f.Add([]byte("flush ruleset\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		checked, err := ParseCanonicalRevokeArtifact(data)
		if err != nil {
			return
		}
		if !bytes.Equal(data, checked.CanonicalBytes()) {
			t.Fatal("accepted revoke did not roundtrip byte-exactly")
		}
		reparsed, err := ParseCanonicalRevokeArtifact(checked.CanonicalBytes())
		if err != nil || reparsed.Digest() != checked.Digest() || reparsed.Value() != checked.Value() {
			t.Fatalf("accepted revoke failed stable roundtrip: %v", err)
		}
	})
}
