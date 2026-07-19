package hil

import "testing"

func FuzzCanonicalArtifactParsers(f *testing.F) {
	f.Add(uint8(0), []byte(`{"reason_code":"other","reason_text":"ok","schema_version":"hil-reason-v1"}`))
	f.Add(uint8(1), []byte(`{"schema_version":"hil-challenge-v1"}`))
	f.Add(uint8(2), []byte(`{"schema_version":"hil-decision-v1"}`))
	if challenge, err := CheckChallenge(revokeChallengeFixture()); err == nil {
		f.Add(uint8(1), challenge.CanonicalBytes())
	}
	value, _, _ := revokeDecisionFixture()
	if decision, err := CheckDecision(value); err == nil {
		f.Add(uint8(2), decision.CanonicalBytes())
	}
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		switch kind % 3 {
		case 0:
			checked, err := ParseCanonicalReason(data)
			if err == nil && !digestEqual(checked.Digest(), digestBytes(checked.CanonicalBytes())) {
				t.Fatal("reason digest mismatch")
			}
		case 1:
			checked, err := ParseCanonicalChallenge(data)
			if err == nil && !digestEqual(checked.Digest(), digestBytes(checked.CanonicalBytes())) {
				t.Fatal("challenge digest mismatch")
			}
		case 2:
			checked, err := ParseCanonicalDecision(data)
			if err == nil && !digestEqual(checked.Digest(), digestBytes(checked.CanonicalBytes())) {
				t.Fatal("decision digest mismatch")
			}
		}
	})
}
