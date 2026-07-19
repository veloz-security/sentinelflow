package capability

import "testing"

func TestReplayIdentityAndClaims(t *testing.T) {
	verified := testVerifiedAdd(t)
	identity, err := verified.ReplayIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Same(identity) {
		t.Fatal("identity is not reflexive")
	}
	if err := ValidateClaim(identity, ClaimResult{State: ClaimedUnseen, Existing: identity}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateClaim(identity, ClaimResult{State: ClaimExactRetry, Existing: identity}); err != nil {
		t.Fatal(err)
	}
	conflict := identity
	conflict.ArtifactDigest = testDigest("conflict")
	if identity.Same(conflict) {
		t.Fatal("conflicting artifact considered exact retry")
	}
	for _, result := range []ClaimResult{
		{State: ClaimExactRetry, Existing: conflict},
		{State: ClaimConflict, Existing: conflict},
		{State: "unknown"},
		{State: ClaimedUnseen, Existing: conflict},
	} {
		if err := ValidateClaim(identity, result); err == nil {
			t.Fatal("conflicting/invalid claim accepted")
		}
	}
}

func TestZeroValuesCannotAuthorize(t *testing.T) {
	if _, err := (VerifiedCapability{}).ReplayIdentity(); err == nil {
		t.Fatal("zero capability produced replay identity")
	}
	if _, err := (VerifiedCapability{}).AddAt(testCommon(OperationAdd).NotBefore); err == nil {
		t.Fatal("zero capability became executable")
	}
	if err := ValidateClaim(ReplayIdentity{}, ClaimResult{State: ClaimedUnseen}); err == nil {
		t.Fatal("zero replay identity accepted")
	}
	if _, err := (CapabilityIssuer{}).Sign(CheckedCapability{}); err == nil {
		t.Fatal("zero issuer signed zero checked value")
	}
}
