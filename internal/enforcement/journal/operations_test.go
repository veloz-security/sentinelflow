package journal

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

func TestRevokeAndInspectPermitsAreOperationSpecific(t *testing.T) {
	base := newFixture(t)
	value := base.verified.Value()
	common := commonFromValue(value)
	original := testDigest("original-add")

	revokeChecked, err := capability.CheckRevoke(capability.Revoke{
		Common: common, OriginalAddDigest: original,
		CanonicalDelete: []byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	revokeSigned, _ := base.issuer.Sign(revokeChecked)
	revokeVerified, _ := base.capVerifier.Verify(revokeSigned)
	revokeFixture := base
	revokeFixture.signed, revokeFixture.verified = revokeSigned, revokeVerified
	revokeJournal, err := Open(revokeFixture.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	revokeOutcome, err := revokeJournal.Begin(revokeSigned, base.received, base.deadline)
	if err != nil {
		t.Fatal(err)
	}
	revokePermit, _ := revokeOutcome.Permit()
	if _, err := revokePermit.TakeAddAt(base.received); err == nil {
		t.Fatal("revoke permit released add")
	}
	revoke, err := revokePermit.TakeRevokeAt(base.received)
	if err != nil || !bytes.HasPrefix(revoke.CanonicalDelete(), []byte("delete element")) {
		t.Fatalf("revoke permit failed: %v", err)
	}
	revokeJournal.Close()

	inspectArtifact := capability.InspectArtifact{
		SchemaVersion: capability.InspectSchemaVersion, ActionID: common.ActionID,
		TargetIPv4: common.TargetIPv4, OriginalAddDigest: original,
		OwnedSchemaDigest: common.OwnedSchemaDigest, Purpose: "reconciliation",
	}
	inspectChecked, err := capability.CheckInspect(capability.Inspect{Common: common, OriginalAddDigest: original, Artifact: inspectArtifact})
	if err != nil {
		t.Fatal(err)
	}
	inspectSigned, _ := base.issuer.Sign(inspectChecked)
	inspectVerified, _ := base.capVerifier.Verify(inspectSigned)
	inspectFixture := base
	inspectFixture.signed, inspectFixture.verified = inspectSigned, inspectVerified
	inspectJournal, err := Open(inspectFixture.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer inspectJournal.Close()
	inspectOutcome, err := inspectJournal.Begin(inspectSigned, base.received, base.deadline)
	if err != nil {
		t.Fatal(err)
	}
	inspectPermit, _ := inspectOutcome.Permit()
	if _, err := inspectPermit.TakeRevokeAt(base.received); err == nil {
		t.Fatal("inspect permit released revoke")
	}
	inspect, err := inspectPermit.TakeInspectAt(base.received)
	if err != nil || inspect.Request().Purpose != "reconciliation" {
		t.Fatalf("inspect permit failed: %v", err)
	}
}

func TestAPIErrorBranchesAndRedaction(t *testing.T) {
	f := newFixture(t)
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	unseen, err := j.Lookup(f.signed)
	if err != nil || unseen.State() != StateUnseen {
		t.Fatalf("unseen lookup failed: %v", err)
	}
	if _, ok := unseen.Terminal(); ok {
		t.Fatal("unseen returned terminal")
	}
	if _, ok := unseen.Recovery(); ok {
		t.Fatal("unseen returned recovery")
	}

	badSignature := f.signed.Signature()
	badSignature[0] ^= 1
	badCapability := capability.NewUntrustedSignedCapability(f.signed.KeyID(), f.signed.CanonicalBytes(), badSignature, f.signed.ArtifactBytes())
	if _, err := j.Lookup(badCapability); err == nil {
		t.Fatal("bad capability signature accepted")
	} else {
		assertCode(t, err, ErrorVerification)
	}

	validResult := f.signedResult(t, 1, capability.ClassificationApplied, f.received, func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return f.resultSigner.SignFor(f.verified, checked)
	})
	if _, _, err := j.Complete(validResult); err == nil {
		t.Fatal("terminal without runtime start accepted")
	} else {
		assertCode(t, err, ErrorMissingStart)
	}
	badResultSignature := validResult.Signature()
	badResultSignature[0] ^= 1
	if _, _, err := j.Complete(capability.NewUntrustedSignedResult(validResult.KeyID(), validResult.ExecutorID(), validResult.CanonicalBytes(), badResultSignature)); err == nil {
		t.Fatal("bad result signature accepted")
	} else {
		assertCode(t, err, ErrorVerification)
	}

	begin, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := begin.Permit()
	wrongSequence := f.signedResult(t, 2, capability.ClassificationApplied, f.received, func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	if _, _, err := j.Complete(wrongSequence); err == nil {
		t.Fatal("wrong journal sequence accepted")
	} else {
		assertCode(t, err, ErrorVerification)
	}

	result := f.signedResult(t, 1, capability.ClassificationApplied, f.received, func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	terminal, _, err := j.Complete(result)
	if err != nil || terminal.ResultDigest() == "" {
		t.Fatalf("terminal digest missing: %v", err)
	}
	for _, value := range []any{terminal, &Recovery{verified: f.verified}} {
		formatted := fmt.Sprintf("%#v", value)
		if strings.Contains(formatted, "add element") || strings.Contains(formatted, encodeBytes(f.signed.Signature())) {
			t.Fatalf("format leaked bytes: %s", formatted)
		}
	}

	var nilError *Error
	if nilError.Error() != "executor journal rejected" {
		t.Fatal("nil error string changed")
	}
	var nilJournal *Journal
	if err := nilJournal.Close(); err != nil {
		t.Fatal(err)
	}
	var nilPermit *Permit
	if nilPermit.Value().CapabilityID != "" {
		t.Fatal("nil permit exposed value")
	}
	if _, err := nilPermit.TakeAddAt(time.Now()); err == nil {
		t.Fatal("nil permit accepted add")
	}
	if _, err := nilPermit.TakeRevokeAt(time.Now()); err == nil {
		t.Fatal("nil permit accepted revoke")
	}
	if _, err := nilPermit.TakeInspectAt(time.Now()); err == nil {
		t.Fatal("nil permit accepted inspect")
	}
	if _, err := nilPermit.SignResult(f.resultSigner, capability.CheckedResult{}); err == nil {
		t.Fatal("nil permit signed result")
	}
	var nilRecovery *Recovery
	if nilRecovery.Value().CapabilityID != "" {
		t.Fatal("nil recovery exposed value")
	}
	if ttl, ok := nilRecovery.ExpectedAddTTLSeconds(); ok || ttl != 0 {
		t.Fatal("nil recovery exposed an add TTL")
	}
	if _, err := nilRecovery.SignResult(f.resultSigner, capability.CheckedResult{}); err == nil {
		t.Fatal("nil recovery signed result")
	}
}

func TestPermitExpiredAfterDurableStartCannotExecute(t *testing.T) {
	f := newFixture(t)
	j, err := Open(f.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	outcome, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := outcome.Permit()
	if _, err := permit.TakeAddAt(f.deadline); err == nil {
		t.Fatal("deadline-inclusive execution accepted")
	} else {
		assertCode(t, err, ErrorFreshness)
	}
}

func commonFromValue(value capability.Value) capability.Common {
	return capability.Common{
		CapabilityID: value.CapabilityID, JobID: value.JobID, ActionID: value.ActionID,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, TargetIPv4: value.TargetIPv4,
		EvidenceSnapshotDigest: value.EvidenceSnapshotDigest, ValidationSnapshotDigest: value.ValidationSnapshotDigest,
		AuthorizationDigest: value.AuthorizationDigest, ActorID: value.ActorID, ReasonDigest: value.ReasonDigest,
		OwnedSchemaDigest: value.OwnedSchemaDigest, IssuedAt: value.IssuedAt, NotBefore: value.NotBefore,
		ExpiresAt: value.ExpiresAt, Nonce: value.Nonce,
	}
}
