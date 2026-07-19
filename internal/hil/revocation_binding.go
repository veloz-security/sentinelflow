package hil

import (
	"bytes"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

// RevocationBindingInput is the immutable lifecycle state that must already be
// eligible for administrator revocation. It deliberately carries no add
// command or add-authority accessor.
type RevocationBindingInput struct {
	ActionID                 string
	ActionVersion            uint32
	TargetIPv4               string
	OriginalAddDigest        string
	PolicyDigest             string
	EvidenceSnapshotDigest   string
	ValidationSnapshotDigest string
	EligibilityValidUntil    time.Time
	Session                  SessionBinding
	IdempotencyKeyDigest     string
	Artifact                 lifecycleartifact.CheckedRevokeArtifact
}

func (RevocationBindingInput) String() string {
	return "hil.RevocationBindingInput{artifact:[REDACTED]}"
}
func (i RevocationBindingInput) GoString() string { return i.String() }

// CheckedRevocationBinding is a checked, byte-exact handoff from lifecycle
// state into the revoke-only HIL path. Its zero value is invalid.
type CheckedRevocationBinding struct {
	actionID                 string
	actionVersion            uint32
	targetIPv4               string
	originalAddDigest        string
	policyDigest             string
	evidenceSnapshotDigest   string
	validationSnapshotDigest string
	eligibilityValidUntil    time.Time
	session                  SessionBinding
	idempotencyKeyDigest     string
	artifact                 lifecycleartifact.CheckedRevokeArtifact
}

func (CheckedRevocationBinding) String() string {
	return "hil.CheckedRevocationBinding{artifact:[REDACTED]}"
}
func (b CheckedRevocationBinding) GoString() string { return b.String() }

func (b CheckedRevocationBinding) ActionID() string               { return b.actionID }
func (b CheckedRevocationBinding) ActionVersion() uint32          { return b.actionVersion }
func (b CheckedRevocationBinding) TargetIPv4() string             { return b.targetIPv4 }
func (b CheckedRevocationBinding) OriginalAddDigest() string      { return b.originalAddDigest }
func (b CheckedRevocationBinding) PolicyDigest() string           { return b.policyDigest }
func (b CheckedRevocationBinding) EvidenceSnapshotDigest() string { return b.evidenceSnapshotDigest }
func (b CheckedRevocationBinding) ValidationSnapshotDigest() string {
	return b.validationSnapshotDigest
}
func (b CheckedRevocationBinding) EligibilityValidUntil() time.Time {
	return b.eligibilityValidUntil
}
func (b CheckedRevocationBinding) RevokeArtifactDigest() string { return b.artifact.Digest() }
func (b CheckedRevocationBinding) RevokeArtifactBytes() []byte  { return b.artifact.CanonicalBytes() }

// CheckRevocationBinding reparses the checked lifecycle artifact instead of
// trusting its Go wrapper. This rejects zero values and inconsistent/forged
// checked values before any HIL artifact can inherit their authority.
func CheckRevocationBinding(input RevocationBindingInput) (CheckedRevocationBinding, error) {
	artifact, err := recheckRevokeArtifact(input.Artifact)
	if err != nil {
		return CheckedRevocationBinding{}, err
	}
	if !validUUID(input.ActionID) || input.ActionVersion == 0 || input.ActionVersion > 2_147_483_647 ||
		!validCanonicalIPv4(input.TargetIPv4) {
		return CheckedRevocationBinding{}, reject(ErrorField)
	}
	for _, digest := range [...]string{
		input.OriginalAddDigest, input.PolicyDigest, input.EvidenceSnapshotDigest,
		input.ValidationSnapshotDigest, input.IdempotencyKeyDigest,
	} {
		if !validDigest(digest) {
			return CheckedRevocationBinding{}, reject(ErrorDigest)
		}
	}
	eligibleUntil, ok := normalizedTime(input.EligibilityValidUntil)
	if !ok {
		return CheckedRevocationBinding{}, reject(ErrorTime)
	}
	session, err := normalizeRevocationSession(input.Session)
	if err != nil {
		return CheckedRevocationBinding{}, err
	}
	if artifact.Value().TargetIPv4 != input.TargetIPv4 {
		return CheckedRevocationBinding{}, reject(ErrorArtifactMismatch)
	}
	return CheckedRevocationBinding{
		actionID:                 input.ActionID,
		actionVersion:            input.ActionVersion,
		targetIPv4:               input.TargetIPv4,
		originalAddDigest:        input.OriginalAddDigest,
		policyDigest:             input.PolicyDigest,
		evidenceSnapshotDigest:   input.EvidenceSnapshotDigest,
		validationSnapshotDigest: input.ValidationSnapshotDigest,
		eligibilityValidUntil:    eligibleUntil,
		session:                  session,
		idempotencyKeyDigest:     input.IdempotencyKeyDigest,
		artifact:                 artifact,
	}, nil
}

func normalizeRevocationSession(value SessionBinding) (SessionBinding, error) {
	if !validUUID(value.SessionID) || !validDigest(value.SessionDigest) ||
		!actorIDPattern.MatchString(value.ActorID) {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	authenticatedAt, authOK := normalizedTime(value.AuthenticatedAt)
	expiresAt, expiryOK := normalizedTime(value.ExpiresAt)
	if !authOK || !expiryOK || !expiresAt.After(authenticatedAt) {
		return SessionBinding{}, reject(ErrorAuthentication)
	}
	value.AuthenticatedAt = authenticatedAt
	value.ExpiresAt = expiresAt
	return value, nil
}

func recheckRevokeArtifact(value lifecycleartifact.CheckedRevokeArtifact) (lifecycleartifact.CheckedRevokeArtifact, error) {
	canonical := value.CanonicalBytes()
	parsed, err := lifecycleartifact.ParseCanonicalRevokeArtifact(canonical)
	if err != nil || len(canonical) == 0 || !digestEqual(parsed.Digest(), value.Digest()) ||
		!bytes.Equal(parsed.CanonicalBytes(), canonical) || parsed.Value() != value.Value() {
		return lifecycleartifact.CheckedRevokeArtifact{}, reject(ErrorArtifact)
	}
	return parsed, nil
}

func recheckRevocationBinding(value CheckedRevocationBinding) (CheckedRevocationBinding, error) {
	checked, err := CheckRevocationBinding(RevocationBindingInput{
		ActionID:                 value.actionID,
		ActionVersion:            value.actionVersion,
		TargetIPv4:               value.targetIPv4,
		OriginalAddDigest:        value.originalAddDigest,
		PolicyDigest:             value.policyDigest,
		EvidenceSnapshotDigest:   value.evidenceSnapshotDigest,
		ValidationSnapshotDigest: value.validationSnapshotDigest,
		EligibilityValidUntil:    value.eligibilityValidUntil,
		Session:                  value.session,
		IdempotencyKeyDigest:     value.idempotencyKeyDigest,
		Artifact:                 value.artifact,
	})
	if err != nil {
		return CheckedRevocationBinding{}, err
	}
	return checked, nil
}

// CheckedRevocationChallenge binds a canonical revoke challenge to one exact
// lifecycle action and one exact delete artifact. Its zero value is invalid.
type CheckedRevocationChallenge struct {
	challenge CheckedChallenge
	binding   CheckedRevocationBinding
}

func (CheckedRevocationChallenge) String() string {
	return "hil.CheckedRevocationChallenge{artifact:[REDACTED]}"
}
func (c CheckedRevocationChallenge) GoString() string { return c.String() }

func (c CheckedRevocationChallenge) Value() Challenge       { return c.challenge.Value() }
func (c CheckedRevocationChallenge) CanonicalBytes() []byte { return c.challenge.CanonicalBytes() }
func (c CheckedRevocationChallenge) Digest() string         { return c.challenge.Digest() }
func (c CheckedRevocationChallenge) RevokeArtifactBytes() []byte {
	return c.binding.RevokeArtifactBytes()
}
func (c CheckedRevocationChallenge) RevokeArtifactDigest() string {
	return c.binding.RevokeArtifactDigest()
}
func (c CheckedRevocationChallenge) EligibilityValidUntil() time.Time {
	return c.binding.EligibilityValidUntil()
}

// BindRevocationChallenge rejects generic or forged checked values and binds
// every lifecycle identity/digest to the exact revoke wire artifact.
func BindRevocationChallenge(
	binding CheckedRevocationBinding,
	challenge CheckedChallenge,
) (CheckedRevocationChallenge, error) {
	checkedBinding, err := recheckRevocationBinding(binding)
	if err != nil {
		return CheckedRevocationChallenge{}, err
	}
	checkedChallenge, err := recheckChallenge(challenge)
	if err != nil {
		return CheckedRevocationChallenge{}, err
	}
	value := checkedChallenge.Value()
	if value.Operation != OperationRevoke || value.ResourceType != ResourceEnforcementAction ||
		value.OriginalAddDigest == nil {
		return CheckedRevocationChallenge{}, reject(ErrorChallengeMismatch)
	}
	session, err := checkSession(checkedBinding.session, value.IssuedAt)
	if err != nil {
		return CheckedRevocationChallenge{}, err
	}
	if !sameSession(session, checkedBinding.session) ||
		!digestEqual(value.SessionDigest, session.SessionDigest) ||
		!value.AuthenticatedAt.Equal(session.AuthenticatedAt) ||
		value.ExpiresAt.After(session.ExpiresAt) {
		return CheckedRevocationChallenge{}, reject(ErrorAuthentication)
	}
	eligibilityValidUntil := checkedBinding.eligibilityValidUntil
	if !eligibilityValidUntil.After(value.IssuedAt) ||
		eligibilityValidUntil.After(value.IssuedAt.Add(ChallengeLifetime)) ||
		eligibilityValidUntil.After(session.ExpiresAt) {
		return CheckedRevocationChallenge{}, reject(ErrorTime)
	}
	if value.ResourceID != checkedBinding.actionID || value.ResourceVersion != checkedBinding.actionVersion ||
		value.TargetIPv4 != checkedBinding.targetIPv4 ||
		!digestEqual(value.PolicyDigest, checkedBinding.policyDigest) ||
		!digestEqual(value.GeneratedArtifactDigest, checkedBinding.artifact.Digest()) ||
		!digestEqual(value.CanonicalArtifactDigest, checkedBinding.artifact.Digest()) ||
		!digestEqual(*value.OriginalAddDigest, checkedBinding.originalAddDigest) ||
		!digestEqual(value.EvidenceSnapshotDigest, checkedBinding.evidenceSnapshotDigest) ||
		!digestEqual(value.ValidationSnapshotDigest, checkedBinding.validationSnapshotDigest) ||
		!value.ValidationValidUntil.Equal(checkedBinding.eligibilityValidUntil) {
		return CheckedRevocationChallenge{}, reject(ErrorArtifactMismatch)
	}
	if !value.ExpiresAt.After(value.IssuedAt) ||
		value.ExpiresAt.After(checkedBinding.eligibilityValidUntil) {
		return CheckedRevocationChallenge{}, reject(ErrorTime)
	}
	return CheckedRevocationChallenge{challenge: checkedChallenge, binding: checkedBinding}, nil
}

func recheckChallenge(value CheckedChallenge) (CheckedChallenge, error) {
	canonical := value.CanonicalBytes()
	parsed, err := ParseCanonicalChallenge(canonical)
	if err != nil || len(canonical) == 0 || !digestEqual(parsed.Digest(), value.Digest()) ||
		!bytes.Equal(parsed.CanonicalBytes(), canonical) ||
		!bytes.Equal(marshalChallengeJCS(value.Value()), canonical) {
		return CheckedChallenge{}, reject(ErrorArtifact)
	}
	return parsed, nil
}

func recheckBoundRevocationChallenge(value CheckedRevocationChallenge) (CheckedRevocationChallenge, error) {
	return BindRevocationChallenge(value.binding, value.challenge)
}

// CheckedRevocationDecision is a revoke-only result. It exposes the exact
// delete bytes, but intentionally exposes neither CheckedDecision nor any
// add-command authorization accessor.
type CheckedRevocationDecision struct {
	decision        CheckedDecision
	challengeDigest string
	binding         CheckedRevocationBinding
	reasonCanonical []byte
}

func (CheckedRevocationDecision) String() string {
	return "hil.CheckedRevocationDecision{reason:[REDACTED],artifact:[REDACTED]}"
}
func (d CheckedRevocationDecision) GoString() string { return d.String() }

func (d CheckedRevocationDecision) Value() Decision        { return d.decision.Value() }
func (d CheckedRevocationDecision) CanonicalBytes() []byte { return d.decision.CanonicalBytes() }
func (d CheckedRevocationDecision) Digest() string         { return d.decision.Digest() }
func (d CheckedRevocationDecision) ChallengeDigest() string {
	return d.challengeDigest
}
func (d CheckedRevocationDecision) ReasonCanonicalBytes() []byte {
	return bytes.Clone(d.reasonCanonical)
}
func (d CheckedRevocationDecision) RevokeArtifactBytes() []byte {
	return d.binding.RevokeArtifactBytes()
}
func (d CheckedRevocationDecision) RevokeArtifactDigest() string {
	return d.binding.RevokeArtifactDigest()
}
func (d CheckedRevocationDecision) EligibilityValidUntil() time.Time {
	return d.binding.EligibilityValidUntil()
}

// RevokesAt reports only revoke authority and is false at the exclusive
// decision/eligibility boundary. It can never authorize an add operation.
func (d CheckedRevocationDecision) RevokesAt(now time.Time) bool {
	value := d.decision.Value()
	now, ok := normalizedTime(now)
	return ok && value.Operation == OperationRevoke && value.Decision == DecisionRevoked &&
		value.ResourceType == ResourceEnforcementAction && value.OriginalAddDigest != nil &&
		len(d.reasonCanonical) > 0 && len(d.binding.RevokeArtifactBytes()) > 0 &&
		!now.Before(value.DecidedAt) && now.Before(value.DecisionValidUntil) &&
		now.Before(d.binding.eligibilityValidUntil) &&
		digestEqual(digestBytes(d.reasonCanonical), value.ReasonDigest) &&
		digestEqual(digestBytes(d.binding.RevokeArtifactBytes()), value.CanonicalArtifactDigest) &&
		digestEqual(value.GeneratedArtifactDigest, value.CanonicalArtifactDigest)
}

// BindRevocationDecision binds an already-consumed generic decision to the
// exact challenge, nonce, session digest, lifecycle fields, checked reason,
// and revoke eligibility horizon. Atomic consumption remains a persistence
// responsibility; this function grants no replay database authority.
func BindRevocationDecision(
	challenge CheckedRevocationChallenge,
	decision CheckedDecision,
	reason CheckedReason,
) (CheckedRevocationDecision, error) {
	checkedChallenge, err := recheckBoundRevocationChallenge(challenge)
	if err != nil {
		return CheckedRevocationDecision{}, err
	}
	checkedDecision, err := recheckDecision(decision)
	if err != nil {
		return CheckedRevocationDecision{}, err
	}
	checkedReason, err := recheckReason(reason)
	if err != nil {
		return CheckedRevocationDecision{}, err
	}
	challengeValue := checkedChallenge.Value()
	decisionValue := checkedDecision.Value()
	if decisionValue.Operation != OperationRevoke || decisionValue.Decision != DecisionRevoked ||
		decisionValue.ResourceType != ResourceEnforcementAction || decisionValue.OriginalAddDigest == nil ||
		decisionValue.ChallengeID != challengeValue.ChallengeID {
		return CheckedRevocationDecision{}, reject(ErrorChallengeMismatch)
	}
	if !digestEqual(decisionValue.SessionDigest, challengeValue.SessionDigest) {
		return CheckedRevocationDecision{}, reject(ErrorAuthentication)
	}
	if decisionValue.ActorID != checkedChallenge.binding.session.ActorID ||
		!digestEqual(decisionValue.SessionDigest, checkedChallenge.binding.session.SessionDigest) {
		return CheckedRevocationDecision{}, reject(ErrorAuthentication)
	}
	if !digestEqual(decisionValue.NonceDigest, challengeValue.NonceDigest) {
		return CheckedRevocationDecision{}, reject(ErrorNonce)
	}
	if decisionValue.ResourceID != challengeValue.ResourceID ||
		decisionValue.ResourceVersion != challengeValue.ResourceVersion ||
		decisionValue.TargetIPv4 != challengeValue.TargetIPv4 ||
		!digestEqual(decisionValue.PolicyDigest, challengeValue.PolicyDigest) ||
		!digestEqual(decisionValue.GeneratedArtifactDigest, challengeValue.GeneratedArtifactDigest) ||
		!digestEqual(decisionValue.CanonicalArtifactDigest, challengeValue.CanonicalArtifactDigest) ||
		!digestEqual(*decisionValue.OriginalAddDigest, *challengeValue.OriginalAddDigest) ||
		!digestEqual(decisionValue.EvidenceSnapshotDigest, challengeValue.EvidenceSnapshotDigest) ||
		!digestEqual(decisionValue.ValidationSnapshotDigest, challengeValue.ValidationSnapshotDigest) {
		return CheckedRevocationDecision{}, reject(ErrorArtifactMismatch)
	}
	if !digestEqual(decisionValue.ReasonDigest, checkedReason.Digest()) {
		return CheckedRevocationDecision{}, reject(ErrorReason)
	}
	if !digestEqual(decisionValue.IdempotencyKeyDigest, checkedChallenge.binding.idempotencyKeyDigest) {
		return CheckedRevocationDecision{}, reject(ErrorIdempotency)
	}
	if decisionValue.DecidedAt.Before(challengeValue.IssuedAt) {
		return CheckedRevocationDecision{}, reject(ErrorTime)
	}
	if !decisionValue.DecidedAt.Before(challengeValue.ExpiresAt) ||
		!decisionValue.DecidedAt.Before(checkedChallenge.binding.eligibilityValidUntil) {
		return CheckedRevocationDecision{}, reject(ErrorChallengeExpired)
	}
	if decisionValue.DecisionValidUntil.After(challengeValue.ExpiresAt) ||
		decisionValue.DecisionValidUntil.After(checkedChallenge.binding.eligibilityValidUntil) {
		return CheckedRevocationDecision{}, reject(ErrorTime)
	}
	return CheckedRevocationDecision{
		decision:        checkedDecision,
		challengeDigest: checkedChallenge.Digest(),
		binding:         checkedChallenge.binding,
		reasonCanonical: checkedReason.CanonicalBytes(),
	}, nil
}

func recheckDecision(value CheckedDecision) (CheckedDecision, error) {
	canonical := value.CanonicalBytes()
	parsed, err := ParseCanonicalDecision(canonical)
	if err != nil || len(canonical) == 0 || !digestEqual(parsed.Digest(), value.Digest()) ||
		!bytes.Equal(parsed.CanonicalBytes(), canonical) ||
		!bytes.Equal(marshalDecisionJCS(value.Value()), canonical) {
		return CheckedDecision{}, reject(ErrorArtifact)
	}
	return parsed, nil
}

func recheckReason(value CheckedReason) (CheckedReason, error) {
	canonical := value.CanonicalBytes()
	parsed, err := ParseCanonicalReason(canonical)
	if err != nil || len(canonical) == 0 || !digestEqual(parsed.Digest(), value.Digest()) ||
		!bytes.Equal(parsed.CanonicalBytes(), canonical) ||
		!bytes.Equal(marshalReasonJCS(value.Value()), canonical) {
		return CheckedReason{}, reject(ErrorReason)
	}
	return parsed, nil
}
