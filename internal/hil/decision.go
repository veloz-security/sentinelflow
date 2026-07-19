package hil

import (
	"bytes"
	"time"
)

// Decision is the exact hil-decision-v1 wire value for policy approval,
// policy rejection, or enforcement-action revocation. Service intentionally
// creates only policy decisions; a dedicated revocation flow owns authority.
type Decision struct {
	SchemaVersion            string
	DecisionID               string
	ChallengeID              string
	SessionDigest            string
	Operation                Operation
	Decision                 DecisionValue
	ResourceType             string
	ResourceID               string
	ResourceVersion          uint32
	TargetIPv4               string
	PolicyDigest             string
	GeneratedArtifactDigest  string
	CanonicalArtifactDigest  string
	OriginalAddDigest        *string
	EvidenceSnapshotDigest   string
	ValidationSnapshotDigest string
	ActorID                  string
	ReasonDigest             string
	NonceDigest              string
	IdempotencyKeyDigest     string
	DecidedAt                time.Time
	DecisionValidUntil       time.Time
}

type CheckedDecision struct {
	value                 Decision
	canonical             []byte
	digest                string
	reasonCanonical       []byte
	canonicalCommandBytes []byte
}

func (CheckedDecision) String() string {
	return "hil.CheckedDecision{reason:[REDACTED],command:[REDACTED]}"
}
func (d CheckedDecision) GoString() string { return d.String() }

func (d CheckedDecision) Value() Decision {
	value := d.value
	if d.value.OriginalAddDigest != nil {
		copyValue := *d.value.OriginalAddDigest
		value.OriginalAddDigest = &copyValue
	}
	return value
}
func (d CheckedDecision) CanonicalBytes() []byte        { return bytes.Clone(d.canonical) }
func (d CheckedDecision) DigestInput() []byte           { return bytes.Clone(d.canonical) }
func (d CheckedDecision) Digest() string                { return d.digest }
func (d CheckedDecision) ReasonCanonicalBytes() []byte  { return bytes.Clone(d.reasonCanonical) }
func (d CheckedDecision) CanonicalCommandBytes() []byte { return bytes.Clone(d.canonicalCommandBytes) }

// AuthorizesAt is true only for a fresh policy approval with its bound command
// and reason bytes. Rejections, revocations, and zero/parsed decisions never
// authorize an add command.
func (d CheckedDecision) AuthorizesAt(now time.Time) bool {
	if d.value.Operation != OperationApprove || d.value.Decision != DecisionApproved ||
		d.value.ResourceType != ResourcePolicy || d.value.OriginalAddDigest != nil ||
		len(d.canonical) == 0 || len(d.reasonCanonical) == 0 || len(d.canonicalCommandBytes) == 0 {
		return false
	}
	now, ok := normalizedTime(now)
	return ok && !now.Before(d.value.DecidedAt) && now.Before(d.value.DecisionValidUntil) &&
		digestBytes(d.canonicalCommandBytes) == d.value.CanonicalArtifactDigest &&
		digestBytes(d.reasonCanonical) == d.value.ReasonDigest
}

func cloneDecision(value CheckedDecision) CheckedDecision {
	value.value.OriginalAddDigest = cloneOptionalString(value.value.OriginalAddDigest)
	value.canonical = bytes.Clone(value.canonical)
	value.reasonCanonical = bytes.Clone(value.reasonCanonical)
	value.canonicalCommandBytes = bytes.Clone(value.canonicalCommandBytes)
	return value
}

func CheckDecision(value Decision) (CheckedDecision, error) {
	if value.SchemaVersion != DecisionSchemaVersion || !validOperation(value.Operation) ||
		!validDecisionBranch(value.Operation, value.Decision, value.ResourceType, value.OriginalAddDigest) {
		return CheckedDecision{}, reject(ErrorSchema)
	}
	if !validUUID(value.DecisionID) || !validUUID(value.ChallengeID) || !validUUID(value.ResourceID) ||
		value.ResourceVersion == 0 || value.ResourceVersion > 2_147_483_647 ||
		!validCanonicalIPv4(value.TargetIPv4) || !actorIDPattern.MatchString(value.ActorID) {
		return CheckedDecision{}, reject(ErrorField)
	}
	for _, digest := range [...]string{
		value.SessionDigest, value.PolicyDigest, value.GeneratedArtifactDigest,
		value.CanonicalArtifactDigest, value.EvidenceSnapshotDigest,
		value.ValidationSnapshotDigest, value.ReasonDigest, value.NonceDigest,
		value.IdempotencyKeyDigest,
	} {
		if !validDigest(digest) {
			return CheckedDecision{}, reject(ErrorDigest)
		}
	}
	if value.OriginalAddDigest != nil && !validDigest(*value.OriginalAddDigest) {
		return CheckedDecision{}, reject(ErrorDigest)
	}
	if value.Operation == OperationRevoke &&
		!digestEqual(value.GeneratedArtifactDigest, value.CanonicalArtifactDigest) {
		return CheckedDecision{}, reject(ErrorArtifactMismatch)
	}
	decidedAt, ok := normalizedTime(value.DecidedAt)
	if !ok {
		return CheckedDecision{}, reject(ErrorTime)
	}
	validUntil, ok := normalizedTime(value.DecisionValidUntil)
	if !ok || !validUntil.After(decidedAt) || validUntil.After(decidedAt.Add(DecisionLifetime)) {
		return CheckedDecision{}, reject(ErrorTime)
	}
	value.DecidedAt = decidedAt
	value.DecisionValidUntil = validUntil
	value.OriginalAddDigest = cloneOptionalString(value.OriginalAddDigest)
	canonical := marshalDecisionJCS(value)
	if len(canonical) > MaxDecisionBytes {
		return CheckedDecision{}, reject(ErrorEncoding)
	}
	return CheckedDecision{value: value, canonical: canonical, digest: digestBytes(canonical)}, nil
}

type decisionWire struct {
	ActorID                  string        `json:"actor_id"`
	CanonicalArtifactDigest  string        `json:"canonical_artifact_digest"`
	ChallengeID              string        `json:"challenge_id"`
	DecidedAt                string        `json:"decided_at"`
	Decision                 DecisionValue `json:"decision"`
	DecisionID               string        `json:"decision_id"`
	DecisionValidUntil       string        `json:"decision_valid_until"`
	EvidenceSnapshotDigest   string        `json:"evidence_snapshot_digest"`
	GeneratedArtifactDigest  string        `json:"generated_artifact_digest"`
	IdempotencyKeyDigest     string        `json:"idempotency_key_digest"`
	NonceDigest              string        `json:"nonce_digest"`
	Operation                Operation     `json:"operation"`
	OriginalAddDigest        *string       `json:"original_add_digest"`
	PolicyDigest             string        `json:"policy_digest"`
	ReasonDigest             string        `json:"reason_digest"`
	ResourceID               string        `json:"resource_id"`
	ResourceType             string        `json:"resource_type"`
	ResourceVersion          uint32        `json:"resource_version"`
	SchemaVersion            string        `json:"schema_version"`
	SessionDigest            string        `json:"session_digest"`
	TargetIPv4               string        `json:"target_ipv4"`
	ValidationSnapshotDigest string        `json:"validation_snapshot_digest"`
}

func ParseCanonicalDecision(data []byte) (CheckedDecision, error) {
	var wire decisionWire
	if err := decodeStrict(data, MaxDecisionBytes, &wire); err != nil {
		return CheckedDecision{}, err
	}
	decidedAt, err := time.Parse(time.RFC3339Nano, wire.DecidedAt)
	if err != nil {
		return CheckedDecision{}, reject(ErrorTime)
	}
	validUntil, err := time.Parse(time.RFC3339Nano, wire.DecisionValidUntil)
	if err != nil {
		return CheckedDecision{}, reject(ErrorTime)
	}
	checked, err := CheckDecision(Decision{
		SchemaVersion:            wire.SchemaVersion,
		DecisionID:               wire.DecisionID,
		ChallengeID:              wire.ChallengeID,
		SessionDigest:            wire.SessionDigest,
		Operation:                wire.Operation,
		Decision:                 wire.Decision,
		ResourceType:             wire.ResourceType,
		ResourceID:               wire.ResourceID,
		ResourceVersion:          wire.ResourceVersion,
		TargetIPv4:               wire.TargetIPv4,
		PolicyDigest:             wire.PolicyDigest,
		GeneratedArtifactDigest:  wire.GeneratedArtifactDigest,
		CanonicalArtifactDigest:  wire.CanonicalArtifactDigest,
		OriginalAddDigest:        wire.OriginalAddDigest,
		EvidenceSnapshotDigest:   wire.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: wire.ValidationSnapshotDigest,
		ActorID:                  wire.ActorID,
		ReasonDigest:             wire.ReasonDigest,
		NonceDigest:              wire.NonceDigest,
		IdempotencyKeyDigest:     wire.IdempotencyKeyDigest,
		DecidedAt:                decidedAt,
		DecisionValidUntil:       validUntil,
	})
	if err != nil {
		return CheckedDecision{}, err
	}
	if !bytes.Equal(data, checked.canonical) {
		return CheckedDecision{}, reject(ErrorCanonical)
	}
	return checked, nil
}

func marshalDecisionJCS(value Decision) []byte {
	result := make([]byte, 0, 1536)
	result = append(result, `{"actor_id":`...)
	result = appendJCSString(result, value.ActorID)
	result = append(result, `,"canonical_artifact_digest":`...)
	result = appendJCSString(result, value.CanonicalArtifactDigest)
	result = append(result, `,"challenge_id":`...)
	result = appendJCSString(result, value.ChallengeID)
	result = append(result, `,"decided_at":`...)
	result = appendJCSString(result, value.DecidedAt.Format(time.RFC3339Nano))
	result = append(result, `,"decision":`...)
	result = appendJCSString(result, string(value.Decision))
	result = append(result, `,"decision_id":`...)
	result = appendJCSString(result, value.DecisionID)
	result = append(result, `,"decision_valid_until":`...)
	result = appendJCSString(result, value.DecisionValidUntil.Format(time.RFC3339Nano))
	result = append(result, `,"evidence_snapshot_digest":`...)
	result = appendJCSString(result, value.EvidenceSnapshotDigest)
	result = append(result, `,"generated_artifact_digest":`...)
	result = appendJCSString(result, value.GeneratedArtifactDigest)
	result = append(result, `,"idempotency_key_digest":`...)
	result = appendJCSString(result, value.IdempotencyKeyDigest)
	result = append(result, `,"nonce_digest":`...)
	result = appendJCSString(result, value.NonceDigest)
	result = append(result, `,"operation":`...)
	result = appendJCSString(result, string(value.Operation))
	result = append(result, `,"original_add_digest":`...)
	result = appendOptionalJCSString(result, value.OriginalAddDigest)
	result = append(result, `,"policy_digest":`...)
	result = appendJCSString(result, value.PolicyDigest)
	result = append(result, `,"reason_digest":`...)
	result = appendJCSString(result, value.ReasonDigest)
	result = append(result, `,"resource_id":`...)
	result = appendJCSString(result, value.ResourceID)
	result = append(result, `,"resource_type":`...)
	result = appendJCSString(result, value.ResourceType)
	result = append(result, `,"resource_version":`...)
	result = appendUint32(result, value.ResourceVersion)
	result = append(result, `,"schema_version":`...)
	result = appendJCSString(result, value.SchemaVersion)
	result = append(result, `,"session_digest":`...)
	result = appendJCSString(result, value.SessionDigest)
	result = append(result, `,"target_ipv4":`...)
	result = appendJCSString(result, value.TargetIPv4)
	result = append(result, `,"validation_snapshot_digest":`...)
	result = appendJCSString(result, value.ValidationSnapshotDigest)
	return append(result, '}')
}

type DecisionRequest struct {
	Operation      Operation
	Session        SessionBinding
	Artifact       ExactArtifact
	Nonce          string
	IdempotencyKey []byte
	Reason         Reason
}

func (DecisionRequest) String() string {
	return "hil.DecisionRequest{nonce:[REDACTED],idempotency_key:[REDACTED],reason:[REDACTED]}"
}
func (r DecisionRequest) GoString() string { return r.String() }

func (s *Service) Consume(guard *OneUseChallenge, request DecisionRequest) (CheckedDecision, error) {
	if s == nil || guard == nil {
		return CheckedDecision{}, reject(ErrorConfiguration)
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()

	bound := cloneBoundChallenge(guard.bound)
	fingerprint, checkedReason, nonceDigest, idempotencyDigest, staticErr := decisionFingerprint(bound, request)
	if guard.consumed != nil {
		if staticErr == nil && digestEqual(fingerprint, guard.fingerprint) {
			return cloneDecision(*guard.consumed), nil
		}
		return CheckedDecision{}, reject(ErrorConflict)
	}
	if staticErr != nil {
		return CheckedDecision{}, staticErr
	}

	now, err := s.now()
	if err != nil {
		return CheckedDecision{}, err
	}
	challengeValue := bound.artifact.value
	if now.Before(challengeValue.IssuedAt) {
		return CheckedDecision{}, reject(ErrorTime)
	}
	if !now.Before(challengeValue.ExpiresAt) {
		return CheckedDecision{}, reject(ErrorChallengeExpired)
	}
	currentSession, err := checkSession(request.Session, now)
	if err != nil {
		return CheckedDecision{}, err
	}
	if !sameSession(bound.session, currentSession) {
		return CheckedDecision{}, reject(ErrorAuthentication)
	}
	if !request.Artifact.FreshAt(now) || !bound.exact.FreshAt(now) {
		return CheckedDecision{}, reject(ErrorValidationStale)
	}

	decisionID, err := s.randomUUID()
	if err != nil {
		return CheckedDecision{}, err
	}
	decisionValue := DecisionRejected
	if request.Operation == OperationApprove {
		decisionValue = DecisionApproved
	}
	validUntil := minTime(now.Add(DecisionLifetime), challengeValue.ExpiresAt,
		bound.exact.ValidationValidUntil(), currentSession.ExpiresAt)
	if !validUntil.After(now) {
		return CheckedDecision{}, reject(ErrorChallengeExpired)
	}
	checked, err := CheckDecision(Decision{
		SchemaVersion:            DecisionSchemaVersion,
		DecisionID:               decisionID,
		ChallengeID:              challengeValue.ChallengeID,
		SessionDigest:            currentSession.SessionDigest,
		Operation:                request.Operation,
		Decision:                 decisionValue,
		ResourceType:             ResourcePolicy,
		ResourceID:               bound.exact.PolicyID(),
		ResourceVersion:          bound.exact.PolicyVersion(),
		TargetIPv4:               bound.exact.TargetIPv4(),
		PolicyDigest:             bound.exact.PolicyDigest(),
		GeneratedArtifactDigest:  bound.exact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:  bound.exact.CanonicalArtifactDigest(),
		OriginalAddDigest:        nil,
		EvidenceSnapshotDigest:   bound.exact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: bound.exact.ValidationSnapshotDigest(),
		ActorID:                  currentSession.ActorID,
		ReasonDigest:             checkedReason.Digest(),
		NonceDigest:              nonceDigest,
		IdempotencyKeyDigest:     idempotencyDigest,
		DecidedAt:                now,
		DecisionValidUntil:       validUntil,
	})
	if err != nil {
		return CheckedDecision{}, err
	}
	checked.reasonCanonical = checkedReason.CanonicalBytes()
	checked.canonicalCommandBytes = bound.exact.CanonicalBytes()
	stored := cloneDecision(checked)
	guard.consumed = &stored
	guard.fingerprint = fingerprint
	return cloneDecision(checked), nil
}

func decisionFingerprint(bound boundChallenge, request DecisionRequest) (string, CheckedReason, string, string, error) {
	if !validPolicyOperation(request.Operation) || request.Operation != bound.artifact.value.Operation {
		return "", CheckedReason{}, "", "", reject(ErrorChallengeMismatch)
	}
	if !validIdempotencyKey(request.IdempotencyKey) {
		return "", CheckedReason{}, "", "", reject(ErrorIdempotency)
	}
	idempotencyDigest := digestBytes(request.IdempotencyKey)
	if !digestEqual(idempotencyDigest, bound.idempotencyKeyDigest) {
		return "", CheckedReason{}, "", "", reject(ErrorIdempotency)
	}
	if !sameExactArtifact(bound.exact, request.Artifact) || !validExactArtifact(request.Artifact) {
		return "", CheckedReason{}, "", "", reject(ErrorArtifactMismatch)
	}
	if request.Session.SessionID != bound.session.SessionID ||
		request.Session.ActorID != bound.session.ActorID ||
		!digestEqual(request.Session.SessionDigest, bound.session.SessionDigest) ||
		!request.Session.AuthenticatedAt.Round(0).UTC().Equal(bound.session.AuthenticatedAt) ||
		!request.Session.ExpiresAt.Round(0).UTC().Equal(bound.session.ExpiresAt) {
		return "", CheckedReason{}, "", "", reject(ErrorAuthentication)
	}
	nonce, ok := canonicalNonce(request.Nonce)
	if !ok {
		return "", CheckedReason{}, "", "", reject(ErrorNonce)
	}
	nonceDigest := digestBytes(nonce)
	clear(nonce)
	if !digestEqual(nonceDigest, bound.artifact.value.NonceDigest) {
		return "", CheckedReason{}, "", "", reject(ErrorNonce)
	}
	checkedReason, err := CheckReason(request.Reason)
	if err != nil {
		return "", CheckedReason{}, "", "", err
	}

	// A compact private JCS tuple makes identical retries deterministic without
	// persisting raw nonce, idempotency key, reason, or command material.
	fingerprintBytes := make([]byte, 0, 1024)
	fingerprintBytes = append(fingerprintBytes, `{"actor_id":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, request.Session.ActorID)
	fingerprintBytes = append(fingerprintBytes, `,"challenge_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, bound.artifact.Digest())
	fingerprintBytes = append(fingerprintBytes, `,"idempotency_key_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, idempotencyDigest)
	fingerprintBytes = append(fingerprintBytes, `,"nonce_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, nonceDigest)
	fingerprintBytes = append(fingerprintBytes, `,"operation":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, string(request.Operation))
	fingerprintBytes = append(fingerprintBytes, `,"reason_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, checkedReason.Digest())
	fingerprintBytes = append(fingerprintBytes, `,"schema_version":"hil-decision-request-fingerprint-v1","session_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, request.Session.SessionDigest)
	fingerprintBytes = append(fingerprintBytes, `,"validation_snapshot_digest":`...)
	fingerprintBytes = appendJCSString(fingerprintBytes, request.Artifact.ValidationSnapshotDigest())
	fingerprintBytes = append(fingerprintBytes, '}')
	return digestBytes(fingerprintBytes), checkedReason, nonceDigest, idempotencyDigest, nil
}
