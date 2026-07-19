package lifecycleartifact

import (
	"bytes"
	"math"
)

type authorizationWire struct {
	SchemaVersion               string `json:"schema_version"`
	AuthorizationID             string `json:"authorization_id"`
	Purpose                     string `json:"purpose"`
	ActionID                    string `json:"action_id"`
	PolicyID                    string `json:"policy_id"`
	PolicyVersion               uint32 `json:"policy_version"`
	TargetIPv4                  string `json:"target_ipv4"`
	OriginalAddDigest           string `json:"original_add_digest"`
	OriginalAuthorizationDigest string `json:"original_authorization_digest"`
	EvidenceSnapshotDigest      string `json:"evidence_snapshot_digest"`
	ValidationSnapshotDigest    string `json:"validation_snapshot_digest"`
	ArtifactDigest              string `json:"artifact_digest"`
	OwnedSchemaDigest           string `json:"owned_schema_digest"`
	SchedulerID                 string `json:"scheduler_id"`
	RequestedAt                 string `json:"requested_at"`
	ValidUntil                  string `json:"valid_until"`
	IdempotencyKeyDigest        string `json:"idempotency_key_digest"`
}

// CheckInspectionAuthorization binds a short-lived, non-HIL authority to one
// exact checked inspect artifact. It cannot accept mutation bytes or a caller-
// supplied replacement for any inspect-bound field.
func CheckInspectionAuthorization(input InspectionAuthorizationInput) (CheckedInspectionAuthorization, error) {
	if !validCheckedInspect(input.Inspect) {
		return CheckedInspectionAuthorization{}, reject(ErrorUnchecked)
	}
	requestedAt, requestedOK := normalizeTime(input.RequestedAt)
	validUntil, validOK := normalizeTime(input.ValidUntil)
	if !requestedOK || !validOK || !validUntil.After(requestedAt) ||
		validUntil.After(requestedAt.Add(MaxAuthorizationValidity)) {
		return CheckedInspectionAuthorization{}, reject(ErrorTime)
	}
	inspect := input.Inspect.Value()
	value := InspectionAuthorizationValue{
		SchemaVersion:               AuthorizationSchemaVersion,
		AuthorizationID:             input.AuthorizationID,
		Purpose:                     inspect.Purpose,
		ActionID:                    inspect.ActionID,
		PolicyID:                    input.PolicyID,
		PolicyVersion:               input.PolicyVersion,
		TargetIPv4:                  inspect.TargetIPv4,
		OriginalAddDigest:           inspect.OriginalAddDigest,
		OriginalAuthorizationDigest: input.OriginalAuthorizationDigest,
		EvidenceSnapshotDigest:      input.EvidenceSnapshotDigest,
		ValidationSnapshotDigest:    input.ValidationSnapshotDigest,
		ArtifactDigest:              input.Inspect.Digest(),
		OwnedSchemaDigest:           inspect.OwnedSchemaDigest,
		SchedulerID:                 input.SchedulerID,
		RequestedAt:                 requestedAt,
		ValidUntil:                  validUntil,
		IdempotencyKeyDigest:        input.IdempotencyKeyDigest,
	}
	if err := validateAuthorizationValue(value); err != nil {
		return CheckedInspectionAuthorization{}, err
	}
	canonical := string(marshalAuthorization(value))
	return CheckedInspectionAuthorization{
		value: value, canonical: canonical, digest: digestBytes([]byte(canonical)), inspect: input.Inspect,
	}, nil
}

// ParseCanonicalInspectionAuthorization checks exact JCS and the complete
// authorization-to-inspect binding. Alternate valid JSON encodings are not
// accepted because the authorization digest is over these exact bytes.
func ParseCanonicalInspectionAuthorization(data []byte, inspect CheckedInspectArtifact) (CheckedInspectionAuthorization, error) {
	if !validCheckedInspect(inspect) {
		return CheckedInspectionAuthorization{}, reject(ErrorUnchecked)
	}
	var wire authorizationWire
	if err := strictDecode(data, MaxAuthorizationBytes, &wire); err != nil {
		return CheckedInspectionAuthorization{}, err
	}
	if wire.SchemaVersion != AuthorizationSchemaVersion {
		return CheckedInspectionAuthorization{}, reject(ErrorSchema)
	}
	requestedAt, requestedOK := parseCanonicalTime(wire.RequestedAt)
	validUntil, validOK := parseCanonicalTime(wire.ValidUntil)
	if !requestedOK || !validOK {
		return CheckedInspectionAuthorization{}, reject(ErrorTime)
	}
	inspectValue := inspect.Value()
	if wire.Purpose != string(inspectValue.Purpose) || wire.ActionID != inspectValue.ActionID ||
		wire.TargetIPv4 != inspectValue.TargetIPv4 || wire.OriginalAddDigest != inspectValue.OriginalAddDigest ||
		wire.ArtifactDigest != inspect.Digest() || wire.OwnedSchemaDigest != inspectValue.OwnedSchemaDigest {
		return CheckedInspectionAuthorization{}, reject(ErrorBinding)
	}
	checked, err := CheckInspectionAuthorization(InspectionAuthorizationInput{
		AuthorizationID:             wire.AuthorizationID,
		PolicyID:                    wire.PolicyID,
		PolicyVersion:               wire.PolicyVersion,
		OriginalAuthorizationDigest: wire.OriginalAuthorizationDigest,
		EvidenceSnapshotDigest:      wire.EvidenceSnapshotDigest,
		ValidationSnapshotDigest:    wire.ValidationSnapshotDigest,
		SchedulerID:                 wire.SchedulerID,
		RequestedAt:                 requestedAt,
		ValidUntil:                  validUntil,
		IdempotencyKeyDigest:        wire.IdempotencyKeyDigest,
		Inspect:                     inspect,
	})
	if err != nil {
		return CheckedInspectionAuthorization{}, err
	}
	if !bytes.Equal(data, checked.CanonicalBytes()) {
		return CheckedInspectionAuthorization{}, reject(ErrorCanonical)
	}
	return checked, nil
}

func validateAuthorizationValue(value InspectionAuthorizationValue) error {
	if value.SchemaVersion != AuthorizationSchemaVersion {
		return reject(ErrorSchema)
	}
	if !uuidPattern.MatchString(value.AuthorizationID) || !uuidPattern.MatchString(value.ActionID) ||
		!uuidPattern.MatchString(value.PolicyID) {
		return reject(ErrorIdentity)
	}
	if value.PolicyVersion == 0 || value.PolicyVersion > math.MaxInt32 {
		return reject(ErrorSchema)
	}
	if !validPurpose(value.Purpose) || !validCanonicalIPv4(value.TargetIPv4) ||
		!schedulerPattern.MatchString(value.SchedulerID) {
		return reject(ErrorSchema)
	}
	for _, digest := range []string{
		value.OriginalAddDigest, value.OriginalAuthorizationDigest, value.EvidenceSnapshotDigest,
		value.ValidationSnapshotDigest, value.ArtifactDigest, value.OwnedSchemaDigest,
		value.IdempotencyKeyDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return reject(ErrorDigest)
		}
	}
	requestedAt, requestedOK := normalizeTime(value.RequestedAt)
	validUntil, validOK := normalizeTime(value.ValidUntil)
	if !requestedOK || !validOK || !requestedAt.Equal(value.RequestedAt) || !validUntil.Equal(value.ValidUntil) ||
		!validUntil.After(requestedAt) || validUntil.After(requestedAt.Add(MaxAuthorizationValidity)) {
		return reject(ErrorTime)
	}
	return nil
}

func marshalAuthorization(value InspectionAuthorizationValue) []byte {
	result := make([]byte, 0, 1600)
	result = append(result, `{"action_id":`...)
	result = appendJCSString(result, value.ActionID)
	result = append(result, `,"artifact_digest":`...)
	result = appendJCSString(result, value.ArtifactDigest)
	result = append(result, `,"authorization_id":`...)
	result = appendJCSString(result, value.AuthorizationID)
	result = append(result, `,"evidence_snapshot_digest":`...)
	result = appendJCSString(result, value.EvidenceSnapshotDigest)
	result = append(result, `,"idempotency_key_digest":`...)
	result = appendJCSString(result, value.IdempotencyKeyDigest)
	result = append(result, `,"original_add_digest":`...)
	result = appendJCSString(result, value.OriginalAddDigest)
	result = append(result, `,"original_authorization_digest":`...)
	result = appendJCSString(result, value.OriginalAuthorizationDigest)
	result = append(result, `,"owned_schema_digest":`...)
	result = appendJCSString(result, value.OwnedSchemaDigest)
	result = append(result, `,"policy_id":`...)
	result = appendJCSString(result, value.PolicyID)
	result = append(result, `,"policy_version":`...)
	result = appendUint(result, uint64(value.PolicyVersion))
	result = append(result, `,"purpose":`...)
	result = appendJCSString(result, string(value.Purpose))
	result = append(result, `,"requested_at":`...)
	result = appendJCSString(result, formatCanonicalTime(value.RequestedAt))
	result = append(result, `,"scheduler_id":`...)
	result = appendJCSString(result, value.SchedulerID)
	result = append(result, `,"schema_version":"inspection-authorization-v1","target_ipv4":`...)
	result = appendJCSString(result, value.TargetIPv4)
	result = append(result, `,"valid_until":`...)
	result = appendJCSString(result, formatCanonicalTime(value.ValidUntil))
	result = append(result, `,"validation_snapshot_digest":`...)
	result = appendJCSString(result, value.ValidationSnapshotDigest)
	return append(result, '}')
}
