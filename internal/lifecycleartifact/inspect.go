package lifecycleartifact

import "bytes"

type inspectWire struct {
	SchemaVersion     string `json:"schema_version"`
	Operation         string `json:"operation"`
	ActionID          string `json:"action_id"`
	TargetIPv4        string `json:"target_ipv4"`
	OriginalAddDigest string `json:"original_add_digest"`
	OwnedSchemaDigest string `json:"owned_schema_digest"`
	Purpose           string `json:"purpose"`
}

// CheckInspectArtifact freezes one typed, read-only nft-inspect-v1 artifact.
func CheckInspectArtifact(input InspectInput) (CheckedInspectArtifact, error) {
	value := InspectValue{
		SchemaVersion:     InspectSchemaVersion,
		Operation:         InspectionOperation,
		ActionID:          input.ActionID,
		TargetIPv4:        input.TargetIPv4,
		OriginalAddDigest: input.OriginalAddDigest,
		OwnedSchemaDigest: input.OwnedSchemaDigest,
		Purpose:           input.Purpose,
	}
	if err := validateInspectValue(value); err != nil {
		return CheckedInspectArtifact{}, err
	}
	canonical := string(marshalInspect(value))
	return CheckedInspectArtifact{value: value, canonical: canonical, digest: digestBytes([]byte(canonical))}, nil
}

// ParseCanonicalInspectArtifact accepts only byte-exact JCS with every schema
// field present, no duplicate or unknown fields, and a fixed inspect operation.
func ParseCanonicalInspectArtifact(data []byte) (CheckedInspectArtifact, error) {
	var wire inspectWire
	if err := strictDecode(data, MaxInspectArtifactBytes, &wire); err != nil {
		return CheckedInspectArtifact{}, err
	}
	if wire.SchemaVersion != InspectSchemaVersion || wire.Operation != InspectionOperation {
		return CheckedInspectArtifact{}, reject(ErrorSchema)
	}
	checked, err := CheckInspectArtifact(InspectInput{
		ActionID:          wire.ActionID,
		TargetIPv4:        wire.TargetIPv4,
		OriginalAddDigest: wire.OriginalAddDigest,
		OwnedSchemaDigest: wire.OwnedSchemaDigest,
		Purpose:           Purpose(wire.Purpose),
	})
	if err != nil {
		return CheckedInspectArtifact{}, err
	}
	if !bytes.Equal(data, checked.CanonicalBytes()) {
		return CheckedInspectArtifact{}, reject(ErrorCanonical)
	}
	return checked, nil
}

func validateInspectValue(value InspectValue) error {
	if value.SchemaVersion != InspectSchemaVersion || value.Operation != InspectionOperation {
		return reject(ErrorSchema)
	}
	if !uuidPattern.MatchString(value.ActionID) {
		return reject(ErrorIdentity)
	}
	if !validCanonicalIPv4(value.TargetIPv4) {
		return reject(ErrorArtifact)
	}
	if !digestPattern.MatchString(value.OriginalAddDigest) || !digestPattern.MatchString(value.OwnedSchemaDigest) {
		return reject(ErrorDigest)
	}
	if !validPurpose(value.Purpose) {
		return reject(ErrorArtifact)
	}
	return nil
}

func marshalInspect(value InspectValue) []byte {
	result := make([]byte, 0, 600)
	result = append(result, `{"action_id":`...)
	result = appendJCSString(result, value.ActionID)
	result = append(result, `,"operation":"inspect","original_add_digest":`...)
	result = appendJCSString(result, value.OriginalAddDigest)
	result = append(result, `,"owned_schema_digest":`...)
	result = appendJCSString(result, value.OwnedSchemaDigest)
	result = append(result, `,"purpose":`...)
	result = appendJCSString(result, string(value.Purpose))
	result = append(result, `,"schema_version":"nft-inspect-v1","target_ipv4":`...)
	result = appendJCSString(result, value.TargetIPv4)
	return append(result, '}')
}

func validCheckedInspect(value CheckedInspectArtifact) bool {
	if validateInspectValue(value.value) != nil {
		return false
	}
	canonical := marshalInspect(value.value)
	return value.canonical != "" && bytes.Equal(canonical, []byte(value.canonical)) &&
		digestPattern.MatchString(value.digest) && digestBytes(canonical) == value.digest
}
